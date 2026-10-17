//! Guest marshalling for MMSYSTEM mixer ordinals 800–809.
//!
//! Guest handles are session words. The host token is never a guest address,
//! and this path does not open a physical mixer or wave device.

use std::collections::BTreeMap;

use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{
    Access, Win16MixerCaps16, Win16MixerControl16, Win16MixerControlDetails16, Win16MixerLine16,
    Win16MixerLineControls16, Win16MixerRequest, MIXERCAPS16_SIZE, MIXERCONTROL16_SIZE,
    MIXERCONTROLDETAILS16_SIZE, MIXERLINE16_SIZE, MIXERLINECONTROLS16_SIZE,
};

use super::{Win16State, guest_ranges::{GuestOutputRange, commit_guest_writes}};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMixerControl,
    Win16HostMixerControlsQuery, Win16HostMixerHandle, Win16HostMixerLine,
    Win16HostMixerLineQuery, Win16HostMixerObject, Win16HostMixerOperation, Win16HostMixerResult,
    MMSYSERR_INVALFLAG, MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM,
    MMSYSERR_NOERROR, MMSYSERR_NOMEM, MMSYSERR_NOTSUPPORTED, MIXERR_INVALCONTROL,
    MIXER_DETAILSF_LISTTEXT, MIXER_DETAILSF_VALUE, MIXER_GETLINECONTROLSF_ALL,
    MIXER_GETLINECONTROLSF_ONEBYID, MIXER_GETLINECONTROLSF_ONEBYTYPE,
    MIXER_GETLINEINFOF_COMPONENTTYPE, MIXER_GETLINEINFOF_DESTINATION, MIXER_GETLINEINFOF_LINEID,
    MIXER_GETLINEINFOF_QUERYMASK, MIXER_GETLINEINFOF_SOURCE, MIXER_GETLINEINFOF_TARGETTYPE,
    MIXER_OBJECTF_HANDLE, MIXER_OBJECTF_MASK, MIXER_SETDETAILSF_CUSTOM,
};
use compat_services::win16_multimedia::CALLBACK_TYPEMASK;

const DETAIL_VALUE_SIZE: usize = 4;

#[derive(Debug, Default)]
pub(super) struct Win16MixerState {
    next_guest: u16,
    handles: BTreeMap<u16, Win16HostMixerHandle>,
}

impl Win16MixerState {
    pub(super) fn native_sources_quiescent(&self) -> bool { self.handles.is_empty() }

    fn host_handle(&self, guest: u16) -> Option<Win16HostMixerHandle> {
        self.handles.get(&guest).copied()
    }

    fn insert(&mut self, host: Win16HostMixerHandle) -> Option<u16> {
        if self.handles.len() >= usize::from(u16::MAX) { return None; }
        let mut candidate = self.next_guest.max(1);
        for _ in 0..u16::MAX {
            if candidate != 0 && !self.handles.contains_key(&candidate) {
                self.handles.insert(candidate, host);
                self.next_guest = candidate.wrapping_add(1);
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1);
        }
        None
    }

    pub(super) fn retire_all(&mut self, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        let mut first = None;
        let guests: Vec<u16> = self.handles.keys().copied().collect();
        for guest in guests {
            let Some(handle) = self.handles.get(&guest).copied() else { continue };
            match host.win16_mixer(Win16HostMixerOperation::Close { handle }) {
                Ok(Win16HostMixerResult::Scalar(0)) => { self.handles.remove(&guest); }
                Ok(Win16HostMixerResult::Scalar(code)) => keep(&mut first, RuntimeError::new(
                    Kind::HostFailure,
                    format!("session mixer close failed during guest teardown (0x{code:08X})"),
                )),
                Ok(_) => keep(&mut first, invariant("mixer close returned the wrong result shape")),
                Err(error) => keep(&mut first, error),
            }
        }
        match first { Some(error) => Err(error), None => Ok(()) }
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn mixer_api(
        &mut self,
        request: Win16MixerRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16MixerRequest::GetNumDevs => match host.win16_mixer(
                Win16HostMixerOperation::DeviceCount,
            )? {
                Win16HostMixerResult::Count(count) => Ok(u32::from(count)),
                _ => Err(invariant("mixerGetNumDevs returned the wrong result shape")),
            },
            Win16MixerRequest::GetDevCaps { device, capabilities, size } => {
                self.device_caps(device, capabilities, size, memory, host)
            }
            Win16MixerRequest::Open { handle_out, device, callback, instance, flags } => {
                self.mixer_open(handle_out, device, callback, instance, flags, memory, host)
            }
            Win16MixerRequest::Close { handle } => self.close(handle, host),
            Win16MixerRequest::Message { handle, message, param1, param2 } => {
                self.message(handle, message, param1, param2, host)
            }
            Win16MixerRequest::GetLineInfo { object, line, flags } => {
                self.line_info(object, line, flags, memory, host)
            }
            Win16MixerRequest::GetId { object, device_id, flags } => {
                self.get_id(object, device_id, flags, memory, host)
            }
            Win16MixerRequest::GetLineControls { object, controls, flags } => {
                self.line_controls(object, controls, flags, memory, host)
            }
            Win16MixerRequest::GetControlDetails { object, details, flags } => {
                self.control_details(object, details, flags, false, memory, host)
            }
            Win16MixerRequest::SetControlDetails { object, details, flags } => {
                self.control_details(object, details, flags, true, memory, host)
            }
        }
    }

    fn device_caps(
        &mut self,
        device: u16,
        capabilities: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let length = usize::from(size).min(MIXERCAPS16_SIZE);
        if length == 0 { return Ok(MMSYSERR_NOERROR); }
        let output = match capture_output(self, memory, capabilities, length) {
            Ok(output) => output,
            Err(error) => return guest_param(error),
        };
        let Win16HostMixerResult::Caps { result, caps } = host.win16_mixer(
            Win16HostMixerOperation::DeviceCaps { device_id: device },
        )? else {
            return Err(invariant("mixerGetDevCaps returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if caps.is_some() { return Err(invariant("failed mixer caps included a record")); }
            return Ok(result);
        }
        let caps = caps.ok_or_else(|| invariant("mixer caps omitted the record"))?;
        let mut bytes = Win16MixerCaps16 {
            manufacturer_id: caps.manufacturer_id,
            product_id: caps.product_id,
            driver_version: caps.driver_version,
            product_name: caps.product_name,
            support: caps.support,
            destinations: caps.destinations,
        }.encode().to_vec();
        bytes.truncate(length);
        commit_one(self, memory, output, bytes)?;
        Ok(result)
    }

    fn mixer_open(
        &mut self,
        handle_out: u32,
        device: u16,
        callback: u32,
        instance: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if flags & CALLBACK_TYPEMASK != 0 { return Ok(MMSYSERR_NOTSUPPORTED); }
        if flags != 0 { return Ok(MMSYSERR_INVALFLAG); }
        if handle_out == 0 { return Ok(MMSYSERR_INVALPARAM); }
        let output = match capture_output(self, memory, handle_out, 2) {
            Ok(output) => output,
            Err(error) => return guest_param(error),
        };
        let Win16HostMixerResult::Opened { result, handle } = host.win16_mixer(
            Win16HostMixerOperation::Open { device_id: device, callback, instance, flags },
        )? else {
            return Err(invariant("mixerOpen returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if handle.is_some() { return Err(invariant("failed mixerOpen returned a handle")); }
            return Ok(result);
        }
        let handle = handle.ok_or_else(|| invariant("mixerOpen omitted its handle"))?;
        let Some(guest) = self.mixer.insert(handle) else {
            let _ = host.win16_mixer(Win16HostMixerOperation::Close { handle })?;
            return Ok(MMSYSERR_NOMEM);
        };
        if let Err(error) = commit_one(self, memory, output, guest.to_le_bytes().to_vec()) {
            self.mixer.handles.remove(&guest);
            let _ = host.win16_mixer(Win16HostMixerOperation::Close { handle })?;
            return Err(error);
        }
        Ok(MMSYSERR_NOERROR)
    }

    fn close(&mut self, guest: u16, host: &mut impl RuntimeHost) -> Result<u32, RuntimeError> {
        let Some(handle) = self.mixer.host_handle(guest) else { return Ok(MMSYSERR_INVALHANDLE); };
        match host.win16_mixer(Win16HostMixerOperation::Close { handle })? {
            Win16HostMixerResult::Scalar(result) => {
                if result == MMSYSERR_NOERROR { self.mixer.handles.remove(&guest); }
                Ok(result)
            }
            _ => Err(invariant("mixerClose returned the wrong result shape")),
        }
    }

    fn message(
        &mut self,
        guest: u16,
        message: u16,
        param1: u32,
        param2: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(handle) = self.mixer.host_handle(guest) else { return Ok(MMSYSERR_INVALHANDLE); };
        match host.win16_mixer(Win16HostMixerOperation::Message {
            handle, message, param1, param2,
        })? {
            Win16HostMixerResult::Scalar(result) => Ok(result),
            _ => Err(invariant("mixerMessage returned the wrong result shape")),
        }
    }

    fn line_info(
        &mut self,
        object: u16,
        line: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if !flag_residue_clear(flags, MIXER_GETLINEINFOF_QUERYMASK) {
            return Ok(MMSYSERR_INVALFLAG);
        }
        if !matches!(flags & MIXER_GETLINEINFOF_QUERYMASK,
            MIXER_GETLINEINFOF_DESTINATION | MIXER_GETLINEINFOF_SOURCE
                | MIXER_GETLINEINFOF_LINEID | MIXER_GETLINEINFOF_COMPONENTTYPE
                | MIXER_GETLINEINFOF_TARGETTYPE)
        {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let object = match self.mixer_object(object, flags) {
            Ok(object) => object,
            Err(code) => return Ok(code),
        };
        let record = match read_fixed(self, memory, line, MIXERLINE16_SIZE) {
            Ok(record) => record,
            Err(error) => return guest_param(error),
        };
        let struct_size = Win16MixerLine16::struct_size(&record);
        if struct_size < MIXERLINE16_SIZE as u32 { return Ok(MMSYSERR_INVALPARAM); }
        let decoded = Win16MixerLine16::decode(&record);
        let query = match flags & MIXER_GETLINEINFOF_QUERYMASK {
            MIXER_GETLINEINFOF_DESTINATION => {
                Win16HostMixerLineQuery::Destination(decoded.destination)
            }
            MIXER_GETLINEINFOF_SOURCE => Win16HostMixerLineQuery::Source {
                destination: decoded.destination,
                source: decoded.source,
            },
            MIXER_GETLINEINFOF_LINEID => Win16HostMixerLineQuery::LineId(decoded.line_id),
            MIXER_GETLINEINFOF_COMPONENTTYPE => {
                Win16HostMixerLineQuery::ComponentType(decoded.component_type)
            }
            MIXER_GETLINEINFOF_TARGETTYPE => Win16HostMixerLineQuery::TargetType(decoded.target_type),
            _ => return Ok(MMSYSERR_INVALFLAG),
        };
        let output = match capture_output(self, memory, line, MIXERLINE16_SIZE) {
            Ok(output) => output,
            Err(error) => return guest_param(error),
        };
        let Win16HostMixerResult::Line { result, line } = host.win16_mixer(
            Win16HostMixerOperation::LineInfo { object, query },
        )? else {
            return Err(invariant("mixerGetLineInfo returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if line.is_some() { return Err(invariant("failed mixer line included a record")); }
            return Ok(result);
        }
        commit_one(self, memory, output, encode_line(&line.ok_or_else(|| {
            invariant("mixer line omitted the record")
        })?).to_vec())?;
        Ok(result)
    }

    fn get_id(
        &mut self,
        object: u16,
        device_id: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if flags & !MIXER_OBJECTF_MASK != 0 { return Ok(MMSYSERR_INVALFLAG); }
        let object = match self.mixer_object(object, flags) {
            Ok(object) => object,
            Err(code) => return Ok(code),
        };
        if device_id == 0 { return Ok(MMSYSERR_INVALPARAM); }
        let output = match capture_output(self, memory, device_id, 2) {
            Ok(output) => output,
            Err(error) => return guest_param(error),
        };
        let Win16HostMixerResult::Id { result, device_id } = host.win16_mixer(
            Win16HostMixerOperation::GetId { object },
        )? else {
            return Err(invariant("mixerGetID returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if device_id.is_some() { return Err(invariant("failed mixerGetID included an id")); }
            return Ok(result);
        }
        let id = device_id.ok_or_else(|| invariant("mixerGetID omitted the id"))?;
        commit_one(self, memory, output, id.to_le_bytes().to_vec())?;
        Ok(result)
    }

    fn line_controls(
        &mut self,
        object: u16,
        controls: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if !flag_residue_clear(flags, MIXER_GETLINEINFOF_QUERYMASK) {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let object = match self.mixer_object(object, flags) {
            Ok(object) => object,
            Err(code) => return Ok(code),
        };
        let header = match read_fixed(self, memory, controls, MIXERLINECONTROLS16_SIZE) {
            Ok(header) => header,
            Err(error) => return guest_param(error),
        };
        let header = Win16MixerLineControls16::decode(&header);
        if header.struct_size < MIXERLINECONTROLS16_SIZE as u32
            || header.control_size < MIXERCONTROL16_SIZE as u32
            || header.count != 1
            || header.controls == 0
        {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let query = match flags & MIXER_GETLINEINFOF_QUERYMASK {
            MIXER_GETLINECONTROLSF_ALL => Win16HostMixerControlsQuery::All {
                line_id: header.line_id,
                count: header.count,
            },
            MIXER_GETLINECONTROLSF_ONEBYID => Win16HostMixerControlsQuery::OneById {
                line_id: header.line_id,
                control_id: header.control,
            },
            MIXER_GETLINECONTROLSF_ONEBYTYPE => Win16HostMixerControlsQuery::OneByType {
                line_id: header.line_id,
                control_type: header.control,
            },
            _ => return Ok(MMSYSERR_INVALFLAG),
        };
        let output = match capture_output(self, memory, header.controls, MIXERCONTROL16_SIZE) {
            Ok(output) => output,
            Err(error) => return guest_param(error),
        };
        let Win16HostMixerResult::Controls { result, controls } = host.win16_mixer(
            Win16HostMixerOperation::LineControls { object, query },
        )? else {
            return Err(invariant("mixerGetLineControls returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if !controls.is_empty() {
                return Err(invariant("failed mixer controls included a record"));
            }
            return Ok(result);
        }
        let control = controls.first().copied().ok_or_else(|| {
            invariant("mixer controls omitted the record")
        })?;
        if controls.len() != 1 { return Err(invariant("mixer controls returned more than one")); }
        commit_one(self, memory, output, encode_control(&control).to_vec())?;
        Ok(result)
    }

    fn control_details(
        &mut self,
        object: u16,
        details: u32,
        flags: u32,
        set: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if !flag_residue_clear(flags, MIXER_GETLINEINFOF_QUERYMASK) {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let kind = flags & MIXER_GETLINEINFOF_QUERYMASK;
        if kind == MIXER_DETAILSF_LISTTEXT || (set && kind == MIXER_SETDETAILSF_CUSTOM) {
            return Ok(MIXERR_INVALCONTROL);
        }
        if kind != MIXER_DETAILSF_VALUE { return Ok(MMSYSERR_INVALFLAG); }
        let object = match self.mixer_object(object, flags) {
            Ok(object) => object,
            Err(code) => return Ok(code),
        };
        let header = match read_fixed(self, memory, details, MIXERCONTROLDETAILS16_SIZE) {
            Ok(header) => header,
            Err(error) => return guest_param(error),
        };
        let header = Win16MixerControlDetails16::decode(&header);
        if header.struct_size < MIXERCONTROLDETAILS16_SIZE as u32
            || header.channels != 1
            || header.multiple_items != 0
            || header.detail_size < DETAIL_VALUE_SIZE as u32
            || header.details == 0
        {
            return Ok(MMSYSERR_INVALPARAM);
        }
        if set {
            let value = match read_fixed(self, memory, header.details, DETAIL_VALUE_SIZE) {
                Ok(value) => u32::from_le_bytes(value),
                Err(error) => return guest_param(error),
            };
            return match host.win16_mixer(Win16HostMixerOperation::SetDetails {
                object,
                control_id: header.control_id,
                channels: header.channels,
                value,
            })? {
                Win16HostMixerResult::Scalar(result) => Ok(result),
                _ => Err(invariant("mixerSetControlDetails returned the wrong result shape")),
            };
        }
        let output = match capture_output(self, memory, header.details, DETAIL_VALUE_SIZE) {
            Ok(output) => output,
            Err(error) => return guest_param(error),
        };
        let Win16HostMixerResult::Details { result, value } = host.win16_mixer(
            Win16HostMixerOperation::GetDetails {
                object,
                control_id: header.control_id,
                channels: header.channels,
            },
        )? else {
            return Err(invariant("mixerGetControlDetails returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if value.is_some() { return Err(invariant("failed mixer details included a value")); }
            return Ok(result);
        }
        let value = value.ok_or_else(|| invariant("mixer details omitted the value"))?;
        commit_one(self, memory, output, value.to_le_bytes().to_vec())?;
        Ok(result)
    }

    fn mixer_object(&self, word: u16, flags: u32) -> Result<Win16HostMixerObject, u32> {
        match flags & MIXER_OBJECTF_MASK {
            0 => Ok(Win16HostMixerObject::Device(word)),
            MIXER_OBJECTF_HANDLE => self.mixer.host_handle(word)
                .map(Win16HostMixerObject::Handle)
                .ok_or(MMSYSERR_INVALHANDLE),
            _ => Err(MMSYSERR_INVALFLAG),
        }
    }
}

fn flag_residue_clear(flags: u32, query_mask: u32) -> bool {
    flags & !(query_mask | MIXER_OBJECTF_MASK) == 0
}

fn encode_line(line: &Win16HostMixerLine) -> [u8; MIXERLINE16_SIZE] {
    Win16MixerLine16 {
        destination: line.destination,
        source: line.source,
        line_id: line.line_id,
        flags: line.flags,
        user: line.user,
        component_type: line.component_type,
        channels: line.channels,
        connections: line.connections,
        controls: line.controls,
        short_name: line.short_name,
        name: line.name,
        target_type: line.target_type,
        target_device: line.target_device,
        target_manufacturer: line.target_manufacturer,
        target_product: line.target_product,
        target_version: line.target_version,
        target_name: line.target_name,
    }.encode()
}

fn encode_control(control: &Win16HostMixerControl) -> [u8; MIXERCONTROL16_SIZE] {
    Win16MixerControl16 {
        control_id: control.control_id,
        control_type: control.control_type,
        flags: control.flags,
        multiple_items: control.multiple_items,
        short_name: control.short_name,
        name: control.name,
        minimum: control.minimum,
        maximum: control.maximum,
        steps: control.steps,
    }.encode()
}

fn capture_output(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    state.selectors.translate(pointer, Access::Write, size, memory).map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, size)
}

fn read_fixed<const N: usize>(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<[u8; N], RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    let address = state.selectors.translate(pointer, Access::Read, size, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = vec![0; size];
    memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
    bytes.try_into().map_err(|_| invariant("mixer record length changed"))
}

fn commit_one(
    state: &Win16State,
    memory: &mut Memory,
    output: GuestOutputRange,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    commit_guest_writes(state, memory, vec![(output, bytes)])
}

fn guest_param(error: RuntimeError) -> Result<u32, RuntimeError> {
    if matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput) {
        Ok(MMSYSERR_INVALPARAM)
    } else {
        Err(error)
    }
}

fn keep(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    if slot.is_none() { *slot = Some(error); }
}

fn invariant(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
