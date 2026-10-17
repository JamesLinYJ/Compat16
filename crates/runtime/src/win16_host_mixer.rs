//! Session mixer behind the host port. It is not a physical audio device.

use std::collections::BTreeSet;

use compat_services::win16_multimedia::CALLBACK_TYPEMASK;

use crate::{MMSYSERR_NOERROR, MMSYSERR_BADDEVICEID, MMSYSERR_INVALPARAM};
pub const MMSYSERR_INVALHANDLE: u32 = 5;
pub const MMSYSERR_NOMEM: u32 = 7;
pub const MMSYSERR_NOTSUPPORTED: u32 = 8;
pub const MMSYSERR_INVALFLAG: u32 = 10;
pub const MIXERR_INVALLINE: u32 = 1024;
pub const MIXERR_INVALCONTROL: u32 = 1025;
pub const MIXERR_INVALVALUE: u32 = 1026;

pub const MIXER_OBJECTF_HANDLE: u32 = 0x8000_0000;
pub const MIXER_OBJECTF_MASK: u32 = 0xF000_0000;
pub const MIXER_GETLINEINFOF_QUERYMASK: u32 = 0x0000_000F;
pub const MIXER_GETLINEINFOF_DESTINATION: u32 = 0;
pub const MIXER_GETLINEINFOF_SOURCE: u32 = 1;
pub const MIXER_GETLINEINFOF_LINEID: u32 = 2;
pub const MIXER_GETLINEINFOF_COMPONENTTYPE: u32 = 3;
pub const MIXER_GETLINEINFOF_TARGETTYPE: u32 = 4;
pub const MIXER_GETLINECONTROLSF_ALL: u32 = 0;
pub const MIXER_GETLINECONTROLSF_ONEBYID: u32 = 1;
pub const MIXER_GETLINECONTROLSF_ONEBYTYPE: u32 = 2;
pub const MIXER_DETAILSF_VALUE: u32 = 0;
pub const MIXER_DETAILSF_LISTTEXT: u32 = 1;
pub const MIXER_SETDETAILSF_CUSTOM: u32 = 1;

pub const MIXERLINE_LINEF_ACTIVE: u32 = 0x0000_0001;
pub const MIXERLINE_COMPONENTTYPE_DST_SPEAKERS: u32 = 4;
pub const MIXERCONTROL_CONTROLF_UNIFORM: u32 = 0x0000_0001;
pub const MIXERCONTROL_CONTROLTYPE_VOLUME: u32 = 0x5003_0001;

pub const SESSION_MIXER_VERSION: u16 = 0x030A;
pub const DESTINATION_LINE_ID: u32 = 0;
pub const VOLUME_CONTROL_ID: u32 = 1;
pub const VOLUME_MAXIMUM: u32 = 0xFFFF;

const PRODUCT_NAME: &[u8] = b"Session Mixer";
const LINE_NAME: &[u8] = b"Speakers";
const CONTROL_NAME: &[u8] = b"Volume";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMixerHandle(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMixerObject {
    Device(u16),
    Handle(Win16HostMixerHandle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMixerCaps {
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
    pub support: u32,
    pub destinations: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMixerLine {
    pub destination: u32,
    pub source: u32,
    pub line_id: u32,
    pub flags: u32,
    pub user: u32,
    pub component_type: u32,
    pub channels: u32,
    pub connections: u32,
    pub controls: u32,
    pub short_name: [u8; 16],
    pub name: [u8; 64],
    pub target_type: u32,
    pub target_device: u32,
    pub target_manufacturer: u16,
    pub target_product: u16,
    pub target_version: u16,
    pub target_name: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMixerControl {
    pub control_id: u32,
    pub control_type: u32,
    pub flags: u32,
    pub multiple_items: u32,
    pub short_name: [u8; 16],
    pub name: [u8; 64],
    pub minimum: u32,
    pub maximum: u32,
    pub steps: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMixerLineQuery {
    Destination(u32),
    Source { destination: u32, source: u32 },
    LineId(u32),
    ComponentType(u32),
    TargetType(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMixerControlsQuery {
    All { line_id: u32, count: u32 },
    OneById { line_id: u32, control_id: u32 },
    OneByType { line_id: u32, control_type: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMixerOperation {
    DeviceCount,
    DeviceCaps { device_id: u16 },
    Open { device_id: u16, callback: u32, instance: u32, flags: u32 },
    Close { handle: Win16HostMixerHandle },
    Message { handle: Win16HostMixerHandle, message: u16, param1: u32, param2: u32 },
    LineInfo { object: Win16HostMixerObject, query: Win16HostMixerLineQuery },
    GetId { object: Win16HostMixerObject },
    LineControls { object: Win16HostMixerObject, query: Win16HostMixerControlsQuery },
    GetDetails { object: Win16HostMixerObject, control_id: u32, channels: u32 },
    SetDetails { object: Win16HostMixerObject, control_id: u32, channels: u32, value: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMixerResult {
    Count(u16),
    Caps { result: u32, caps: Option<Win16HostMixerCaps> },
    Opened { result: u32, handle: Option<Win16HostMixerHandle> },
    Scalar(u32),
    Line { result: u32, line: Option<Win16HostMixerLine> },
    Id { result: u32, device_id: Option<u16> },
    Controls { result: u32, controls: Vec<Win16HostMixerControl> },
    Details { result: u32, value: Option<u32> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16SessionMixer {
    next_handle: u64,
    open: BTreeSet<u64>,
    volume: u32,
}

impl Default for Win16SessionMixer {
    fn default() -> Self {
        Self { next_handle: 1, open: BTreeSet::new(), volume: VOLUME_MAXIMUM }
    }
}

impl Win16SessionMixer {
    pub fn execute(&mut self, operation: Win16HostMixerOperation) -> Win16HostMixerResult {
        match operation {
            Win16HostMixerOperation::DeviceCount => Win16HostMixerResult::Count(1),
            Win16HostMixerOperation::DeviceCaps { device_id } => self.caps(device_id),
            Win16HostMixerOperation::Open { device_id, flags, .. } => self.open(device_id, flags),
            Win16HostMixerOperation::Close { handle } => {
                Win16HostMixerResult::Scalar(self.close(handle))
            }
            Win16HostMixerOperation::Message { handle, .. } => {
                Win16HostMixerResult::Scalar(self.message(handle))
            }
            Win16HostMixerOperation::LineInfo { object, query } => self.line_info(object, query),
            Win16HostMixerOperation::GetId { object } => self.get_id(object),
            Win16HostMixerOperation::LineControls { object, query } => {
                self.line_controls(object, query)
            }
            Win16HostMixerOperation::GetDetails { object, control_id, channels } => {
                self.get_details(object, control_id, channels)
            }
            Win16HostMixerOperation::SetDetails { object, control_id, channels, value } => {
                Win16HostMixerResult::Scalar(self.set_details(object, control_id, channels, value))
            }
        }
    }

    fn caps(&self, device_id: u16) -> Win16HostMixerResult {
        if device_id != 0 {
            return Win16HostMixerResult::Caps { result: MMSYSERR_BADDEVICEID, caps: None };
        }
        Win16HostMixerResult::Caps {
            result: MMSYSERR_NOERROR,
            caps: Some(Win16HostMixerCaps {
                manufacturer_id: 0,
                product_id: 0,
                driver_version: SESSION_MIXER_VERSION,
                product_name: fixed_name(PRODUCT_NAME),
                support: 0,
                destinations: 1,
            }),
        }
    }

    fn open(&mut self, device_id: u16, flags: u32) -> Win16HostMixerResult {
        if flags & CALLBACK_TYPEMASK != 0 {
            return Win16HostMixerResult::Opened { result: MMSYSERR_NOTSUPPORTED, handle: None };
        }
        if flags != 0 {
            return Win16HostMixerResult::Opened { result: MMSYSERR_INVALFLAG, handle: None };
        }
        if device_id != 0 {
            return Win16HostMixerResult::Opened { result: MMSYSERR_BADDEVICEID, handle: None };
        }
        let id = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        if id == 0 || !self.open.insert(id) {
            return Win16HostMixerResult::Opened { result: MMSYSERR_NOTSUPPORTED, handle: None };
        }
        Win16HostMixerResult::Opened {
            result: MMSYSERR_NOERROR,
            handle: Some(Win16HostMixerHandle(id)),
        }
    }

    fn close(&mut self, handle: Win16HostMixerHandle) -> u32 {
        if self.open.remove(&handle.0) { MMSYSERR_NOERROR } else { MMSYSERR_INVALHANDLE }
    }

    fn message(&self, handle: Win16HostMixerHandle) -> u32 {
        if self.open.contains(&handle.0) { MMSYSERR_NOTSUPPORTED } else { MMSYSERR_INVALHANDLE }
    }

    fn line_info(
        &self,
        object: Win16HostMixerObject,
        query: Win16HostMixerLineQuery,
    ) -> Win16HostMixerResult {
        if let Err(result) = self.require_object(object) {
            return Win16HostMixerResult::Line { result, line: None };
        }
        let matches = match query {
            Win16HostMixerLineQuery::Destination(0) => true,
            Win16HostMixerLineQuery::Destination(_) => false,
            Win16HostMixerLineQuery::Source { .. } => false,
            Win16HostMixerLineQuery::LineId(id) => id == DESTINATION_LINE_ID,
            Win16HostMixerLineQuery::ComponentType(kind) => {
                kind == MIXERLINE_COMPONENTTYPE_DST_SPEAKERS
            }
            Win16HostMixerLineQuery::TargetType(kind) => kind == 0,
        };
        if !matches {
            return Win16HostMixerResult::Line { result: MIXERR_INVALLINE, line: None };
        }
        Win16HostMixerResult::Line { result: MMSYSERR_NOERROR, line: Some(speakers_line()) }
    }

    fn get_id(&self, object: Win16HostMixerObject) -> Win16HostMixerResult {
        match self.require_object(object) {
            Ok(()) => Win16HostMixerResult::Id { result: MMSYSERR_NOERROR, device_id: Some(0) },
            Err(result) => Win16HostMixerResult::Id { result, device_id: None },
        }
    }

    fn line_controls(
        &self,
        object: Win16HostMixerObject,
        query: Win16HostMixerControlsQuery,
    ) -> Win16HostMixerResult {
        if let Err(result) = self.require_object(object) {
            return Win16HostMixerResult::Controls { result, controls: Vec::new() };
        }
        let line_id = match query {
            Win16HostMixerControlsQuery::All { line_id, count } => {
                if count != 1 { return controls_error(MMSYSERR_INVALPARAM); }
                line_id
            }
            Win16HostMixerControlsQuery::OneById { line_id, control_id } => {
                if control_id != VOLUME_CONTROL_ID { return controls_error(MIXERR_INVALCONTROL); }
                line_id
            }
            Win16HostMixerControlsQuery::OneByType { line_id, control_type } => {
                if control_type != MIXERCONTROL_CONTROLTYPE_VOLUME {
                    return controls_error(MIXERR_INVALCONTROL);
                }
                line_id
            }
        };
        if line_id != DESTINATION_LINE_ID { return controls_error(MIXERR_INVALLINE); }
        Win16HostMixerResult::Controls {
            result: MMSYSERR_NOERROR,
            controls: vec![volume_control()],
        }
    }

    fn get_details(
        &self,
        object: Win16HostMixerObject,
        control_id: u32,
        channels: u32,
    ) -> Win16HostMixerResult {
        match self.detail_target(object, control_id, channels) {
            Ok(()) => Win16HostMixerResult::Details {
                result: MMSYSERR_NOERROR,
                value: Some(self.volume),
            },
            Err(result) => Win16HostMixerResult::Details { result, value: None },
        }
    }

    fn set_details(
        &mut self,
        object: Win16HostMixerObject,
        control_id: u32,
        channels: u32,
        value: u32,
    ) -> u32 {
        if let Err(result) = self.detail_target(object, control_id, channels) { return result; }
        if value > VOLUME_MAXIMUM { return MIXERR_INVALVALUE; }
        self.volume = value;
        MMSYSERR_NOERROR
    }

    fn detail_target(
        &self,
        object: Win16HostMixerObject,
        control_id: u32,
        channels: u32,
    ) -> Result<(), u32> {
        self.require_object(object)?;
        if control_id != VOLUME_CONTROL_ID { return Err(MIXERR_INVALCONTROL); }
        if channels != 1 { return Err(MMSYSERR_INVALPARAM); }
        Ok(())
    }

    fn require_object(&self, object: Win16HostMixerObject) -> Result<(), u32> {
        match object {
            Win16HostMixerObject::Device(0) => Ok(()),
            Win16HostMixerObject::Device(_) => Err(MMSYSERR_BADDEVICEID),
            Win16HostMixerObject::Handle(handle) if self.open.contains(&handle.0) => Ok(()),
            Win16HostMixerObject::Handle(_) => Err(MMSYSERR_INVALHANDLE),
        }
    }
}

fn controls_error(result: u32) -> Win16HostMixerResult {
    Win16HostMixerResult::Controls { result, controls: Vec::new() }
}

fn speakers_line() -> Win16HostMixerLine {
    Win16HostMixerLine {
        destination: 0,
        source: 0,
        line_id: DESTINATION_LINE_ID,
        flags: MIXERLINE_LINEF_ACTIVE,
        user: 0,
        component_type: MIXERLINE_COMPONENTTYPE_DST_SPEAKERS,
        channels: 2,
        connections: 0,
        controls: 1,
        short_name: fixed_name(LINE_NAME),
        name: fixed_name(LINE_NAME),
        target_type: 0,
        target_device: 0,
        target_manufacturer: 0,
        target_product: 0,
        target_version: 0,
        target_name: [0; 32],
    }
}

fn volume_control() -> Win16HostMixerControl {
    Win16HostMixerControl {
        control_id: VOLUME_CONTROL_ID,
        control_type: MIXERCONTROL_CONTROLTYPE_VOLUME,
        flags: MIXERCONTROL_CONTROLF_UNIFORM,
        multiple_items: 0,
        short_name: fixed_name(CONTROL_NAME),
        name: fixed_name(CONTROL_NAME),
        minimum: 0,
        maximum: VOLUME_MAXIMUM,
        steps: VOLUME_MAXIMUM + 1,
    }
}

fn fixed_name<const N: usize>(text: &[u8]) -> [u8; N] {
    let mut bytes = [0; N];
    let length = text.len().min(N.saturating_sub(1));
    bytes[..length].copy_from_slice(&text[..length]);
    bytes
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn shared_volume_follows_the_open_handle_and_rejects_a_second_close() {
        let mut mixer = Win16SessionMixer::default();
        assert!(matches!(mixer.execute(Win16HostMixerOperation::DeviceCount),
            Win16HostMixerResult::Count(1)));
        let Win16HostMixerResult::Opened { result, handle } = mixer.execute(
            Win16HostMixerOperation::Open { device_id: 0, callback: 0, instance: 0, flags: 0 },
        ) else { panic!("open shape"); };
        assert_eq!(result, 0);
        let handle = handle.unwrap();
        assert_eq!(mixer.execute(Win16HostMixerOperation::SetDetails {
            object: Win16HostMixerObject::Handle(handle),
            control_id: VOLUME_CONTROL_ID,
            channels: 1,
            value: 0x1234,
        }), Win16HostMixerResult::Scalar(0));
        assert_eq!(mixer.execute(Win16HostMixerOperation::GetDetails {
            object: Win16HostMixerObject::Device(0),
            control_id: VOLUME_CONTROL_ID,
            channels: 1,
        }), Win16HostMixerResult::Details { result: 0, value: Some(0x1234) });
        assert_eq!(mixer.execute(Win16HostMixerOperation::SetDetails {
            object: Win16HostMixerObject::Device(0),
            control_id: VOLUME_CONTROL_ID,
            channels: 1,
            value: 0x1_0000,
        }), Win16HostMixerResult::Scalar(MIXERR_INVALVALUE));
        assert_eq!(mixer.execute(Win16HostMixerOperation::Close { handle }),
            Win16HostMixerResult::Scalar(0));
        assert_eq!(mixer.execute(Win16HostMixerOperation::Close { handle }),
            Win16HostMixerResult::Scalar(MMSYSERR_INVALHANDLE));
        assert_eq!(mixer.execute(Win16HostMixerOperation::Message {
            handle, message: 1, param1: 0, param2: 0,
        }), Win16HostMixerResult::Scalar(MMSYSERR_INVALHANDLE));
    }
}
