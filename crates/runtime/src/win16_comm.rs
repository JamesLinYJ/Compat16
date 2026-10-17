//! USER communications ports.
//!
//! Guest ids are words. The host token stays in this table and is never
//! written into guest memory. Line state, break, event bits, and notification
//! thresholds live here. The host only opens, reads, writes, and closes the
//! named device; this code does not program a UART or post `WM_COMMNOTIFY`.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use win16_abi::Win16UserCommRequest;
use win16_abi::comm_abi::{
    self, CE_IOE, CE_MODE, CLRDTR, CLRRTS, CommDeviceName, DCB16_LEN, EV_RXCHAR, EV_TXEMPTY,
    GETMAXCOM, GETMAXLPT, IE_BADID, IE_DEFAULT, IE_HARDWARE, IE_MEMORY, IE_NOPEN, IE_OPEN,
    MAX_COM_ID, MAX_LPT_ID, RESETDEV, SETDTR, SETRTS, SETXOFF, SETXON,
};
use win16_abi::global::GMEM_ZEROINIT;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCommDevice, Win16HostCommPort,
};

use super::Win16State;

#[derive(Default)]
pub(super) struct Win16CommPorts {
    ports: BTreeMap<u16, Port>,
}

struct Port {
    host: Win16HostCommPort,
    dcb: [u8; DCB16_LEN],
    error: u16,
    break_set: bool,
    xoff: bool,
    rts: bool,
    dtr: bool,
    unget: Option<u8>,
    event_mask: u16,
    events: u16,
    event_selector: Option<u16>,
    notify_window: u16,
    input_threshold: i16,
    output_threshold: i16,
}

impl Win16State {
    pub(super) fn dispatch_comm(
        &mut self,
        request: Win16UserCommRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let value = match request {
            Win16UserCommRequest::Open {
                device,
                in_queue,
                out_queue,
            } => self.open_comm(&device, in_queue, out_queue, host)?,
            Win16UserCommRequest::SetState { dcb } => self.set_comm_state(&dcb)?,
            Win16UserCommRequest::GetState { id, dcb } => self.get_comm_state(id, dcb, memory)?,
            Win16UserCommRequest::GetError { id, status } => {
                self.get_comm_error(id, status, memory)?
            }
            Win16UserCommRequest::Read { id, buffer, count } => {
                self.read_comm(id, buffer, count, memory, host)?
            }
            Win16UserCommRequest::Write { id, bytes } => {
                self.write_comm(id, &bytes, memory, host)?
            }
            Win16UserCommRequest::Transmit { id, byte } => {
                self.transmit_comm(id, byte, memory, host)?
            }
            Win16UserCommRequest::Close { id } => self.close_comm(id, host)?,
            Win16UserCommRequest::SetEventMask { id, mask } => {
                self.set_comm_event_mask(id, mask, memory, host)?
            }
            Win16UserCommRequest::GetEventMask { id, clear } => {
                self.get_comm_event_mask(id, clear, memory)?
            }
            Win16UserCommRequest::SetBreak { id } => self.set_comm_break(id, true),
            Win16UserCommRequest::ClearBreak { id } => self.set_comm_break(id, false),
            Win16UserCommRequest::Unget { id, byte } => self.unget_comm(id, byte),
            Win16UserCommRequest::BuildDcb { definition, dcb } => {
                self.build_comm_dcb(&definition, dcb, memory)?
            }
            Win16UserCommRequest::Escape { id, function } => self.escape_comm(id, function),
            Win16UserCommRequest::Flush { id, queue } => self.flush_comm(id, queue),
            Win16UserCommRequest::EnableNotification {
                id,
                window,
                input_threshold,
                output_threshold,
            } => self.enable_comm_notification(id, window, input_threshold, output_threshold),
        };
        Ok(value)
    }

    fn open_comm(
        &mut self,
        device_bytes: &[u8],
        in_queue: u16,
        out_queue: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = comm_abi::parse_device_name(device_bytes) else {
            return Ok(word(IE_BADID));
        };
        let id = comm_abi::guest_comm_id(device);
        if self.comm_ports.ports.contains_key(&id) {
            return Ok(word(IE_OPEN));
        }
        let host_device = match device {
            CommDeviceName::Com(number) => Win16HostCommDevice::Com(number),
            CommDeviceName::Lpt(number) => Win16HostCommDevice::Lpt(number),
        };
        let opened = host.win16_comm_open(host_device, in_queue, out_queue);
        let token = match opened {
            Ok(token) => token,
            Err(error) => return map_open_error(error),
        };
        self.comm_ports.ports.insert(
            id,
            Port {
                host: token,
                dcb: comm_abi::default_dcb(id, in_queue),
                error: 0,
                break_set: false,
                xoff: false,
                rts: true,
                dtr: true,
                unget: None,
                event_mask: 0,
                events: 0,
                event_selector: None,
                notify_window: 0,
                input_threshold: -1,
                output_threshold: -1,
            },
        );
        Ok(u32::from(id))
    }

    fn set_comm_state(&mut self, bytes: &[u8]) -> Result<u32, RuntimeError> {
        let Ok(dcb) = <[u8; DCB16_LEN]>::try_from(bytes) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "comm DCB width changed",
            ));
        };
        let id = u16::from(comm_abi::dcb_id(&dcb));
        if !self.comm_ports.ports.contains_key(&id) {
            return Ok(word(IE_BADID));
        }
        if let Err(error) = comm_abi::validate_dcb(&dcb) {
            return Ok(word(error));
        }
        self.comm_ports
            .ports
            .get_mut(&id)
            .expect("port checked")
            .dcb = dcb;
        Ok(0)
    }

    fn get_comm_state(&self, id: u16, dcb: u32, memory: &mut Memory) -> Result<u32, RuntimeError> {
        let Some(port) = self.comm_ports.ports.get(&id) else {
            return Ok(word(IE_BADID));
        };
        if dcb == 0 {
            return Ok(word(IE_BADID));
        }
        self.write_guest(memory, dcb, &port.dcb)?;
        Ok(0)
    }

    fn get_comm_error(
        &mut self,
        id: u16,
        status: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let image = {
            let Some(port) = self.comm_ports.ports.get_mut(&id) else {
                return Ok(word(IE_BADID));
            };
            let error = std::mem::take(&mut port.error);
            let encoded = if status == 0 {
                None
            } else {
                let flags = u8::from(port.xoff) << 3;
                let queued = u16::from(port.unget.is_some());
                Some(comm_abi::encode_comstat(flags, queued, 0))
            };
            (error, encoded)
        };
        if let Some(encoded) = image.1 {
            self.write_guest(memory, status, &encoded)?;
        }
        Ok(u32::from(image.0))
    }

    fn read_comm(
        &mut self,
        id: u16,
        buffer: u32,
        count: i16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if count < 0 {
            return self.note_comm_mode(id);
        }
        let Some(port) = self.comm_ports.ports.get(&id) else {
            return Ok(0);
        };
        let token = port.host;
        let pushed = if count == 0 {
            None
        } else {
            self.comm_ports
                .ports
                .get_mut(&id)
                .and_then(|port| port.unget.take())
        };
        let mut data = Vec::new();
        if let Some(byte) = pushed {
            data.push(byte);
        }
        let remaining = usize::from(count as u16).saturating_sub(data.len());
        if remaining > 0 {
            let mut host_bytes = Vec::new();
            host_bytes.try_reserve_exact(remaining).map_err(|error| {
                RuntimeError::with_source(Kind::ResourceExhausted, "allocate comm read", error)
            })?;
            host_bytes.resize(remaining, 0);
            match host.win16_comm_read(token, &mut host_bytes) {
                Ok(read) if read <= host_bytes.len() => data.extend_from_slice(&host_bytes[..read]),
                Ok(_) => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "comm read exceeded its buffer",
                    ));
                }
                Err(error) => {
                    self.latch_comm_error(id, CE_IOE);
                    if matches!(
                        error.kind(),
                        Kind::HostFailure | Kind::CompatibilityGap | Kind::InvalidInput
                    ) {
                        if !data.is_empty()
                            && let Ok(read) = i16::try_from(data.len())
                        {
                            self.write_guest(memory, buffer, &data)?;
                            self.note_comm_event(id, EV_RXCHAR, memory)?;
                            return Ok(word(-read));
                        }
                        return Ok(0);
                    }
                    return Err(error);
                }
            }
        }
        if !data.is_empty() {
            self.write_guest(memory, buffer, &data)?;
            self.note_comm_event(id, EV_RXCHAR, memory)?;
        }
        Ok(u32::try_from(data.len()).unwrap_or(0))
    }

    fn write_comm(
        &mut self,
        id: u16,
        bytes: &[u8],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(token) = self.comm_ports.ports.get(&id).map(|port| port.host) else {
            return Ok(0);
        };
        match host.win16_comm_write(token, bytes) {
            Ok(written) if written <= bytes.len() => {
                if written == bytes.len() {
                    self.note_comm_event(id, EV_TXEMPTY, memory)?;
                }
                Ok(u32::try_from(written).unwrap_or(0))
            }
            Ok(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "comm write exceeded its buffer",
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    Kind::HostFailure | Kind::CompatibilityGap | Kind::InvalidInput
                ) =>
            {
                self.latch_comm_error(id, CE_IOE);
                Ok(0)
            }
            Err(error) => Err(error),
        }
    }

    fn transmit_comm(
        &mut self,
        id: u16,
        byte: u8,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(token) = self.comm_ports.ports.get(&id).map(|port| port.host) else {
            return Ok(word(IE_BADID));
        };
        match host.win16_comm_write(token, &[byte]) {
            Ok(1) => {
                self.note_comm_event(id, EV_TXEMPTY, memory)?;
                Ok(0)
            }
            Ok(_) => Ok(word(IE_HARDWARE)),
            Err(error)
                if matches!(
                    error.kind(),
                    Kind::HostFailure | Kind::CompatibilityGap | Kind::InvalidInput
                ) =>
            {
                self.latch_comm_error(id, CE_IOE);
                Ok(word(IE_HARDWARE))
            }
            Err(error) => Err(error),
        }
    }

    fn close_comm(&mut self, id: u16, host: &mut impl RuntimeHost) -> Result<u32, RuntimeError> {
        let Some(port) = self.comm_ports.ports.get(&id) else {
            return Ok(word(if known_comm_id(id) {
                IE_NOPEN
            } else {
                IE_BADID
            }));
        };
        let token = port.host;
        let selector = port.event_selector;
        host.win16_comm_close(token)?;
        self.comm_ports.ports.remove(&id);
        if let Some(selector) = selector {
            let freed = self.global_free(selector)?;
            if freed != 0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "comm event word remained allocated after CloseComm",
                ));
            }
        }
        Ok(0)
    }

    fn set_comm_event_mask(
        &mut self,
        id: u16,
        mask: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if !self.comm_ports.ports.contains_key(&id) {
            return Ok(0);
        }
        if self
            .comm_ports
            .ports
            .get(&id)
            .and_then(|port| port.event_selector)
            .is_none()
        {
            let handle = self.global_alloc(GMEM_ZEROINIT, 2, memory, host)?;
            if handle == 0 {
                return Ok(0);
            }
            self.comm_ports
                .ports
                .get_mut(&id)
                .expect("port checked")
                .event_selector = Some(handle);
        }
        let (selector, events) = {
            let port = self.comm_ports.ports.get_mut(&id).expect("port checked");
            port.event_mask = mask;
            port.events &= mask;
            (
                port.event_selector.expect("event word allocated"),
                port.events,
            )
        };
        self.write_guest(memory, u32::from(selector) << 16, &events.to_le_bytes())?;
        Ok(u32::from(selector) << 16)
    }

    fn get_comm_event_mask(
        &mut self,
        id: u16,
        clear: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let (current, selector, events) = {
            let Some(port) = self.comm_ports.ports.get_mut(&id) else {
                return Ok(0);
            };
            let current = port.events;
            port.events &= !clear;
            (current, port.event_selector, port.events)
        };
        if let Some(selector) = selector {
            self.write_guest(memory, u32::from(selector) << 16, &events.to_le_bytes())?;
        }
        Ok(u32::from(current))
    }

    fn set_comm_break(&mut self, id: u16, enabled: bool) -> u32 {
        let Some(port) = self.comm_ports.ports.get_mut(&id) else {
            return word(IE_NOPEN);
        };
        port.break_set = enabled;
        0
    }

    fn unget_comm(&mut self, id: u16, byte: u8) -> u32 {
        let Some(port) = self.comm_ports.ports.get_mut(&id) else {
            return word(IE_BADID);
        };
        if port.unget.is_some() {
            return word(IE_MEMORY);
        }
        port.unget = Some(byte);
        0
    }

    fn build_comm_dcb(
        &self,
        definition: &[u8],
        output: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if output == 0 {
            return Ok(word(IE_DEFAULT));
        }
        match comm_abi::build_dcb(definition) {
            Ok(dcb) => {
                self.write_guest(memory, output, &dcb)?;
                Ok(0)
            }
            Err(error) => Ok(word(error)),
        }
    }

    fn escape_comm(&mut self, id: u16, function: i16) -> u32 {
        if function == GETMAXCOM {
            return u32::from(MAX_COM_ID);
        }
        if function == GETMAXLPT {
            return u32::from(MAX_LPT_ID);
        }
        let Some(port) = self.comm_ports.ports.get_mut(&id) else {
            return long(IE_BADID);
        };
        match function {
            SETXOFF => port.xoff = true,
            SETXON => port.xoff = false,
            SETRTS => port.rts = true,
            CLRRTS => port.rts = false,
            SETDTR => port.dtr = true,
            CLRDTR => port.dtr = false,
            RESETDEV => {
                port.break_set = false;
                port.xoff = false;
                port.error = 0;
                port.rts = true;
                port.dtr = true;
            }
            _ => return long(IE_HARDWARE),
        }
        0
    }

    fn flush_comm(&mut self, id: u16, queue: i16) -> u32 {
        let Some(port) = self.comm_ports.ports.get_mut(&id) else {
            return word(IE_BADID);
        };
        match queue {
            0 => {}
            1 => port.unget = None,
            _ => return word(IE_DEFAULT),
        }
        0
    }

    fn enable_comm_notification(
        &mut self,
        id: u16,
        window: u16,
        input_threshold: i16,
        output_threshold: i16,
    ) -> u32 {
        let Some(port) = self.comm_ports.ports.get_mut(&id) else {
            return 0;
        };
        if window == 0 {
            port.notify_window = 0;
            port.input_threshold = -1;
            port.output_threshold = -1;
        } else {
            port.notify_window = window;
            port.input_threshold = input_threshold;
            port.output_threshold = output_threshold;
        }
        1
    }

    fn note_comm_mode(&mut self, id: u16) -> Result<u32, RuntimeError> {
        self.latch_comm_error(id, CE_MODE);
        Ok(0)
    }

    fn latch_comm_error(&mut self, id: u16, flag: u16) {
        if let Some(port) = self.comm_ports.ports.get_mut(&id) {
            port.error |= flag;
        }
    }

    fn note_comm_event(
        &mut self,
        id: u16,
        event: u16,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let published = {
            let Some(port) = self.comm_ports.ports.get_mut(&id) else {
                return Ok(());
            };
            port.events |= event & port.event_mask;
            port.event_selector.map(|selector| (selector, port.events))
        };
        if let Some((selector, events)) = published {
            self.write_guest(memory, u32::from(selector) << 16, &events.to_le_bytes())?;
        }
        Ok(())
    }

    fn write_guest(&self, memory: &mut Memory, far: u32, bytes: &[u8]) -> Result<(), RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.selectors
            .write(memory, pointer, bytes)
            .map_err(crate::runtime_error)
    }
}

fn known_comm_id(id: u16) -> bool {
    id <= MAX_COM_ID || (0x80..=MAX_LPT_ID).contains(&id)
}

fn word(value: i16) -> u32 {
    u32::from(value as u16)
}

fn long(value: i16) -> u32 {
    i32::from(value) as u32
}

fn map_open_error(error: RuntimeError) -> Result<u32, RuntimeError> {
    match error.kind() {
        Kind::CompatibilityGap | Kind::HostFailure | Kind::InvalidInput => Ok(word(IE_HARDWARE)),
        Kind::ResourceExhausted => Ok(word(IE_MEMORY)),
        _ => Err(error),
    }
}

#[cfg(test)]
#[path = "win16_comm_tests.rs"]
mod tests;
