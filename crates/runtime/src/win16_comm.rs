//! USER communications ports.
//!
//! Guest ids are words. The host token stays in this table and is never
//! written into guest memory. `SetCommState`, break, modem escapes, and
//! `FlushComm` are sent to that token. A device that cannot accept the
//! operation returns `IE_HARDWARE` or `IE_DEFAULT`, and the guest-visible
//! record is left unchanged. This code does not post `WM_COMMNOTIFY` or
//! read UART registers. The task that opened a port owns its host token and
//! event-word allocation; task exit retires both, and a failed close or free
//! keeps that port so a later pass can retry without closing the token twice.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use win16_abi::Win16UserCommRequest;
use win16_abi::comm_abi::{
    self, CE_CTSTO, CE_DSRTO, CE_IOE, CE_MODE, CE_RLSDTO, CE_RXOVER, CLRDTR, CLRRTS, CSTF_EOF,
    CSTF_XOFFHOLD, CommDeviceName, DCB16_LEN, EV_RXCHAR, EV_RXFLAG, EV_TXEMPTY, GETMAXCOM,
    GETMAXLPT, IE_BADID, IE_BAUDRATE, IE_DEFAULT, IE_HARDWARE, IE_MEMORY, IE_NOPEN, IE_OPEN,
    MAX_COM_ID, MAX_LPT_ID, RESETDEV, SETDTR, SETRTS, SETXOFF, SETXON,
};
use win16_abi::global::GMEM_ZEROINIT;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCommConfig, Win16HostCommControl,
    Win16HostCommDevice, Win16HostCommLine, Win16HostCommLines, Win16HostCommPort,
    Win16HostCommQueue,
};

use super::Win16State;

#[derive(Default)]
pub(super) struct Win16CommPorts {
    ports: BTreeMap<u16, Port>,
}

struct Port {
    host: Win16HostCommPort,
    /// Set after the host token has been closed and must not be closed again.
    host_closed: bool,
    dcb: [u8; DCB16_LEN],
    error: u16,
    break_set: bool,
    xoff: bool,
    rts: bool,
    dtr: bool,
    unget: Option<u8>,
    /// `CSTF_EOF` after a non-binary read sees `EofChar`. Q101419 does not clear it.
    eof: bool,
    event_mask: u16,
    events: u16,
    event_selector: Option<u16>,
    notify_window: u16,
    input_threshold: i16,
    output_threshold: i16,
}

impl Win16CommPorts {
    pub(super) fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
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
            Win16UserCommRequest::SetState { dcb } => self.set_comm_state(&dcb, host)?,
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
            Win16UserCommRequest::SetBreak { id } => self.set_comm_break(id, true, host)?,
            Win16UserCommRequest::ClearBreak { id } => self.set_comm_break(id, false, host)?,
            Win16UserCommRequest::Unget { id, byte } => self.unget_comm(id, byte),
            Win16UserCommRequest::BuildDcb { definition, dcb } => {
                self.build_comm_dcb(&definition, dcb, memory)?
            }
            Win16UserCommRequest::Escape { id, function } => {
                self.escape_comm(id, function, host)?
            }
            Win16UserCommRequest::Flush { id, queue } => self.flush_comm(id, queue, host)?,
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
        let dcb = comm_abi::default_dcb(id);
        if matches!(device, CommDeviceName::Com(_)) {
            let Ok(config) = host_config(&dcb) else {
                let _ = host.win16_comm_close(token);
                return Ok(word(IE_DEFAULT));
            };
            if let Err(error) = host.win16_comm_configure(token, &config) {
                host.win16_comm_close(token)?;
                return map_device_error(error, false);
            }
        }
        self.comm_ports.ports.insert(
            id,
            Port {
                host: token,
                host_closed: false,
                dcb,
                error: 0,
                break_set: false,
                xoff: false,
                rts: true,
                dtr: true,
                unget: None,
                eof: false,
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

    fn set_comm_state(
        &mut self,
        bytes: &[u8],
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Ok(dcb) = <[u8; DCB16_LEN]>::try_from(bytes) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "comm DCB width changed",
            ));
        };
        let id = u16::from(comm_abi::dcb_id(&dcb));
        let Some(token) = self.comm_ports.ports.get(&id).map(|port| port.host) else {
            return Ok(word(IE_BADID));
        };
        if let Err(error) = comm_abi::validate_dcb(&dcb) {
            return Ok(word(error));
        }
        let config = match host_config(&dcb) {
            Ok(config) => config,
            Err(error) => return Ok(word(error)),
        };
        if let Err(error) = host.win16_comm_configure(token, &config) {
            return map_device_error(error, false);
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
                let mut flags = 0;
                if port.xoff {
                    flags |= CSTF_XOFFHOLD;
                }
                if port.eof {
                    flags |= CSTF_EOF;
                }
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
        let dcb = port.dcb;
        let already_eof = port.eof;
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
        let mut host_error = false;
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
                    if matches!(
                        error.kind(),
                        Kind::HostFailure | Kind::CompatibilityGap | Kind::InvalidInput
                    ) {
                        host_error = true;
                        self.latch_comm_error(id, CE_IOE);
                    } else {
                        self.restore_unget(id, pushed);
                        return Err(error);
                    }
                }
            }
        }
        let host_len = data.len() - usize::from(pushed.is_some());
        let viewed = interpret_comm_read(&dcb, &data, host_len, already_eof);
        if !viewed.bytes.is_empty() {
            if let Err(error) = self.write_guest(memory, buffer, viewed.bytes) {
                self.restore_unget(id, pushed);
                return Err(error);
            }
        }
        if viewed.eof
            && let Some(port) = self.comm_ports.ports.get_mut(&id)
        {
            port.eof = true;
        }
        if viewed.overflow {
            self.latch_comm_error(id, CE_RXOVER);
        }
        let mut event = 0;
        if host_len > 0 {
            event |= EV_RXCHAR;
        }
        if viewed.rxflag {
            event |= EV_RXFLAG;
        }
        if event != 0 {
            self.note_comm_event(id, event, memory)?;
        }
        let length = i16::try_from(viewed.bytes.len()).unwrap_or(i16::MAX);
        if (host_error || viewed.overflow) && length > 0 {
            Ok(word(-length))
        } else {
            Ok(u32::from(length as u16))
        }
    }

    fn write_comm(
        &mut self,
        id: u16,
        bytes: &[u8],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(port) = self.comm_ports.ports.get(&id) else {
            return Ok(0);
        };
        let token = port.host;
        let dcb = port.dcb;
        if armed_line_timeout(&dcb) {
            match host.win16_comm_lines(token) {
                Ok(lines) => {
                    if let Some(flag) = line_timeout_error(&dcb, lines) {
                        self.latch_comm_error(id, flag);
                        return Ok(0);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        Kind::HostFailure | Kind::CompatibilityGap | Kind::InvalidInput
                    ) =>
                {
                    self.latch_comm_error(id, CE_IOE);
                    return Ok(0);
                }
                Err(error) => return Err(error),
            }
        }
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
        if !self.comm_ports.ports.contains_key(&id) {
            return Ok(word(if known_comm_id(id) {
                IE_NOPEN
            } else {
                IE_BADID
            }));
        }
        self.release_comm_port(id, host)?;
        Ok(0)
    }

    /// Close one port's host token, then free its event word. A failure leaves
    /// the port in place. A token that already closed is not closed again.
    fn release_comm_port(
        &mut self,
        id: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(port) = self.comm_ports.ports.get(&id) else {
            return Ok(());
        };
        if !port.host_closed {
            host.win16_comm_close(port.host)?;
            if let Some(port) = self.comm_ports.ports.get_mut(&id) {
                port.host_closed = true;
            }
        }
        let selector = self
            .comm_ports
            .ports
            .get(&id)
            .and_then(|port| port.event_selector);
        if let Some(selector) = selector {
            let freed = self.global_free(selector)?;
            if freed != 0 {
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "comm event word remained allocated",
                ));
            }
            if let Some(port) = self.comm_ports.ports.get_mut(&id) {
                port.event_selector = None;
            }
        }
        self.comm_ports.ports.remove(&id);
        Ok(())
    }

    pub(in crate::win16_runtime) fn retire_comm_ports(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first = None;
        let ids: Vec<u16> = self.comm_ports.ports.keys().copied().collect();
        for id in ids {
            if let Err(error) = self.release_comm_port(id, host) {
                if first.is_none() {
                    first = Some(error);
                }
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
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

    fn set_comm_break(
        &mut self,
        id: u16,
        enabled: bool,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(token) = self.comm_ports.ports.get(&id).map(|port| port.host) else {
            return Ok(word(IE_NOPEN));
        };
        let control = if enabled {
            Win16HostCommControl::SetBreak
        } else {
            Win16HostCommControl::ClearBreak
        };
        if let Err(error) = host.win16_comm_control(token, control) {
            return map_device_error(error, false);
        }
        self.comm_ports
            .ports
            .get_mut(&id)
            .expect("port checked")
            .break_set = enabled;
        Ok(0)
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

    fn escape_comm(
        &mut self,
        id: u16,
        function: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if function == GETMAXCOM {
            return Ok(u32::from(MAX_COM_ID));
        }
        if function == GETMAXLPT {
            return Ok(u32::from(MAX_LPT_ID));
        }
        let Some(control) = host_control(function) else {
            return Ok(long(IE_HARDWARE));
        };
        let Some(token) = self.comm_ports.ports.get(&id).map(|port| port.host) else {
            return Ok(long(IE_BADID));
        };
        if let Err(error) = host.win16_comm_control(token, control) {
            return map_device_error(error, true);
        }
        let port = self.comm_ports.ports.get_mut(&id).expect("port checked");
        match control {
            Win16HostCommControl::SetXoff => port.xoff = true,
            Win16HostCommControl::SetXon => port.xoff = false,
            Win16HostCommControl::SetRts => port.rts = true,
            Win16HostCommControl::ClearRts => port.rts = false,
            Win16HostCommControl::SetDtr => port.dtr = true,
            Win16HostCommControl::ClearDtr => port.dtr = false,
            Win16HostCommControl::Reset => {
                port.break_set = false;
                port.xoff = false;
                port.error = 0;
                port.rts = true;
                port.dtr = true;
            }
            Win16HostCommControl::SetBreak => port.break_set = true,
            Win16HostCommControl::ClearBreak => port.break_set = false,
        }
        Ok(0)
    }

    fn flush_comm(
        &mut self,
        id: u16,
        queue: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(token) = self.comm_ports.ports.get(&id).map(|port| port.host) else {
            return Ok(word(IE_BADID));
        };
        let queue = match queue {
            0 => Win16HostCommQueue::Transmit,
            1 => Win16HostCommQueue::Receive,
            _ => return Ok(word(IE_DEFAULT)),
        };
        if let Err(error) = host.win16_comm_flush(token, queue) {
            return map_device_error(error, false);
        }
        if queue == Win16HostCommQueue::Receive
            && let Some(port) = self.comm_ports.ports.get_mut(&id)
        {
            port.unget = None;
        }
        Ok(0)
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

    fn restore_unget(&mut self, id: u16, byte: Option<u8>) {
        let Some(byte) = byte else {
            return;
        };
        if let Some(port) = self.comm_ports.ports.get_mut(&id)
            && port.unget.is_none()
        {
            port.unget = Some(byte);
        }
    }

    fn latch_comm_error(&mut self, id: u16, flag: u16) {
        if let Some(port) = self.comm_ports.ports.get_mut(&id) {
            // The SDK's `GetCommError` table says `CE_MODE`, when set, is the
            // only valid error.
            if flag == CE_MODE || port.error & CE_MODE != 0 {
                port.error = CE_MODE;
            } else {
                port.error |= flag;
            }
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

/// Q101419: flow control is active only when the disable bit is clear.
/// Both bits set drives the line low.
fn flow_line(disable: bool, handshake: bool) -> Win16HostCommLine {
    if handshake && !disable {
        Win16HostCommLine::Handshake
    } else if disable {
        Win16HostCommLine::Disable
    } else {
        Win16HostCommLine::Enable
    }
}

struct CommReadView<'a> {
    bytes: &'a [u8],
    eof: bool,
    overflow: bool,
    rxflag: bool,
}

/// Non-binary reads stop at `EofChar` and do not return it or anything after it.
/// Bytes after it are `CE_RXOVER`. Q101419 keeps that rule across later host
/// reads: once EOF is latched, characters received afterward are overflow even
/// when they arrive in a new buffer. The unget byte was placed by the caller.
/// `EvtChar` in the host bytes is `EV_RXFLAG` whether or not `fChEvt` is set;
/// Q101419 says that flag is unused.
fn interpret_comm_read<'a>(
    dcb: &[u8; DCB16_LEN],
    data: &'a [u8],
    host_len: usize,
    already_eof: bool,
) -> CommReadView<'a> {
    let host_start = data.len().saturating_sub(host_len);
    let rxflag = data[host_start..].contains(&dcb[22]);
    let flags = u16::from_le_bytes([dcb[12], dcb[13]]);
    if flags & 1 != 0 {
        return CommReadView {
            bytes: data,
            eof: false,
            overflow: false,
            rxflag,
        };
    }
    if already_eof {
        let prefix = &data[..host_start];
        let returned = prefix
            .iter()
            .position(|byte| *byte == dcb[21])
            .map_or(prefix.len(), |index| index);
        return CommReadView {
            bytes: &prefix[..returned],
            eof: true,
            overflow: host_len > 0,
            rxflag,
        };
    }
    let Some(index) = data.iter().position(|byte| *byte == dcb[21]) else {
        return CommReadView {
            bytes: data,
            eof: false,
            overflow: false,
            rxflag,
        };
    };
    CommReadView {
        bytes: &data[..index],
        eof: true,
        overflow: index + 1 < data.len(),
        rxflag,
    }
}

fn armed_line_timeout(dcb: &[u8; DCB16_LEN]) -> bool {
    dcb_timeout(dcb, 6) != 0 || dcb_timeout(dcb, 8) != 0 || dcb_timeout(dcb, 10) != 0
}

fn line_timeout_error(dcb: &[u8; DCB16_LEN], lines: Win16HostCommLines) -> Option<u16> {
    if dcb_timeout(dcb, 6) != 0 && !lines.rlsd {
        Some(CE_RLSDTO)
    } else if dcb_timeout(dcb, 8) != 0 && !lines.cts {
        Some(CE_CTSTO)
    } else if dcb_timeout(dcb, 10) != 0 && !lines.dsr {
        Some(CE_DSRTO)
    } else {
        None
    }
}

fn dcb_timeout(dcb: &[u8; DCB16_LEN], offset: usize) -> u16 {
    u16::from_le_bytes([dcb[offset], dcb[offset + 1]])
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

fn map_device_error(error: RuntimeError, wide: bool) -> Result<u32, RuntimeError> {
    match error.kind() {
        Kind::CompatibilityGap | Kind::HostFailure | Kind::InvalidInput => Ok(if wide {
            long(IE_HARDWARE)
        } else {
            word(IE_HARDWARE)
        }),
        _ => Err(error),
    }
}

fn host_control(function: i16) -> Option<Win16HostCommControl> {
    Some(match function {
        SETXOFF => Win16HostCommControl::SetXoff,
        SETXON => Win16HostCommControl::SetXon,
        SETRTS => Win16HostCommControl::SetRts,
        CLRRTS => Win16HostCommControl::ClearRts,
        SETDTR => Win16HostCommControl::SetDtr,
        CLRDTR => Win16HostCommControl::ClearDtr,
        RESETDEV => Win16HostCommControl::Reset,
        _ => return None,
    })
}

fn host_config(dcb: &[u8; DCB16_LEN]) -> Result<Win16HostCommConfig, i16> {
    let baud_rate = comm_abi::numeric_baud(comm_abi::dcb_baud(dcb)).ok_or(IE_BAUDRATE)?;
    let flags = u16::from_le_bytes([dcb[12], dcb[13]]);
    // Win32 `SetCommState` fails when the XON and XOFF characters are equal.
    if dcb[14] == dcb[15] {
        return Err(IE_DEFAULT);
    }
    let rts = flow_line(flags & (1 << 1) != 0, flags & (1 << 14) != 0);
    let dtr = flow_line(flags & (1 << 7) != 0, flags & (1 << 13) != 0);
    Ok(Win16HostCommConfig {
        baud_rate,
        byte_size: dcb[3],
        parity: dcb[4],
        stop_bits: dcb[5],
        binary: flags & 1 != 0,
        parity_check: flags & (1 << 2) != 0,
        cts_output_flow: flags & (1 << 3) != 0,
        dsr_output_flow: flags & (1 << 4) != 0,
        dtr,
        rts,
        xon_output: flags & (1 << 8) != 0,
        xon_input: flags & (1 << 9) != 0,
        error_char_enabled: flags & (1 << 10) != 0,
        strip_null: flags & (1 << 11) != 0,
        xon_char: dcb[14],
        xoff_char: dcb[15],
        error_char: dcb[20],
        eof_char: dcb[21],
        event_char: dcb[22],
        xon_limit: u16::from_le_bytes([dcb[16], dcb[17]]),
        xoff_limit: u16::from_le_bytes([dcb[18], dcb[19]]),
    })
}

#[cfg(test)]
#[path = "win16_comm_tests.rs"]
mod tests;
