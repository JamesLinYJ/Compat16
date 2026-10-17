//! Named `COMn` and `LPTn` devices through the Unicode file API.
//!
//! The path is built from the parsed device number. Guest bytes and guest
//! ids never become a `HANDLE`. Serial timeouts, `SetCommState`, break,
//! modem escapes, and queue flushes go only to a COM handle. An LPT handle
//! is not given those calls. This does not touch UART registers or BIOS
//! serial services. Reads return the bytes already buffered so a quiet device
//! cannot stall the guest.

use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCommConfig, Win16HostCommControl,
    Win16HostCommDevice, Win16HostCommLine, Win16HostCommPort, Win16HostCommQueue,
    win16_comm_device_is_serial,
};
use windows_sys::Win32::Devices::Communication::{
    CLRDTR, CLRRTS, COMMTIMEOUTS, ClearCommBreak, DCB, EscapeCommFunction, GetCommState,
    PURGE_RXCLEAR, PURGE_TXCLEAR, PurgeComm, SETDTR, SETRTS, SETXOFF, SETXON, SetCommBreak,
    SetCommState, SetCommTimeouts,
};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, ReadFile, WriteFile,
};

/// Win32 `RESETDEV`. `windows-sys` does not export this escape name.
const RESETDEV: u32 = 7;

pub(super) struct Win16CommPorts {
    ports: BTreeMap<Win16HostCommPort, OpenPort>,
    next_id: u64,
}

struct OpenPort {
    handle: OwnedHandle,
    serial: bool,
}

impl Win16CommPorts {
    pub(super) fn new() -> Self {
        Self {
            ports: BTreeMap::new(),
            next_id: 1,
        }
    }

    pub(super) fn open(
        &mut self,
        device: Win16HostCommDevice,
        _in_queue: u16,
        _out_queue: u16,
    ) -> Result<Win16HostCommPort, RuntimeError> {
        let path = device_path(device)?;
        let serial = win16_comm_device_is_serial(device);
        // SAFETY: `path` is an owned UTF-16 NUL-terminated `\\.\COMn` or
        // `\\.\LPTn` name. The resulting HANDLE is owned by `OwnedHandle`.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(device_error("open"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        if serial {
            let timeouts = COMMTIMEOUTS {
                ReadIntervalTimeout: u32::MAX,
                ReadTotalTimeoutMultiplier: 0,
                ReadTotalTimeoutConstant: 0,
                WriteTotalTimeoutMultiplier: 0,
                WriteTotalTimeoutConstant: 1_000,
            };
            // SAFETY: `handle` is the CreateFileW HANDLE just opened, and
            // `timeouts` is a local value that stays live for the call.
            // LPT handles never reach this call.
            let timed = unsafe { SetCommTimeouts(handle.as_raw_handle(), &timeouts) };
            if timed == 0 {
                return Err(device_error("set timeouts"));
            }
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 comm port identity exhausted",
            ));
        };
        let token = Win16HostCommPort(self.next_id);
        self.next_id = next_id;
        self.ports.insert(token, OpenPort { handle, serial });
        Ok(token)
    }

    pub(super) fn configure(
        &mut self,
        port: Win16HostCommPort,
        config: &Win16HostCommConfig,
    ) -> Result<(), RuntimeError> {
        let handle = self.serial_handle(port)?;
        let mut dcb = DCB::default();
        dcb.DCBlength = u32::try_from(std::mem::size_of::<DCB>()).map_err(|error| {
            RuntimeError::with_source(Kind::InternalInvariant, "comm DCB width", error)
        })?;
        // SAFETY: `handle` is an owned COM CreateFileW HANDLE. `dcb` is local
        // and stays live for both calls. No guest address is passed.
        let current = unsafe { GetCommState(handle, &mut dcb) };
        if current == 0 {
            return Err(device_error("read state"));
        }
        dcb.BaudRate = config.baud_rate;
        dcb.ByteSize = config.byte_size;
        dcb.Parity = config.parity;
        dcb.StopBits = config.stop_bits;
        dcb._bitfield = win32_flags(config);
        dcb.XonLim = config.xon_limit;
        dcb.XoffLim = config.xoff_limit;
        dcb.XonChar = config.xon_char as i8;
        dcb.XoffChar = config.xoff_char as i8;
        dcb.ErrorChar = config.error_char as i8;
        dcb.EofChar = config.eof_char as i8;
        dcb.EvtChar = config.event_char as i8;
        let applied = unsafe { SetCommState(handle, &dcb) };
        if applied == 0 {
            return Err(device_error("set state"));
        }
        Ok(())
    }

    pub(super) fn control(
        &mut self,
        port: Win16HostCommPort,
        control: Win16HostCommControl,
    ) -> Result<(), RuntimeError> {
        let handle = self.serial_handle(port)?;
        // SAFETY: `handle` is an owned COM CreateFileW HANDLE. Break and
        // modem escapes take no guest pointer.
        let applied = unsafe {
            match control {
                Win16HostCommControl::SetBreak => SetCommBreak(handle),
                Win16HostCommControl::ClearBreak => ClearCommBreak(handle),
                Win16HostCommControl::SetXoff => EscapeCommFunction(handle, SETXOFF),
                Win16HostCommControl::SetXon => EscapeCommFunction(handle, SETXON),
                Win16HostCommControl::SetRts => EscapeCommFunction(handle, SETRTS),
                Win16HostCommControl::ClearRts => EscapeCommFunction(handle, CLRRTS),
                Win16HostCommControl::SetDtr => EscapeCommFunction(handle, SETDTR),
                Win16HostCommControl::ClearDtr => EscapeCommFunction(handle, CLRDTR),
                Win16HostCommControl::Reset => EscapeCommFunction(handle, RESETDEV),
            }
        };
        if applied == 0 {
            return Err(device_error("line control"));
        }
        Ok(())
    }

    pub(super) fn flush(
        &mut self,
        port: Win16HostCommPort,
        queue: Win16HostCommQueue,
    ) -> Result<(), RuntimeError> {
        let handle = self.serial_handle(port)?;
        let flags = match queue {
            Win16HostCommQueue::Transmit => PURGE_TXCLEAR,
            Win16HostCommQueue::Receive => PURGE_RXCLEAR,
        };
        // SAFETY: `handle` is an owned COM CreateFileW HANDLE. The flags only
        // name which driver queue to discard.
        let applied = unsafe { PurgeComm(handle, flags) };
        if applied == 0 {
            return Err(device_error("flush"));
        }
        Ok(())
    }

    pub(super) fn read(
        &mut self,
        port: Win16HostCommPort,
        output: &mut [u8],
    ) -> Result<usize, RuntimeError> {
        let handle = self.handle(port)?;
        transfer(handle, output)
    }

    pub(super) fn write(
        &mut self,
        port: Win16HostCommPort,
        input: &[u8],
    ) -> Result<usize, RuntimeError> {
        let handle = self.handle(port)?;
        let mut moved = 0_u32;
        let count = u32::try_from(input.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "comm write length", error)
        })?;
        let pointer = if input.is_empty() {
            std::ptr::null()
        } else {
            input.as_ptr()
        };
        // SAFETY: `handle` is an owned CreateFileW HANDLE. `input` covers
        // `count` bytes, or the pointer is null for a zero-length write.
        let success =
            unsafe { WriteFile(handle, pointer, count, &mut moved, std::ptr::null_mut()) };
        if success == 0 {
            return Err(device_error("write"));
        }
        let moved = usize::try_from(moved).map_err(|error| {
            RuntimeError::with_source(Kind::InternalInvariant, "comm write length", error)
        })?;
        if moved > input.len() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "comm write exceeded its buffer",
            ));
        }
        Ok(moved)
    }

    pub(super) fn close(&mut self, port: Win16HostCommPort) -> Result<(), RuntimeError> {
        self.ports.remove(&port).map(|_| ()).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "Win16 comm port token is not open")
        })
    }

    fn serial_handle(&self, port: Win16HostCommPort) -> Result<HANDLE, RuntimeError> {
        let open = self.ports.get(&port).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "Win16 comm port token is not open")
        })?;
        if !open.serial {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "LPT handle does not accept serial timeouts or line control",
            ));
        }
        Ok(open.handle.as_raw_handle())
    }

    fn handle(&self, port: Win16HostCommPort) -> Result<HANDLE, RuntimeError> {
        self.ports
            .get(&port)
            .map(|open| open.handle.as_raw_handle())
            .ok_or_else(|| {
                RuntimeError::new(Kind::InvalidInput, "Win16 comm port token is not open")
            })
    }
}

fn win32_flags(config: &Win16HostCommConfig) -> u32 {
    let mut flags = 0_u32;
    if config.binary {
        flags |= 1 << 0;
    }
    if config.parity_check {
        flags |= 1 << 1;
    }
    if config.cts_output_flow {
        flags |= 1 << 2;
    }
    if config.dsr_output_flow {
        flags |= 1 << 3;
    }
    flags |= line_code(config.dtr) << 4;
    if config.xon_output {
        flags |= 1 << 8;
    }
    if config.xon_input {
        flags |= 1 << 9;
    }
    if config.error_char_enabled {
        flags |= 1 << 10;
    }
    if config.strip_null {
        flags |= 1 << 11;
    }
    flags |= line_code(config.rts) << 12;
    flags
}

fn line_code(line: Win16HostCommLine) -> u32 {
    match line {
        Win16HostCommLine::Disable => 0,
        Win16HostCommLine::Enable => 1,
        Win16HostCommLine::Handshake => 2,
    }
}

fn device_path(device: Win16HostCommDevice) -> Result<Vec<u16>, RuntimeError> {
    let name = match device {
        Win16HostCommDevice::Com(number @ 1..=9) => format!("\\\\.\\COM{number}"),
        Win16HostCommDevice::Lpt(number @ 1..=3) => format!("\\\\.\\LPT{number}"),
        Win16HostCommDevice::Com(_) | Win16HostCommDevice::Lpt(_) => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 comm device number is out of range",
            ));
        }
    };
    Ok(name.encode_utf16().chain(std::iter::once(0)).collect())
}

fn transfer(handle: HANDLE, buffer: &mut [u8]) -> Result<usize, RuntimeError> {
    let mut moved = 0_u32;
    let count = u32::try_from(buffer.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "comm transfer length", error)
    })?;
    let pointer = if buffer.is_empty() {
        std::ptr::null_mut()
    } else {
        buffer.as_mut_ptr().cast()
    };
    // SAFETY: `handle` is an owned CreateFileW HANDLE retained in the port
    // table. `buffer` covers `count` bytes, or the pointer is null for a
    // zero-length call. No guest address is passed.
    let success = unsafe { ReadFile(handle, pointer, count, &mut moved, std::ptr::null_mut()) };
    if success == 0 {
        return Err(device_error("read"));
    }
    let moved = usize::try_from(moved).map_err(|error| {
        RuntimeError::with_source(Kind::InternalInvariant, "comm transfer length", error)
    })?;
    if moved > buffer.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "comm transfer exceeded its buffer",
        ));
    }
    Ok(moved)
}

fn device_error(action: &str) -> RuntimeError {
    // SAFETY: GetLastError reads the calling thread's last error and has no pointer arguments.
    let code = unsafe { GetLastError() };
    RuntimeError::new(
        Kind::HostFailure,
        format!("Win16 comm device {action} failed with Windows error {code}"),
    )
}
