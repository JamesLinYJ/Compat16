//! Named `COMn` and `LPTn` devices through the Unicode file API.
//!
//! The path is built from the parsed device number. Guest bytes and guest
//! ids never become a `HANDLE`. This does not touch UART registers or BIOS
//! serial services. Reads return the bytes already buffered so a quiet device
//! cannot stall the guest.

use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostCommDevice, Win16HostCommPort};
use windows_sys::Win32::Devices::Communication::{COMMTIMEOUTS, SetCommTimeouts};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, ReadFile, WriteFile,
};

pub(super) struct Win16CommPorts {
    ports: BTreeMap<Win16HostCommPort, OwnedHandle>,
    next_id: u64,
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
        let timeouts = COMMTIMEOUTS {
            ReadIntervalTimeout: u32::MAX,
            ReadTotalTimeoutMultiplier: 0,
            ReadTotalTimeoutConstant: 0,
            WriteTotalTimeoutMultiplier: 0,
            WriteTotalTimeoutConstant: 1_000,
        };
        // SAFETY: `handle` is the CreateFileW HANDLE just opened, and
        // `timeouts` is a local value that stays live for the call.
        let timed = unsafe { SetCommTimeouts(handle.as_raw_handle(), &timeouts) };
        if timed == 0 {
            return Err(device_error("set timeouts"));
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 comm port identity exhausted",
            ));
        };
        let token = Win16HostCommPort(self.next_id);
        self.next_id = next_id;
        self.ports.insert(token, handle);
        Ok(token)
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

    fn handle(&self, port: Win16HostCommPort) -> Result<HANDLE, RuntimeError> {
        self.ports
            .get(&port)
            .map(|handle| handle.as_raw_handle())
            .ok_or_else(|| {
                RuntimeError::new(Kind::InvalidInput, "Win16 comm port token is not open")
            })
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
