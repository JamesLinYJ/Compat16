//! GDI printer environment and QueryAbort.
//!
//! Windows 3.1 `SetEnvironment` / `GetEnvironment` keep a GDI-owned binary
//! block per port. The block is copied guest bytes, never a host pointer and
//! never a process environment string. A null `GetEnvironment` buffer returns
//! the stored size and writes nothing. A short buffer receives only the
//! copied prefix; the remainder stays as the caller left it.
//!
//! `QueryAbort` answers whether printing should continue. With no abort
//! procedure installed, a live device context continues. The code word is the
//! value an installed procedure receives. It is not a pointer and it is not
//! forwarded to the host.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use win16_abi::gdi_abi::DEVMODE16_DEVICE_NAME_SIZE;

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    pub(super) fn set_printer_environment(
        &mut self,
        port: Option<Vec<u8>>,
        environment: Option<Vec<u8>>,
        capacity: u16,
    ) -> Result<u32, RuntimeError> {
        let Some(key) = environment_key(port, environment.as_deref(), capacity) else {
            return Ok(0);
        };
        if capacity == 0 {
            self.printer_environments.remove(&key);
            return Ok(1);
        }
        let Some(bytes) = environment else {
            return Ok(0);
        };
        if bytes.len() != usize::from(capacity) {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "SetEnvironment copied a different byte count than its capacity",
            ));
        }
        self.printer_environments.insert(key, bytes);
        Ok(u32::from(capacity))
    }

    pub(super) fn get_printer_environment(
        &mut self,
        port: Option<Vec<u8>>,
        environment: u32,
        capacity: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(key) = port.filter(|port| !port.is_empty()) else {
            return Ok(0);
        };
        let Some(stored) = self.printer_environments.get(&key).cloned() else {
            return Ok(0);
        };
        if environment == 0 {
            let size = u16::try_from(stored.len()).map_err(|_| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "printer environment is larger than a Win16 UINT",
                )
            })?;
            return Ok(u32::from(size));
        }
        let copy = usize::from(capacity).min(stored.len());
        if copy == 0 {
            return Ok(0);
        }
        let pointer = self.selectors.pointer_from_far(environment)?;
        self.selectors.write(memory, pointer, &stored[..copy])?;
        let copied = u16::try_from(copy).map_err(|_| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "copied printer environment exceeds a Win16 UINT",
            )
        })?;
        Ok(u32::from(copied))
    }

    /// No installed abort procedure means printing continues on a live DC.
    /// An unknown HDC has no job to continue. `QueryAbort` enters an installed
    /// procedure from the GDI dispatch path instead of this answer.
    pub(super) fn query_abort(&self, dc: u16) -> Result<u32, RuntimeError> {
        Ok(u32::from(self.guest_gdi.dc(dc).is_some()))
    }
}

/// Port bytes are the key. A null or empty port uses the leading device-name
/// bytes of an environment being stored, which is how a null port locates its
/// block. Deleting without a port has no key.
fn environment_key(
    port: Option<Vec<u8>>,
    environment: Option<&[u8]>,
    capacity: u16,
) -> Option<Vec<u8>> {
    if let Some(port) = port.filter(|port| !port.is_empty()) {
        return Some(port);
    }
    if capacity == 0 {
        return None;
    }
    let bytes = environment?;
    let window = &bytes[..bytes.len().min(DEVMODE16_DEVICE_NAME_SIZE)];
    let end = window
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(window.len());
    if end == 0 {
        None
    } else {
        Some(window[..end].to_vec())
    }
}

pub(super) type PrinterEnvironments = BTreeMap<Vec<u8>, Vec<u8>>;
