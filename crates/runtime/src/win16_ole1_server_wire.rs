//! Checked OLE1 server/document/client interface and vtable decoding.
//!
//! These routines accept only segmented guest addresses. A returned callback
//! address is executable only after selector-table validation; no guest FAR
//! pointer is converted into a host function pointer.

use guest_core::MemoryError;
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, Win16Error};

use super::Win16State;
use super::ole1::{OLE1_ERROR_ADDRESS, OLE1_ERROR_OBJECT};
use super::win16_ole1_server_callbacks::{ServerCallbackMethod, ServerDocumentCallbackMethod};

/// Guest pointer/table faults retain their documented OLE status, while a
/// sticky backing-store fault must stop execution with its original cause.
#[derive(Debug)]
pub(super) enum Ole1ServerWireError {
    GuestStatus(u16),
    Runtime(crate::RuntimeError),
}

pub(super) fn selector_error(error: Win16Error, guest_status: u16) -> Ole1ServerWireError {
    match error {
        error @ Win16Error::Memory(MemoryError::StorageAccess { .. }) => {
            Ole1ServerWireError::Runtime(crate::runtime_error(error))
        }
        _ => Ole1ServerWireError::GuestStatus(guest_status),
    }
}

pub(super) fn into_runtime_error(
    error: Ole1ServerWireError,
    context: &'static str,
) -> crate::RuntimeError {
    match error {
        Ole1ServerWireError::GuestStatus(status) => crate::RuntimeError::new(
            crate::DiagnosticKind::GuestFault,
            format!("{context} ({status})"),
        ),
        Ole1ServerWireError::Runtime(error) => error.with_context(context),
    }
}

pub(super) fn status_or_runtime(error: Ole1ServerWireError) -> Result<u16, crate::RuntimeError> {
    match error {
        Ole1ServerWireError::GuestStatus(status) => Ok(status),
        Ole1ServerWireError::Runtime(error) => Err(error),
    }
}

const FAR_POINTER_BYTES: u32 = 4;
const SERVER_VTABLE_SLOTS: u32 = ServerCallbackMethod::vtable_slots();
const DOCUMENT_VTABLE_SLOTS: u32 = ServerDocumentCallbackMethod::vtable_slots();

impl Win16State {
    pub(super) fn ole1_server_method_address(
        &self,
        server_far: u32,
        slot: u32,
        memory: &mut Memory,
    ) -> Result<u32, Ole1ServerWireError> {
        self.ole1_interface_method_address(server_far, slot, SERVER_VTABLE_SLOTS, memory)
    }

    pub(super) fn ole1_server_document_method_address(
        &self,
        document_far: u32,
        slot: u32,
        memory: &mut Memory,
    ) -> Result<u32, Ole1ServerWireError> {
        self.ole1_interface_method_address(document_far, slot, DOCUMENT_VTABLE_SLOTS, memory)
    }

    /// Validate the complete interface prefix and exact requested table slot.
    /// Table extents match OLE.H: OLESERVERVTBL is 7 FARPROC entries,
    /// OLESERVERDOCVTBL is 8, and OLECLIENTVTBL is one.
    pub(super) fn ole1_interface_method_address(
        &self,
        interface_far: u32,
        slot: u32,
        table_slots: u32,
        memory: &mut Memory,
    ) -> Result<u32, Ole1ServerWireError> {
        if interface_far == 0 || slot >= table_slots {
            return Err(Ole1ServerWireError::GuestStatus(OLE1_ERROR_OBJECT));
        }
        let interface = self
            .selectors
            .pointer_from_far(interface_far)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        self.selectors
            .translate(interface, Access::Read, FAR_POINTER_BYTES as usize, memory)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        let mut vtable_bytes = [0_u8; 4];
        self.selectors
            .read(memory, interface, &mut vtable_bytes)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        let vtable_far = u32::from_le_bytes(vtable_bytes);
        if vtable_far == 0 {
            return Err(Ole1ServerWireError::GuestStatus(OLE1_ERROR_OBJECT));
        }

        let extent = table_slots
            .checked_mul(FAR_POINTER_BYTES)
            .ok_or(Ole1ServerWireError::GuestStatus(OLE1_ERROR_OBJECT))?;
        let table = self
            .selectors
            .pointer_from_far(vtable_far)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        self.selectors
            .translate(table, Access::Read, extent as usize, memory)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;

        let slot_offset = slot
            .checked_mul(FAR_POINTER_BYTES)
            .ok_or(Ole1ServerWireError::GuestStatus(OLE1_ERROR_OBJECT))?;
        let method_slot = self
            .selectors
            .add_bytes(table, slot_offset)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        let mut method_bytes = [0_u8; 4];
        self.selectors
            .read(memory, method_slot, &mut method_bytes)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        let method_far = u32::from_le_bytes(method_bytes);
        if method_far == 0 {
            return Err(Ole1ServerWireError::GuestStatus(OLE1_ERROR_OBJECT));
        }
        let method = self
            .selectors
            .pointer_from_far(method_far)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        self.selectors
            .translate(method, Access::Execute, 1, memory)
            .map_err(|error| selector_error(error, OLE1_ERROR_OBJECT))?;
        Ok(method_far)
    }

    /// Preflight a FAR string without converting it or retaining a host view.
    /// The caller supplies the ABI-specific maximum; the returned length does
    /// not include the terminating NUL.
    pub(super) fn ole1_checked_string_len(
        &self,
        far: u32,
        max_bytes: usize,
        memory: &mut Memory,
    ) -> Result<usize, Ole1ServerWireError> {
        if far == 0 {
            return Err(Ole1ServerWireError::GuestStatus(OLE1_ERROR_ADDRESS));
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|error| selector_error(error, OLE1_ERROR_ADDRESS))?;
        for index in 0..=max_bytes {
            let offset = u32::try_from(index)
                .map_err(|_| Ole1ServerWireError::GuestStatus(OLE1_ERROR_ADDRESS))?;
            let byte = self
                .selectors
                .add_bytes(pointer, offset)
                .map_err(|error| selector_error(error, OLE1_ERROR_ADDRESS))?;
            self.selectors
                .translate(byte, Access::Read, 1, memory)
                .map_err(|error| selector_error(error, OLE1_ERROR_ADDRESS))?;
            let mut value = [0_u8; 1];
            self.selectors
                .read(memory, byte, &mut value)
                .map_err(|error| selector_error(error, OLE1_ERROR_ADDRESS))?;
            if value[0] == 0 {
                return Ok(index);
            }
        }
        Err(Ole1ServerWireError::GuestStatus(OLE1_ERROR_ADDRESS))
    }

    pub(super) fn ole1_checked_output_pointer(
        &self,
        far: u32,
        bytes: usize,
        memory: &mut Memory,
    ) -> Result<SegmentedPointer, Ole1ServerWireError> {
        if far == 0 {
            return Err(Ole1ServerWireError::GuestStatus(OLE1_ERROR_ADDRESS));
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|error| selector_error(error, OLE1_ERROR_ADDRESS))?;
        self.selectors
            .translate(pointer, Access::Write, bytes, memory)
            .map_err(|error| selector_error(error, OLE1_ERROR_ADDRESS))?;
        Ok(pointer)
    }
}
