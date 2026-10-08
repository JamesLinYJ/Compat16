use crate::{DiagnosticKind as Kind, RuntimeError, Win32HostSearchHandle};

use super::Win32ImportState;

pub(super) const FIRST_GUEST_SEARCH_HANDLE: u32 = 0xe000_0001;
const GUEST_SEARCH_HANDLE_LIMIT: u32 = 0xf000_0000;

#[derive(Clone, Copy, Debug)]
pub(super) struct SearchHandleRecord {
    value: u32,
    reservation: u64,
    native: Option<Win32HostSearchHandle>,
    closing: bool,
}

#[derive(Debug)]
pub(crate) struct Win32GuestSearchHandleReservation { value: u32, serial: u64 }

impl Win32ImportState {
    pub(crate) fn reserve_guest_search_handle(
        &mut self,
    ) -> Result<Win32GuestSearchHandleReservation, RuntimeError> {
        let value = self.next_guest_search_handle
            .ok_or_else(|| exhausted("PE32 guest search handles"))?;
        if value >= GUEST_SEARCH_HANDLE_LIMIT { return Err(exhausted("PE32 guest search handles")); }
        let serial = self.next_search_serial
            .ok_or_else(|| exhausted("PE32 search-handle generations"))?;
        self.search_handles.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve PE32 guest search handle", error))?;
        self.next_guest_search_handle = value.checked_add(1);
        self.next_search_serial = serial.checked_add(1);
        self.search_handles.push(SearchHandleRecord {
            value, reservation: serial, native: None, closing: false,
        });
        Ok(Win32GuestSearchHandleReservation { value, serial })
    }

    pub(crate) fn publish_guest_search_handle(
        &mut self, reservation: &Win32GuestSearchHandleReservation,
        native: Win32HostSearchHandle,
    ) -> Result<u32, RuntimeError> {
        let record = self.search_handles.iter_mut().find(|record|
            record.value == reservation.value && record.reservation == reservation.serial)
            .ok_or_else(|| invariant("PE32 guest search-handle reservation is stale"))?;
        if record.native.is_some() || record.closing {
            return Err(invariant("PE32 guest search-handle reservation was already completed"));
        }
        record.native = Some(native);
        Ok(record.value)
    }

    pub(crate) fn cancel_guest_search_handle(
        &mut self, reservation: Win32GuestSearchHandleReservation,
    ) -> Result<(), RuntimeError> {
        let index = self.search_handles.iter().position(|record|
            record.value == reservation.value && record.reservation == reservation.serial)
            .ok_or_else(|| invariant("PE32 guest search-handle reservation is stale"))?;
        if self.search_handles[index].native.is_some() {
            return Err(invariant("cancelled PE32 search handle owns a native search"));
        }
        self.search_handles.swap_remove(index);
        Ok(())
    }

    pub(crate) fn native_search_handle(&self, value: u32) -> Option<Win32HostSearchHandle> {
        self.search_handles.iter().find(|record| record.value == value && !record.closing)
            .and_then(|record| record.native)
    }

    pub(crate) fn live_guest_search_handles(
        &self,
    ) -> impl Iterator<Item = (u32, Win32HostSearchHandle)> + '_ {
        self.search_handles.iter().filter_map(|record| record.native
            .filter(|_| !record.closing).map(|native| (record.value, native)))
    }

    pub(crate) fn begin_close_search_handle(
        &mut self, value: u32,
    ) -> Result<Win32HostSearchHandle, RuntimeError> {
        let record = self.search_handles.iter_mut().find(|record| record.value == value)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "invalid PE32 search HANDLE"))?;
        let native = record.native
            .ok_or_else(|| invariant("PE32 search HANDLE is not published"))?;
        if record.closing { return Err(invariant("PE32 search HANDLE close is already active")); }
        record.closing = true;
        Ok(native)
    }

    pub(crate) fn finish_close_search_handle(
        &mut self, value: u32, closed: bool,
    ) -> Result<(), RuntimeError> {
        let index = self.search_handles.iter().position(|record| record.value == value)
            .ok_or_else(|| invariant("PE32 search HANDLE disappeared during close"))?;
        if !self.search_handles[index].closing {
            return Err(invariant("PE32 search HANDLE close completion has no matching request"));
        }
        if closed { self.search_handles.swap_remove(index); }
        else { self.search_handles[index].closing = false; }
        Ok(())
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}
