//! Windows global atoms with per-runtime reference cleanup.

use std::collections::BTreeMap;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostAtomName};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::System::DataExchange::{
    GlobalAddAtomW, GlobalDeleteAtom, GlobalFindAtomW, GlobalGetAtomNameW,
};

use super::guest_text::GuestTextCodec;

const MAX_ATOM_NAME_BYTES: usize = 255;
const FIRST_STRING_ATOM: u16 = 0xC000;

pub(super) struct Win16Atoms {
    owned: BTreeMap<u16, u32>,
}

impl Win16Atoms {
    pub(super) fn new() -> Self { Self { owned: BTreeMap::new() } }

    fn call_name(
        codec: GuestTextCodec,
        name: Win16HostAtomName<'_>,
        call: unsafe extern "system" fn(*const u16) -> u16,
    )
        -> Result<u16, RuntimeError> {
        match name {
            Win16HostAtomName::Integer(id) => {
                if !(1..FIRST_STRING_ATOM).contains(&id) { return Ok(0); }
                // SAFETY: MAKEINTATOM is the documented low-word integer
                // encoding. No Rust code dereferences the pseudo-pointer.
                Ok(unsafe { call(usize::from(id) as *const u16) })
            }
            Win16HostAtomName::String(bytes) => {
                if bytes.len() > MAX_ATOM_NAME_BYTES || bytes.contains(&0) { return Ok(0); }
                let wide = match codec.to_wide_z(bytes) {
                    Ok(wide) => wide,
                    Err(error) if guest_text_failure(&error) => return Ok(0),
                    Err(error) => return Err(error),
                };
                // SAFETY: The converted name is an owned NUL-terminated UTF-16
                // string and remains live for the native atom-table call.
                Ok(unsafe { call(wide.as_ptr()) })
            }
        }
    }

    pub(super) fn add(
        &mut self,
        codec: GuestTextCodec,
        name: Win16HostAtomName<'_>,
    ) -> Result<u16, RuntimeError> {
        let atom = Self::call_name(codec, name, GlobalAddAtomW)?;
        if atom >= FIRST_STRING_ATOM {
            let count = self.owned.entry(atom).or_default();
            let Some(next) = count.checked_add(1) else {
                // SAFETY: Undo the new reference before returning failure.
                unsafe { GlobalDeleteAtom(atom) };
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 global atom reference count exhausted"));
            };
            *count = next;
        }
        Ok(atom)
    }

    pub(super) fn find(
        &self,
        codec: GuestTextCodec,
        name: Win16HostAtomName<'_>,
    ) -> Result<u16, RuntimeError> {
        Self::call_name(codec, name, GlobalFindAtomW)
    }

    pub(super) fn delete(&mut self, atom: u16) -> Result<(), RuntimeError> {
        // SAFETY: GlobalDeleteAtom accepts integer and string atom values. A
        // zero result is its documented return regardless of success.
        unsafe { SetLastError(0) };
        unsafe { GlobalDeleteAtom(atom) };
        // The documented ATOM return is always zero. Resource retirement
        // needs the actual deletion outcome, independent of the guest return.
        let error = unsafe { GetLastError() };
        if error != 0 {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "delete Windows global atom",
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
        if let Some(count) = self.owned.get_mut(&atom) {
            *count -= 1;
            if *count == 0 { self.owned.remove(&atom); }
        }
        Ok(())
    }

    pub(super) fn get_name(&self, codec: GuestTextCodec, atom: u16, capacity: u16)
        -> Result<(Vec<u8>, u16), RuntimeError> {
        if capacity == 0 { return Ok((Vec::new(), 0)); }
        let mut wide = Vec::new();
        wide.try_reserve_exact(MAX_ATOM_NAME_BYTES + 1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 atom name output", error,
        ))?;
        wide.resize(MAX_ATOM_NAME_BYTES + 1, 0);
        // Win16 reports a truncated name's copied length, while Win32
        // reports zero for a short caller buffer. Read the full atom name,
        // then apply the Win16 buffer contract at the guest boundary.
        // SAFETY: `wide` is writable for 256 UTF-16 units and stays live.
        let full_length = unsafe { GlobalGetAtomNameW(
            atom, wide.as_mut_ptr(), (MAX_ATOM_NAME_BYTES + 1) as i32,
        ) };
        if full_length == 0 { return Ok((Vec::new(), 0)); }
        let full_length = usize::try_from(full_length).map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Windows returned an invalid atom name length",
        ))?;
        if full_length >= wide.len() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Windows atom name exceeded the native buffer"));
        }
        let guest_capacity = usize::from(capacity).saturating_sub(1).min(MAX_ATOM_NAME_BYTES);
        let output = match codec.from_wide_bounded(&wide[..full_length], guest_capacity) {
            Ok(output) => output,
            Err(error) if guest_text_failure(&error) => return Ok((Vec::new(), 0)),
            Err(error) => return Err(error),
        };
        let copied = u16::try_from(output.bytes.len()).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "Win16 atom name length exceeds WORD", error,
        ))?;
        let mut bytes = output.bytes;
        bytes.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "terminate Win16 atom name output", error,
        ))?;
        bytes.push(0);
        Ok((bytes, copied))
    }
}

fn guest_text_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::HostFailure | Kind::InvalidInput)
}

impl Drop for Win16Atoms {
    fn drop(&mut self) {
        for (atom, count) in std::mem::take(&mut self.owned) {
            for _ in 0..count {
                // SAFETY: Each count corresponds to one successful Add call
                // that the guest did not balance with Delete.
                unsafe { GlobalDeleteAtom(atom) };
            }
        }
    }
}
