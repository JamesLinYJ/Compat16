//! KERNEL local atoms belong to the calling data segment's real local heap.
//!
//! No host atom or selector-indexed cache participates in identity. We take a
//! checked snapshot for name comparisons and let LocalOperation perform all
//! mutations, including automatic-DGROUP growth and tracked writeback.

use guest_core::memory::Memory;
use win16_abi::{Win16AtomName, Win16KernelAtomsRequest, Win16OutputBuffer};
use win16_abi::local_heap::{LocalAtomEntry, LocalHeap, LocalHeapError};

use super::{Win16State, local_heap::LocalOperation};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const FIRST_STRING_ATOM: u16 = 0xc000;
const MAX_ATOM_NAME_BYTES: usize = 255;

enum AtomInput {
    Invalid,
    Integer(u16),
    String(Vec<u8>),
}

/// Integer spellings are parsed before any heap or host service is touched.
/// A leading '#' only selects the integer form when every following byte is
/// a decimal digit. Other '#' names remain ordinary strings, safely including
/// the first call before an atom table exists.
fn classify_name(name: Win16AtomName) -> AtomInput {
    match name {
        Win16AtomName::Integer(atom) => {
            if (1..FIRST_STRING_ATOM).contains(&atom) { AtomInput::Integer(atom) }
            else { AtomInput::Invalid }
        }
        Win16AtomName::String(bytes) => {
            // Bounded policy for inputs whose historic edge behavior differs
            // between versions: reject empty/overlong names without truncating.
            if bytes.is_empty() || bytes.len() > MAX_ATOM_NAME_BYTES || bytes.contains(&0) {
                return AtomInput::Invalid;
            }
            if bytes[0] == b'#' && bytes.len() > 1 && bytes[1..].iter().all(u8::is_ascii_digit) {
                let mut value = 0u16;
                for &digit in &bytes[1..] {
                    let Some(next) = value.checked_mul(10)
                        .and_then(|value| value.checked_add(u16::from(digit - b'0'))) else {
                        return AtomInput::Invalid;
                    };
                    value = next;
                }
                if (1..FIRST_STRING_ATOM).contains(&value) { AtomInput::Integer(value) }
                else { AtomInput::Invalid }
            } else {
                AtomInput::String(bytes)
            }
        }
    }
}

impl Win16State {
    pub(super) fn local_atom_request(
        &mut self,
        caller_ds: u16,
        request: Win16KernelAtomsRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        match request {
            Win16KernelAtomsRequest::InitAtomTable { buckets } => {
                // A signed invalid argument does not need to inspect DS.
                if buckets < 0 { return Ok(0); }
                self.local_operation(caller_ds, LocalOperation::AtomInit { buckets }, memory)
                    .map(|value| value as u16)
            }
            Win16KernelAtomsRequest::AddAtom { name } => {
                self.local_atom_lookup(caller_ds, name, true, memory, host)
            }
            Win16KernelAtomsRequest::FindAtom { name } => {
                self.local_atom_lookup(caller_ds, name, false, memory, host)
            }
            Win16KernelAtomsRequest::DeleteAtom { atom } => {
                if atom < FIRST_STRING_ATOM { return Ok(0); }
                self.local_operation(caller_ds, LocalOperation::AtomDelete { atom }, memory)
                    .map(|value| value as u16)
            }
            Win16KernelAtomsRequest::GetAtomHandle { atom } => {
                // Integer atoms have no allocated string storage.
                if atom < FIRST_STRING_ATOM { return Ok(0); }
                self.local_operation(caller_ds, LocalOperation::AtomHandle { atom }, memory)
                    .map(|value| value as u16)
            }
            Win16KernelAtomsRequest::GetAtomName { atom, output_buffer } => {
                self.local_atom_get_name(caller_ds, atom, output_buffer, memory)
            }
        }
    }

    fn local_atom_lookup(
        &mut self,
        caller_ds: u16,
        name: Win16AtomName,
        add: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let bytes = match classify_name(name) {
            AtomInput::Invalid => return Ok(0),
            AtomInput::Integer(atom) => return Ok(atom),
            AtomInput::String(bytes) => bytes,
        };
        let Some(entries) = self.local_atom_entries(caller_ds, memory)? else { return Ok(0); };
        // The existing host boundary decodes the configured guest ANSI page,
        // performs Unicode case conversion and encodes the result. Never case
        // individual bytes: a DBCS trail byte can look like an ASCII letter.
        // We normalize all names afresh so changes to backing or code-page
        // policy cannot leave a cached lookup key attached to a reused selector.
        let key = host.win16_ansi_lower_string(&bytes)?;
        let mut matching_atom = None;
        for entry in entries {
            if host.win16_ansi_lower_string(&entry.name)? == key {
                matching_atom = Some(entry.atom);
                break;
            }
        }
        if !add { return Ok(matching_atom.unwrap_or(0)); }
        // Bucket placement is an internal distribution policy, not an API
        // guarantee. Equality above always checks the complete validated table.
        let hash = key.iter().fold(0u32, |hash, &byte| {
            hash.wrapping_mul(31).wrapping_add(u32::from(byte))
        });
        self.local_operation(caller_ds,
            LocalOperation::AtomAdd { name: bytes, matching_atom, hash }, memory)
            .map(|value| value as u16)
    }

    fn local_atom_entries(
        &self,
        caller_ds: u16,
        memory: &Memory,
    ) -> Result<Option<Vec<LocalAtomEntry>>, RuntimeError> {
        let mut bytes = match self.local_segment(caller_ds, false, memory) {
            Ok((_, bytes)) => bytes,
            Err(error) if error.kind() == Kind::ResourceExhausted => return Ok(None),
            Err(error) => return Err(error),
        };
        let result = LocalHeap::open(&mut bytes).and_then(|heap| heap.atom_entries());
        match result {
            Ok(entries) => Ok(Some(entries)),
            Err(LocalHeapError::Uninitialized | LocalHeapError::OutOfMemory) => Ok(None),
            Err(error) => Err(RuntimeError::with_source(Kind::GuestFault,
                format!("validate Win16 local atoms in data segment 0x{caller_ds:04X}"), error)),
        }
    }

    fn local_atom_get_name(
        &self,
        caller_ds: u16,
        atom: u16,
        output_buffer: Option<Win16OutputBuffer>,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some(output) = output_buffer.filter(|output| output.capacity != 0) else { return Ok(0); };
        if atom == 0 { return Ok(0); }
        let name = if atom < FIRST_STRING_ATOM {
            format!("#{atom}").into_bytes()
        } else {
            let Some(entries) = self.local_atom_entries(caller_ds, memory)? else { return Ok(0); };
            let Some(entry) = entries.into_iter().find(|entry| entry.atom == atom) else { return Ok(0); };
            entry.name
        };
        // The Win16 capacity/result are byte counts. Preserve the first
        // spelling verbatim; truncation is a byte prefix plus a terminator.
        let copied = name.len().min(usize::from(output.capacity - 1));
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(copied + 1).is_err() { return Ok(0); }
        bytes.extend_from_slice(&name[..copied]);
        bytes.push(0);
        // Preflight the complete caller-declared capacity before the first
        // write, even if the result is shorter or overlaps its atom entry.
        // PreparedTextWrite also rolls back a failed cross-selector commit.
        let prepared = self.prepare_text_write(memory, output.pointer, usize::from(output.capacity))?;
        prepared.commit(memory, &bytes)?;
        Ok(copied as u16)
    }
}

#[cfg(test)]
#[path = "win16_local_atoms_tests.rs"]
mod tests;
