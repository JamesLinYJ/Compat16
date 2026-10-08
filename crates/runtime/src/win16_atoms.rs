//! Win16 global atom requests translated to host-neutral names and buffers.

use guest_core::memory::Memory;
use win16_abi::{Win16AtomName, Win16OutputBuffer};

use super::Win16State;
use crate::{RuntimeError, RuntimeHost, Win16HostAtomName};

fn host_name(name: &Win16AtomName) -> Win16HostAtomName<'_> {
    match name {
        Win16AtomName::Integer(id) => Win16HostAtomName::Integer(*id),
        Win16AtomName::String(bytes) => Win16HostAtomName::String(bytes),
    }
}

impl Win16State {
    pub(super) fn global_add_atom(
        &mut self,
        name: Win16AtomName,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        host.win16_global_add_atom(host_name(&name))
    }

    pub(super) fn global_find_atom(
        &self,
        name: Win16AtomName,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if let Win16AtomName::String(bytes) = &name {
            let lower = host.win16_ansi_lower_string(bytes)?;
            if let Some(atom) = self.registered_class_atom_by_lower_name(&lower) {
                return Ok(atom);
            }
        }
        host.win16_global_find_atom(host_name(&name))
    }

    pub(super) fn global_get_atom_name(
        &self,
        atom: u16,
        output_buffer: Option<Win16OutputBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(output_buffer) = output_buffer else { return Ok(0); };
        if let Some(name) = self.registered_class_name(atom) {
            let copied = name.len().min(usize::from(output_buffer.capacity).saturating_sub(1));
            let mut bytes = name[..copied].to_vec();
            bytes.push(0);
            self.write_output(memory, output_buffer, &bytes)?;
            return Ok(copied as u16);
        }
        let (bytes, copied) = host.win16_global_get_atom_name(atom, output_buffer.capacity)?;
        if !bytes.is_empty() {
            self.write_output(memory, output_buffer, &bytes)?;
        }
        Ok(copied)
    }
}
