//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserAtomsRequest {
    /// Add an ANSI string atom or integer atom to the Win16 global atom table.
    GlobalAddAtom { name: Win16AtomName },

    /// Decrement the reference count for a global string atom.
    GlobalDeleteAtom { atom: u16 },

    /// Find an ANSI string atom or integer atom in the Win16 global atom table.
    GlobalFindAtom { name: Win16AtomName },

    /// Copy an atom's name to checked guest memory. A non-positive signed
    /// capacity has no output buffer because the API returns failure without
    /// accessing the pointer.
    GlobalGetAtomName {
        atom: u16,
        output_buffer: Option<Win16OutputBuffer>,
    },
}
