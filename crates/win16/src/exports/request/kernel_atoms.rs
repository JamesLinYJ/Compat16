//! Owned requests for the calling data segment's KERNEL local atom table.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelAtomsRequest {
    /// Initialize the local table with a signed Win16 bucket-count argument.
    InitAtomTable { buckets: i16 },

    /// Find an ANSI string atom or a selector-zero integer atom.
    FindAtom { name: Win16AtomName },

    /// Add an ANSI string atom or a selector-zero integer atom.
    AddAtom { name: Win16AtomName },

    /// Decrement the reference count for a local string atom.
    DeleteAtom { atom: u16 },

    /// Copy an atom's name into checked guest memory. Non-positive signed
    /// capacities fail without accessing the output pointer.
    GetAtomName {
        atom: u16,
        output_buffer: Option<Win16OutputBuffer>,
    },

    /// Retrieve the local-heap handle backing a local string atom.
    GetAtomHandle { atom: u16 },
}
