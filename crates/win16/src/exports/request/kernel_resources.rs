//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelResourcesRequest {
    /// Find a resource-info handle in a Win16 module. Names are owned copies or
    /// integer resource identifiers; no guest or host pointer escapes.
    FindResource {
        module: u16,
        name: Win16ResourceName,
        resource_type: Win16ResourceName,
    },

    /// Load a resource-info handle into a guest global-memory block.
    LoadResource { module: u16, info: u16 },

    /// Return the guest far address for a previously loaded resource handle.
    LockResource { data: u16 },

    /// Free one resource reference. Win16 returns zero on success and nonzero
    /// when freeing fails, opposite the usual BOOL success convention.
    FreeResource { data: u16 },

    /// Open the module file and seek to the resource. The return is an INT16
    /// file handle, with -1 represented by the WORD bit pattern 0xffff.
    AccessResource { module: u16, info: u16 },

    /// Return the resource size in bytes as a Win16 DWORD.
    SizeofResource { module: u16, info: u16 },

    /// Allocate a guest global-memory block suitable for the resource.
    AllocResource { module: u16, info: u16, size: u32 },

    /// Replace the resource-type loader while preserving its guest FARPROC bits.
    SetResourceHandler {
        module: u16,
        type_name: Win16ResourceName,
        handler: u32,
    },

    /// Historical KERNEL.456 default resource-loader callback ABI. The three
    /// values remain guest words: resource data, module, then resource info.
    DefResourceHandler { data: u16, module: u16, info: u16 },
}
