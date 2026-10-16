//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelModulesRequest {
    /// The parameter block is checked only for an executable, before any
    /// asynchronous launch. DLL loading does not consume EXECBLOCK.
    LoadModule { module: Win16ModuleReference, parameters: u32 },

    /// Release a loaded module through the loader's checked WEP owner.
    FreeModule { module: u16 },

    /// Get the selected Win16 module's filename into a checked guest buffer.
    /// A non-positive signed capacity suppresses buffer validation and yields
    /// no output buffer; the runtime returns the API's zero result in that case.
    GetModuleFileName {
        module: u16,
        output: Option<Win16OutputBuffer>,
    },

    /// Resolve a module by a checked guest name or selector-zero HINSTANCE.
    GetModuleHandle { module: Win16ModuleReference },

    /// Return the guest loader's current usage count for a module handle.
    GetModuleUsage { module: u16 },

    /// Return a guest FARPROC encoded as DX:AX, with name or ordinal preserved.
    GetProcAddress {
        module: Win16ModuleReference,
        procedure: Win16ProcReference,
    },

    /// Load a Win16 library by its checked guest ANSI name.
    LoadLibrary { library_name: Vec<u8> },

    /// Release one Win16 library reference. This API has no semantic return value.
    FreeLibrary { module: u16 },
}
