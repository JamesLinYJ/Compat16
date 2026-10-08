//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelRuntimeRequest {
    GetVersion,

    GetCurrentTask,

    /// Query the classic Win16 drive type using a zero-based drive number.
    GetDriveType {
        drive: u16,
    },

    /// Set the native process error mode and retain the requested flags in the current guest TDB.
    SetErrorMode {
        mode: u16,
    },

    GetWinFlags,

    WaitEvent {
        task_handle: u16,
    },

    PostEvent {
        task_handle: u16,
    },

    /// Preserve the guest FARPROC bits for runtime selector validation and
    /// procedure-instance thunk creation. This is never a host pointer; the
    /// runtime owns API-compatible handling of a null or invalid procedure.
    MakeProcInstance {
        procedure: u32,
        instance: u16,
    },

    /// Preserve the guest FARPROC bits for runtime-owned thunk release. This
    /// is never a host pointer; unknown or unowned procedure pointers remain
    /// available for the API layer's compatible no-op behavior.
    FreeProcInstance {
        procedure: u32,
    },

    ExitProcess {
        status: u16,
    },
}
