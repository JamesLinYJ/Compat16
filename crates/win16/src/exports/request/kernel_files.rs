//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelFilesRequest {
    CloseFile {
        file_handle: u16,
    },

    OpenFile {
        path: Vec<u8>,
        mode: i16,
    },

    /// Read file bytes into the raw guest far buffer. The decoder retains the
    /// signed count and never validates or dereferences the pointer; zero count
    /// leaves the pointer unused and negative counts are rejected by runtime.
    ReadFile {
        file_handle: u16,
        buffer: u32,
        count: i32,
    },

    SeekFile {
        file_handle: u16,
        offset: i32,
        origin: i16,
    },

    CreateFile {
        path: Vec<u8>,
        attributes: u16,
    },

    /// Write file bytes from the raw guest far buffer. The decoder retains the
    /// signed count and never validates or dereferences the pointer; zero count
    /// leaves the pointer unused and negative counts are rejected by runtime.
    WriteFile {
        file_handle: u16,
        buffer: u32,
        count: i32,
    },

    /// Copy the requested number of bytes between raw guest huge pointers.
    /// Pointer range validation and cross-segment copying belong to runtime.
    HugeMemoryCopy {
        destination: u32,
        source: u32,
        count: i32,
    },

    /// Request the number of DOS/Windows file handles available to the task.
    /// The WORD result reports the number actually available.
    SetHandleCount {
        requested_count: u16,
    },
}
