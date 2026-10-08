//! Owned arguments for the Windows 3.1 KERNEL file and directory exports.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelFileSystemRequest {
    /// FileCDR accepts a far procedure pointer. Selector FFFFh is the
    /// documented query sentinel and must remain an integer here.
    FileCdr {
        procedure: u32,
    },
    CreateDirectory {
        path: Vec<u8>,
        security_attributes: u32,
    },
    RemoveDirectory {
        path: Vec<u8>,
    },
    DeleteFile {
        path: Vec<u8>,
    },
    /// Win32-compatible GetCurrentDirectory: capacity, then output pointer.
    GetCurrentDirectory {
        capacity: u32,
        output: u32,
    },
    SetCurrentDirectory {
        path: Vec<u8>,
    },
    FindFirstFile {
        search_file: Vec<u8>,
        find_data: u32,
    },
    FindNextFile {
        search_handle: u16,
        find_data: u32,
    },
    FindClose {
        search_handle: u16,
    },
    GetFileAttributes {
        path: Vec<u8>,
    },
    SetFileAttributes {
        path: Vec<u8>,
        attributes: u32,
    },
    GetDiskFreeSpace {
        root_path: Option<Vec<u8>>,
        sectors_per_cluster: u32,
        bytes_per_sector: u32,
        free_clusters: u32,
        total_clusters: u32,
    },
}
