//! Pointer-free guest wire records and host-side filesystem DTOs.

use guest_core::OwnerId;
use zerocopy::byteorder::{LittleEndian, U32, U64};
use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

use super::owner::invariant;
use crate::RuntimeError;

/// Public KERNEL FindFirst/FindNext project the ANSI WIN32_FIND_DATA layout:
/// 44-byte scalar/time prefix, cFileName[260] at 44, cAlternateFileName[14]
/// at 304, then two bytes of DWORD-alignment padding.
pub const WIN16_FIND_DATA_BYTES: usize = 320;

/// Host-resolved path identity retained by a Win16 task. The drive is an
/// A-based index and components are actual Unicode directory-entry names.
/// Once created, a canonical path is never parsed through a guest alias map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16CanonicalPath {
    pub drive: u8,
    pub components: Vec<String>,
}

/// Filename namespace selected by the API family at its typed boundary.
/// DOS services use the stable virtual 8.3 namespace; KERNEL AutoThunk file
/// services use native Windows long/short-name semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16PathNamespace {
    DosVirtual,
    NativeWindows,
}

/// Provenance for a path component. Canonical cwd components bypass guest
/// name translation; only components read from this API call are translated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16PathComponentSource {
    CanonicalCwd,
    GuestInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16PathComponent {
    pub text: String,
    pub source: Win16PathComponentSource,
}

/// A normalized drive-qualified path with cwd and new input provenance kept
/// separate until the host resolves it in the selected namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16GuestPath {
    pub drive: u8,
    pub namespace: Win16PathNamespace,
    pub components: Vec<Win16PathComponent>,
}

/// Host operations accept either fresh guest input (translated once) or an
/// already-resolved canonical identity (used without another lookup).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostFileSystemPath {
    Guest(Win16GuestPath),
    Canonical(Win16CanonicalPath),
}

/// The public FindFirst/FindNext thunks expose the fixed ANSI WIN32_FIND_DATA
/// wire layout. Little-endian zerocopy scalars keep the DWORD/QWORD fields
/// unaligned and make the guest byte order explicit.
#[derive(Clone, Copy, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct Win16FindDataWire {
    attributes: U32<LittleEndian>,
    creation_time: U64<LittleEndian>,
    last_access_time: U64<LittleEndian>,
    last_write_time: U64<LittleEndian>,
    file_size_high: U32<LittleEndian>,
    file_size_low: U32<LittleEndian>,
    reserved0: U32<LittleEndian>,
    reserved1: U32<LittleEndian>,
    file_name: [u8; 260],
    alternate_file_name: [u8; 14],
    tail_padding: [u8; 2],
}

const _: () = {
    assert!(std::mem::size_of::<Win16FindDataWire>() == WIN16_FIND_DATA_BYTES);
    assert!(std::mem::offset_of!(Win16FindDataWire, attributes) == 0);
    assert!(std::mem::offset_of!(Win16FindDataWire, creation_time) == 4);
    assert!(std::mem::offset_of!(Win16FindDataWire, last_access_time) == 12);
    assert!(std::mem::offset_of!(Win16FindDataWire, last_write_time) == 20);
    assert!(std::mem::offset_of!(Win16FindDataWire, file_size_high) == 28);
    assert!(std::mem::offset_of!(Win16FindDataWire, file_size_low) == 32);
    assert!(std::mem::offset_of!(Win16FindDataWire, reserved0) == 36);
    assert!(std::mem::offset_of!(Win16FindDataWire, reserved1) == 40);
    assert!(std::mem::offset_of!(Win16FindDataWire, file_name) == 44);
    assert!(std::mem::offset_of!(Win16FindDataWire, alternate_file_name) == 304);
    assert!(std::mem::offset_of!(Win16FindDataWire, tail_padding) == 318);
};

/// Opaque identity allocated by the host. It is never a guest search handle
/// or a native Windows HANDLE.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Win16HostSearchId(u64);

impl Win16HostSearchId {
    pub const fn from_host_id(id: u64) -> Self {
        Self(id)
    }
    pub const fn host_id(self) -> u64 {
        self.0
    }
}

/// Fixed, pointer-free file facts returned by the Windows host adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostFindData {
    pub attributes: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub file_size_high: u32,
    pub file_size_low: u32,
    pub reserved: [u32; 2],
    /// NUL-free guest ANSI bytes in this task's current ANSI code page.
    /// Runtime adds the fixed wire terminator.
    pub file_name: Vec<u8>,
    pub alternate_file_name: Vec<u8>,
}

impl Win16HostFindData {
    pub(super) fn to_win16_wire(&self) -> Result<[u8; WIN16_FIND_DATA_BYTES], RuntimeError> {
        if self.file_name.len() >= 260
            || self.alternate_file_name.len() >= 14
            || self.file_name.contains(&0)
            || self.alternate_file_name.contains(&0)
        {
            return Err(invariant(
                "host Win16 find-data names exceed the fixed ANSI fields",
            ));
        }
        let mut file_name = [0_u8; 260];
        file_name[..self.file_name.len()].copy_from_slice(&self.file_name);
        let mut alternate_file_name = [0_u8; 14];
        alternate_file_name[..self.alternate_file_name.len()]
            .copy_from_slice(&self.alternate_file_name);
        let fields = Win16FindDataWire {
            attributes: U32::new(self.attributes),
            creation_time: U64::new(self.creation_time),
            last_access_time: U64::new(self.last_access_time),
            last_write_time: U64::new(self.last_write_time),
            file_size_high: U32::new(self.file_size_high),
            file_size_low: U32::new(self.file_size_low),
            reserved0: U32::new(self.reserved[0]),
            reserved1: U32::new(self.reserved[1]),
            file_name,
            alternate_file_name,
            tail_padding: [0; 2],
        };
        let mut wire = [0_u8; WIN16_FIND_DATA_BYTES];
        wire.copy_from_slice(fields.as_bytes());
        Ok(wire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostDiskSpace {
    pub sectors_per_cluster: u32,
    pub bytes_per_sector: u32,
    pub free_clusters: u32,
    pub total_clusters: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostFindFirst {
    pub search: Win16HostSearchId,
    pub entry: Win16HostFindData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostFileSystemCall {
    pub owner: OwnerId,
    /// Explicit Win16 task ANSI page for returned FindData name bytes.
    pub ansi_code_page: u32,
    pub operation: Win16HostFileSystemOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostFileSystemOperation {
    NormalizePath {
        path: Win16GuestPath,
        follow_final: bool,
        allow_missing_final: bool,
    },
    CreateDirectory {
        path: Win16HostFileSystemPath,
    },
    RemoveDirectory {
        path: Win16HostFileSystemPath,
    },
    DeleteFile {
        path: Win16HostFileSystemPath,
    },
    /// Query only: this must not change the process-wide native current dir.
    QueryDirectory {
        path: Win16HostFileSystemPath,
    },
    GetFileAttributes {
        path: Win16HostFileSystemPath,
    },
    SetFileAttributes {
        path: Win16HostFileSystemPath,
        attributes: u32,
    },
    GetDiskFreeSpace {
        path: Win16HostFileSystemPath,
    },
    FindFirst {
        search_file: Win16GuestPath,
    },
    FindNext {
        search: Win16HostSearchId,
    },
    FindClose {
        search: Win16HostSearchId,
    },
    RetireTask,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostFileSystemResult {
    /// Ordinary native API success/failure (false is not promoted to success).
    Completed(bool),
    NormalizedPath(Option<Win16CanonicalPath>),
    Attributes(Option<u32>),
    DiskSpace(Option<Win16HostDiskSpace>),
    FindFirst(Option<Win16HostFindFirst>),
    FindNext(Option<Win16HostFindData>),
    FindClose(bool),
    TaskRetired,
}
