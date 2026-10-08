//! Pointer-free requests shared with the native Win32 import adapter.
//!
//! These DTOs describe x86 guest services using owned values and opaque host
//! identities. Native HANDLE, HMODULE, FARPROC and buffers never cross here.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32HostModule(u64);

impl Win32HostModule {
    pub const fn from_host_id(id: u64) -> Self { Self(id) }
    pub const fn host_id(self) -> u64 { self.0 }
}

/// Exact PE32-task provider generation that owns one native LoadLibrary
/// reference in the host adapter. The HMODULE identity can be shared across
/// tasks, but this owner key is never shared or released on another task's
/// behalf.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win32HostModuleOwner {
    task: u64,
    provider: u64,
    generation: u64,
}

impl Win32HostModuleOwner {
    pub const fn from_parts(task: u64, provider: u64, generation: u64) -> Self {
        Self { task, provider, generation }
    }

    pub const fn task(self) -> u64 { self.task }
    pub const fn provider(self) -> u64 { self.provider }
    pub const fn generation(self) -> u64 { self.generation }

    pub(crate) fn release_failure(self, cause: crate::RuntimeError) -> crate::RuntimeError {
        crate::RuntimeError::with_source(cause.kind(),
            "native provider reference remains owned for retry",
            NativeModuleOwnerFailure { owner: self, cause })
    }
}

#[derive(Debug)]
struct NativeModuleOwnerFailure {
    owner: Win32HostModuleOwner,
    cause: crate::RuntimeError,
}

impl std::fmt::Display for NativeModuleOwnerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "task {} provider {} generation {}: {}",
            self.owner.task(), self.owner.provider(), self.owner.generation(), self.cause)
    }
}

impl std::error::Error for NativeModuleOwnerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.cause) }
}

/// Opaque proof that a native export resolved through Windows to a catalogued
/// system API. The underlying FARPROC never leaves the Windows adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32HostResolvedExport(u64);

impl Win32HostResolvedExport {
    pub const fn from_host_id(id: u64) -> Self { Self(id) }
    pub const fn host_id(self) -> u64 { self.0 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32HostImportFamily { Runtime, Loader, File, Path, Volume, Environment, System }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32HostServiceIdentity {
    id: u16,
    family: Win32HostImportFamily,
    export: &'static [u8],
}

impl Win32HostServiceIdentity {
    pub(crate) const fn from_catalog(
        id: u16,
        family: Win32HostImportFamily,
        export: &'static [u8],
    ) -> Self { Self { id, family, export } }

    pub const fn id(self) -> u16 { self.id }
    pub const fn family(self) -> Win32HostImportFamily { self.family }
    pub const fn export(self) -> &'static [u8] { self.export }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32HostHandle(u64);

impl Win32HostHandle {
    pub const fn from_host_id(id: u64) -> Self { Self(id) }
    pub const fn host_id(self) -> u64 { self.0 }
}

/// Opaque host-table identity for a FindFirstFile search, distinct from a file HANDLE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32HostSearchHandle(u64);

impl Win32HostSearchHandle {
    pub const fn from_host_id(id: u64) -> Self { Self(id) }
    pub const fn host_id(self) -> u64 { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win32HostFindData {
    Ansi {
        attributes: u32,
        creation_time_low: u32, creation_time_high: u32,
        last_access_time_low: u32, last_access_time_high: u32,
        last_write_time_low: u32, last_write_time_high: u32,
        file_size_high: u32, file_size_low: u32,
        reserved0: u32, reserved1: u32,
        file_name: [u8; 260], alternate_file_name: [u8; 14],
    },
    Wide {
        attributes: u32,
        creation_time_low: u32, creation_time_high: u32,
        last_access_time_low: u32, last_access_time_high: u32,
        last_write_time_low: u32, last_write_time_high: u32,
        file_size_high: u32, file_size_low: u32,
        reserved0: u32, reserved1: u32,
        file_name: [u16; 260], alternate_file_name: [u16; 14],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32ImportTextEncoding { Ansi, Wide }

/// Terminated guest text copied into an owned host value. The terminator is
/// omitted; the adapter constructs a native terminated string at its boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win32ImportString { Ansi(Vec<u8>), Wide(Vec<u16>) }

impl Win32ImportString {
    pub const fn encoding(&self) -> Win32ImportTextEncoding {
        match self { Self::Ansi(_) => Win32ImportTextEncoding::Ansi, Self::Wide(_) => Win32ImportTextEncoding::Wide }
    }

    pub(crate) fn is_empty(&self) -> bool {
        match self { Self::Ansi(value) => value.is_empty(), Self::Wide(value) => value.is_empty() }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win32ImportSymbol { Name(Vec<u8>), Ordinal(u16) }

#[derive(Clone, Debug)]
pub enum Win32HostImportCall {
    /// Load one exact task/provider generation through the system-directory
    /// path. Repeated guest loads in that task share this owner and only raise
    /// its guest-reference count; other tasks get separate native owners.
    LoadSystemModule { basename: Win32ImportString, owner: Win32HostModuleOwner },
    /// Classifies an already-resolved file candidate for loader precedence.
    /// This returns only path provenance, never a native module or address.
    IsSystemDirectoryPath { path: Win32ImportString },
    /// Queries an already loaded module by its original A/W name or path.
    /// GetModuleHandle does not acquire a reference; `path` is returned only
    /// for a proven System32 module, with `module` set only for a known token.
    FindLoadedSystemModule { name: Win32ImportString },
    /// Acquires one native reference to a path already resolved as System32
    /// for this exact provider generation. GetModuleHandle uses a zero guest
    /// count and this internal lease solely to keep later typed calls safe.
    RetainSystemModulePath { path: Win32ImportString, owner: Win32HostModuleOwner },
    FreeSystemModule { module: Win32HostModule, owner: Win32HostModuleOwner },
    /// Resolves through Windows and returns an opaque token only when the final
    /// native target matches the official catalogued system API identity.
    ResolveSystemExport { module: Win32HostModule, symbol: Win32ImportSymbol,
        service: Win32HostServiceIdentity },
    /// Releases one task-owned opaque handle during dispatcher retirement.
    /// This management path balances the host table's owner without needing
    /// the guest to have imported CloseHandle itself.
    CloseOwnedHandle { handle: Win32HostHandle },
    /// Releases one task-owned search identity with FindClose, never CloseHandle.
    CloseOwnedSearchHandle { handle: Win32HostSearchHandle },
    InvokeService { export: Win32HostResolvedExport, service: Win32HostServiceIdentity,
        operation: Win32HostServiceOperation },
    Shutdown,
}

#[derive(Clone, Debug)]
pub enum Win32HostServiceOperation {
    Loader(Win32HostLoaderCall),
    File(Win32HostFileCall),
    Path(Win32HostPathCall),
    Volume(Win32HostVolumeCall),
    Environment(Win32HostEnvironmentCall),
    System(Win32HostSystemCall),
}

#[derive(Clone, Debug)]
pub enum Win32HostLoaderCall {
    LoadSystemModule { basename: Win32ImportString, owner: Win32HostModuleOwner },
    FreeSystemModule { module: Win32HostModule, owner: Win32HostModuleOwner },
    GetModuleHandle { expected: Win32HostModule, name: Win32ImportString },
    GetModuleFileName {
        module: Win32HostModule,
        encoding: Win32ImportTextEncoding,
        capacity: u32,
    },
}

#[derive(Clone, Debug)]
pub enum Win32HostFileCall {
    Create {
        path: Win32ImportString,
        desired_access: u32,
        share_mode: u32,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template: Option<Win32HostHandle>,
    },
    Read { handle: Win32HostHandle, capacity: u32 },
    Write { handle: Win32HostHandle, bytes: Vec<u8> },
    Close { handle: Win32HostHandle },
    Delete { path: Win32ImportString },
    Move { from: Win32ImportString, to: Win32ImportString },
    Copy { from: Win32ImportString, to: Win32ImportString, fail_if_exists: bool },
    CreateDirectory { path: Win32ImportString },
    RemoveDirectory { path: Win32ImportString },
    GetAttributes { path: Win32ImportString },
    SetAttributes { path: Win32ImportString, attributes: u32 },
    GetType { handle: Win32HostHandle },
    GetSize { handle: Win32HostHandle, high_output: bool },
    GetSizeEx { handle: Win32HostHandle },
    SetPointer { handle: Win32HostHandle, low: i32, high: Option<i32>, method: u32 },
    SetEndOfFile { handle: Win32HostHandle },
    Flush { handle: Win32HostHandle },
    FindFirst { path: Win32ImportString },
    FindFirstEx { path: Win32ImportString, information_level: u32,
        search_operation: u32, additional_flags: u32 },
    FindNext { handle: Win32HostSearchHandle, encoding: Win32ImportTextEncoding },
    FindClose { handle: Win32HostSearchHandle },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32PathQuery { CurrentDirectory, SystemDirectory, WindowsDirectory, TempPath }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32PathTransform { Full, Long, Short }

#[derive(Clone, Debug)]
pub enum Win32HostPathCall {
    Query { kind: Win32PathQuery, encoding: Win32ImportTextEncoding,
        capacity: u32, output_present: bool },
    SetCurrentDirectory { path: Win32ImportString },
    Transform {
        kind: Win32PathTransform,
        path: Win32ImportString,
        capacity: u32,
        output_present: bool,
        request_file_part: bool,
    },
}

#[derive(Clone, Debug)]
pub enum Win32HostVolumeCall {
    LogicalDrives,
    DriveType { root: Option<Win32ImportString>, wide: bool },
    DiskFreeSpace { root: Option<Win32ImportString>, wide: bool },
    DiskFreeSpaceEx { root: Option<Win32ImportString>, wide: bool, available_present: bool,
        total_present: bool, free_present: bool },
    VolumeInformation {
        root: Option<Win32ImportString>,
        wide: bool,
        volume_name_capacity: u32,
        filesystem_name_capacity: u32,
        volume_name_buffer_present: bool,
        filesystem_name_buffer_present: bool,
        want_serial: bool,
        want_maximum_component: bool,
        want_flags: bool,
    },
}

#[derive(Clone, Debug)]
pub enum Win32HostEnvironmentCall {
    Get { name: Win32ImportString, capacity: u32, output_present: bool },
    Set { name: Win32ImportString, value: Option<Win32ImportString> },
    Expand { source: Win32ImportString, capacity: u32, output_present: bool },
}

#[derive(Clone, Debug)]
pub enum Win32HostSystemCall {
    Version,
    VersionInfo { encoding: Win32ImportTextEncoding, extended: bool },
    TickCount,
    ProcessId,
    ThreadId,
    SystemTime { local: bool },
    SystemTimeAsFileTime,
    QueryPerformance { frequency: bool },
    /// The runtime must replace processor fields with the guest CPU contract;
    /// host processor metadata is not evidence of guest instruction support.
    SystemInfo { native: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win32HostImportResult {
    pub value: Win32HostImportValue,
    /// Present only when the Windows contract says the caller should observe
    /// the API's thread-local GetLastError value on this outcome.
    pub last_error: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win32HostImportValue {
    Void,
    /// A module token identifies a host-table HMODULE; on loaded-module
    /// queries, `None` with a nonempty verified System32 path means the native
    /// module exists but this task must acquire its own exact provider lease.
    Module { module: Option<Win32HostModule>, path: Vec<u16> },
    ResolvedExport(Option<Win32HostResolvedExport>),
    Bool(bool),
    Dword(u32),
    Qword(u64),
    FileHandle(Option<Win32HostHandle>),
    FindStart { handle: Option<Win32HostSearchHandle>, data: Option<Win32HostFindData> },
    FindData(Option<Win32HostFindData>),
    Transfer { success: bool, bytes: Vec<u8>, count: u32 },
    FileSize { success: bool, low: u32, high: Option<u32> },
    FilePosition { success: bool, low: u32, high: Option<i32> },
    Text { result: u32, output_valid: bool, text: Win32ImportString,
        file_part_offset: Option<u32> },
    /// Native GetModuleFileName output span. Unlike `Text`, this can include
    /// the API-written NUL; `terminated` records what the host actually wrote.
    ModuleFileName { result: u32, output_valid: bool, output: Win32ImportString,
        terminated: bool },
    DiskFreeSpace { success: bool, sectors_per_cluster: u32, bytes_per_sector: u32,
        free_clusters: u32, total_clusters: u32 },
    DiskFreeSpaceEx { success: bool, available: u64, total: u64, free: u64 },
    VolumeInformation { success: bool, volume_name: Win32ImportString,
        filesystem_name: Win32ImportString, serial: Option<u32>,
        maximum_component: Option<u32>, flags: Option<u32> },
    VersionInfo { success: bool, major: u32, minor: u32, build: u32,
        platform: u32, service_pack: Win32ImportString, service_pack_major: u16,
        service_pack_minor: u16, suite_mask: u16, product_type: u8 },
    SystemTime([u16; 8]),
    FileTime(u64),
    ScalarQuery { success: bool, value: u64 },
    SystemInfo { architecture: u16, page_size: u32, minimum_address: u64,
        maximum_address: u64, active_processor_mask: u64, processor_count: u32,
        processor_type: u32, allocation_granularity: u32, processor_level: u16,
        processor_revision: u16 },
}
