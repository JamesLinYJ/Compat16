use crate::diagnostics::{DosErrorCode, DosHostError};

/// Stable host-side identity for an open file; never a guest pointer or OS handle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct DosHostFile(pub u64);

/// Opaque host-owned token for one directory enumeration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct DosHostSearch(pub u64);

/// File facts obtained from the same open object as the opaque host token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosFileStatus {
    /// Canonical OEM 8.3 alias, space-padded without the separating dot.
    pub short_name: [u8; 11],
    pub size: u32,
    pub position: u32,
    pub attributes: u8,
    pub write_time: u16,
    pub write_date: u16,
}

/// Byte counts reported by the host for one mapped DOS drive.
///
/// DOS converts these values into a synthetic FAT-style allocation geometry;
/// they do not claim to describe the host volume's physical sectors or format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosDiskSpace {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// One of the three standard streams whose backing DOS object is host-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosIoctlStream {
    Input,
    Output,
    Error,
}

/// Host facts needed to report the DOS IOCTL 4400 information word.
///
/// This deliberately contains only facts the host can establish. Unsupported
/// device capabilities are absent rather than being guessed by DOS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosIoctlObjectInfo {
    File {
        /// Zero-based DOS drive number (0 = A:, 2 = C:).
        drive: u8,
        /// Whether writes have occurred through this open-file identity.
        written: bool,
    },
    CharacterDevice {
        /// True when input is at EOF; DOS reports that by clearing bit 6.
        input_eof: bool,
        raw_mode: bool,
        standard_input: bool,
        standard_output: bool,
    },
}

/// One entry returned by a DOS directory enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DosDirectoryEntry {
    /// Canonical DOS 8.3 alias in uppercase OEM bytes, without padding or NUL.
    pub short_name: Vec<u8>,
    /// DOS attributes: read-only 01h, hidden 02h, system 04h, volume 08h,
    /// directory 10h, archive 20h.
    pub attributes: u8,
    /// DOS packed local time and date fields.
    pub write_time: u16,
    pub write_date: u16,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosFileAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// DOS INT 21h/AH=3Dh sharing mode, translated by the host file adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosFileSharing {
    Compatibility,
    DenyAll,
    DenyWrite,
    DenyRead,
    DenyNone,
}

/// Non-destructive INT 21h/AX=6C00 dispositions. Replacement is intentionally
/// absent until the host can preserve existing-only and attribute contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosFileDisposition {
    OpenExisting,
    CreateNew,
    OpenOrCreate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosFileOpenRequest {
    pub access: DosFileAccess,
    pub sharing: DosFileSharing,
    pub disposition: DosFileDisposition,
    /// Creation attributes only; existing files must remain unchanged.
    pub attributes: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosFileOpenOutcome {
    Opened,
    Created,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosFileOpenResult {
    pub file: DosHostFile,
    pub outcome: DosFileOpenOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosSeekOrigin {
    Start,
    Current,
    End,
}

/// Local calendar fields for DOS date/time register services.
#[derive(Clone, Copy, Debug)]
pub struct DosLocalDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub weekday: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub hundredth: u8,
}

/// Operations the host must perform for DOS services.
/// Paths are raw DOS code-page bytes with the trailing NUL removed. File IDs
/// are opaque tokens owned by the host adapter, never guest-visible handles.
pub trait DosHost {
    fn local_date_time(&mut self) -> Result<DosLocalDateTime, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
    /// Blocking input. Returns bytes read, zero at redirected-stream EOF,
    /// or a DOS-mappable error. An empty output buffer also returns zero.
    fn read_stdin(&mut self, output: &mut [u8]) -> Result<usize, DosHostError>;
    /// Poll and consume at most one byte without waiting.
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError>;
    fn write_stdout(&mut self, input: &[u8]) -> Result<usize, DosHostError>;
    fn write_stderr(&mut self, input: &[u8]) -> Result<usize, DosHostError>;
    fn flush_stdin(&mut self) -> Result<(), DosHostError>;

    fn file_create(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError>;
    /// Atomically create a new read/write file in compatibility sharing mode.
    /// An existing entry must remain unchanged and return FileExists. Hosts
    /// must not emulate this using an existence check followed by file_create.
    fn file_create_new(
        &mut self,
        _path: &[u8],
        _attributes: u8,
    ) -> Result<DosHostFile, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
    /// Open/create without replacing an existing file, retaining the requested
    /// access and sharing on the returned distinct closeable token. Outcomes
    /// must come from the successful operation, not an existence precheck.
    /// Unsupported modes must fail before creating or changing a file. A host
    /// may reject read-only creation while still supporting existing-file reads.
    /// DOS owns no-inherit and its critical-error policy; commit-on-write is
    /// rejected before this boundary rather than silently dropping that flag.
    fn file_extended_open(
        &mut self,
        _path: &[u8],
        _request: DosFileOpenRequest,
    ) -> Result<DosFileOpenResult, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
    fn file_open(&mut self, path: &[u8], access: DosFileAccess) -> Result<DosHostFile, DosHostError>;
    /// Open with DOS's sharing mode. Hosts without a native sharing primitive
    /// must make an explicit policy choice. Windows enforces the requested
    /// read/write sharing contract through its native file-open flags.
    fn file_open_with_sharing(
        &mut self,
        path: &[u8],
        access: DosFileAccess,
        sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError>;
    /// Return a distinct closeable token sharing the same open-file cursor.
    fn file_duplicate(&mut self, file: DosHostFile) -> Result<DosHostFile, DosHostError>;
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError>;
    fn file_read(&mut self, file: DosHostFile, output: &mut [u8]) -> Result<usize, DosHostError>;
    fn file_write(&mut self, file: DosHostFile, input: &[u8]) -> Result<usize, DosHostError>;
    fn file_seek(&mut self, file: DosHostFile, offset: i32, origin: DosSeekOrigin) -> Result<u32, DosHostError>;
    fn file_set_len(&mut self, file: DosHostFile, length: u32) -> Result<(), DosHostError>;
    fn file_status(&mut self, _file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
    /// Query DOS-facing identity for an opaque file token. Hosts that cannot
    /// prove this information must leave the default unsupported result.
    fn file_ioctl_info(&self, _file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
    /// Query the DOS-facing identity of a standard stream. In particular, a
    /// redirected stream must not be reported as a console device by default.
    fn standard_ioctl_info(
        &self,
        _stream: DosIoctlStream,
    ) -> Result<DosIoctlObjectInfo, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
    fn file_delete(&mut self, path: &[u8]) -> Result<(), DosHostError>;

    fn directory_create(&mut self, path: &[u8]) -> Result<(), DosHostError>;
    fn directory_remove(&mut self, path: &[u8]) -> Result<(), DosHostError>;
    fn directory_set_current(&mut self, path: &[u8]) -> Result<(), DosHostError>;
    /// `drive` is zero-based (0 is A:). Returns an unterminated path, excluding
    /// the drive and leading root separator; the caller owns the NUL byte.
    fn directory_get_current(&mut self, drive: u8, output: &mut [u8]) -> Result<usize, DosHostError>;
    fn file_rename(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<(), DosHostError>;
    fn file_get_attributes(&mut self, path: &[u8]) -> Result<u8, DosHostError>;
    fn file_set_attributes(&mut self, path: &[u8], attributes: u8) -> Result<(), DosHostError>;

    /// Start enumerating entries directly contained in `directory`. The bytes
    /// are an unterminated DOS path; an empty path means the current directory.
    /// Returned tokens must be unique while open and stay valid until close.
    fn directory_search_open(&mut self, directory: &[u8]) -> Result<DosHostSearch, DosHostError>;
    /// Return the next entry or `None` after the enumeration is exhausted.
    fn directory_search_next(&mut self, search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError>;
    fn directory_search_close(&mut self, search: DosHostSearch) -> Result<(), DosHostError>;

    /// Active guest OEM code page for DOS path and filename interpretation.
    fn guest_code_page(&self) -> text_codec::CodePage;

    fn current_drive(&self) -> u8;
    fn select_drive(&mut self, drive: u8) -> Result<(), DosHostError>;
    /// Number of logical drive letters supported, as returned by INT 21h/0Eh.
    fn logical_drive_count(&self) -> u8;

    /// Return space visible to the current user for a zero-based DOS drive.
    /// Hosts must reject drives that are not mapped into the guest.
    fn disk_space(&self, _drive: u8) -> Result<DosDiskSpace, DosHostError> {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DosAction {
    Continue,
    Exit(u8),
    /// Execute one DOS child program synchronously in the current guest.
    ///
    /// The DOS layer has decoded and copied the caller's path, EXEC parameter
    /// block, command tail, and FCBs. Runtime code owns image loading, process
    /// memory, CPU state, and parent/child scheduling.
    Execute(DosExecRequest),
    /// This interrupt or service is not implemented by this DOS core.
    Unhandled,
}

/// Input to INT 21h/AH=4Bh, AL=00h after DOS has copied guest-owned data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DosExecRequest {
    /// NUL-terminated path with the terminator removed, in the active DOS OEM
    /// code page. The path has already been bounded and validated by DOS.
    pub program_path: Vec<u8>,
    /// Environment block segment from the EXEC parameter block. Zero means
    /// inherit the current process environment.
    pub environment_segment: u16,
    /// PSP command-tail bytes: length, command bytes, CR, then zero padding.
    pub command_tail: [u8; 128],
    /// The first 16-byte FCB copied for the child PSP.
    pub first_fcb: [u8; 16],
    /// The second 16-byte FCB copied for the child PSP.
    pub second_fcb: [u8; 16],
}
