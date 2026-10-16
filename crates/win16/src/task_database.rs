//! A guest-owned prefix of the historical Win16 task database.
//!
//! This module models the historical `TD` signature and supported TDB prefix;
//! it does not claim that the entire private structure is implemented. The
//! prefix ends before the host scheduler handle at offset `0xfc`; fields that
//! this module does not model remain zero. In particular, no host pointer or
//! host handle is stored in these guest bytes. Microsoft SDK documentation for
//! task APIs does not publish this private structure's field offsets.

/// Number of guest bytes in the supported TDB prefix, ending before the
/// host-only scheduler handle that follows the historical `magic` field.
pub const TASK_DATABASE_PREFIX_SIZE: usize = 0xFC;

/// Guest SS:SP saved by the task scheduler and stack-switch APIs.
pub const TASK_DATABASE_STACK_POINTER_OFFSET: usize = 0x02;
pub const TASK_DATABASE_STACK_SELECTOR_OFFSET: usize = 0x04;
/// Previous SS:SP saved in the alternate stack's INSTANCEDATA header.
pub const INSTANCE_DATA_OLD_STACK_POINTER_OFFSET: usize = 0x02;
pub const INSTANCE_DATA_OLD_STACK_SELECTOR_OFFSET: usize = 0x04;

/// Offset of `nEvents`, the task's pending Win16 event count.
pub const TASK_DATABASE_EVENT_COUNT_OFFSET: usize = 0x06;
/// Short runtime-facing name for the event-count field offset.
pub const TASK_EVENT_COUNT_OFFSET: usize = TASK_DATABASE_EVENT_COUNT_OFFSET;
/// Offset of `error_mode`, the Win16 task's SetErrorMode flags in this prefix.
pub const TASK_DATABASE_ERROR_MODE_OFFSET: usize = 0x18;
/// Offset of `hSelf`, the task's guest selector/handle.
pub const TASK_DATABASE_HSELF_OFFSET: usize = 0x0C;
/// Offset of `hInstance`, the task's guest instance handle.
pub const TASK_DATABASE_HINSTANCE_OFFSET: usize = 0x1C;
/// Offset of `hModule`, the task's guest module handle.
pub const TASK_DATABASE_HMODULE_OFFSET: usize = 0x1E;
/// Offset of `hPDB`, the task's guest PSP/PDB selector.
pub const TASK_DATABASE_HPDB_OFFSET: usize = 0x60;
/// Offset of `dta`, a guest far pointer to the task's DOS transfer area.
pub const TASK_DATABASE_DTA_OFFSET: usize = 0x62;
/// Offset of `nCmdShow`, the task's WinMain show command.
pub const TASK_DATABASE_SHOW_COMMAND_OFFSET: usize = 0xA8;
/// Offset of `INSTANCEDATA.stackTop` in the task's DGROUP instance header.
pub const INSTANCE_DATA_STACK_TOP_OFFSET: usize = 0x0A;
/// Offset of `INSTANCEDATA.stackMin` in the task's DGROUP instance header.
pub const INSTANCE_DATA_STACK_MINIMUM_OFFSET: usize = 0x0C;
/// Offset of `INSTANCEDATA.stackBottom` in the task's DGROUP instance header.
pub const INSTANCE_DATA_STACK_BOTTOM_OFFSET: usize = 0x0E;
/// Offset of the two-byte TDB signature.
pub const TASK_DATABASE_MAGIC_OFFSET: usize = 0xFA;

/// Historical little-endian `TD` task-database signature used by the external
/// compatibility comparison. This does not imply support for other TDB fields.
pub const TASK_DATABASE_MAGIC: u16 = u16::from_le_bytes([b'T', b'D']);

/// Zero-initialized guest bytes for the fields modeled by this compatibility
/// layer. Unmodeled positions stay zero and are never host pointers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDatabase {
    bytes: [u8; TASK_DATABASE_PREFIX_SIZE],
}

impl TaskDatabase {
    /// Creates a zero-initialized task-database prefix.
    pub const fn new() -> Self {
        Self { bytes: [0; TASK_DATABASE_PREFIX_SIZE] }
    }

    /// Returns the complete fixed-size guest prefix for checked guest-memory
    /// initialization.
    pub fn as_bytes(&self) -> &[u8; TASK_DATABASE_PREFIX_SIZE] {
        &self.bytes
    }

    /// Sets `hSelf` to a guest Win16 task handle/selector.
    pub fn set_hself(&mut self, handle: u16) {
        self.write_word(TASK_DATABASE_HSELF_OFFSET, handle);
    }

    /// Sets `hPDB` to the task's guest PSP/PDB selector.
    pub fn set_hpdb(&mut self, selector: u16) {
        self.write_word(TASK_DATABASE_HPDB_OFFSET, selector);
    }

    /// Sets the guest instance handle exposed in `hInstance`.
    pub fn set_hinstance(&mut self, handle: u16) {
        self.write_word(TASK_DATABASE_HINSTANCE_OFFSET, handle);
    }

    /// Sets the guest module handle exposed in `hModule`.
    pub fn set_hmodule(&mut self, handle: u16) {
        self.write_word(TASK_DATABASE_HMODULE_OFFSET, handle);
    }

    /// Sets the task's pending event count.
    pub fn set_event_count(&mut self, count: u16) {
        self.write_word(TASK_DATABASE_EVENT_COUNT_OFFSET, count);
    }

    /// Sets the task's current SetErrorMode flags.
    pub fn set_error_mode(&mut self, mode: u16) {
        self.write_word(TASK_DATABASE_ERROR_MODE_OFFSET, mode);
    }

    /// Sets `nCmdShow`, the guest show command supplied to WinMain.
    pub fn set_show_command(&mut self, command: u16) {
        self.write_word(TASK_DATABASE_SHOW_COMMAND_OFFSET, command);
    }

    /// Sets the two-byte historical signature field.
    pub fn set_magic(&mut self, magic: u16) {
        self.write_word(TASK_DATABASE_MAGIC_OFFSET, magic);
    }

    /// Sets the guest far pointer to the current DOS transfer area.
    pub fn set_dta(&mut self, far_pointer: u32) {
        self.write_dword(TASK_DATABASE_DTA_OFFSET, far_pointer);
    }

    fn write_word(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_dword(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

impl Default for TaskDatabase {
    fn default() -> Self {
        Self::new()
    }
}
