//! Host-independent Win16 service-gate test fixtures.

use crate::{RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};

// These APIs only operate on checked guest memory. Any required host service
// being reached is a test failure, rather than an invented successful reply.
pub(super) struct NoHost;

impl DosHost for NoHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _file: DosHostFile, _offset: i32, _origin: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _drive: u8, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

impl RuntimeHost for NoHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for NoHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for NoHost {}
impl crate::RuntimeMidiHost for NoHost {}
impl crate::RuntimeNetbiosHost for NoHost {}

pub(super) fn tiny_ne_executable() -> Vec<u8> {
    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    let mut bytes = vec![0; 0x92];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u16(&mut bytes, 0x08, 4);
    bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());

    let ne = 0x40;
    bytes[ne..ne + 2].copy_from_slice(b"NE");
    put_u16(&mut bytes, ne + 0x04, 0x51); // entry table
    put_u16(&mut bytes, ne + 0x06, 1);
    put_u16(&mut bytes, ne + 0x0e, 2); // automatic data segment
    put_u16(&mut bytes, ne + 0x10, 0x100); // heap reserve
    put_u16(&mut bytes, ne + 0x12, 0x100); // stack reserve
    put_u16(&mut bytes, ne + 0x14, 0); // initial IP
    put_u16(&mut bytes, ne + 0x16, 1); // initial CS
    put_u16(&mut bytes, ne + 0x18, 0x80); // initial SP
    put_u16(&mut bytes, ne + 0x1a, 2); // initial SS
    put_u16(&mut bytes, ne + 0x1c, 2); // segment count
    put_u16(&mut bytes, ne + 0x22, 0x40); // segment table
    put_u16(&mut bytes, ne + 0x26, 0x50); // resident names
    put_u16(&mut bytes, ne + 0x28, 0x51); // module references
    put_u16(&mut bytes, ne + 0x2a, 0x51); // imported names

    // Both segments are zero-filled: executable code followed by writable
    // automatic data. The resident-name and entry tables each have terminators.
    put_u16(&mut bytes, 0x80 + 0x04, 0x0000);
    put_u16(&mut bytes, 0x80 + 0x06, 0x0100);
    put_u16(&mut bytes, 0x88 + 0x04, 0x0001);
    put_u16(&mut bytes, 0x88 + 0x06, 0x0100);
    bytes[0x90] = 0;
    bytes[0x91] = 0;
    bytes
}
