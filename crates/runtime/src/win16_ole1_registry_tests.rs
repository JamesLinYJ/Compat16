//! OLE1 string clients retain expandable registration text and byte counts.
use crate::{RuntimeError, RuntimeHost, Win16HostRegistryOperation as Operation,
    Win16HostRegistryResult as RegistryResult, Win16RegistryQueryOutput,
    Win16RegistryQueryView};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

struct RegistryHost {
    value: Vec<u8>,
    kind: u32,
    capacities: Vec<u32>,
}
impl RegistryHost {
    fn new(value: &[u8], kind: u32) -> Self {
        Self { value: value.to_vec(), kind, capacities: Vec::new() }
    }
}
impl RuntimeHost for RegistryHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
    fn win16_registry(&mut self, operation: Operation) -> Result<RegistryResult, RuntimeError> {
        let Operation::QueryValue { subkey, output: Win16RegistryQueryOutput::Bounded(capacity), view, .. } = operation else {
            panic!("unexpected registry operation: {operation:?}");
        };
        assert_eq!(subkey, b"FixtureClass\\protocol\\StdFileEditing\\server");
        self.capacities.push(capacity);
        // Model the native type rejection that the real host reports for
        // expandable values, including values that happen to look like REG_SZ.
        let supported = self.kind == 1 || (self.kind == 2 && view == Win16RegistryQueryView::Win31Strings);
        let required = self.value.len() as u32;
        Ok(RegistryResult::QueryValue {
            status: if self.kind == 0 { 2 } else if !supported { 13 }
                else if capacity < required { 234 } else { 0 },
            value_type: self.kind,
            required_bytes: if supported { required } else { 0 },
            bytes: if supported && capacity >= required { self.value.clone() } else { Vec::new() },
        })
    }
}
impl crate::RuntimeDdeHost for RegistryHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for RegistryHost {}
impl crate::RuntimeMidiHost for RegistryHost {}
impl crate::RuntimeNetbiosHost for RegistryHost {}
impl DosHost for RegistryHost {
    fn read_stdin(&mut self, _: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _: &[u8], _: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _: &[u8], _: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _: &[u8], _: DosFileAccess, _: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _: DosHostFile, _: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _: DosHostFile, _: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _: DosHostFile, _: i32, _: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _: DosHostFile, _: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _: u8, _: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _: &[u8], _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _: &[u8], _: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

#[test]
fn ole1_registry_server_accepts_expandable_text_without_expanding_it() {
    let original = b"%UnresolvedFixtureVariable%\\server.exe\0";
    let mut host = RegistryHost::new(original, 2);
    let result = super::super::win16_ole1_server_registration::validate_server_registration(
        &mut host, b"FixtureClass").unwrap().unwrap();
    assert_eq!(result.registry_value, &original[..original.len() - 1]);
    assert_eq!(result.executable_name, b"server.exe");
    assert_eq!(host.value, original);
}

#[test]
fn ole1_registry_client_sizes_and_preserves_long_oem_expandable_text() {
    let mut original = b"%UnresolvedFixtureVariable%\\".to_vec();
    original.extend([0xc7, 0xb0].repeat(80));
    original.extend_from_slice(b"\\server.exe\0");
    let mut host = RegistryHost::new(&original, 2);
    let result = super::registry_resolver::resolve_class_application(
        &mut host, b"FixtureClass", b"StdFileEditing").unwrap().unwrap();
    assert_eq!(result.class_name, b"FixtureClass");
    assert_eq!(result.application_name, &original[..original.len() - 1]);
    assert_eq!(host.capacities, [0, original.len() as u32]);
    assert_eq!(host.value, original);
}

#[test]
fn ole1_registry_missing_binary_empty_and_oversized_registrations_still_fail() {
    for (value, kind) in [(b"looks-like-text.exe\0".to_vec(), 0),
        (b"looks-like-text.exe\0".to_vec(), 3), (vec![0], 2)] {
        let mut host = RegistryHost::new(&value, kind);
        assert_eq!(super::super::win16_ole1_server_registration::validate_server_registration(
            &mut host, b"FixtureClass").unwrap().unwrap_err(),
            super::super::win16_ole1_server_state::OLE_ERROR_REGISTRATION);
        assert!(super::registry_resolver::resolve_class_application(
            &mut host, b"FixtureClass", b"StdFileEditing").unwrap().is_none());
        assert_eq!(host.value, value);
    }
    let mut oversized = vec![b'x'; 124]; oversized.push(0);
    let mut host = RegistryHost::new(&oversized, 2);
    assert!(super::super::win16_ole1_server_registration::validate_server_registration(
        &mut host, b"FixtureClass").unwrap().is_err());
    assert_eq!(host.capacities, [124]);
}
