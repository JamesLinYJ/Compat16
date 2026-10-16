//! USER.433–436: low-byte input, canonical BOOL, Pascal cleanup and error isolation.
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, Win16CharacterClassification as Classification, lookup_export};

struct ClassificationHost { result: bool, calls: Vec<(u8, Classification)>, fail: bool }
impl DosHost for ClassificationHost {
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


impl RuntimeHost for ClassificationHost {
    fn win16_classify_character(&mut self, value: u8, classification: Classification) -> Result<bool, RuntimeError> {
        self.calls.push((value, classification));
        if self.fail { Err(RuntimeError::new(Kind::HostFailure, "classification test failure")) }
        else { Ok(self.result) }
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for ClassificationHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ClassificationHost {}
impl crate::RuntimeMidiHost for ClassificationHost {}
impl crate::RuntimeNetbiosHost for ClassificationHost {}

const EXPORTS: [(u16, &str, Classification); 4] = [
    (433, "IsCharAlpha", Classification::Alpha),
    (434, "IsCharAlphaNumeric", Classification::AlphaNumeric),
    (435, "IsCharUpper", Classification::Upper),
    (436, "IsCharLower", Classification::Lower),
];

fn prepare(ordinal: u16, name: Option<&str>, value: u16) -> (Runtime, (u16, u16, u16), Vec<u8>) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\CLASSIFY.NE").unwrap();
    let target = name.map_or(ExportLookupTarget::Ordinal(ordinal), |name| ExportLookupTarget::Name(name.as_bytes()));
    let descriptor = lookup_export(b"USER", target).unwrap();
    let return_to: (u16, u16, u16) = (runtime.cpu.regs.cs, 0x12, runtime.cpu.regs.sp() + 6);
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&[0x11, 0x22]);
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0x1234_a55a;
    runtime.cpu.regs.edx = 0x5678_5aa5;
    (runtime, return_to, bytes)
}

fn stack_bytes(runtime: &Runtime, stack: u16) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    let mut bytes = vec![0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn dispatch(runtime: &mut Runtime, host: &mut impl RuntimeHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}

#[test]
fn character_classification_named_and_ordinal_gates_return_word_bool() {
    for (ordinal, name, classification) in EXPORTS {
        for named in [false, true] {
            for result in [false, true] {
                let (mut runtime, return_to, bytes) = prepare(ordinal, named.then_some(name), 0xff41);
                let mut host = ClassificationHost { result, calls: Vec::new(), fail: false };
                assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
                assert_eq!(runtime.cpu.regs.eax, 0x1234_0000 | u32::from(result));
                assert_eq!(runtime.cpu.regs.edx, 0x5678_5aa5);
                assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
                assert_eq!(stack_bytes(&runtime, return_to.2 - 6), bytes);
                assert_eq!(host.calls, [(b'A', classification)]);
            }
        }
    }
}

#[test]
fn character_classification_errors_do_not_commit_return_or_stack() {
    for (ordinal, name, classification) in EXPORTS {
        for named in [false, true] {
            for unsupported in [false, true] {
                let (mut runtime, return_to, bytes) = prepare(ordinal, named.then_some(name), 0xffe9);
                let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
                let mut host = ClassificationHost { result: true, calls: Vec::new(), fail: true };
                let error = if unsupported { dispatch(&mut runtime, &mut NoHost) }
                    else { dispatch(&mut runtime, &mut host) }.unwrap_err();
                assert_eq!(error.kind(), if unsupported { Kind::CompatibilityGap } else { Kind::HostFailure });
                if !unsupported { assert_eq!(host.calls, [(0xe9, classification)]); }
                assert_eq!((runtime.cpu.regs.eax, runtime.cpu.regs.edx), (0x1234_a55a, 0x5678_5aa5));
                assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
                assert_eq!(stack_bytes(&runtime, return_to.2 - 6), bytes);
            }
        }
    }
}
