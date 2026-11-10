//! Service-gate checks for the Win16 profile string, integer, and section calls.
//! The host is a fake: these tests lock the guest contract, not a Windows file.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, SelectorRef, StackCleanup,
    Win16ExportStackCleanup, lookup_export,
};

const BASE: u32 = 0x80000;
const EAX_SENTINEL: u32 = 0x1357_a55a;
const EDX_SENTINEL: u32 = 0x2468_5aa5;

enum Allowed {
    Nothing,
    SectionNames,
    KeyNames,
}

struct ProbeHost {
    allowed: Allowed,
    calls: u32,
}

impl ProbeHost {
    fn new(allowed: Allowed) -> Self {
        Self { allowed, calls: 0 }
    }
}

impl DosHost for ProbeHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        text_codec::CodePage::CP437
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for ProbeHost {
    fn win16_system_profile_string(
        &mut self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        default: Option<&[u8]>,
        capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        assert!(default.is_none());
        assert!(capacity >= 16);
        self.calls += 1;
        match self.allowed {
            Allowed::SectionNames => {
                assert!(section.is_none());
                assert!(key.is_none());
                Ok((b"Windows\0\0".to_vec(), 8))
            }
            Allowed::KeyNames => {
                assert_eq!(section, Some(b"Sec".as_slice()));
                assert!(key.is_none());
                Ok((b"Alpha\0Beta\0\0".to_vec(), 11))
            }
            Allowed::Nothing => panic!("profile string host was called"),
        }
    }
    fn epoch_seconds(&self) -> i64 {
        0
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        Err(RuntimeError::new(Kind::CompatibilityGap, "no key"))
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        Ok(())
    }
}
impl crate::RuntimeDdeHost for ProbeHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for ProbeHost {}
impl crate::RuntimeMidiHost for ProbeHost {}
impl crate::RuntimeNetbiosHost for ProbeHost {}

fn place(runtime: &mut Runtime, bytes: &[u8]) -> SelectorRef {
    runtime
        .memory
        .write_physical(PhysAddr(BASE), bytes)
        .unwrap();
    runtime
        .win16
        .as_mut()
        .unwrap()
        .selectors
        .alloc_block(
            PhysAddr(BASE),
            bytes.len() as u32,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap()
}

fn far(selector: SelectorRef, offset: u16) -> u32 {
    SegmentedPointer::new(selector, offset).far_value()
}

/// Pascal places the last argument nearest the return address.
fn pascal_arguments(slots: &[&[u8]]) -> Vec<u8> {
    let mut arguments = Vec::new();
    for slot in slots.iter().rev() {
        arguments.extend_from_slice(slot);
    }
    arguments
}

fn pop_bytes(ordinal: u16) -> u16 {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    match descriptor.stack_cleanup {
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes, ..
        }) => callee_pop_bytes,
        _ => panic!("profile export {ordinal} has a fixed stack"),
    }
}

fn gate(runtime: &mut Runtime, ordinal: u16, arguments: &[u8]) -> u16 {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_ip = 0x12_u16;
    let return_cs = runtime.cpu.regs.cs;
    let stack = runtime.cpu.regs.sp();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(arguments);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &frame)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    stack
}

fn assert_word(runtime: &Runtime, stack: u16, popped: u16, ax: u16) {
    assert_eq!(
        runtime.cpu.regs.eax,
        (EAX_SENTINEL & 0xffff_0000) | u32::from(ax)
    );
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!(runtime.cpu.regs.sp(), stack + 4 + popped);
}

fn read_at(runtime: &Runtime, offset: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    runtime
        .memory
        .read_physical(PhysAddr(BASE + offset as u32), &mut bytes)
        .unwrap();
    bytes
}

fn filled(text: &[u8], at: usize) -> Vec<u8> {
    let mut bytes = vec![0xA5; 64];
    bytes[at..at + text.len()].copy_from_slice(text);
    bytes
}

#[test]
fn null_section_string_writes_one_nul_and_skips_the_host() {
    let bytes = filled(b"Key\0", 0);
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let key = far(selector, 0).to_le_bytes();
    let output = far(selector, 32).to_le_bytes();
    let capacity = 5_u16.to_le_bytes();
    let stack = gate(
        &mut runtime,
        58,
        &pascal_arguments(&[
            &0_u32.to_le_bytes(),
            &key,
            &0_u32.to_le_bytes(),
            &output,
            &capacity,
        ]),
    );
    let mut host = ProbeHost::new(Allowed::Nothing);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(58), 0);
    assert_eq!(host.calls, 0);
    let mut expected = vec![0xA5; 5];
    expected[0] = 0;
    assert_eq!(read_at(&runtime, 32, 5), expected);
}

#[test]
fn both_null_string_arguments_do_not_enumerate_sections() {
    let bytes = vec![0xA5; 64];
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let output = far(selector, 32).to_le_bytes();
    let capacity = 8_u16.to_le_bytes();
    let stack = gate(
        &mut runtime,
        58,
        &pascal_arguments(&[
            &0_u32.to_le_bytes(),
            &0_u32.to_le_bytes(),
            &0_u32.to_le_bytes(),
            &output,
            &capacity,
        ]),
    );
    let mut host = ProbeHost::new(Allowed::Nothing);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(58), 0);
    assert_eq!(host.calls, 0);
    assert_eq!(read_at(&runtime, 32, 2), [0, 0xA5]);
}

#[test]
fn nonpositive_string_capacity_leaves_the_guest_buffer_unchanged() {
    for capacity in [0_u16, 0x8000] {
        let bytes = filled(b"Sec\0Key\0", 0);
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
        let selector = place(&mut runtime, &bytes);
        let section = far(selector, 0).to_le_bytes();
        let key = far(selector, 4).to_le_bytes();
        let output = far(selector, 32).to_le_bytes();
        let size = capacity.to_le_bytes();
        let stack = gate(
            &mut runtime,
            58,
            &pascal_arguments(&[&section, &key, &0_u32.to_le_bytes(), &output, &size]),
        );
        let mut host = ProbeHost::new(Allowed::Nothing);
        runtime
            .win16
            .as_mut()
            .unwrap()
            .dispatch(
                &mut runtime.cpu,
                &mut runtime.memory,
                &mut runtime.dos,
                &mut host,
                0,
            )
            .unwrap();
        assert_word(&runtime, stack, pop_bytes(58), 0);
        assert_eq!(host.calls, 0);
        assert_eq!(read_at(&runtime, 32, 8), vec![0xA5; 8]);
    }
}

#[test]
fn null_profile_integer_returns_the_default_word() {
    let bytes = filled(b"Sec\0", 0);
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let default = (-1_i16).to_le_bytes();
    let stack = gate(
        &mut runtime,
        57,
        &pascal_arguments(&[&section, &0_u32.to_le_bytes(), &default]),
    );
    let mut host = ProbeHost::new(Allowed::Nothing);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(57), 0xffff);
    assert_eq!(host.calls, 0);
    assert_eq!(read_at(&runtime, 0, 4), b"Sec\0");
}

#[test]
fn null_section_query_writes_nothing() {
    let bytes = vec![0xA5; 64];
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let output = far(selector, 16).to_le_bytes();
    let capacity = 8_u16.to_le_bytes();
    let stack = gate(
        &mut runtime,
        418,
        &pascal_arguments(&[
            &0_u32.to_le_bytes(),
            &output,
            &capacity,
            &0_u32.to_le_bytes(),
        ]),
    );
    let mut host = ProbeHost::new(Allowed::Nothing);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(418), 0);
    assert_eq!(host.calls, 0);
    assert_eq!(read_at(&runtime, 16, 8), vec![0xA5; 8]);
}

#[test]
fn oversized_section_capacity_does_not_touch_the_buffer() {
    let bytes = filled(b"Sec\0", 0);
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let output = far(selector, 16).to_le_bytes();
    let capacity = 0xffff_u16.to_le_bytes();
    let stack = gate(
        &mut runtime,
        419,
        &pascal_arguments(&[&section, &output, &capacity]),
    );
    let mut host = ProbeHost::new(Allowed::Nothing);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(419), 0);
    assert_eq!(host.calls, 0);
    assert_eq!(read_at(&runtime, 16, 8), vec![0xA5; 8]);
}

#[test]
fn section_names_still_enumerate() {
    let bytes = vec![0xA5; 64];
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let output = far(selector, 16).to_le_bytes();
    let capacity = 32_u16.to_le_bytes();
    let stack = gate(&mut runtime, 142, &pascal_arguments(&[&output, &capacity]));
    let mut host = ProbeHost::new(Allowed::SectionNames);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(142), 8);
    assert_eq!(host.calls, 1);
    let mut expected = vec![0xA5; 16];
    expected[..9].copy_from_slice(b"Windows\0\0");
    assert_eq!(read_at(&runtime, 16, 16), expected);
}

#[test]
fn null_key_enumerates_key_names() {
    let bytes = filled(b"Sec\0", 0);
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let output = far(selector, 16).to_le_bytes();
    let capacity = 32_u16.to_le_bytes();
    let stack = gate(
        &mut runtime,
        58,
        &pascal_arguments(&[
            &section,
            &0_u32.to_le_bytes(),
            &0_u32.to_le_bytes(),
            &output,
            &capacity,
        ]),
    );
    let mut host = ProbeHost::new(Allowed::KeyNames);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_word(&runtime, stack, pop_bytes(58), 11);
    assert_eq!(host.calls, 1);
    let mut expected = vec![0xA5; 16];
    expected[..12].copy_from_slice(b"Alpha\0Beta\0\0");
    assert_eq!(read_at(&runtime, 16, 16), expected);
}
