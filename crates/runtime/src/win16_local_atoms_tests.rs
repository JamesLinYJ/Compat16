//! Local-atom runtime coverage against real guest heaps and checked selectors.

use super::super::{ImportBinding, local_heap::LocalOperation, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, SelectorRef, Win16Argument,
    Win16AtomName, Win16ExportStackCleanup, Win16KernelAtomsRequest as Request,
    Win16OutputBuffer, Win16ReturnKind, lookup_export,
};

#[derive(Default)]
struct AtomHost {
    lower_calls: Vec<Vec<u8>>,
    fail_lower: bool,
}

impl DosHost for AtomHost {
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

impl RuntimeHost for AtomHost {
    fn win16_ansi_lower_string(&mut self, source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        self.lower_calls.push(source.to_vec());
        if self.fail_lower {
            return Err(RuntimeError::new(Kind::HostFailure, "test ANSI conversion failure"));
        }
        // Model a DBCS page: a trail byte is part of its preceding character,
        // even when that byte happens to have an ASCII letter's numeric value.
        let mut bytes = source.to_vec();
        let mut index = 0;
        while index < bytes.len() {
            if matches!(bytes[index], 0x81..=0x9f | 0xe0..=0xfc) && index + 1 < bytes.len() {
                index += 2;
            } else {
                bytes[index].make_ascii_lowercase();
                index += 1;
            }
        }
        Ok(bytes)
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for AtomHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for AtomHost {}
impl crate::RuntimeMidiHost for AtomHost {}
impl crate::RuntimeNetbiosHost for AtomHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\ATOMS.NE").unwrap();
    let ds = runtime.cpu.regs.ds;
    // Loading reserves automatic data capacity; InitTask normally installs
    // the local heap. These API-level tests initialize the same tail reserve.
    assert_eq!(runtime.win16.as_ref().unwrap()
        .local_init(ds, ds, 0, 0x100, &mut runtime.memory).unwrap(), 1);
    runtime
}

fn request(
    runtime: &mut Runtime, ds: u16, request: Request, host: &mut AtomHost,
) -> Result<u16, RuntimeError> {
    runtime.win16.as_mut().unwrap()
        .local_atom_request(ds, request, &mut runtime.memory, host)
}

fn add(runtime: &mut Runtime, ds: u16, name: &[u8], host: &mut AtomHost) -> u16 {
    request(runtime, ds, Request::AddAtom { name: Win16AtomName::String(name.to_vec()) }, host).unwrap()
}

fn find(runtime: &mut Runtime, ds: u16, name: &[u8], host: &mut AtomHost) -> u16 {
    request(runtime, ds, Request::FindAtom { name: Win16AtomName::String(name.to_vec()) }, host).unwrap()
}

fn local(runtime: &mut Runtime, ds: u16, operation: LocalOperation) -> u32 {
    runtime.win16.as_mut().unwrap().local_operation(ds, operation, &mut runtime.memory).unwrap()
}

fn snapshot(runtime: &Runtime, ds: u16) -> (PhysAddr, Vec<u8>) {
    let state = runtime.win16.as_ref().unwrap();
    let reference = state.selectors.reference(Selector(ds)).unwrap();
    let descriptor = state.selectors.describe(reference).unwrap();
    let mut bytes = vec![0; descriptor.limit as usize + 1];
    runtime.memory.read_physical(descriptor.base, &mut bytes).unwrap();
    (descriptor.base, bytes)
}

fn segment(runtime: &mut Runtime, base: u32, size: u32, rights: AccessRights) -> SelectorRef {
    runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(base), size, rights, &runtime.memory).unwrap()
}

fn heap_segment(runtime: &mut Runtime, base: u32, size: u16) -> u16 {
    let selector = segment(runtime, base, u32::from(size), AccessRights::read_write()).raw().0;
    assert_eq!(runtime.win16.as_ref().unwrap()
        .local_init(selector, selector, 0x10, size - 1, &mut runtime.memory).unwrap(), 1);
    selector
}

fn output(runtime: &mut Runtime, capacity: u16) -> Win16OutputBuffer {
    let selector = segment(runtime, 0x88000, 512, AccessRights::read_write());
    runtime.memory.write_physical(PhysAddr(0x88000), &[0xa5; 512]).unwrap();
    Win16OutputBuffer { pointer: SegmentedPointer::new(selector, 0), capacity }
}

fn read_output(runtime: &Runtime, output: Win16OutputBuffer, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    runtime.win16.as_ref().unwrap().selectors
        .read(&runtime.memory, output.pointer, &mut bytes).unwrap();
    bytes
}

#[test]
fn local_atom_integer_boundaries_do_not_touch_ds_or_host() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let before = snapshot(&runtime, ds);
    let mut host = AtomHost::default();
    for atom in [1, 2, 0x7fff, 0xbfff] {
        for request_kind in [
            Request::AddAtom { name: Win16AtomName::Integer(atom) },
            Request::FindAtom { name: Win16AtomName::Integer(atom) },
        ] {
            assert_eq!(request(&mut runtime, 0, request_kind, &mut host).unwrap(), atom);
        }
        assert_eq!(request(&mut runtime, 0, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
        assert_eq!(request(&mut runtime, 0, Request::GetAtomHandle { atom }, &mut host).unwrap(), 0);
    }
    for atom in [0, 0xc000, 0xffff] {
        assert_eq!(request(&mut runtime, 0, Request::AddAtom {
            name: Win16AtomName::Integer(atom),
        }, &mut host).unwrap(), 0);
        assert_eq!(request(&mut runtime, 0, Request::FindAtom {
            name: Win16AtomName::Integer(atom),
        }, &mut host).unwrap(), 0);
    }
    assert_eq!(snapshot(&runtime, ds), before);
    assert!(host.lower_calls.is_empty());
}

#[test]
fn local_atom_decimal_integer_spellings_are_bounded_and_allocation_free() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let before = snapshot(&runtime, ds);
    let mut host = AtomHost::default();
    for (name, expected) in [
        (b"#1".as_slice(), 1), (b"#00042", 42), (b"#49151", 0xbfff),
        (b"#0", 0), (b"#0000", 0), (b"#49152", 0), (b"#65535", 0),
        (b"#65536", 0), (b"#99999999999999999999999999", 0),
    ] {
        assert_eq!(add(&mut runtime, 0, name, &mut host), expected);
        assert_eq!(find(&mut runtime, 0, name, &mut host), expected);
    }
    assert_eq!(snapshot(&runtime, ds), before);
    assert!(host.lower_calls.is_empty());
}

#[test]
fn local_atom_invalid_names_and_negative_bucket_counts_do_not_access_ds() {
    let mut runtime = fixture();
    let mut host = AtomHost::default();
    for name in [Vec::new(), vec![b'A'; 256], b"a\0b".to_vec()] {
        assert_eq!(add(&mut runtime, 0, &name, &mut host), 0);
        assert_eq!(find(&mut runtime, 0, &name, &mut host), 0);
    }
    for buckets in [-1, i16::MIN] {
        assert_eq!(request(&mut runtime, 0, Request::InitAtomTable { buckets }, &mut host).unwrap(), 0);
    }
    assert!(host.lower_calls.is_empty());
}

#[test]
fn local_atom_lazy_initialization_accepts_literal_hash_names_and_255_bytes() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let before = snapshot(&runtime, ds);
    let mut host = AtomHost::default();
    assert_eq!(find(&mut runtime, ds, b"missing", &mut host), 0);
    assert_eq!(snapshot(&runtime, ds), before);
    for name in [b"#".to_vec(), b"#name".to_vec(), b"#12x".to_vec(), b"#+1".to_vec(), vec![b'A'; 255]] {
        let atom = add(&mut runtime, ds, &name, &mut host);
        assert!(atom >= 0xc000);
        assert_eq!(find(&mut runtime, ds, &name, &mut host), atom);
    }
}

#[test]
fn local_atom_duplicate_case_folding_preserves_first_spelling_and_reference_counts() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let mut host = AtomHost::default();
    let atom = add(&mut runtime, ds, b"First Spelling", &mut host);
    assert!(atom >= 0xc000);
    assert_eq!(add(&mut runtime, ds, b"fIRST sPELLING", &mut host), atom);
    let output = output(&mut runtime, 32);
    assert_eq!(request(&mut runtime, ds, Request::GetAtomName {
        atom, output_buffer: Some(output),
    }, &mut host).unwrap(), 14);
    assert_eq!(read_output(&runtime, output, 16), b"First Spelling\0\xa5");
    let before_find = snapshot(&runtime, ds);
    for _ in 0..3 {
        assert_eq!(find(&mut runtime, ds, b"FIRST SPELLING", &mut host), atom);
    }
    assert_eq!(snapshot(&runtime, ds), before_find);
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
    assert_eq!(find(&mut runtime, ds, b"first spelling", &mut host), atom);
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
    assert_eq!(find(&mut runtime, ds, b"first spelling", &mut host), 0);
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), atom);
}

#[test]
fn local_atom_dbcs_trail_bytes_are_not_independently_case_folded() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let mut host = AtomHost::default();
    let first = add(&mut runtime, ds, &[0x81, b'A', b'Z'], &mut host);
    assert_eq!(add(&mut runtime, ds, &[0x81, b'A', b'z'], &mut host), first);
    let distinct = add(&mut runtime, ds, &[0x81, b'a', b'Z'], &mut host);
    assert!(first >= 0xc000 && distinct >= 0xc000);
    assert_ne!(first, distinct);
    assert!(host.lower_calls.contains(&vec![0x81, b'A', b'Z']));
}

#[test]
fn local_atom_get_handle_returns_a_real_local_heap_allocation() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let mut host = AtomHost::default();
    let atom = add(&mut runtime, ds, b"GuestStorage", &mut host);
    let before = snapshot(&runtime, ds);
    let handle = request(&mut runtime, ds, Request::GetAtomHandle { atom }, &mut host).unwrap();
    assert_ne!(handle, 0);
    assert_eq!(snapshot(&runtime, ds), before);
    let size = local(&mut runtime, ds, LocalOperation::Size { handle });
    assert!(size >= 13);
    let locked = local(&mut runtime, ds, LocalOperation::Lock { handle });
    assert_eq!(locked >> 16, u32::from(ds));
    let pointer = runtime.win16.as_ref().unwrap().selectors.pointer_from_far(locked).unwrap();
    let mut storage = vec![0; size as usize];
    runtime.win16.as_ref().unwrap().selectors.read(&runtime.memory, pointer, &mut storage).unwrap();
    assert!(storage.windows(13).any(|bytes| bytes == b"GuestStorage\0"));
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
    assert_eq!(request(&mut runtime, ds, Request::GetAtomHandle { atom }, &mut host).unwrap(), 0);
    assert_eq!(local(&mut runtime, ds, LocalOperation::Size { handle }), 0);
    assert_eq!(local(&mut runtime, ds, LocalOperation::Lock { handle }), 0);
}

#[test]
fn local_atom_repeated_initialization_retains_existing_atoms_and_references() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let mut host = AtomHost::default();
    assert_eq!(request(&mut runtime, ds, Request::InitAtomTable { buckets: 7 }, &mut host).unwrap(), 1);
    let atom = add(&mut runtime, ds, b"Keep", &mut host);
    assert_eq!(add(&mut runtime, ds, b"KEEP", &mut host), atom);
    let before = snapshot(&runtime, ds);
    for buckets in [0, 1, 7, 97] {
        assert_eq!(request(&mut runtime, ds, Request::InitAtomTable { buckets }, &mut host).unwrap(), 1);
        assert_eq!(snapshot(&runtime, ds), before);
    }
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
    assert_eq!(find(&mut runtime, ds, b"keep", &mut host), atom);
}

#[test]
fn local_atom_state_is_in_guest_memory_and_survives_selector_aliases() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let alias = segment(&mut runtime, 0x80000, 4096, AccessRights::read_write()).raw().0;
    let mut host = AtomHost::default();
    let original = add(&mut runtime, ds, b"Original", &mut host);
    assert_eq!(find(&mut runtime, alias, b"ORIGINAL", &mut host), original);
    let saved = snapshot(&runtime, ds);
    let later = add(&mut runtime, alias, b"Later", &mut host);
    assert_eq!(find(&mut runtime, ds, b"later", &mut host), later);
    runtime.memory.write_physical(saved.0, &saved.1).unwrap();
    assert_eq!(find(&mut runtime, alias, b"later", &mut host), 0);
    assert_eq!(find(&mut runtime, alias, b"original", &mut host), original);
    assert_eq!(request(&mut runtime, alias, Request::DeleteAtom { atom: original }, &mut host).unwrap(), 0);
    assert_eq!(find(&mut runtime, ds, b"original", &mut host), 0);
}

#[test]
fn local_atom_custom_data_segments_have_independent_tables() {
    let mut runtime = fixture();
    let first_ds = heap_segment(&mut runtime, 0x80000, 4096);
    let second_ds = heap_segment(&mut runtime, 0x82000, 4096);
    let mut host = AtomHost::default();
    let first = add(&mut runtime, first_ds, b"FirstOnly", &mut host);
    let second = add(&mut runtime, second_ds, b"SecondOnly", &mut host);
    assert_eq!(find(&mut runtime, first_ds, b"SecondOnly", &mut host), 0);
    assert_eq!(find(&mut runtime, second_ds, b"FirstOnly", &mut host), 0);
    assert_eq!(find(&mut runtime, first_ds, b"FirstOnly", &mut host), first);
    assert_eq!(find(&mut runtime, second_ds, b"SecondOnly", &mut host), second);
}

#[test]
fn local_atom_reused_selector_resolves_its_new_backing_without_cached_names() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let mut host = AtomHost::default();
    let original = add(&mut runtime, ds, b"OldBacking", &mut host);
    let old_reference = runtime.win16.as_ref().unwrap().selectors.reference(Selector(ds)).unwrap();
    runtime.win16.as_mut().unwrap().selectors.free_block(old_reference).unwrap();
    let replacement = heap_segment(&mut runtime, 0x82000, 4096);
    let new_reference = runtime.win16.as_ref().unwrap().selectors.reference(Selector(replacement)).unwrap();
    assert_eq!(replacement, ds);
    assert_ne!(new_reference.generation(), old_reference.generation());
    assert_eq!(find(&mut runtime, replacement, b"OldBacking", &mut host), 0);
    let new_atom = add(&mut runtime, replacement, b"NewBacking", &mut host);
    assert!(new_atom >= 0xc000);
    let old_alias = segment(&mut runtime, 0x80000, 4096, AccessRights::read_write()).raw().0;
    assert_eq!(find(&mut runtime, old_alias, b"OldBacking", &mut host), original);
    assert_eq!(find(&mut runtime, old_alias, b"NewBacking", &mut host), 0);
}

#[test]
fn local_atom_get_name_uses_guest_byte_capacities_and_a_terminator() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let mut host = AtomHost::default();
    let name = [0x81, b'A', b'Z'];
    let atom = add(&mut runtime, ds, &name, &mut host);
    for capacity in [1, 2, 3, 4, 8] {
        let output = output(&mut runtime, capacity);
        let copied = name.len().min(usize::from(capacity - 1));
        assert_eq!(request(&mut runtime, ds, Request::GetAtomName {
            atom, output_buffer: Some(output),
        }, &mut host).unwrap(), copied as u16);
        let mut expected = name[..copied].to_vec();
        expected.push(0);
        expected.push(0xa5);
        assert_eq!(read_output(&runtime, output, copied + 2), expected);
    }
    for atom in [1, 0xbfff] {
        let output = output(&mut runtime, 16);
        let expected = format!("#{atom}");
        assert_eq!(request(&mut runtime, 0, Request::GetAtomName {
            atom, output_buffer: Some(output),
        }, &mut host).unwrap(), expected.len() as u16);
        let mut bytes = expected.into_bytes();
        bytes.push(0);
        assert_eq!(read_output(&runtime, output, bytes.len()), bytes);
    }
    assert_eq!(request(&mut runtime, 0, Request::GetAtomName {
        atom, output_buffer: None,
    }, &mut host).unwrap(), 0);
}

#[test]
fn local_atom_get_name_preflights_declared_capacity_without_partial_writes() {
    for (size, rights) in [(2, AccessRights::read_write()), (8, AccessRights::read_only())] {
        let mut runtime = fixture();
        let ds = runtime.cpu.regs.ds;
        let mut host = AtomHost::default();
        let atom = add(&mut runtime, ds, b"X", &mut host);
        runtime.memory.write_physical(PhysAddr(0x88000), &[0x5a; 8]).unwrap();
        let selector = segment(&mut runtime, 0x88000, size, rights);
        let output = Win16OutputBuffer { pointer: SegmentedPointer::new(selector, 0), capacity: 8 };
        let before = snapshot(&runtime, ds);
        let error = request(&mut runtime, ds, Request::GetAtomName {
            atom, output_buffer: Some(output),
        }, &mut host).unwrap_err();
        assert_eq!(error.kind(), Kind::GuestFault);
        let mut bytes = [0; 8];
        runtime.memory.read_physical(PhysAddr(0x88000), &mut bytes).unwrap();
        assert_eq!(bytes, [0x5a; 8]);
        assert_eq!(snapshot(&runtime, ds), before);
    }
}

#[test]
fn local_atom_get_name_rejects_stale_output_selector_generation() {
    let mut runtime = fixture();
    let mut host = AtomHost::default();
    let output = output(&mut runtime, 8);
    let reference = output.pointer.selector();
    runtime.win16.as_mut().unwrap().selectors.free_block(reference).unwrap();
    let replacement = segment(&mut runtime, 0x88000, 512, AccessRights::read_write());
    assert_eq!(replacement.raw(), reference.raw());
    assert_ne!(replacement.generation(), reference.generation());
    let error = request(&mut runtime, 0, Request::GetAtomName {
        atom: 42, output_buffer: Some(output),
    }, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    let mut bytes = [0; 8];
    runtime.memory.read_physical(PhysAddr(0x88000), &mut bytes).unwrap();
    assert_eq!(bytes, [0xa5; 8]);
}

#[test]
fn local_atom_failed_ansi_conversion_does_not_initialize_or_mutate_heap() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let mut host = AtomHost { fail_lower: true, ..Default::default() };
    let before = snapshot(&runtime, ds);
    let error = request(&mut runtime, ds, Request::AddAtom {
        name: Win16AtomName::String(b"NotAdded".to_vec()),
    }, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!(snapshot(&runtime, ds), before);
    host.fail_lower = false;
    let atom = add(&mut runtime, ds, b"AlreadyAdded", &mut host);
    let before = snapshot(&runtime, ds);
    host.fail_lower = true;
    let error = request(&mut runtime, ds, Request::AddAtom {
        name: Win16AtomName::String(b"alreadyadded".to_vec()),
    }, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!(snapshot(&runtime, ds), before);
    host.fail_lower = false;
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
    assert_eq!(find(&mut runtime, ds, b"AlreadyAdded", &mut host), 0);
}

#[test]
fn local_atom_allocation_failure_rolls_back_lazy_table_and_existing_table() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 256);
    let mut host = AtomHost::default();
    let name = [b'X'; 255];
    let before = snapshot(&runtime, ds);
    assert_eq!(add(&mut runtime, ds, &name, &mut host), 0);
    assert_eq!(snapshot(&runtime, ds), before);
    assert_eq!(request(&mut runtime, ds, Request::InitAtomTable { buckets: 1 }, &mut host).unwrap(), 1);
    let atom = add(&mut runtime, ds, b"Keep", &mut host);
    assert!(atom >= 0xc000);
    let before = snapshot(&runtime, ds);
    assert_eq!(add(&mut runtime, ds, &name, &mut host), 0);
    assert_eq!(snapshot(&runtime, ds), before);
    assert_eq!(find(&mut runtime, ds, b"Keep", &mut host), atom);
}

#[test]
fn local_atom_automatic_dgroup_growth_preserves_fixed_pointers_and_aliases() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let mut host = AtomHost::default();
    let fixed = local(&mut runtime, ds, LocalOperation::Alloc { flags: 0, size: 16 }) as u16;
    assert_ne!(fixed, 0);
    let locked = local(&mut runtime, ds, LocalOperation::Lock { handle: fixed });
    let pointer = runtime.win16.as_ref().unwrap().selectors.pointer_from_far(locked).unwrap();
    runtime.win16.as_ref().unwrap().selectors.write(&mut runtime.memory, pointer, &[0x6b; 16]).unwrap();
    let before = snapshot(&runtime, ds);
    let alias = segment(&mut runtime, before.0.0, before.1.len() as u32, AccessRights::read_write());
    let reference = runtime.win16.as_ref().unwrap().selectors.reference(Selector(ds)).unwrap();
    let atom = add(&mut runtime, ds, &[b'G'; 255], &mut host);
    assert!(atom >= 0xc000);
    let after = snapshot(&runtime, ds);
    assert_eq!(after.0, before.0);
    assert!(after.1.len() > before.1.len());
    assert_eq!(runtime.win16.as_ref().unwrap().selectors.reference(Selector(ds)).unwrap(), reference);
    assert_eq!(snapshot(&runtime, alias.raw().0), after);
    assert_eq!(local(&mut runtime, ds, LocalOperation::Lock { handle: fixed }), locked);
    let mut bytes = [0; 16];
    runtime.win16.as_ref().unwrap().selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    assert_eq!(bytes, [0x6b; 16]);
    assert_eq!(find(&mut runtime, alias.raw().0, &[b'g'; 255], &mut host), atom);
}

#[test]
fn local_atom_growth_preflight_failure_does_not_publish_heap_or_selector_changes() {
    let mut runtime = fixture();
    let ds = runtime.cpu.regs.ds;
    let mut host = AtomHost::default();
    let before = snapshot(&runtime, ds);
    // A longer independently exposed view makes backing ownership ambiguous.
    // The existing DGROUP growth transaction must reject it before committing.
    let alias = segment(&mut runtime, before.0.0, before.1.len() as u32 + 16, AccessRights::read_write());
    let alias_before = snapshot(&runtime, alias.raw().0);
    assert_eq!(add(&mut runtime, ds, &[b'G'; 255], &mut host), 0);
    assert_eq!(snapshot(&runtime, ds), before);
    assert_eq!(snapshot(&runtime, alias.raw().0), alias_before);
}

fn gate(
    runtime: &mut Runtime, ordinal: u16, arguments: &[Win16Argument], host: &mut AtomHost,
) -> u16 {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("local atom gate must have a fixed Pascal frame");
    };
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    for argument in arguments.iter().rev() {
        match argument {
            Win16Argument::Word(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            Win16Argument::Dword(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            _ => panic!("unexpected local atom argument width"),
        }
    }
    assert_eq!(bytes.len(), 4 + usize::from(cleanup.callee_pop_bytes));
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0).unwrap(), None);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + bytes.len() as u16));
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
    runtime.cpu.regs.ax()
}

#[test]
fn local_atom_service_gate_round_trip_uses_calling_ds_and_pascal_cleanup() {
    use Win16Argument::{Dword, Word};
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let other_ds = runtime.cpu.regs.ds;
    runtime.cpu.regs.ds = ds;
    let name_selector = segment(&mut runtime, 0x82000, 128, AccessRights::read_write());
    let pointer = SegmentedPointer::new(name_selector, 0);
    runtime.win16.as_ref().unwrap().selectors.write(&mut runtime.memory, pointer, b"GateAtom\0").unwrap();
    let mut host = AtomHost::default();
    assert_eq!(gate(&mut runtime, 68, &[Word(7)], &mut host), 1);
    let atom = gate(&mut runtime, 70, &[Dword(pointer.far_value())], &mut host);
    assert!(atom >= 0xc000);
    assert_eq!(gate(&mut runtime, 69, &[Dword(pointer.far_value())], &mut host), atom);
    assert_eq!(find(&mut runtime, other_ds, b"GateAtom", &mut host), 0);
    let handle = gate(&mut runtime, 73, &[Word(atom)], &mut host);
    assert_ne!(handle, 0);
    assert_ne!(local(&mut runtime, ds, LocalOperation::Size { handle }), 0);
    let output = SegmentedPointer::new(name_selector, 32);
    assert_eq!(gate(&mut runtime, 72, &[Word(atom), Dword(output.far_value()), Word(16)], &mut host), 8);
    let mut bytes = [0; 9];
    runtime.win16.as_ref().unwrap().selectors.read(&runtime.memory, output, &mut bytes).unwrap();
    assert_eq!(&bytes, b"GateAtom\0");
    assert_eq!(gate(&mut runtime, 71, &[Word(atom)], &mut host), 0);
    assert_eq!(gate(&mut runtime, 69, &[Dword(pointer.far_value())], &mut host), 0);
}


#[test]
fn local_atom_reinitialized_heap_rejects_stale_atom_metadata() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let mut host = AtomHost::default();
    let atom = add(&mut runtime, ds, b"BeforeLocalInit", &mut host);
    assert!(atom >= 0xc000);
    assert_eq!(runtime.win16.as_ref().unwrap()
        .local_init(ds, ds, 0x10, 4095, &mut runtime.memory).unwrap(), 1);
    // LocalInit preserves the instance header. Its old atom-table pointer
    // must be diagnosed as stale, never followed into now-free storage.
    let before = snapshot(&runtime, ds);
    for operation in [
        Request::FindAtom { name: Win16AtomName::String(b"BeforeLocalInit".to_vec()) },
        Request::AddAtom { name: Win16AtomName::String(b"AfterLocalInit".to_vec()) },
        Request::GetAtomHandle { atom },
        Request::DeleteAtom { atom },
    ] {
        assert_eq!(request(&mut runtime, ds, operation, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(snapshot(&runtime, ds), before);
    }
}

#[test]
fn local_atom_read_only_data_alias_permits_lookup_but_rejects_mutation() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let mut host = AtomHost::default();
    let atom = add(&mut runtime, ds, b"ReadOnly", &mut host);
    let alias = segment(&mut runtime, 0x80000, 4096, AccessRights::read_only()).raw().0;
    let before = snapshot(&runtime, ds);
    assert_eq!(find(&mut runtime, alias, b"readonly", &mut host), atom);
    assert_ne!(request(&mut runtime, alias, Request::GetAtomHandle { atom }, &mut host).unwrap(), 0);
    for operation in [
        Request::AddAtom { name: Win16AtomName::String(b"readonly".to_vec()) },
        Request::DeleteAtom { atom },
        Request::InitAtomTable { buckets: 7 },
    ] {
        assert_eq!(request(&mut runtime, alias, operation, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(snapshot(&runtime, ds), before);
    }
    assert_eq!(request(&mut runtime, ds, Request::DeleteAtom { atom }, &mut host).unwrap(), 0);
    assert_eq!(find(&mut runtime, ds, b"ReadOnly", &mut host), 0);
}

#[test]
fn local_atom_output_spans_checked_selectors_and_preflights_the_last_chunk() {
    for (size, succeeds) in [(0x1_0008, true), (0x1_0002, false)] {
        let mut runtime = fixture();
        let mut host = AtomHost::default();
        let selector = segment(&mut runtime, 0x80000, size, AccessRights::read_write());
        let output = Win16OutputBuffer {
            pointer: SegmentedPointer::new(selector, 0xfffe), capacity: 8,
        };
        runtime.memory.write_physical(PhysAddr(0x8fffe), &[0x5a; 8]).unwrap();
        let result = request(&mut runtime, 0, Request::GetAtomName {
            atom: 123, output_buffer: Some(output),
        }, &mut host);
        let mut bytes = [0; 8];
        runtime.memory.read_physical(PhysAddr(0x8fffe), &mut bytes).unwrap();
        if succeeds {
            assert_eq!(result.unwrap(), 4);
            assert_eq!(&bytes, b"#123\0ZZZ");
        } else {
            assert_eq!(result.unwrap_err().kind(), Kind::GuestFault);
            assert_eq!(bytes, [0x5a; 8]);
        }
    }
}
