//! EXEC default FCBs through DOS pointer decoding and child PSP installation.

use super::{Win16DosAddressSpace, Win16DosCallerAddresses};
use crate::{Runtime, RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosCallerAddressSpaceFailureKind, DosCallerId, DosDirectoryEntry,
    DosError, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, PhysAddr, Registers, real_address};
use win16_abi::{AccessRights, SelectorTable};
#[path = "win16_dos_canonical_name_tests.rs"]
mod canonical_name_tests;

const PATH: &[u8] = b"CHILD.COM\0";
const FCB_INPUTS: [[u8; 16]; 2] = [
    *b"\x01FIRST   TXT\xa1\xa2\xa3\xa4",
    *b"\x02SECOND  BIN\xb1\xb2\xb3\xb4",
];

#[derive(Default)]
struct ExecHost {
    open: bool,
    opens: usize,
    closes: usize,
    cursor: usize,
    search_entries: Vec<DosDirectoryEntry>,
    search_position: usize,
    search_opens: usize,
    search_closes: usize,
    deleted: Vec<Vec<u8>>,
    renamed: Vec<(Vec<u8>, Vec<u8>)>,
}

impl DosHost for ExecHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, path: &[u8], access: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        assert_eq!(path, b"CHILD.COM");
        assert_eq!(access, DosFileAccess::ReadOnly);
        assert!(!self.open);
        self.open = true;
        self.opens += 1;
        Ok(DosHostFile(1))
    }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        assert_eq!(file, DosHostFile(1));
        assert!(self.open);
        self.open = false;
        self.closes += 1;
        Ok(())
    }
    fn file_read(&mut self, file: DosHostFile, output: &mut [u8]) -> Result<usize, DosHostError> {
        assert_eq!(file, DosHostFile(1));
        assert!(self.open);
        let image = [0xcd, 0x20];
        let count = output.len().min(image.len() - self.cursor);
        output[..count].copy_from_slice(&image[self.cursor..self.cursor + count]);
        self.cursor += count;
        Ok(count)
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _file: DosHostFile, _offset: i32, _origin: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, path: &[u8]) -> Result<(), DosHostError> { self.deleted.push(path.to_vec()); Ok(()) }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, drive: u8, output: &mut [u8]) -> Result<usize, DosHostError> {
        assert_eq!(drive,2); output[..4].copy_from_slice(b"WORK"); Ok(4)
    }
    fn file_rename(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<(), DosHostError> { self.renamed.push((old_path.to_vec(), new_path.to_vec())); Ok(()) }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        assert!(directory.is_empty()); self.search_position = 0; self.search_opens += 1; Ok(DosHostSearch(1))
    }
    fn directory_search_next(&mut self, search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        assert_eq!(search, DosHostSearch(1)); let result = self.search_entries.get(self.search_position).cloned();
        if result.is_some() { self.search_position += 1; } Ok(result)
    }
    fn directory_search_close(&mut self, search: DosHostSearch) -> Result<(), DosHostError> {
        assert_eq!(search, DosHostSearch(1)); self.search_closes += 1; Ok(())
    }
    fn guest_code_page(&self) -> text_codec::CodePage { text_codec::CodePage::Cp437 }
    fn current_drive(&self) -> u8 { 2 }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { 3 }
}

impl RuntimeHost for ExecHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for ExecHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for ExecHost {}
impl crate::RuntimeMidiHost for ExecHost {}
impl crate::RuntimeNetbiosHost for ExecHost {}

#[path = "win16_dos_fcb_parse_tests.rs"]
mod parse_tests;

#[path = "win16_dos_fcb_search_tests.rs"]
mod search_tests;

#[path = "win16_dos_fcb_mutation_tests.rs"]
mod mutation_tests;


fn fixture() -> (Runtime, ExecHost) {
    let mut runtime = Runtime::load(&[0xcd, 0x20], &[], b"PARENT.COM").unwrap();
    let mut host = ExecHost::default();
    // Keep both wrapping source windows owned by the parent, with room for
    // the child above them. A COM parent initially owns all conventional RAM.
    let mut regs = Registers::default();
    regs.set_ax(0x4a00);
    regs.es = runtime.dos.psp_segment();
    regs.set_bx(0x2000);
    assert_eq!(runtime.dos.interrupt(0x21, &mut regs, &mut runtime.memory.bus(), &mut host).unwrap(), DosAction::Continue);
    assert!(!regs.carry());
    (runtime, host)
}

fn parameter_block(pointers: [(u16, u16); 2]) -> [u8; 14] {
    let mut block = [0; 14];
    // Zero environment and command-tail pointers select their existing
    // inheritance/empty-tail behavior; only the two FCB pointers vary here.
    for (index, (segment, offset)) in pointers.into_iter().enumerate() {
        let start = 6 + index * 4;
        block[start..start + 2].copy_from_slice(&offset.to_le_bytes());
        block[start + 2..start + 4].copy_from_slice(&segment.to_le_bytes());
    }
    block
}

fn real_exec(
    runtime: &mut Runtime,
    host: &mut ExecHost,
    pointers: [(u16, u16); 2],
) -> (Registers, DosAction) {
    let parent = runtime.dos.psp_segment();
    runtime.memory.write(real_address(parent, 0x180), PATH).unwrap();
    runtime.memory.write(real_address(parent, 0x300), &parameter_block(pointers)).unwrap();
    let mut regs = Registers::default();
    regs.set_ax(0x4b00);
    regs.ds = parent;
    regs.set_dx(0x180);
    regs.es = parent;
    regs.set_bx(0x300);
    let action = runtime.dos.interrupt(0x21, &mut regs, &mut runtime.memory.bus(), host).unwrap();
    assert!(!regs.carry());
    (regs, action)
}

fn protected_exec(
    runtime: &mut Runtime,
    host: &mut ExecHost,
    readable: [u32; 2],
    null: [bool; 2],
) -> (Registers, Result<DosAction, DosError>) {
    let parent = runtime.dos.psp_segment();
    let mut selectors = SelectorTable::new().unwrap();
    let mut addresses = Win16DosCallerAddresses::default();
    let mut pointers = [(0, 0); 2];
    for index in 0..2 {
        let base = real_address(parent, 0x800 + index as u16 * 0x100);
        runtime.memory.write(PhysAddr(base.0 + 4), &FCB_INPUTS[index]).unwrap();
        let selector = selectors.alloc_block(
            base, 4 + readable[index], AccessRights::read_only(), &runtime.memory,
        ).unwrap();
        if !null[index] {
            pointers[index] = (selector.raw().0, 4);
        }
    }
    let path_address = real_address(parent, 0x180);
    runtime.memory.write(path_address, PATH).unwrap();
    let path = selectors.alloc_block(
        path_address, PATH.len() as u32, AccessRights::read_only(), &runtime.memory,
    ).unwrap();
    let block_address = real_address(parent, 0x300);
    runtime.memory.write(block_address, &parameter_block(pointers)).unwrap();
    let block = selectors.alloc_block(
        block_address, 14, AccessRights::read_only(), &runtime.memory,
    ).unwrap();
    let mut regs = Registers::default();
    regs.set_ax(0x4b00);
    regs.ds = path.raw().0;
    regs.es = block.raw().0;
    let mut memory = Win16DosAddressSpace {
        selectors: &mut selectors,
        addresses: &mut addresses,
        memory: runtime.memory.bus(),
        caller: DosCallerId::new(1).unwrap(),
    };
    let result = runtime.dos.interrupt_with_address_space(0x21, &mut regs, &mut memory, host);
    (regs, result)
}

fn assert_child_fcbs(
    runtime: &mut Runtime,
    host: &mut ExecHost,
    regs: Registers,
    action: DosAction,
    null: [bool; 2],
) {
    assert!(!regs.carry());
    let DosAction::Execute(request) = action else { panic!("EXEC did not produce a child request") };
    let parent = runtime.dos.psp_segment();
    assert_eq!(runtime.start_child_process(request, host, 0, regs).unwrap(), None);
    let child = runtime.dos.psp_segment();
    assert_ne!(child, parent);
    assert_eq!(runtime.process_frames.len(), 1);
    assert_eq!(runtime.cpu.regs.ds, child);
    assert_eq!((host.opens, host.closes, host.open), (1, 1, false));
    // Check the installed PSP after image loading and child-owner creation,
    // rather than checking only the intermediate DosExecRequest buffers.
    for index in 0..2 {
        let mut expected = [0; 16];
        if !null[index] {
            expected[..12].copy_from_slice(&FCB_INPUTS[index][..12]);
        }
        let mut actual = [0xff; 16];
        runtime.memory.read(real_address(child, 0x5c + index as u16 * 16), &mut actual).unwrap();
        assert_eq!(actual, expected, "child FCB {index}");
    }
    let mut image = [0; 2];
    runtime.memory.read(real_address(child, 0x100), &mut image).unwrap();
    assert_eq!(image, [0xcd, 0x20]);
}

#[test]
fn exec_fcb_real_inputs_clear_both_record_fields_in_child_psp() {
    let (mut runtime, mut host) = fixture();
    let parent = runtime.dos.psp_segment();
    let pointers = [(parent, 0x400), (parent, 0x500)];
    for (index, (segment, offset)) in pointers.into_iter().enumerate() {
        runtime.memory.write(real_address(segment, offset), &FCB_INPUTS[index]).unwrap();
    }
    let (regs, action) = real_exec(&mut runtime, &mut host, pointers);
    assert_child_fcbs(&mut runtime, &mut host, regs, action, [false; 2]);
    for (index, (segment, offset)) in pointers.into_iter().enumerate() {
        let mut original = [0; 16];
        runtime.memory.read(real_address(segment, offset), &mut original).unwrap();
        assert_eq!(original, FCB_INPUTS[index], "caller FCB must remain unchanged");
    }
}

#[test]
fn exec_fcb_real_twelve_byte_prefix_wraps_each_offset_in_child_psp() {
    let (mut runtime, mut host) = fixture();
    let parent = runtime.dos.psp_segment();
    let pointers: [(u16, u16); 2] = [(parent + 0x100, 0xfffa), (parent + 0x200, 0xfffa)];
    for (index, (segment, offset)) in pointers.into_iter().enumerate() {
        // Poison linear continuation so only offset wrap can yield the name.
        runtime.memory.write(PhysAddr(real_address(segment, 0xffff).0 + 1), &[0xee; 10]).unwrap();
        for (delta, byte) in FCB_INPUTS[index].iter().copied().enumerate() {
            runtime.memory.write_u8(real_address(segment, offset.wrapping_add(delta as u16)), byte).unwrap();
        }
    }
    let (regs, action) = real_exec(&mut runtime, &mut host, pointers);
    assert_child_fcbs(&mut runtime, &mut host, regs, action, [false; 2]);
}

#[test]
fn exec_fcb_real_null_pointers_zero_only_the_selected_child_fcbs() {
    for null in [[true, false], [false, true], [true, true]] {
        let (mut runtime, mut host) = fixture();
        let parent = runtime.dos.psp_segment();
        runtime.memory.write(PhysAddr(0), &[0xcc; 16]).unwrap();
        let mut pointers = [(parent, 0x400), (parent, 0x500)];
        for index in 0..2 {
            runtime.memory.write(real_address(pointers[index].0, pointers[index].1), &FCB_INPUTS[index]).unwrap();
            if null[index] { pointers[index] = (0, 0); }
        }
        let (regs, action) = real_exec(&mut runtime, &mut host, pointers);
        assert_child_fcbs(&mut runtime, &mut host, regs, action, null);
    }
}

#[test]
fn exec_fcb_protected_inputs_clear_both_record_fields_in_child_psp() {
    let (mut runtime, mut host) = fixture();
    let (regs, result) = protected_exec(&mut runtime, &mut host, [16; 2], [false; 2]);
    assert_child_fcbs(&mut runtime, &mut host, regs, result.unwrap(), [false; 2]);
}

#[test]
fn exec_fcb_protected_exactly_twelve_read_only_bytes_reach_child_psp() {
    let (mut runtime, mut host) = fixture();
    let (regs, result) = protected_exec(&mut runtime, &mut host, [12; 2], [false; 2]);
    assert_child_fcbs(&mut runtime, &mut host, regs, result.unwrap(), [false; 2]);
}

#[test]
fn exec_fcb_protected_eleven_readable_bytes_reject_either_input_before_child_start() {
    for readable in [[11, 12], [12, 11]] {
        let (mut runtime, mut host) = fixture();
        let parent = runtime.dos.psp_segment();
        let (_, result) = protected_exec(&mut runtime, &mut host, readable, [false; 2]);
        assert!(matches!(result, Err(DosError::CallerAddressSpace {
            kind: DosCallerAddressSpaceFailureKind::InvalidPointer, ..
        })));
        assert_eq!(runtime.dos.psp_segment(), parent);
        assert!(runtime.process_frames.is_empty());
        assert_eq!((host.opens, host.closes, host.open), (0, 0, false));
    }
}

#[test]
fn exec_fcb_protected_null_pointers_zero_only_the_selected_child_fcbs() {
    for null in [[true, false], [false, true], [true, true]] {
        let (mut runtime, mut host) = fixture();
        // A null selector is invalid in this adapter. Successful child startup
        // therefore also proves that absent FCBs never resolve selector zero.
        let (regs, result) = protected_exec(&mut runtime, &mut host, [12; 2], null);
        assert_child_fcbs(&mut runtime, &mut host, regs, result.unwrap(), null);
    }
}
