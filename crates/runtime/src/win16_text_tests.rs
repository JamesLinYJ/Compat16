//! Bounded AnsiNext reads, selector ownership, and both Win16 service gates.

use super::{probe_next_character, super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}}};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16AnsiNextProbe as Probe};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup,
    Win16ReturnKind, lookup_export};

#[derive(Default)]
struct ProbeHost {
    utf8: bool,
    probes: Vec<Vec<u8>>,
}

impl DosHost for ProbeHost {
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

impl RuntimeHost for ProbeHost {
    fn win16_ansi_next_probe(&mut self, source: &[u8]) -> Result<Probe, RuntimeError> {
        self.probes.push(source.to_vec());
        model_probe(self.utf8, source)
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for ProbeHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for ProbeHost {}
impl crate::RuntimeMidiHost for ProbeHost {}
impl crate::RuntimeNetbiosHost for ProbeHost {}

// This host model isolates the runtime byte-transfer contract. Actual code
// pages and conversion behavior are covered by the native host tests.
fn model_probe(utf8: bool, source: &[u8]) -> Result<Probe, RuntimeError> {
    if utf8 {
        return match std::str::from_utf8(source) {
            Ok(text) => Ok(Probe::Complete(text.chars().next().unwrap().len_utf8())),
            Err(error) if error.error_len().is_none() => Ok(Probe::NeedMore),
            Err(_) => Err(RuntimeError::new(Kind::InvalidInput, "invalid first test character")),
        };
    }
    Ok(if matches!(source[0], 0x81..=0x9f | 0xe0..=0xfc) {
        match source.get(1) {
            None => Probe::NeedMore,
            Some(0) => Probe::Complete(1),
            Some(_) => Probe::Complete(2),
        }
    } else { Probe::Complete(1) })
}

const BASE: u32 = 0x80000;
const AX_SENTINEL: u16 = 0xa55a;
const DX_SENTINEL: u16 = 0x5aa5;
const EXPORTS: [(&[u8], u16); 2] = [(b"USER", 472), (b"KERNEL", 77)];

fn fixture(bytes: &[u8], rights: AccessRights) -> (Runtime, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TEXT.NE").unwrap();
    runtime.memory.write_physical(PhysAddr(BASE), bytes).unwrap();
    let selector = runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(BASE), bytes.len() as u32, rights, &runtime.memory).unwrap();
    (runtime, SegmentedPointer::new(selector, 0).far_value())
}

fn prepare(runtime: &mut Runtime, export: (&[u8], u16), pointer: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(export.0, ExportLookupTarget::Ordinal(export.1)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::FarPointer);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("AnsiNext must use a fixed Pascal frame");
    };
    assert_eq!((cleanup.callee_pop_bytes, cleanup.caller_pop_bytes), (4, 0));
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(&pointer.to_le_bytes());
    let stack_pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, stack_pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX_SENTINEL);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    (return_cs, return_ip, stack + 8)
}

fn dispatch(runtime: &mut Runtime, host: &mut impl RuntimeHost) -> Result<u32, RuntimeError> {
    assert_eq!(runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )?, None);
    Ok((u32::from(runtime.cpu.regs.dx()) << 16) | u32::from(runtime.cpu.regs.ax()))
}

#[test]
fn ansi_next_service_gates_read_only_the_first_character() {
    for export in EXPORTS {
        for (source, offset, expected_probes) in [
            (&[b'A', 0xff][..], 1, vec![vec![b'A']]),
            (&[0x81, b'A', 0][..], 2, vec![vec![0x81], vec![0x81, b'A']]),
            (&[0x81, 0x81, 0][..], 2, vec![vec![0x81], vec![0x81, 0x81]]),
            (&[0x81, 0][..], 1, vec![vec![0x81], vec![0x81, 0]]),
        ] {
            let (mut runtime, pointer) = fixture(source, AccessRights::read_only());
            let return_to = prepare(&mut runtime, export, pointer);
            let mut host = ProbeHost::default();
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), pointer + offset);
            assert_eq!(host.probes, expected_probes);
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
            let mut unchanged = vec![0; source.len()];
            runtime.memory.read_physical(PhysAddr(BASE), &mut unchanged).unwrap();
            assert_eq!(unchanged, source);
        }
    }
}

#[test]
fn ansi_next_nul_at_allocation_end_returns_exact_pointer_without_host() {
    for export in EXPORTS {
        let (mut runtime, pointer) = fixture(&[0], AccessRights::read_only());
        let pointer = pointer | (7 << 16);
        prepare(&mut runtime, export, pointer);
        assert_eq!(dispatch(&mut runtime, &mut NoHost).unwrap(), pointer);
    }
}

#[test]
fn ansi_next_preserves_alias_and_every_original_selector_bit() {
    for export in EXPORTS {
        for bits in 0..8 {
            let (mut runtime, original) = fixture(b"A\0", AccessRights::read_only());
            let alias = runtime.win16.as_mut().unwrap().selectors
                .alloc_block(PhysAddr(BASE), 2, AccessRights::read_only(), &runtime.memory).unwrap();
            let pointer = SegmentedPointer::new(alias, 0).far_value() | (bits << 16);
            assert_ne!(pointer >> 19, original >> 19);
            prepare(&mut runtime, export, pointer);
            assert_eq!(dispatch(&mut runtime, &mut ProbeHost::default()).unwrap(), pointer + 1);
        }
    }
}

#[test]
fn ansi_next_crosses_only_descriptors_in_the_owned_block() {
    for export in EXPORTS {
        let mut bytes = vec![0; 0x10002];
        bytes[0xffff] = 0x81;
        bytes[0x10000] = 0x40;
        let (mut runtime, pointer) = fixture(&bytes, AccessRights::read_only());
        let pointer = pointer | 0xffff | (7 << 16);
        let state = runtime.win16.as_ref().unwrap();
        let start = state.selectors.pointer_from_far(pointer).unwrap();
        let expected = state.selectors.add_bytes(start, 2).unwrap().far_value();
        prepare(&mut runtime, export, pointer);
        let mut host = ProbeHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), expected);
        assert_eq!(host.probes, [vec![0x81], vec![0x81, 0x40]]);
    }
}

#[test]
fn ansi_next_rejects_adjacent_unrelated_allocation() {
    for export in EXPORTS {
        let mut bytes = vec![0; 0x10000];
        bytes[0xffff] = 0x81;
        let (mut runtime, pointer) = fixture(&bytes, AccessRights::read_only());
        runtime.memory.write_physical(PhysAddr(BASE + 0x10000), &[0x40, 0]).unwrap();
        runtime.win16.as_mut().unwrap().selectors.alloc_block(
            PhysAddr(BASE + 0x10000), 2, AccessRights::read_only(), &runtime.memory,
        ).unwrap();
        prepare(&mut runtime, export, pointer | 0xffff);
        let mut host = ProbeHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(host.probes, [vec![0x81]]);
        assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX_SENTINEL, DX_SENTINEL));
    }
}

#[test]
fn ansi_next_rejects_missing_bytes_and_unbacked_result() {
    for export in EXPORTS {
        // The first case needs an unavailable trail; the others have a
        // complete character but no backed next position. No implicit NUL.
        for source in [&[0x81][..], &[b'A'], &[0x81, 0x40]] {
            let (mut runtime, pointer) = fixture(source, AccessRights::read_only());
            prepare(&mut runtime, export, pointer);
            let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
            assert_eq!(dispatch(&mut runtime, &mut ProbeHost::default()).unwrap_err().kind(), Kind::GuestFault);
            assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX_SENTINEL, DX_SENTINEL));
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
        }
    }
}

#[test]
fn ansi_next_rejects_null_freed_and_unreadable_selectors_without_host() {
    for export in EXPORTS {
        for case in 0..3 {
            let rights = if case == 2 { AccessRights::new(false, false, true) }
                else { AccessRights::read_only() };
            let (mut runtime, mut pointer) = fixture(b"A\0", rights);
            if case == 0 { pointer = 0; }
            if case == 1 {
                let state = runtime.win16.as_mut().unwrap();
                let selector = state.selectors.pointer_from_far(pointer).unwrap().selector();
                state.selectors.free_block(selector).unwrap();
            }
            prepare(&mut runtime, export, pointer);
            assert_eq!(dispatch(&mut runtime, &mut NoHost).unwrap_err().kind(), Kind::GuestFault);
        }
    }
}

#[test]
fn ansi_next_utf8_distinguishes_first_and_later_invalid_bytes() {
    for export in EXPORTS {
        let (mut runtime, pointer) = fixture(&[b'A', 0xff, 0], AccessRights::read_only());
        let mut host = ProbeHost { utf8: true, ..Default::default() };
        prepare(&mut runtime, export, pointer);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), pointer + 1);
        assert_eq!(host.probes, [vec![b'A']]);
        prepare(&mut runtime, export, pointer + 1);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InvalidInput);
        for source in [&[0xf0, 0x9f, 0x99, 0x82, 0][..], &[0xe2, 0x82, 0xac, 0], &[0xc2, 0xa2, 0]] {
            let (mut runtime, pointer) = fixture(source, AccessRights::read_only());
            prepare(&mut runtime, export, pointer);
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), pointer + source.len() as u32 - 1);
        }
        let (mut runtime, pointer) = fixture(&[0xf0, 0x9f], AccessRights::read_only());
        prepare(&mut runtime, export, pointer);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
    }
}

#[test]
fn ansi_next_default_host_is_explicitly_unsupported() {
    let (mut runtime, pointer) = fixture(b"A\0", AccessRights::read_only());
    prepare(&mut runtime, EXPORTS[0], pointer);
    assert_eq!(dispatch(&mut runtime, &mut NoHost).unwrap_err().kind(), Kind::CompatibilityGap);
}

#[test]
fn ansi_next_probe_rejects_invalid_host_progress_and_offsets() {
    for (bytes, reply, expected_reads) in [
        (&[b'A'][..], Probe::Complete(0), 1),
        (&[b'A'][..], Probe::Complete(2), 1),
        (&[0x81, 0][..], Probe::NeedMore, 2),
        (&[1, 2, 3, 4][..], Probe::NeedMore, 4),
    ] {
        let mut reads = 0;
        let result = probe_next_character(|offset| {
            reads += 1;
            Ok(bytes[offset])
        }, |_| Ok(reply));
        assert_eq!(result.unwrap_err().kind(), Kind::InternalInvariant);
        assert_eq!(reads, expected_reads);
    }
    // A dishonest complete result cannot advance past an observed NUL.
    assert_eq!(probe_next_character(|offset| Ok([0x81, 0][offset]), |source| {
        Ok(if source.len() == 1 { Probe::NeedMore } else { Probe::Complete(2) })
    }).unwrap_err().kind(), Kind::InternalInvariant);
}

#[test]
fn ansi_next_walk_probe_bytes_scale_linearly() {
    for (utf8, character) in [(false, &b"A"[..]), (false, &[0x81, 0x40][..]),
        (true, &[0xf0, 0x9f, 0x99, 0x82][..])]
    {
        for count in [4096, 8192] {
            let mut bytes = character.repeat(count);
            bytes.push(0);
            let (runtime, mut pointer) = fixture(&bytes, AccessRights::read_only());
            let mut host = ProbeHost { utf8, ..Default::default() };
            let state = runtime.win16.as_ref().unwrap();
            for _ in 0..count {
                pointer = state.ansi_next(pointer, &runtime.memory, &mut host).unwrap();
            }
            assert_eq!(state.ansi_next(pointer, &runtime.memory, &mut host).unwrap(), pointer);
            let width = character.len();
            assert_eq!(host.probes.len(), count * width);
            assert_eq!(host.probes.iter().map(Vec::len).sum::<usize>(), count * width * (width + 1) / 2);
            assert!(host.probes.iter().all(|prefix| prefix.len() <= 4));
        }
    }
}

#[test]
fn ansi_next_walk_guest_byte_reads_scale_linearly() {
    for (utf8, character) in [(false, &b"A"[..]), (false, &[0x81, 0x40][..]),
        (true, &[0xf0, 0x9f, 0x99, 0x82][..])]
    {
        for count in [4096, 8192] {
            let mut source = character.repeat(count);
            source.push(0);
            let mut current = 0;
            let mut reads = 0;
            loop {
                let next = probe_next_character(|offset| {
                    reads += 1;
                    Ok(source[current + offset])
                }, |prefix| model_probe(utf8, prefix)).unwrap();
                if next == 0 { break; }
                current += next;
            }
            assert_eq!(current, count * character.len());
            assert_eq!(reads, count * character.len() + 1);
        }
    }
}
