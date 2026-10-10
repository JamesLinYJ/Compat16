//! Service-gate coverage for the paired GDI rectangle predicate exports.

use super::super::{ImportBinding, module::ProcedureLookup, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingRect, Win16DrawingResult as HostResult, Win16HostDc, Win16HostGdiObject};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use formats::NeImportTarget;
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup,
    Win16ModuleReference, Win16ProcReference, Win16ReturnKind, lookup_export};

const EXPORTS: [(u16, &[u8]); 4] = [
    (104, b"RectVisible"),
    (181, b"RectInRegion"),
    (465, b"RectVisible_EHH"),
    (466, b"RectInRegion_EHH"),
];
const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);
const NATIVE_REGION: Win16HostGdiObject = Win16HostGdiObject(0xfedc_ba98_7654);
const EAX_SENTINEL: u32 = 0xa1b2_a55a;
const EDX_SENTINEL: u32 = 0xc3d4_5aa5;

#[derive(Default)]
struct RectangleHost {
    calls: Vec<Operation>,
    result: Option<HostResult>,
    fail: bool,
}

impl DosHost for RectangleHost {
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

impl RuntimeHost for RectangleHost {
    fn win16_gdi(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
        self.calls.push(operation);
        if self.fail {
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        }
        Ok(self.result.take().expect("test supplies a native result"))
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for RectangleHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for RectangleHost {}
impl crate::RuntimeMidiHost for RectangleHost {}
impl crate::RuntimeNetbiosHost for RectangleHost {}

fn fixture(edges: [i16; 4]) -> (Runtime, u16, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\RECT.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let region = state.guest_gdi.allocate_object(NATIVE_REGION).unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(0x70000), 0x10000,
        AccessRights::read_write(), &runtime.memory).unwrap();
    let pointer = SegmentedPointer::new(selector, 0x24);
    let bytes: Vec<u8> = edges.into_iter().flat_map(i16::to_le_bytes).collect();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    (runtime, dc, region, pointer.far_value())
}

fn read_rect(runtime: &Runtime, far: u32) -> [i16; 4] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = [0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    std::array::from_fn(|i| i16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]))
}

fn handle(ordinal: u16, dc: u16, region: u16) -> u16 {
    match ordinal {
        104 | 465 => dc,
        181 | 466 => region,
        _ => panic!("unexpected rectangle export"),
    }
}

fn expected_operation(ordinal: u16, edges: [i16; 4]) -> Operation {
    let rect = Win16DrawingRect {
        left: i32::from(edges[0]), top: i32::from(edges[1]),
        right: i32::from(edges[2]), bottom: i32::from(edges[3]),
    };
    match ordinal {
        104 | 465 => Operation::RectVisible { dc: NATIVE_DC, rect },
        181 | 466 => Operation::RectInRegion { region: NATIVE_REGION, rect },
        _ => panic!("unexpected rectangle export"),
    }
}

fn prepare(runtime: &mut Runtime, ordinal: u16, name: &[u8], handle: u16, rect: u32)
    -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"GDI", ExportLookupTarget::Name(name)).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("rectangle predicates require a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 6);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    // Physical FAR Pascal frame: return IP:CS, RECT offset:selector, handle.
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&rect.to_le_bytes());
    bytes.extend_from_slice(&handle.to_le_bytes());
    assert_eq!(bytes.len(), 10);
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    (return_cs, return_ip, stack + 10)
}

fn dispatch(runtime: &mut Runtime, host: &mut RectangleHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), success: bool) {
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | u32::from(success));
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
}

#[test]
fn rectangle_exports_forward_signed_coordinates_and_pack_word_results() {
    let edges = [i16::MIN, -123, 456, i16::MAX];
    for (ordinal, name) in EXPORTS {
        for success in [false, true] {
            let (mut runtime, dc, region, rect) = fixture(edges);
            let return_to = prepare(&mut runtime, ordinal, name, handle(ordinal, dc, region), rect);
            let mut host = RectangleHost { result: Some(HostResult::Bool(success)), ..Default::default() };
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None, "GDI.{ordinal}");
            assert_return(&runtime, return_to, success);
            assert_eq!(host.calls, [expected_operation(ordinal, edges)], "GDI.{ordinal}");
            assert_eq!(read_rect(&runtime, rect), edges);
        }
    }
}

#[test]
fn rectangle_exports_forward_empty_and_inverted_rectangles_unchanged() {
    for (ordinal, name) in EXPORTS {
        for edges in [[5, -7, 5, 9], [-8, 4, 12, 4], [12, 9, -8, -7]] {
            let (mut runtime, dc, region, rect) = fixture(edges);
            let return_to = prepare(&mut runtime, ordinal, name, handle(ordinal, dc, region), rect);
            // The host owns the predicate; the bridge must not normalize or reject edges.
            let mut host = RectangleHost { result: Some(HostResult::Bool(true)), ..Default::default() };
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None, "GDI.{ordinal}");
            assert_return(&runtime, return_to, true);
            assert_eq!(host.calls, [expected_operation(ordinal, edges)], "GDI.{ordinal}");
            assert_eq!(read_rect(&runtime, rect), edges);
        }
    }
}

#[test]
fn rectangle_exports_invalid_handles_and_null_rectangles_return_false_without_host_calls() {
    let edges = [-8, -7, 12, 9];
    for (ordinal, name) in EXPORTS {
        let (mut runtime, dc, region, rect) = fixture(edges);
        let valid_handle = handle(ordinal, dc, region);
        let wrong_kind = handle(ordinal, region, dc);
        for (guest_handle, pointer) in [
            (0, rect), (u16::MAX, rect), (wrong_kind, rect),
            (valid_handle, 0), (0, 0),
        ] {
            let return_to = prepare(&mut runtime, ordinal, name, guest_handle, pointer);
            let mut host = RectangleHost::default();
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None, "GDI.{ordinal}");
            assert_return(&runtime, return_to, false);
            assert!(host.calls.is_empty(), "GDI.{ordinal}");
            assert_eq!(read_rect(&runtime, rect), edges);
        }
    }
}

#[test]
fn rectangle_exports_invalid_guest_rectangles_fault_before_host_calls_or_returns() {
    let edges = [-8, -7, 12, 9];
    for (ordinal, name) in EXPORTS {
        for invalid_handle in [false, true] {
            for fault in 0..3 {
                let (mut runtime, dc, region, rect) = fixture(edges);
                let pointer = match fault {
                    0 => 0xffff_0024, // Unmapped selector.
                    1 => (rect & 0xffff_0000) | 0xfffc, // Cannot read eight bytes within the allocation.
                    _ => {
                        let state = runtime.win16.as_mut().unwrap();
                        let short = state.selectors.alloc_block(PhysAddr(0x70000), 7,
                            AccessRights::read_only(), &runtime.memory).unwrap();
                        SegmentedPointer::new(short, 0).far_value()
                    }
                };
                let guest_handle = if invalid_handle { 0 } else { handle(ordinal, dc, region) };
                prepare(&mut runtime, ordinal, name, guest_handle, pointer);
                let gate = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
                let mut host = RectangleHost::default();
                assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault,
                    "GDI.{ordinal}, fault {fault}, invalid handle {invalid_handle}");
                assert!(host.calls.is_empty());
                assert_eq!(runtime.cpu.regs.eax, EAX_SENTINEL);
                assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
                assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), gate);
                assert_eq!(read_rect(&runtime, rect), edges);
            }
        }
    }
}

#[test]
fn rectangle_exports_host_failures_and_wrong_result_types_do_not_publish_success() {
    let edges = [-8, -7, 12, 9];
    for (ordinal, name) in EXPORTS {
        for (result, fail, expected) in [
            (None, true, Kind::HostFailure),
            (Some(HostResult::Mode(1)), false, Kind::InternalInvariant),
        ] {
            let (mut runtime, dc, region, rect) = fixture(edges);
            prepare(&mut runtime, ordinal, name, handle(ordinal, dc, region), rect);
            let gate = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
            let mut host = RectangleHost { result, fail, ..Default::default() };
            assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), expected, "GDI.{ordinal}");
            assert_eq!(host.calls, [expected_operation(ordinal, edges)]);
            assert_eq!(runtime.cpu.regs.eax, EAX_SENTINEL);
            assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
            assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), gate);
            assert_eq!(read_rect(&runtime, rect), edges);
        }
    }
}

#[test]
fn rectangle_exports_named_imports_and_get_proc_address_share_ordinal_gates() {
    for (ordinal, name) in EXPORTS.into_iter().chain([
        (104, b"RectVisibleOld".as_slice()), (181, b"RectInRegionOld".as_slice()),
    ]) {
        let (mut runtime, _, _, _) = fixture([0, 0, 1, 1]);
        let state = runtime.win16.as_mut().unwrap();
        let mut host = RectangleHost::default();
        let module = Win16ModuleReference::Name(b"GDI".to_vec());
        let by_name = state.get_proc_address(&module, &Win16ProcReference::Name(name.to_vec()),
            &mut host).unwrap();
        let ProcedureLookup::Address(far) = by_name else { panic!("callable named export required"); };
        assert_eq!(state.get_proc_address(&module, &Win16ProcReference::Ordinal(ordinal),
            &mut host).unwrap(), by_name);
        let import = state.bind_builtin(b"GDI", &NeImportTarget::Name(name.to_vec()), false)
            .unwrap().expect("named import must be callable");
        assert_eq!(far, (u32::from(import.selector.0) << 16) | u32::from(import.offset));
        let ImportBinding::Supported(descriptor) = &state.bindings[usize::from(import.offset) / 2]
            else { panic!("rectangle import must have a typed binding"); };
        assert_eq!(descriptor.ordinal(), ordinal);
        assert_eq!(descriptor.id, lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap().id);
        assert!(host.calls.is_empty());
    }
}
