//! Full service-gate coverage for the direct GDI brush factories.

use super::*;
use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{Runtime, Win16HostGdiObject};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, Win16ReturnKind, Win16ExportStackCleanup, lookup_export};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

#[derive(Default)]
struct BrushHost {
    calls: Vec<Operation>,
    result: Option<Win16HostGdiObject>,
    deleted: Vec<Win16HostGdiObject>,
}

impl DosHost for BrushHost {
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

impl RuntimeHost for BrushHost {
    fn win16_create_gdi_object(&mut self, operation: Operation) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        self.calls.push(operation);
        Ok(self.result)
    }
    fn win16_delete_object(&mut self, object: Win16HostGdiObject) -> Result<bool, RuntimeError> {
        self.deleted.push(object);
        Ok(true)
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for BrushHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for BrushHost {}
impl crate::RuntimeMidiHost for BrushHost {}
impl crate::RuntimeNetbiosHost for BrushHost {}


fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\BRUSH.NE").unwrap()
}

// Supply bytes in physical Pascal stack order, after the FAR return address.
fn call(runtime: &mut Runtime, host: &mut BrushHost, ordinal: u16, name: &[u8], args: &[u8]) -> u16 {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"GDI", ExportLookupTarget::Name(name)).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("brush factories require a fixed Pascal frame");
    };
    assert_eq!(usize::from(cleanup.callee_pop_bytes), args.len());
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(args);
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0).unwrap(), None);
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + bytes.len() as u16));
    runtime.cpu.regs.ax()
}

#[test]
fn brush_exports_preserve_hatch_color_and_owned_return_handles() {
    for hatch in 0_u16..=5 {
        let mut runtime = fixture();
        let token = Win16HostGdiObject(0x1234_5678_9abc);
        let mut host = BrushHost { result: Some(token), ..Default::default() };
        let color = 0x0234_5678_u32; // Keep palette/COLORREF high bits too.
        let mut args = color.to_le_bytes().to_vec();
        args.extend_from_slice(&hatch.to_le_bytes());
        let brush = call(&mut runtime, &mut host, 58, b"CreateHatchBrush", &args);
        assert_ne!(brush, 0);
        assert_eq!(host.calls, vec![Operation::CreateBrushIndirect {
            logbrush: Win16HostLogBrush { style: 2, color, hatch: u32::from(hatch) },
            pattern_bitmap: None, dib_pattern: None,
        }]);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.guest_gdi.object(brush), Some(token));
        assert_eq!(state.delete_object(brush, &mut runtime.memory, &mut host).unwrap(), 1);
        assert_eq!(state.guest_gdi.object(brush), None);
        assert_eq!(host.deleted, vec![token]);
    }
}

#[test]
fn brush_exports_translate_pattern_handle_and_propagate_host_failure() {
    for result in [None, Some(Win16HostGdiObject(0x1234_5678_9abc))] {
        let mut runtime = fixture();
        let bitmap = Win16HostGdiObject(0xfedc_ba98_7654);
        let guest_bitmap = runtime.win16.as_mut().unwrap().guest_gdi.allocate_object(bitmap).unwrap();
        let mut host = BrushHost { result, ..Default::default() };
        let brush = call(&mut runtime, &mut host, 60, b"CreatePatternBrush", &guest_bitmap.to_le_bytes());
        assert_eq!(host.calls, vec![Operation::CreateBrushIndirect {
            logbrush: Win16HostLogBrush { style: 3, color: 0, hatch: u32::from(guest_bitmap) },
            pattern_bitmap: Some(bitmap), dib_pattern: None,
        }]);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.guest_gdi.object(brush), result);
        if result.is_some() {
            assert_ne!(brush, guest_bitmap);
            assert_eq!(state.delete_object(brush, &mut runtime.memory, &mut host).unwrap(), 1);
        } else {
            assert_eq!(brush, 0);
        }
        assert_eq!(state.guest_gdi.object(guest_bitmap), Some(bitmap));
    }
}

fn packed_dib() -> Vec<u8> {
    let mut dib = vec![0; 44];
    dib[..4].copy_from_slice(&40_u32.to_le_bytes());
    dib[4..8].copy_from_slice(&1_i32.to_le_bytes());
    dib[8..12].copy_from_slice(&1_i32.to_le_bytes());
    dib[12..14].copy_from_slice(&1_u16.to_le_bytes());
    dib[14..16].copy_from_slice(&24_u16.to_le_bytes());
    dib[40..].copy_from_slice(&[0x12, 0x34, 0x56, 0]);
    dib
}

fn allocate_dib(runtime: &mut Runtime, host: &mut BrushHost, bytes: &[u8]) -> u16 {
    let state = runtime.win16.as_mut().unwrap();
    let handle = state.global_alloc(0x0002, bytes.len() as u32, &mut runtime.memory, host).unwrap();
    assert_ne!(handle, 0);
    let far = state.global_lock(handle, &runtime.memory).unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
    state.global_unlock(handle).unwrap();
    handle
}

#[test]
fn brush_exports_snapshot_dib_and_release_global_lock() {
    let mut runtime = fixture();
    let mut host = BrushHost { result: Some(Win16HostGdiObject(0x1234_5678)), ..Default::default() };
    let dib = packed_dib();
    let handle = allocate_dib(&mut runtime, &mut host, &dib);
    let mut args = 0_u16.to_le_bytes().to_vec();
    args.extend_from_slice(&handle.to_le_bytes());
    assert_ne!(call(&mut runtime, &mut host, 445, b"CreateDIBPatternBrush", &args), 0);
    // Freeing guest storage must not invalidate the host request's snapshot.
    assert_eq!(runtime.win16.as_mut().unwrap().global_free(handle).unwrap(), 0);
    assert_eq!(host.calls, vec![Operation::CreateBrushIndirect {
        logbrush: Win16HostLogBrush { style: 5, color: 0, hatch: u32::from(handle) },
        pattern_bitmap: None,
        dib_pattern: Some(Win16HostDib { info: dib[..40].to_vec(), bits: dib[40..].to_vec() }),
    }]);
}

#[test]
fn brush_exports_reject_invalid_scalars_and_handles_before_host_call() {
    for (ordinal, name, args) in [
        (58, b"CreateHatchBrush".as_slice(), vec![0, 0, 0, 0, 6, 0]),
        (58, b"CreateHatchBrush".as_slice(), vec![0, 0, 0, 0, 255, 255]),
        (60, b"CreatePatternBrush".as_slice(), vec![0, 0]),
        (60, b"CreatePatternBrush".as_slice(), vec![255, 255]),
        (445, b"CreateDIBPatternBrush".as_slice(), vec![0, 0, 255, 255]),
    ] {
        let mut runtime = fixture();
        let mut host = BrushHost::default();
        assert_eq!(call(&mut runtime, &mut host, ordinal, name, &args), 0);
        assert!(host.calls.is_empty());
    }
}

#[test]
fn brush_exports_reject_truncated_dib_and_invalid_color_usage() {
    for (length, usage) in [(39, 0_u16), (43, 0), (44, 2)] {
        let mut runtime = fixture();
        let mut host = BrushHost::default();
        let handle = allocate_dib(&mut runtime, &mut host, &packed_dib()[..length]);
        let mut args = usage.to_le_bytes().to_vec();
        args.extend_from_slice(&handle.to_le_bytes());
        assert_eq!(call(&mut runtime, &mut host, 445, b"CreateDIBPatternBrush", &args), 0);
        assert!(host.calls.is_empty());
        assert_eq!(runtime.win16.as_mut().unwrap().global_free(handle).unwrap(), 0);
    }
}

#[test]
fn brush_exports_reject_unsupported_indirect_pointer_styles() {
    for style in [4, 6, 7, 8, 9, u16::MAX] {
        let mut runtime = fixture();
        let mut host = BrushHost::default();
        let state = runtime.win16.as_mut().unwrap();
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x10).unwrap();
        let logbrush = LogBrush16 { style, color: 0, hatch: -1 };
        state.selectors.write(&mut runtime.memory, pointer, &logbrush.encode()).unwrap();
        let far = pointer.far_value();
        assert_eq!(call(&mut runtime, &mut host, 50, b"CreateBrushIndirect", &far.to_le_bytes()), 0);
        assert!(host.calls.is_empty());
    }
}
