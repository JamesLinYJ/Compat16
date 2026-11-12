//! Guest-visible palette returns for the Win16 GDI and USER exports.

use std::collections::VecDeque;

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation,
    Win16DrawingResult, Win16GdiDeviceOperation, Win16GdiDeviceResult, Win16HostDc,
    Win16HostGdiObject, Win16PaletteTransferKind,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);
const PALETTE: Win16HostGdiObject = Win16HostGdiObject(0x1111_2222_3333);
const PREVIOUS: Win16HostGdiObject = Win16HostGdiObject(0x4444_5555_6666);
const LOGPALETTE: u16 = 0x20;
const OUTPUT: u16 = 0x60;

struct Host {
    device: Vec<Win16GdiDeviceOperation>,
    drawing: Vec<Win16DrawingOperation>,
    device_results: VecDeque<Win16GdiDeviceResult>,
    color: u32,
}

impl DosHost for Host {
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
        panic!("unexpected host call")
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

impl RuntimeHost for Host {
    fn win16_gdi(
        &mut self,
        operation: Win16DrawingOperation,
    ) -> Result<Win16DrawingResult, RuntimeError> {
        self.drawing.push(operation);
        Ok(Win16DrawingResult::Color(self.color))
    }

    fn win16_gdi_device(
        &mut self,
        operation: Win16GdiDeviceOperation,
    ) -> Result<Win16GdiDeviceResult, RuntimeError> {
        self.device.push(operation);
        Ok(self
            .device_results
            .pop_front()
            .expect("palette host result"))
    }

    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}

impl crate::RuntimeDdeHost for Host {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for Host {}
impl crate::RuntimeMidiHost for Host {}
impl crate::RuntimeNetbiosHost for Host {}

fn loaded() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\PAL.NE").unwrap()
}

fn far(runtime: &Runtime, offset: u16) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(offset)
}

fn write_bytes(runtime: &mut Runtime, offset: u16, bytes: &[u8]) {
    let far = far(runtime, offset);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
}

fn read_bytes(runtime: &Runtime, offset: u16, len: usize) -> Vec<u8> {
    let far = far(runtime, offset);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; len];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn dc_and_palette(runtime: &mut Runtime) -> (u16, u16) {
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let palette = state.guest_gdi.allocate_object(PALETTE).unwrap();
    (dc, palette)
}

/// Pascal arguments are stored last-parameter-first after the far return.
fn call(
    runtime: &mut Runtime,
    host: &mut Host,
    module: &[u8],
    ordinal: u16,
    name: &[u8],
    return_kind: Win16ReturnKind,
    physical_args: &[u8],
) -> Result<(), RuntimeError> {
    let descriptor = lookup_export(module, ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(
        descriptor.id,
        lookup_export(module, ExportLookupTarget::Name(name))
            .unwrap()
            .id
    );
    assert_eq!(descriptor.return_kind, return_kind);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("{name:?} requires a fixed Pascal frame");
    };
    assert_eq!(usize::from(cleanup.callee_pop_bytes), physical_args.len());
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(physical_args);
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    let result = state.dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    );
    if result.is_ok() {
        assert_eq!(
            (
                runtime.cpu.regs.cs,
                runtime.cpu.regs.ip(),
                runtime.cpu.regs.sp()
            ),
            (return_cs, return_ip, stack + bytes.len() as u16)
        );
        if matches!(return_kind, Win16ReturnKind::Word) {
            assert_eq!(runtime.cpu.regs.dx(), DX);
        }
    }
    result.map(|_| ())
}

fn word(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn dword(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn args(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .rev()
        .flat_map(|part| part.iter().copied())
        .collect()
}

#[test]
fn create_palette_keeps_version_0x0300_and_rejects_any_other() {
    let mut runtime = loaded();
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::new(),
        color: 0,
    };
    let mut log = 0x0200_u16.to_le_bytes().to_vec();
    log.extend_from_slice(&1_u16.to_le_bytes());
    log.extend_from_slice(&[9, 8, 7, 1]);
    write_bytes(&mut runtime, LOGPALETTE, &log);
    let log_far = far(&runtime, LOGPALETTE);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        360,
        b"CreatePalette",
        Win16ReturnKind::Word,
        &dword(log_far),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert!(host.device.is_empty());

    log[..2].copy_from_slice(&0x0300_u16.to_le_bytes());
    write_bytes(&mut runtime, LOGPALETTE, &log);
    host.device_results
        .push_back(Win16GdiDeviceResult::Object(Some(PALETTE)));
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        360,
        b"CreatePalette",
        Win16ReturnKind::Word,
        &dword(log_far),
    )
    .unwrap();
    let handle = runtime.cpu.regs.ax();
    assert_ne!(handle, 0);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::CreatePalette {
            version: 0x0300,
            entries: vec![[9, 8, 7, 1]],
        }]
    );
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.object(handle),
        Some(PALETTE)
    );
}

#[test]
fn select_palette_treats_any_nonzero_flag_as_background_and_reuses_handles() {
    let mut runtime = loaded();
    let (dc, palette) = dc_and_palette(&mut runtime);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([
            Win16GdiDeviceResult::Object(Some(PREVIOUS)),
            Win16GdiDeviceResult::Object(Some(PREVIOUS)),
        ]),
        color: 0,
    };
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        361,
        b"GDISelectPalette",
        Win16ReturnKind::Word,
        &args(&[&word(dc), &word(palette), &word(2)]),
    )
    .unwrap();
    let previous = runtime.cpu.regs.ax();
    assert_ne!(previous, 0);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::SelectPalette {
            dc: NATIVE_DC,
            palette: PALETTE,
            force_background: true,
        }]
    );

    host.device.clear();
    call(
        &mut runtime,
        &mut host,
        b"USER",
        282,
        b"SelectPalette",
        Win16ReturnKind::Word,
        &args(&[&word(dc), &word(palette), &word(0)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), previous);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::SelectPalette {
            dc: NATIVE_DC,
            palette: PALETTE,
            force_background: false,
        }]
    );

    host.device.clear();
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        361,
        b"GDISelectPalette",
        Win16ReturnKind::Word,
        &args(&[&word(0), &word(palette), &word(1)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert!(host.device.is_empty());
}

#[test]
fn realize_palette_returns_zero_for_gdi_error_and_a_count_that_does_not_fit() {
    let mut runtime = loaded();
    let (dc, _) = dc_and_palette(&mut runtime);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([
            Win16GdiDeviceResult::Count(20),
            Win16GdiDeviceResult::Count(-1),
            Win16GdiDeviceResult::Count(70_000),
        ]),
        color: 0,
    };
    for (ordinal, module, name) in [
        (362_u16, &b"GDI"[..], &b"GDIRealizePalette"[..]),
        (283, b"USER", b"RealizePalette"),
    ] {
        host.device.clear();
        let result = if ordinal == 362 { 20 } else { 0 };
        call(
            &mut runtime,
            &mut host,
            module,
            ordinal,
            name,
            Win16ReturnKind::Word,
            &word(dc),
        )
        .unwrap();
        assert_eq!(runtime.cpu.regs.ax(), result);
        assert_eq!(
            host.device,
            [Win16GdiDeviceOperation::RealizePalette { dc: NATIVE_DC }]
        );
    }
    host.device.clear();
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        365,
        b"RealizeDefaultPalette",
        Win16ReturnKind::Word,
        &word(dc),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::RealizeDefaultPalette { dc: NATIVE_DC }]
    );
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        362,
        b"GDIRealizePalette",
        Win16ReturnKind::Word,
        &word(0),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(host.device.len(), 1);
}

#[test]
fn palette_entry_queries_leave_unretrieved_bytes_and_report_the_length() {
    let mut runtime = loaded();
    let (_, palette) = dc_and_palette(&mut runtime);
    let output = far(&runtime, OUTPUT);
    write_bytes(&mut runtime, OUTPUT, &[0xa5; 12]);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([
            Win16GdiDeviceResult::PaletteEntries {
                count: 4,
                entries: Vec::new(),
            },
            Win16GdiDeviceResult::PaletteEntries {
                count: 4,
                entries: Vec::new(),
            },
            Win16GdiDeviceResult::PaletteEntries {
                count: 1,
                entries: vec![[1, 2, 3, 4], [0, 0, 0, 0], [0, 0, 0, 0]],
            },
            Win16GdiDeviceResult::PaletteEntries {
                count: 0,
                entries: Vec::new(),
            },
        ]),
        color: 0,
    };

    call(
        &mut runtime,
        &mut host,
        b"GDI",
        363,
        b"GetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(0), &word(0), &dword(u32::MAX)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 4);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette: PALETTE,
            start: 0,
            count: 0,
            entries: None,
        }]
    );

    host.device.clear();
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        363,
        b"GetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(1), &word(3), &dword(0)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 4);
    assert_eq!(
        host.device[0],
        Win16GdiDeviceOperation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette: PALETTE,
            start: 1,
            count: 0,
            entries: None,
        }
    );
    assert_eq!(read_bytes(&runtime, OUTPUT, 12), vec![0xa5; 12]);

    host.device.clear();
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        363,
        b"GetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(0), &word(3), &dword(output)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 1);
    assert_eq!(
        read_bytes(&runtime, OUTPUT, 12),
        [1, 2, 3, 4, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]
    );

    write_bytes(&mut runtime, OUTPUT, &[0xa5; 12]);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        363,
        b"GetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(0), &word(3), &dword(output)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(read_bytes(&runtime, OUTPUT, 12), vec![0xa5; 12]);

    host.device.clear();
    host.device_results
        .push_back(Win16GdiDeviceResult::PaletteEntries {
            count: 4,
            entries: vec![[1, 2, 3, 4]; 4],
        });
    let error = call(
        &mut runtime,
        &mut host,
        b"GDI",
        363,
        b"GetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(0), &word(3), &dword(output)]),
    )
    .unwrap_err();
    assert_eq!(error.kind(), Kind::InternalInvariant);
    assert_eq!(read_bytes(&runtime, OUTPUT, 12), vec![0xa5; 12]);

    host.device.clear();
    let error = call(
        &mut runtime,
        &mut host,
        b"GDI",
        363,
        b"GetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(0), &word(1), &dword(u32::MAX)]),
    )
    .unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    assert!(host.device.is_empty());
}

#[test]
fn set_palette_entries_returns_zero_unless_the_count_fits_the_request() {
    let mut runtime = loaded();
    let (_, palette) = dc_and_palette(&mut runtime);
    write_bytes(&mut runtime, LOGPALETTE, &[4, 5, 6, 7, 8, 9, 10, 11]);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([
            Win16GdiDeviceResult::Count(2),
            Win16GdiDeviceResult::Count(3),
            Win16GdiDeviceResult::Count(-1),
        ]),
        color: 0,
    };
    let pointer = far(&runtime, LOGPALETTE);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        364,
        b"SetPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(1), &word(2), &dword(pointer)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 2);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::PaletteEntries {
            kind: Win16PaletteTransferKind::Set,
            palette: PALETTE,
            start: 1,
            count: 2,
            entries: Some(vec![[4, 5, 6, 7], [8, 9, 10, 11]]),
        }]
    );
    assert_eq!(
        read_bytes(&runtime, LOGPALETTE, 8),
        [4, 5, 6, 7, 8, 9, 10, 11]
    );

    for expected in [0, 0] {
        call(
            &mut runtime,
            &mut host,
            b"GDI",
            364,
            b"SetPaletteEntries",
            Win16ReturnKind::Word,
            &args(&[&word(palette), &word(1), &word(2), &dword(pointer)]),
        )
        .unwrap();
        assert_eq!(runtime.cpu.regs.ax(), expected);
    }
}

#[test]
fn animate_palette_is_void_and_does_not_publish_the_host_bool() {
    let mut runtime = loaded();
    let (_, palette) = dc_and_palette(&mut runtime);
    write_bytes(&mut runtime, LOGPALETTE, &[1, 2, 3, 0x01]);
    let log_far = far(&runtime, LOGPALETTE);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([Win16GdiDeviceResult::Count(1)]),
        color: 0,
    };
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        367,
        b"AnimatePalette",
        Win16ReturnKind::Void,
        &args(&[&word(palette), &word(0), &word(1), &dword(log_far)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), AX);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::PaletteEntries {
            kind: Win16PaletteTransferKind::Animate,
            palette: PALETTE,
            start: 0,
            count: 1,
            entries: Some(vec![[1, 2, 3, 0x01]]),
        }]
    );
}

#[test]
fn resize_update_unrealize_and_nearest_index_use_documented_failures() {
    let mut runtime = loaded();
    let (dc, palette) = dc_and_palette(&mut runtime);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([
            Win16GdiDeviceResult::Bool(true),
            Win16GdiDeviceResult::Bool(true),
            Win16GdiDeviceResult::Bool(true),
            Win16GdiDeviceResult::Count(4),
            Win16GdiDeviceResult::Count(-1),
            Win16GdiDeviceResult::Count(70_000),
        ]),
        color: 0,
    };
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        368,
        b"ResizePalette",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &word(8)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 1);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        368,
        b"ResizePalette",
        Win16ReturnKind::Word,
        &args(&[&word(0), &word(8)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);

    call(
        &mut runtime,
        &mut host,
        b"GDI",
        366,
        b"UpdateColors",
        Win16ReturnKind::Word,
        &word(dc),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 1);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        366,
        b"UpdateColors",
        Win16ReturnKind::Word,
        &word(0),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);

    call(
        &mut runtime,
        &mut host,
        b"GDI",
        150,
        b"UnrealizeObject",
        Win16ReturnKind::Word,
        &word(palette),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 1);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        150,
        b"UnrealizeObject",
        Win16ReturnKind::Word,
        &word(0),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);

    call(
        &mut runtime,
        &mut host,
        b"GDI",
        370,
        b"GetNearestPaletteIndex",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &dword(0x0001_0203)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 4);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        370,
        b"GetNearestPaletteIndex",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &dword(0)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), u16::MAX);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        370,
        b"GetNearestPaletteIndex",
        Win16ReturnKind::Word,
        &args(&[&word(0), &dword(0)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), u16::MAX);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        370,
        b"GetNearestPaletteIndex",
        Win16ReturnKind::Word,
        &args(&[&word(palette), &dword(1)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), u16::MAX);
}

#[test]
fn system_palette_queries_match_logical_palette_output_rules() {
    let mut runtime = loaded();
    let (dc, _) = dc_and_palette(&mut runtime);
    write_bytes(&mut runtime, OUTPUT, &[0xa5; 8]);
    let output = far(&runtime, OUTPUT);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::from([
            Win16GdiDeviceResult::PaletteEntries {
                count: 256,
                entries: Vec::new(),
            },
            Win16GdiDeviceResult::PaletteEntries {
                count: 1,
                entries: vec![[9, 8, 7, 0]],
            },
            Win16GdiDeviceResult::PaletteEntries {
                count: -1,
                entries: Vec::new(),
            },
        ]),
        color: 0,
    };
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        375,
        b"GetSystemPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(dc), &word(0), &word(0), &dword(u32::MAX)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 256);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::GetSystemPaletteEntries {
            dc: NATIVE_DC,
            start: 0,
            count: 0,
        }]
    );

    call(
        &mut runtime,
        &mut host,
        b"GDI",
        375,
        b"GetSystemPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(dc), &word(2), &word(2), &dword(output)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 1);
    assert_eq!(
        read_bytes(&runtime, OUTPUT, 8),
        [9, 8, 7, 0, 0xa5, 0xa5, 0xa5, 0xa5]
    );

    write_bytes(&mut runtime, OUTPUT, &[0xa5; 8]);
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        375,
        b"GetSystemPaletteEntries",
        Win16ReturnKind::Word,
        &args(&[&word(dc), &word(0), &word(0), &dword(output)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(read_bytes(&runtime, OUTPUT, 8), vec![0xa5; 8]);
}

#[test]
fn get_nearest_color_returns_clr_invalid_for_an_unknown_dc() {
    let mut runtime = loaded();
    let (dc, _) = dc_and_palette(&mut runtime);
    let mut host = Host {
        device: Vec::new(),
        drawing: Vec::new(),
        device_results: VecDeque::new(),
        color: 0x00aa_bbcc,
    };
    call(
        &mut runtime,
        &mut host,
        b"GDI",
        154,
        b"GetNearestColor",
        Win16ReturnKind::Dword,
        &args(&[&word(0), &dword(0x0011_2233)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0xffff);
    assert_eq!(runtime.cpu.regs.dx(), 0xffff);
    assert!(host.drawing.is_empty());

    call(
        &mut runtime,
        &mut host,
        b"GDI",
        154,
        b"GetNearestColor",
        Win16ReturnKind::Dword,
        &args(&[&word(dc), &dword(0x0011_2233)]),
    )
    .unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0xbbcc);
    assert_eq!(runtime.cpu.regs.dx(), 0x00aa);
    assert_eq!(
        host.drawing,
        [Win16DrawingOperation::GetNearestColor {
            dc: NATIVE_DC,
            color: 0x0011_2233
        }]
    );
}
