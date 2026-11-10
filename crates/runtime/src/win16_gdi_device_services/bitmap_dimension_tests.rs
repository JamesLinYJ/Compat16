//! GDI.162 returns the bitmap's 0.1 mm dimensions, or zero.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16GdiDeviceOperation, Win16GdiDeviceResult,
    Win16HostGdiObject,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};

const BITMAP: Win16HostGdiObject = Win16HostGdiObject(0x1111_2222_3333);

struct Host {
    result: Win16GdiDeviceResult,
    calls: Vec<Win16GdiDeviceOperation>,
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
    fn win16_gdi_device(
        &mut self,
        operation: Win16GdiDeviceOperation,
    ) -> Result<Win16GdiDeviceResult, RuntimeError> {
        self.calls.push(operation);
        Ok(self.result.clone())
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

fn point(success: bool, x: i32, y: i32) -> Win16GdiDeviceResult {
    Win16GdiDeviceResult::Point { success, x, y }
}

fn query(
    handle: Option<u16>,
    result: Win16GdiDeviceResult,
) -> (u16, u16, Vec<Win16GdiDeviceOperation>) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\BITMAP.NE").unwrap();
    let bitmap = handle.unwrap_or_else(|| {
        runtime
            .win16
            .as_mut()
            .unwrap()
            .guest_gdi
            .allocate_object(BITMAP)
            .unwrap()
    });
    let mut host = Host {
        result,
        calls: Vec::new(),
    };
    let (ax, dx) = call(&mut runtime, &mut host, &bitmap.to_le_bytes());
    (ax, dx, host.calls)
}

fn call(runtime: &mut Runtime, host: &mut Host, physical_args: &[u8]) -> (u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(162)).unwrap();
    assert_eq!(
        descriptor.id,
        lookup_export(b"GDI", ExportLookupTarget::Name(b"GetBitmapDimension"))
            .unwrap()
            .id
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("GetBitmapDimension requires a fixed Pascal frame");
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
    runtime.cpu.regs.eax = 0xa1b2_a55a;
    runtime.cpu.regs.edx = 0xc3d4_5aa5;
    assert_eq!(
        state
            .dispatch(
                &mut runtime.cpu,
                &mut runtime.memory,
                &mut runtime.dos,
                host,
                0,
            )
            .unwrap(),
        None
    );
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        (return_cs, return_ip, stack + bytes.len() as u16)
    );
    assert_eq!(runtime.cpu.regs.eax & 0xffff_0000, 0xa1b2_0000);
    assert_eq!(runtime.cpu.regs.edx & 0xffff_0000, 0xc3d4_0000);
    (runtime.cpu.regs.ax(), runtime.cpu.regs.dx())
}

#[test]
fn get_bitmap_dimension_packs_a_signed_16_bit_width_and_height() {
    let cases = [
        (8, 16, 8_u16, 16_u16),
        (-1, 1, 0xffff, 1),
        (0, 0, 0, 0),
        (i32::from(i16::MIN), i32::from(i16::MAX), 0x8000, 0x7fff),
    ];
    for (width, height, low, high) in cases {
        let (ax, dx, calls) = query(None, point(true, width, height));
        assert_eq!((ax, dx), (low, high), "dimensions {width},{height}");
        assert_eq!(
            calls,
            vec![Win16GdiDeviceOperation::GetBitmapDimension { bitmap: BITMAP }]
        );
    }
}

#[test]
fn get_bitmap_dimension_returns_zero_when_a_dimension_does_not_fit() {
    let outside = [32_768, -32_769, i32::MIN, i32::MAX];
    for width in outside {
        let (ax, dx, calls) = query(None, point(true, width, 12));
        assert_eq!((ax, dx), (0, 0), "width {width}");
        assert_eq!(
            calls,
            vec![Win16GdiDeviceOperation::GetBitmapDimension { bitmap: BITMAP }]
        );
    }
    for height in outside {
        let (ax, dx, _) = query(None, point(true, 12, height));
        assert_eq!((ax, dx), (0, 0), "height {height}");
    }
    // A failed host query is the same published zero, including when the
    // SIZE fields would otherwise fit.
    let (ax, dx, calls) = query(None, point(false, 8, 16));
    assert_eq!((ax, dx), (0, 0));
    assert_eq!(
        calls,
        vec![Win16GdiDeviceOperation::GetBitmapDimension { bitmap: BITMAP }]
    );

    let (ax, dx, calls) = query(Some(0), point(true, 8, 16));
    assert_eq!((ax, dx), (0, 0));
    assert!(calls.is_empty());
}
