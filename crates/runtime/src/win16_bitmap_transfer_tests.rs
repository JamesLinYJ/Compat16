//! Bitmap transfer return codes and source-free raster operations.

use super::super::drawing::stretch_dibits;
use super::super::test_support::{NoHost, tiny_ne_executable};
use super::{prepare_bitmap_transfer, raster_operation_uses_source};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingResult as HostResult, Win16HostDc,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::PhysAddr;
use win16_abi::{AccessRights, SegmentedPointer, Win16ApiRequest, Win16GdiDrawingRequest};

const DEST: Win16HostDc = Win16HostDc(0x1111_0000_0000_0001);
const SRC: Win16HostDc = Win16HostDc(0x2222_0000_0000_0002);
const SRCCOPY: u32 = 0x00CC_0020;
const PATCOPY: u32 = 0x00F0_0021;
const BLACKNESS: u32 = 0x0000_0042;
const WHITENESS: u32 = 0x00FF_0062;
const DSTINVERT: u32 = 0x0055_0009;
const PATINVERT: u32 = 0x005A_0049;
const NOTSRCCOPY: u32 = 0x0033_0008;
const SRCAND: u32 = 0x0088_00C6;
const PATPAINT: u32 = 0x00FB_0A09;
const NOMIRRORBITMAP: u32 = 0x8000_0000;
const CAPTUREBLT: u32 = 0x4000_0000;
const GDI_ERROR16: u32 = 0xFFFF;

struct BlitHost {
    calls: Vec<Operation>,
    result: HostResult,
}

impl DosHost for BlitHost {
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

impl RuntimeHost for BlitHost {
    fn win16_gdi(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
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

impl crate::RuntimeDdeHost for BlitHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for BlitHost {}
impl crate::RuntimeMidiHost for BlitHost {}
impl crate::RuntimeNetbiosHost for BlitHost {}

fn runtime() -> (Runtime, u16, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\BLT.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let destination = state.guest_gdi.allocate_dc(DEST).unwrap();
    let source = state.guest_gdi.allocate_dc(SRC).unwrap();
    (runtime, destination, source)
}

fn transfer(
    runtime: &mut Runtime,
    host: &mut impl RuntimeHost,
    request: Win16ApiRequest,
) -> Result<u32, RuntimeError> {
    let Some(request) = prepare_bitmap_transfer(request) else {
        return Ok(0);
    };
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drawing(request, &mut runtime.memory, host)
}

fn bitblt(destination: u16, source: u16, rop: u32) -> Win16ApiRequest {
    Win16ApiRequest::GdiDrawing(Win16GdiDrawingRequest::BitBlt {
        destination,
        destination_x: 1,
        destination_y: 2,
        width: 3,
        height: 4,
        source,
        source_x: 5,
        source_y: 6,
        rop,
    })
}

fn stretchblt(destination: u16, source: u16, rop: u32) -> Win16ApiRequest {
    Win16ApiRequest::GdiDrawing(Win16GdiDrawingRequest::StretchBlt {
        destination,
        destination_x: 1,
        destination_y: 2,
        width: -3,
        height: 4,
        source,
        source_x: 5,
        source_y: 6,
        source_width: -7,
        source_height: 8,
        rop,
    })
}

fn patblt(dc: u16, rop: u32) -> Win16ApiRequest {
    Win16ApiRequest::GdiDrawing(Win16GdiDrawingRequest::PatBlt {
        dc,
        x: 1,
        y: 2,
        width: 3,
        height: 4,
        rop,
    })
}

fn success_host() -> BlitHost {
    BlitHost {
        calls: Vec::new(),
        result: HostResult::Bool(true),
    }
}

#[test]
fn raster_operation_source_test_matches_published_rop3_codes() {
    for rop in [
        SRCCOPY,
        NOTSRCCOPY,
        SRCAND,
        PATPAINT,
        SRCCOPY | NOMIRRORBITMAP,
    ] {
        assert!(raster_operation_uses_source(rop), "{rop:#x}");
    }
    for rop in [
        PATCOPY,
        BLACKNESS,
        WHITENESS,
        DSTINVERT,
        PATINVERT,
        PATCOPY | NOMIRRORBITMAP,
        BLACKNESS | CAPTUREBLT,
        PATCOPY | NOMIRRORBITMAP | CAPTUREBLT,
    ] {
        assert!(!raster_operation_uses_source(rop), "{rop:#x}");
    }
}

#[test]
fn source_free_blit_ignores_a_handle_that_is_not_a_device_context() {
    let (mut runtime, destination, source) = runtime();
    let mut host = success_host();
    let missing = 0x7FFE;
    assert_eq!(
        transfer(
            &mut runtime,
            &mut host,
            bitblt(destination, missing, PATCOPY)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        transfer(
            &mut runtime,
            &mut host,
            bitblt(destination, source, PATCOPY | NOMIRRORBITMAP)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        transfer(
            &mut runtime,
            &mut host,
            stretchblt(destination, missing, BLACKNESS | CAPTUREBLT)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        transfer(&mut runtime, &mut host, bitblt(destination, 0, SRCCOPY)).unwrap(),
        1
    );
    assert_eq!(host.calls.len(), 4);
    assert!(matches!(
        &host.calls[0],
        Operation::BitBlt {
            source: None,
            rop: PATCOPY,
            ..
        }
    ));
    match &host.calls[1] {
        Operation::BitBlt {
            source: None, rop, ..
        } => assert_eq!(*rop, PATCOPY | NOMIRRORBITMAP),
        other => panic!("live source was not ignored: {other:?}"),
    }
    match &host.calls[2] {
        Operation::StretchBlt {
            source: None,
            destination_width: -3,
            source_width: -7,
            ..
        } => {}
        other => panic!("stretch source was not ignored: {other:?}"),
    }
    assert!(matches!(
        &host.calls[3],
        Operation::BitBlt {
            source: None,
            rop: SRCCOPY,
            ..
        }
    ));
}

#[test]
fn source_blit_still_requires_a_live_source_device_context() {
    let (mut runtime, destination, source) = runtime();
    let mut quiet = NoHost;
    assert_eq!(
        transfer(
            &mut runtime,
            &mut quiet,
            bitblt(destination, 0x7FFE, SRCCOPY)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        transfer(&mut runtime, &mut quiet, stretchblt(0, source, SRCCOPY)).unwrap(),
        0
    );
    assert_eq!(
        transfer(&mut runtime, &mut quiet, bitblt(0, source, PATCOPY)).unwrap(),
        0
    );

    let mut host = success_host();
    assert_eq!(
        transfer(&mut runtime, &mut host, bitblt(destination, source, SRCAND)).unwrap(),
        1
    );
    assert_eq!(
        transfer(
            &mut runtime,
            &mut host,
            stretchblt(destination, source, NOTSRCCOPY)
        )
        .unwrap(),
        1
    );
    assert!(matches!(
        &host.calls[0],
        Operation::BitBlt {
            source: Some(SRC),
            rop: SRCAND,
            ..
        }
    ));
    assert!(matches!(
        &host.calls[1],
        Operation::StretchBlt {
            source: Some(SRC),
            rop: NOTSRCCOPY,
            ..
        }
    ));
}

#[test]
fn patblt_rejects_a_source_rop_and_forwards_a_pattern_rop() {
    let (mut runtime, destination, _) = runtime();
    let mut quiet = NoHost;
    for rop in [SRCCOPY, NOTSRCCOPY, PATPAINT, SRCCOPY | NOMIRRORBITMAP] {
        assert_eq!(
            transfer(&mut runtime, &mut quiet, patblt(destination, rop)).unwrap(),
            0,
            "{rop:#x}"
        );
    }
    let mut host = success_host();
    assert_eq!(
        transfer(
            &mut runtime,
            &mut host,
            patblt(destination, PATCOPY | NOMIRRORBITMAP)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        transfer(&mut runtime, &mut host, patblt(destination, WHITENESS)).unwrap(),
        1
    );
    assert_eq!(
        transfer(&mut runtime, &mut host, patblt(0, DSTINVERT)).unwrap(),
        0
    );
    assert!(
        matches!(&host.calls[0], Operation::PatBlt { rop, .. } if *rop == PATCOPY | NOMIRRORBITMAP)
    );
    assert!(matches!(
        &host.calls[1],
        Operation::PatBlt { rop: WHITENESS, .. }
    ));
    assert_eq!(host.calls.len(), 2);
}

fn mono_dib() -> [u8; 48] {
    let mut info = [0_u8; 48];
    info[0..4].copy_from_slice(&40_u32.to_le_bytes());
    info[4..8].copy_from_slice(&1_i32.to_le_bytes());
    info[8..12].copy_from_slice(&1_i32.to_le_bytes());
    info[12..14].copy_from_slice(&1_u16.to_le_bytes());
    info[14..16].copy_from_slice(&1_u16.to_le_bytes());
    info
}

fn place_dib(runtime: &mut Runtime) -> (u32, u32) {
    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            0x100,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let info = SegmentedPointer::new(selector, 0);
    let bits = SegmentedPointer::new(selector, 64);
    state
        .selectors
        .write(&mut runtime.memory, info, &mono_dib())
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, bits, &[0x5A, 0x5A, 0x5A, 0x5A])
        .unwrap();
    (info.far_value(), bits.far_value())
}

fn read_guest(runtime: &Runtime, far: u32, len: usize) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; len];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn stretch(
    runtime: &mut Runtime,
    host: &mut impl RuntimeHost,
    dc: u16,
    info: u32,
    bits: u32,
    usage: u16,
) -> Result<u32, RuntimeError> {
    let state = runtime.win16.as_ref().unwrap();
    stretch_dibits(
        state,
        &runtime.memory,
        host,
        dc,
        0,
        0,
        1,
        1,
        0,
        0,
        1,
        1,
        info,
        bits,
        usage,
        SRCCOPY,
    )
}

#[test]
fn stretch_dibits_ordinary_failure_is_zero_and_keeps_native_gdi_error() {
    let (mut runtime, destination, _) = runtime();
    let (info, bits) = place_dib(&mut runtime);
    let before_info = read_guest(&runtime, info, 48);
    let before_bits = read_guest(&runtime, bits, 4);
    let mut quiet = NoHost;
    assert_eq!(
        stretch(&mut runtime, &mut quiet, 0, info, bits, 0).unwrap(),
        0
    );
    assert_eq!(
        stretch(&mut runtime, &mut quiet, destination, 0, bits, 0).unwrap(),
        0
    );
    assert_eq!(
        stretch(&mut runtime, &mut quiet, destination, info, 0, 0).unwrap(),
        0
    );
    assert_eq!(
        stretch(&mut runtime, &mut quiet, destination, info, bits, 2).unwrap(),
        0
    );
    assert_eq!(read_guest(&runtime, info, 48), before_info);
    assert_eq!(read_guest(&runtime, bits, 4), before_bits);

    for (lines, expected) in [
        (-1, GDI_ERROR16),
        (7, 7),
        (0, 0),
        (32_768, 0),
        (i32::from(i16::MIN), 0x8000),
    ] {
        let mut host = BlitHost {
            calls: Vec::new(),
            result: HostResult::Dibits(lines),
        };
        assert_eq!(
            stretch(&mut runtime, &mut host, destination, info, bits, 0).unwrap(),
            expected,
            "{lines}"
        );
        assert_eq!(host.calls.len(), 1);
    }
    assert_eq!(read_guest(&runtime, info, 48), before_info);
    assert_eq!(read_guest(&runtime, bits, 4), before_bits);
}
