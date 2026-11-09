//! Signed mapping results, polygon counts, and one ExtTextOut spacing int per byte.

use super::super::test_support::{NoHost, tiny_ne_executable};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation, Win16DrawingPoint,
    Win16DrawingResult as HostResult, Win16HostDc,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::PhysAddr;
use win16_abi::{AccessRights, Point16, SegmentedPointer, Win16ApiRequest};

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);

struct MapHost {
    calls: Vec<Operation>,
    point: Win16DrawingPoint,
    size: (i32, i32),
}

impl DosHost for MapHost {
    fn read_stdin(&mut self, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _: &[u8], _: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(&mut self, _: &[u8], _: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _: &[u8],
        _: DosFileAccess,
        _: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _: DosHostFile, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _: DosHostFile, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(&mut self, _: DosHostFile, _: i32, _: DosSeekOrigin) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _: DosHostFile, _: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(&mut self, _: u8, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _: &[u8], _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _: &[u8], _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for MapHost {
    fn win16_gdi(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
        let result = match &operation {
            Operation::GetWindowExtEx { .. } | Operation::SetWindowExtEx { .. } => {
                HostResult::BoolSize {
                    success: true,
                    width: self.size.0,
                    height: self.size.1,
                }
            }
            Operation::ExtTextOut { .. } => HostResult::Bool(true),
            _ => HostResult::BoolPoint {
                success: true,
                point: self.point,
            },
        };
        self.calls.push(operation);
        Ok(result)
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeDdeHost for MapHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for MapHost {}
impl crate::RuntimeMidiHost for MapHost {}
impl crate::RuntimeNetbiosHost for MapHost {}

fn runtime() -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\MAP.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            32,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let pointer = SegmentedPointer::new(selector, 0);
    state
        .selectors
        .write(&mut runtime.memory, pointer, &[0x5a; 8])
        .unwrap();
    (runtime, dc, pointer.far_value())
}

fn read_output(runtime: &Runtime, far: u32) -> [u8; 8] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = [0; 8];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn draw(
    runtime: &mut Runtime,
    host: &mut impl RuntimeHost,
    request: Win16ApiRequest,
) -> Result<u32, RuntimeError> {
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drawing(request, &mut runtime.memory, host)
}

#[test]
fn mapping_ex_rejects_a_point_outside_signed_16_bit_without_writing() {
    let (mut runtime, dc, output) = runtime();
    let mut host = MapHost {
        calls: Vec::new(),
        point: Win16DrawingPoint { x: 32_768, y: 1 },
        size: (32_768, -1),
    };
    let result = draw(
        &mut runtime,
        &mut host,
        Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetWindowOrgEx {
            dc,
            output,
        }),
    )
    .unwrap();
    assert_eq!(result, 0);
    assert_eq!(read_output(&runtime, output), [0x5a; 8]);
    assert!(matches!(
        host.calls.as_slice(),
        [Operation::GetWindowOrgEx { dc: NATIVE_DC }]
    ));

    host.calls.clear();
    let result = draw(
        &mut runtime,
        &mut host,
        Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetWindowExtEx {
            dc,
            x: 10,
            y: 20,
            output,
        }),
    )
    .unwrap();
    assert_eq!(result, 0);
    assert_eq!(read_output(&runtime, output), [0x5a; 8]);
    assert!(matches!(
        host.calls.as_slice(),
        [Operation::SetWindowExtEx {
            dc: NATIVE_DC,
            x: 10,
            y: 20,
        }]
    ));
}

#[test]
fn mapping_ex_writes_a_fitting_point_and_ignores_a_null_output() {
    let (mut runtime, dc, output) = runtime();
    let mut host = MapHost {
        calls: Vec::new(),
        point: Win16DrawingPoint { x: 7, y: -8 },
        size: (3, 4),
    };
    let result = draw(
        &mut runtime,
        &mut host,
        Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetWindowOrgEx {
            dc,
            output,
        }),
    )
    .unwrap();
    assert_eq!(result, 1);
    assert_eq!(
        &read_output(&runtime, output)[..4],
        &i16::to_le_bytes(7)
            .into_iter()
            .chain(i16::to_le_bytes(-8))
            .collect::<Vec<_>>()
    );

    let result = draw(
        &mut runtime,
        &mut host,
        Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetWindowOrgEx {
            dc,
            x: 1,
            y: 2,
            output: 0,
        }),
    )
    .unwrap();
    assert_eq!(result, 1);
    assert_eq!(&read_output(&runtime, output)[4..], &[0x5a; 4]);
}

#[test]
fn short_polygon_polyline_and_unknown_flood_do_not_call_the_host() {
    let (mut runtime, dc, _) = runtime();
    let mut host = NoHost;
    let point = Point16 { x: 1, y: 2 };
    assert_eq!(
        draw(
            &mut runtime,
            &mut host,
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Polygon {
                dc,
                count: 1,
                points: vec![point],
            }),
        )
        .unwrap(),
        0
    );
    assert_eq!(
        draw(
            &mut runtime,
            &mut host,
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Polyline {
                dc,
                count: 1,
                points: vec![point],
            }),
        )
        .unwrap(),
        0
    );
    assert_eq!(
        draw(
            &mut runtime,
            &mut host,
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PolyPolygon {
                dc,
                polygon_count: 1,
                point_counts: vec![1],
                points: vec![point],
                valid: true,
            }),
        )
        .unwrap(),
        0
    );
    assert_eq!(
        draw(
            &mut runtime,
            &mut host,
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ExtFloodFill {
                dc,
                x: 0,
                y: 0,
                color: 0,
                fill_type: 2,
            }),
        )
        .unwrap(),
        0
    );
}

#[test]
fn ext_text_out_keeps_one_spacing_int_per_byte_when_the_spacing_option_is_set() {
    let (mut runtime, dc, _) = runtime();
    let mut host = MapHost {
        calls: Vec::new(),
        point: Win16DrawingPoint { x: 0, y: 0 },
        size: (0, 0),
    };
    let result = draw(
        &mut runtime,
        &mut host,
        Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::ExtTextOut {
            dc,
            x: 1,
            y: 2,
            options: 0x2000,
            rect: None,
            text: b"AB".to_vec(),
            count: 2,
            spacing: Some(vec![10, 20]),
        }),
    )
    .unwrap();
    assert_eq!(result, 1);
    assert_eq!(
        host.calls,
        [Operation::ExtTextOut {
            dc: NATIVE_DC,
            x: 1,
            y: 2,
            options: 0x2000,
            rect: None,
            text: b"AB".to_vec(),
            spacing: Some(vec![10, 20]),
            code_page: None,
        }]
    );
}
