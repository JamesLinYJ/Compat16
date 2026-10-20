//! Stretch-blt mode stays inside the Windows 3.1 set.

use super::super::test_support::{NoHost, tiny_ne_executable};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingResult as HostResult, Win16HostDc,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use win16_abi::Win16ApiRequest;

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);

struct ModeHost {
    modes: Vec<i32>,
    result: i32,
}

impl DosHost for ModeHost {
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

impl RuntimeHost for ModeHost {
    fn win16_gdi(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
        match operation {
            Operation::SetStretchBltMode { mode, .. } => self.modes.push(mode),
            Operation::GetStretchBltMode { .. } => {}
            _ => panic!("unexpected drawing operation"),
        }
        Ok(HostResult::Mode(self.result))
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

impl crate::RuntimeDdeHost for ModeHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for ModeHost {}
impl crate::RuntimeMidiHost for ModeHost {}
impl crate::RuntimeNetbiosHost for ModeHost {}

fn runtime() -> (Runtime, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\STRETCH.NE").unwrap();
    let dc = runtime
        .win16
        .as_mut()
        .unwrap()
        .guest_gdi
        .allocate_dc(NATIVE_DC)
        .unwrap();
    (runtime, dc)
}

fn set_mode(runtime: &mut Runtime, host: &mut impl RuntimeHost, dc: u16, mode: i16) -> u32 {
    let request =
        Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetStretchBltMode {
            dc,
            mode,
        });
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drawing_geometry_requests(request, &mut runtime.memory, host)
        .unwrap()
}

fn get_mode(runtime: &mut Runtime, host: &mut impl RuntimeHost, dc: u16) -> u32 {
    let request =
        Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetStretchBltMode { dc });
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drawing_geometry_requests(request, &mut runtime.memory, host)
        .unwrap()
}

#[test]
fn stretch_blt_mode_outside_win31_returns_zero_without_the_host() {
    let (mut runtime, dc) = runtime();
    let mut host = NoHost;
    // HALFTONE (4) and the other unknown modes do not change the DC.
    for mode in [0, 4, -1, i16::MAX] {
        assert_eq!(set_mode(&mut runtime, &mut host, dc, mode), 0, "{mode}");
    }
    assert_eq!(set_mode(&mut runtime, &mut host, 0, 1), 0);
    // BLACKONWHITE, WHITEONBLACK, and COLORONCOLOR still query the host.
    for mode in [1, 2, 3] {
        assert!(
            runtime
                .win16
                .as_mut()
                .unwrap()
                .drawing_geometry_requests(
                    Win16ApiRequest::GdiDrawing(
                        win16_abi::Win16GdiDrawingRequest::SetStretchBltMode { dc, mode },
                    ),
                    &mut runtime.memory,
                    &mut host,
                )
                .is_err(),
            "{mode}",
        );
    }
}

#[test]
fn stretch_blt_mode_keeps_a_win31_previous_mode_and_restores_a_later_one() {
    let (mut runtime, dc) = runtime();
    let mut host = ModeHost {
        modes: Vec::new(),
        result: 2,
    };
    assert_eq!(set_mode(&mut runtime, &mut host, dc, 3), 2);
    assert_eq!(host.modes, [3]);

    host.modes.clear();
    host.result = 4;
    assert_eq!(set_mode(&mut runtime, &mut host, dc, 1), 0);
    assert_eq!(host.modes, [1, 4]);

    host.result = 1;
    assert_eq!(get_mode(&mut runtime, &mut host, dc), 1);
    host.result = 4;
    assert_eq!(get_mode(&mut runtime, &mut host, dc), 0);
    assert_eq!(get_mode(&mut runtime, &mut host, 0), 0);
}
