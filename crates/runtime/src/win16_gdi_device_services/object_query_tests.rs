//! Win16 GetObject copies a whole LOGPEN or LOGBRUSH, or it writes nothing.
//!
//! Windows 3.1 GetObject requires the buffer to hold the object. A shorter
//! buffer returns zero. Learn documents the same failure as a zero result and
//! names LOGPEN for a pen and LOGBRUSH for a brush. A brush style or hatch
//! that does not fit that 16-bit structure is the same zero result.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    Diagnostic, DiagnosticKind, Runtime, RuntimeError, RuntimeHost, Win16GdiDeviceOperation,
    Win16GdiDeviceResult, Win16GdiObjectInfo, Win16HostGdiObject, Win16HostLogBrush,
    Win16HostLogPen,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::gdi_abi::{LogBrush16, LogPen16};
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const OBJECT: Win16HostGdiObject = Win16HostGdiObject(0x1111_2222_3333);
const PATTERN: Win16HostGdiObject = Win16HostGdiObject(0x4444_5555_6666);
const BUFFER: u16 = 0x20;
const SENTINEL: u8 = 0xa5;

struct Host {
    info: Option<Win16GdiObjectInfo>,
    queried: Vec<Win16HostGdiObject>,
    diagnostics: Vec<DiagnosticKind>,
}

impl DosHost for Host {
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

impl RuntimeHost for Host {
    fn win16_gdi_device(
        &mut self,
        operation: Win16GdiDeviceOperation,
    ) -> Result<Win16GdiDeviceResult, RuntimeError> {
        let Win16GdiDeviceOperation::GetObject { object } = operation else {
            panic!("unexpected GDI device operation");
        };
        self.queried.push(object);
        Ok(Win16GdiDeviceResult::ObjectInfo(self.info.clone()))
    }

    fn report_diagnostic(&mut self, diagnostic: &Diagnostic) {
        self.diagnostics.push(diagnostic.kind());
    }

    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for Host {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for Host {}
impl crate::RuntimeMidiHost for Host {}
impl crate::RuntimeNetbiosHost for Host {}

struct Outcome {
    ax: u16,
    buffer: Vec<u8>,
    diagnostics: Vec<DiagnosticKind>,
    queried: Vec<Win16HostGdiObject>,
    pattern: Option<u16>,
}

fn far(runtime: &Runtime, offset: u16) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(offset)
}

fn write_bytes(runtime: &mut Runtime, offset: u16, bytes: &[u8]) {
    let far = far(runtime, offset);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
}

fn read_bytes(runtime: &Runtime, offset: u16, len: usize) -> Vec<u8> {
    let far = far(runtime, offset);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; len];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn logical_pen() -> Win16GdiObjectInfo {
    // PS_DASH. lopnWidth.y is the unused POINT member of Win16 LOGPEN.
    Win16GdiObjectInfo::Pen(Win16HostLogPen {
        style: 1,
        width_x: 4,
        width_y: 0,
        color: 0x00aa_bbcc,
    })
}

fn logical_brush(style: u16, hatch: u32, pattern: Option<Win16HostGdiObject>) -> Win16GdiObjectInfo {
    Win16GdiObjectInfo::Brush {
        brush: Win16HostLogBrush { style, color: 0x00ab_cdef, hatch },
        pattern,
    }
}

fn query(info: Option<Win16GdiObjectInfo>, count: i16, use_buffer: bool) -> Outcome {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\OBJECT.NE").unwrap();
    let pattern = if let Some(Win16GdiObjectInfo::Brush { pattern: Some(token), .. }) = &info {
        Some(runtime.win16.as_mut().unwrap().guest_gdi.allocate_object(*token).unwrap())
    } else {
        None
    };
    let handle = runtime.win16.as_mut().unwrap().guest_gdi.allocate_object(OBJECT).unwrap();
    assert_ne!(handle, 0);
    let sentinel = vec![SENTINEL; 16];
    write_bytes(&mut runtime, BUFFER, &sentinel);
    let output = if use_buffer { far(&runtime, BUFFER) } else { 0 };
    let mut host = Host { info, queried: Vec::new(), diagnostics: Vec::new() };
    let mut physical = output.to_le_bytes().to_vec();
    physical.extend_from_slice(&count.to_le_bytes());
    physical.extend_from_slice(&handle.to_le_bytes());
    call(&mut runtime, &mut host, &physical);
    Outcome {
        ax: runtime.cpu.regs.ax(),
        buffer: read_bytes(&runtime, BUFFER, sentinel.len()),
        diagnostics: host.diagnostics,
        queried: host.queried,
        pattern,
    }
}

fn call(runtime: &mut Runtime, host: &mut Host, physical_args: &[u8]) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(82)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"GDI", ExportLookupTarget::Name(b"GetObject")).unwrap().id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("GetObject requires a fixed Pascal frame");
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
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0).unwrap(), None);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + bytes.len() as u16),
    );
}

fn assert_unchanged(outcome: &Outcome) {
    assert!(outcome.buffer.iter().all(|byte| *byte == SENTINEL));
}

fn assert_copied(outcome: &Outcome, bytes: &[u8]) {
    assert_eq!(outcome.ax, bytes.len() as u16);
    assert_eq!(&outcome.buffer[..bytes.len()], bytes);
    assert!(outcome.buffer[bytes.len()..].iter().all(|byte| *byte == SENTINEL));
    assert_eq!(outcome.queried, vec![OBJECT]);
    assert!(outcome.diagnostics.is_empty());
}

#[test]
fn get_object_copies_a_logical_pen_only_into_a_fitting_buffer() {
    let pen = LogPen16 { style: 1, width_x: 4, width_y: 0, color: 0x00aa_bbcc }.encode();
    assert_eq!(pen.len(), LogPen16::SIZE);
    let info = Some(logical_pen());

    let sized = query(info.clone(), 0, false);
    assert_eq!(sized.ax, pen.len() as u16);
    assert_unchanged(&sized);
    assert_eq!(sized.queried, vec![OBJECT]);

    for count in [0, -1] {
        let short = query(info.clone(), count, true);
        assert_eq!(short.ax, 0);
        assert_unchanged(&short);
        assert!(short.queried.is_empty());
    }
    let nine = query(info.clone(), (pen.len() as i16) - 1, true);
    assert_eq!(nine.ax, 0);
    assert_unchanged(&nine);
    assert_eq!(nine.queried, vec![OBJECT]);

    for count in [pen.len() as i16, 16] {
        assert_copied(&query(info.clone(), count, true), &pen);
    }
}

#[test]
fn get_object_copies_a_logical_brush_only_into_a_fitting_buffer() {
    // BS_HATCHED and HS_DIAGCROSS. Both fields fit the 8-byte LOGBRUSH.
    let brush = LogBrush16 { style: 2, color: 0x00ab_cdef, hatch: 5 }.encode();
    assert_eq!(brush.len(), LogBrush16::SIZE);
    let info = Some(logical_brush(2, 5, None));

    let sized = query(info.clone(), 0, false);
    assert_eq!(sized.ax, brush.len() as u16);
    assert_unchanged(&sized);

    for count in [0, brush.len() as i16 - 1] {
        let short = query(info.clone(), count, true);
        assert_eq!(short.ax, 0);
        assert_unchanged(&short);
    }
    assert_copied(&query(info.clone(), brush.len() as i16, true), &brush);
    assert_copied(&query(info, 16, true), &brush);

    // BS_PATTERN stores the guest bitmap WORD in the signed lbHatch field.
    let pattern = query(Some(logical_brush(3, 0, Some(PATTERN))), 8, true);
    let handle = pattern.pattern.unwrap();
    let stored = LogBrush16 { style: 3, color: 0x00ab_cdef, hatch: handle as i16 }.encode();
    assert_copied(&pattern, &stored);

    let short_pattern = query(Some(logical_brush(3, 0, Some(PATTERN))), 7, true);
    assert_eq!(short_pattern.ax, 0);
    assert_unchanged(&short_pattern);
    assert_eq!(short_pattern.queried, vec![OBJECT]);
}

#[test]
fn get_object_leaves_the_buffer_when_a_brush_field_does_not_fit() {
    // lbHatch is a Win16 int. A value outside that field is not truncated.
    let wide_hatch = query(Some(logical_brush(2, 0x1_0000, None)), 16, true);
    assert_eq!(wide_hatch.ax, 0);
    assert_unchanged(&wide_hatch);
    assert_eq!(wide_hatch.queried, vec![OBJECT]);
    assert!(wide_hatch.diagnostics.is_empty());
    let wide_size = query(Some(logical_brush(2, 0x1_0000, None)), 0, false);
    assert_eq!(wide_size.ax, 0);
    assert_unchanged(&wide_size);

    // A DIB-pattern or other brush whose style does not fit LOGBRUSH.
    let style = query(Some(Win16GdiObjectInfo::UnsupportedBrush), 16, true);
    assert_eq!(style.ax, 0);
    assert_unchanged(&style);
    assert_eq!(style.queried, vec![OBJECT]);
    assert_eq!(style.diagnostics, vec![DiagnosticKind::CompatibilityGap]);
    let style_size = query(Some(Win16GdiObjectInfo::UnsupportedBrush), 0, false);
    assert_eq!(style_size.ax, 0);
    assert_eq!(style_size.diagnostics, vec![DiagnosticKind::CompatibilityGap]);

    let missing = query(None, 16, true);
    assert_eq!(missing.ax, 0);
    assert_unchanged(&missing);
    assert!(missing.diagnostics.is_empty());
}
