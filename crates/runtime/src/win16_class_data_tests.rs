//! Host-independent USER.129–132 service-gate and class-lifetime coverage.

#[path = "win16_dispatch_arrange_iconic_windows_tests.rs"]
mod arrange_iconic_windows_tests;

#[path = "win16_dispatch_set_parent_tests.rs"]
mod set_parent_tests;

#[path = "win16_dispatch_open_icon_tests.rs"]
mod open_icon_tests;

#[path = "win16_class_procedure_tests.rs"]
mod class_procedure_tests;

#[path = "win16_creation_class_procedure_tests.rs"]
mod creation_class_procedure_tests;

#[path = "win16_unregister_class_tests.rs"]
mod class_data_unregister_tests;

#[path = "win16_callback_class_retention_tests.rs"]
mod callback_class_retention_tests;

#[path = "win16_parent_callback_tests.rs"]
mod parent_callback_tests;

use super::super::{ImportBinding, test_support::tiny_ne_executable, windows::WindowProcedure};
use crate::{
    Diagnostic, DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost,
    Win16ClassBackground, Win16HostClass, Win16HostClassSpec, Win16HostCursor,
    Win16HostGdiObject, Win16HostIcon, Win16HostProcedure, Win16HostSystemClass,
    Win16HostSystemClassInfo, Win16HostWindow, Win16RegisteredClass,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{
    ExportLookupTarget, Win16ClassName, Win16ExportStackCleanup, Win16ResourceName,
    Win16ReturnKind, WndClass16, lookup_export,
};

#[derive(Clone, Copy, Default)]
enum HostResult {
    #[default]
    Success,
    Refused,
    Error,
}

#[derive(Default)]
struct ClassDataHost {
    registrations: Vec<(Win16HostClassSpec, Win16RegisteredClass)>,
    registration_result: HostResult,
    unregistrations: Vec<Win16HostClass>,
    unregistration_result: HostResult,
    diagnostics: Vec<Kind>,
    atom_name: Option<(u16, Vec<u8>)>,
    dbcs_case: bool,
}

impl DosHost for ClassDataHost {
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


impl RuntimeHost for ClassDataHost {
    fn win16_ansi_lower_string(&mut self, source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        if self.dbcs_case {
            let mut lower = source.to_vec();
            let mut index = 0;
            while index < lower.len() {
                if lower[index] == 0x82 && index + 1 < lower.len() { index += 2; }
                else { lower[index] = lower[index].to_ascii_lowercase(); index += 1; }
            }
            return Ok(lower);
        }
        Ok(source.to_ascii_lowercase())
    }
    fn win16_register_window_class(
        &mut self, spec: Win16HostClassSpec,
    ) -> Result<Option<Win16RegisteredClass>, RuntimeError> {
        match self.registration_result {
            HostResult::Refused => return Ok(None),
            HostResult::Error => return Err(RuntimeError::new(Kind::HostFailure,
                "test class registration failure")),
            HostResult::Success => {},
        }
        let sequence = self.registrations.len() as u16 + 1;
        let registered = Win16RegisteredClass {
            class: Win16HostClass(0x1234_5678_abcd_0000 + u64::from(sequence)),
            atom: 0xa000 + sequence,
        };
        self.registrations.push((spec, registered));
        Ok(Some(registered))
    }
    fn win16_unregister_window_class(&mut self, class: Win16HostClass) -> Result<bool, RuntimeError> {
        self.unregistrations.push(class);
        match self.unregistration_result {
            HostResult::Success => Ok(true),
            HostResult::Refused => Ok(false),
            HostResult::Error => Err(RuntimeError::new(Kind::HostFailure,
                "test class removal failure")),
        }
    }
    fn win16_global_get_atom_name(&mut self, atom: u16, capacity: u16)
        -> Result<(Vec<u8>, u16), RuntimeError>
    {
        let (expected, name) = self.atom_name.as_ref().expect("unexpected atom lookup");
        assert_eq!(atom, *expected);
        assert!(name.len() < usize::from(capacity));
        Ok((name.clone(), name.len() as u16))
    }
    fn win16_system_class_info(&mut self, class: Win16HostSystemClass)
        -> Result<Option<Win16HostSystemClassInfo>, RuntimeError>
    {
        Ok(Some(Win16HostSystemClassInfo {
            spec: Win16HostClassSpec {
                style: 0x2000, class_extra: 8, window_extra: 8,
                icon: None, cursor: None, background: None, system_class: Some(class),
            },
            procedure: Win16HostProcedure(0xffff_0123_4567_89ab),
        }))
    }
    fn report_diagnostic(&mut self, diagnostic: &Diagnostic) {
        self.diagnostics.push(diagnostic.kind());
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for ClassDataHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ClassDataHost {}
impl crate::RuntimeMidiHost for ClassDataHost {}
impl crate::RuntimeNetbiosHost for ClassDataHost {}

#[derive(Clone, Copy)]
struct Registered {
    class: Win16HostClass,
    atom: u16,
    info: WndClass16,
}

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\CLASSDATA.NE").unwrap()
}

fn class_info(runtime: &Runtime, extra: i16) -> WndClass16 {
    let state = runtime.win16.as_ref().unwrap();
    WndClass16 {
        style: 0x8123,
        lpfn_wnd_proc: (u32::from(runtime.cpu.regs.cs) << 16) | 0x20,
        cb_cls_extra: extra,
        cb_wnd_extra: 6,
        h_instance: state.modules.records[&state.modules.main].instance,
        ..WndClass16::default()
    }
}

fn register(
    runtime: &mut Runtime, host: &mut ClassDataHost, info: WndClass16,
    name: Win16ClassName,
) -> Registered {
    let atom = runtime.win16.as_mut().unwrap().register_class(
        info, name, Some(Win16ResourceName::Id(7)), &runtime.memory, host,
    ).unwrap();
    assert_ne!(atom, 0);
    let registered = host.registrations.last().unwrap().1;
    assert_eq!(atom, registered.atom);
    Registered { class: registered.class, atom, info }
}

fn named_class(runtime: &mut Runtime, host: &mut ClassDataHost, name: &[u8], extra: i16) -> Registered {
    let info = class_info(runtime, extra);
    register(runtime, host, info, Win16ClassName::Name(name.to_vec()))
}

fn window(runtime: &mut Runtime, class: Registered, native: u64) -> u16 {
    let state = runtime.win16.as_mut().unwrap();
    let window = state.allocate_window_handle(Win16HostWindow(0xfedc_0000_0000 + native)).unwrap();
    state.initialize_window_data(window, Some(class.class), class.info.h_instance,
        false, Some(class.info.cb_wnd_extra as usize)).unwrap();
    state.window_procedures.insert(window, WindowProcedure {
        class: class.class, address: class.info.lpfn_wnd_proc, instance: class.info.h_instance,
    });
    window
}

// Install the physical Pascal frame and dispatch through the real import gate.
// The same helper covers window subclassing so no class test changes the
// procedure table in place to simulate SetWindowLong.
fn call(
    runtime: &mut Runtime, host: &mut ClassDataHost, ordinal: u16,
    window: u16, index: i16, value: Option<u32>,
) -> u32 {
    let (name, kind, argument_bytes, setter) = match ordinal {
        129 => (b"GetClassWord".as_slice(), Win16ReturnKind::Word, 4, false),
        130 => (b"SetClassWord".as_slice(), Win16ReturnKind::Word, 6, true),
        131 => (b"GetClassLong".as_slice(), Win16ReturnKind::Dword, 4, false),
        132 => (b"SetClassLong".as_slice(), Win16ReturnKind::Dword, 8, true),
        135 => (b"GetWindowLong".as_slice(), Win16ReturnKind::Dword, 4, false),
        136 => (b"SetWindowLong".as_slice(), Win16ReturnKind::Dword, 8, true),
        _ => panic!("unexpected test export"),
    };
    assert_eq!(value.is_some(), setter);
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.id, lookup_export(b"USER", ExportLookupTarget::Name(name)).unwrap().id);
    assert_eq!(descriptor.return_kind, kind);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("class data requires a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, argument_bytes);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    if let Some(value) = value {
        if kind == Win16ReturnKind::Word {
            bytes.extend_from_slice(&(value as u16).to_le_bytes());
        } else {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(&window.to_le_bytes());
    assert_eq!(bytes.len(), usize::from(argument_bytes) + 4);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, host, 0).unwrap(), None);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + bytes.len() as u16));
    let result = if kind == Win16ReturnKind::Word {
        assert_eq!(runtime.cpu.regs.dx(), 0x5aa5, "WORD returns preserve DX");
        u32::from(runtime.cpu.regs.ax())
    } else {
        u32::from(runtime.cpu.regs.ax()) | (u32::from(runtime.cpu.regs.dx()) << 16)
    };
    // Reuse the caller's test stack area for the next independent invocation.
    runtime.cpu.regs.set_sp(stack);
    result
}

fn gap(
    runtime: &mut Runtime, host: &mut ClassDataHost, ordinal: u16,
    window: u16, index: i16, value: Option<u32>,
) {
    host.diagnostics.clear();
    assert_eq!(call(runtime, host, ordinal, window, index, value), 0);
    assert!(host.diagnostics.contains(&Kind::CompatibilityGap),
        "USER.{ordinal} at index {index} must report its unsupported contract");
}

#[test]
fn class_data_shares_bytes_between_windows_but_not_registrations() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let first = named_class(&mut runtime, &mut host, b"First", 9);
    let second = named_class(&mut runtime, &mut host, b"Second", 9);
    let a = window(&mut runtime, first, 1);
    let b = window(&mut runtime, first, 2);
    let c = window(&mut runtime, second, 3);
    assert_eq!(call(&mut runtime, &mut host, 131, a, 1, None), 0);
    assert_eq!(call(&mut runtime, &mut host, 132, a, 1, Some(0x89ab_cdef)), 0);
    assert_eq!(call(&mut runtime, &mut host, 129, b, 1, None), 0xcdef);
    assert_eq!(call(&mut runtime, &mut host, 129, b, 3, None), 0x89ab);
    assert_eq!(call(&mut runtime, &mut host, 130, b, 2, Some(0x1234)), 0xabcd);
    assert_eq!(call(&mut runtime, &mut host, 131, a, 1, None), 0x8912_34ef);
    assert_eq!(call(&mut runtime, &mut host, 132, b, 1, Some(0xfedc_ba98)), 0x8912_34ef);
    assert_eq!(call(&mut runtime, &mut host, 131, a, 1, None), 0xfedc_ba98);
    assert_eq!(call(&mut runtime, &mut host, 131, c, 1, None), 0);
    assert_eq!(call(&mut runtime, &mut host, 130, c, 1, Some(0x7654)), 0);
    assert_eq!(call(&mut runtime, &mut host, 131, a, 1, None), 0xfedc_ba98);
    assert!(host.diagnostics.is_empty());
}

#[test]
fn class_data_full_span_bounds_never_partially_modify_storage() {
    for length in [0, 1, 2, 3, 4, 5, 7] {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"Bounds", length);
        let hwnd = window(&mut runtime, class, 1);
        let mut expected = vec![0_u8; length as usize];
        for offset in (0..=length + 1).chain(std::iter::once(i16::MAX)) {
            for (get, set, width, value) in [(129, 130, 2, 0xa1b2_u32), (131, 132, 4, 0xfedc_9876)] {
                let range = offset as usize..offset as usize + width;
                let old = expected.get(range.clone()).map_or(0, |bytes| {
                    let mut raw = [0; 4];
                    raw[..width].copy_from_slice(bytes);
                    u32::from_le_bytes(raw)
                });
                assert_eq!(call(&mut runtime, &mut host, get, hwnd, offset, None), old);
                assert_eq!(call(&mut runtime, &mut host, set, hwnd, offset, Some(value)), old);
                if let Some(bytes) = expected.get_mut(range) {
                    bytes.copy_from_slice(&value.to_le_bytes()[..width]);
                }
                for (index, bytes) in expected.windows(2).enumerate() {
                    assert_eq!(call(&mut runtime, &mut host, 129, hwnd, index as i16, None),
                        u32::from(u16::from_le_bytes([bytes[0], bytes[1]])));
                }
            }
        }
    }
}

#[test]
fn class_data_signed_index_limit_checks_the_entire_access() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Maximum", i16::MAX);
    let hwnd = window(&mut runtime, class, 1);
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, 32763, Some(0x1122_3344)), 0);
    assert_eq!(call(&mut runtime, &mut host, 129, hwnd, 32765, None), 0x1122);
    for offset in [32764, 32765, 32766, 32767] {
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, offset, Some(u32::MAX)), 0);
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, offset, None), 0);
    }
    for offset in [32766, 32767] {
        assert_eq!(call(&mut runtime, &mut host, 130, hwnd, offset, Some(0xffff)), 0);
        assert_eq!(call(&mut runtime, &mut host, 129, hwnd, offset, None), 0);
    }
    assert_eq!(call(&mut runtime, &mut host, 131, hwnd, 32763, None), 0x1122_3344);
}

#[test]
fn class_data_metadata_returns_guest_resources_and_registration_atom() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let mut info = class_info(&runtime, 7);
    let icon = Win16HostIcon(0x1122_3344_5566_aa11);
    let cursor = Win16HostCursor(0x2233_4455_6677_bb22);
    let brush = Win16HostGdiObject(0x3344_5566_7788_cc33);
    let state = runtime.win16.as_mut().unwrap();
    info.h_icon = state.guest_images.allocate_icon(icon).unwrap().0;
    info.h_cursor = state.guest_images.allocate_cursor(cursor).unwrap();
    info.hbr_background = state.guest_gdi.allocate_object(brush).unwrap();
    host.atom_name = Some((0xc123, b"AtomNamedClass".to_vec()));
    let class = register(&mut runtime, &mut host, info, Win16ClassName::Atom(0xc123));
    assert_ne!(class.atom, 0xc123);
    let spec = host.registrations.last().unwrap().0;
    assert_eq!(spec.icon, Some(icon));
    assert_eq!(spec.cursor, Some(cursor));
    assert_eq!(spec.background, Some(Win16ClassBackground::Brush(brush)));
    let hwnd = window(&mut runtime, class, 1);
    for (index, expected) in [(-32, class.atom), (-26, info.style), (-20, 7), (-18, 6),
        (-14, info.h_icon), (-12, info.h_cursor), (-10, info.hbr_background)] {
        assert_eq!(call(&mut runtime, &mut host, 129, hwnd, index, None), u32::from(expected));
    }
    assert_eq!(call(&mut runtime, &mut host, 131, hwnd, -24, None), info.lpfn_wnd_proc);
    assert!(host.diagnostics.is_empty());
}

#[test]
fn class_data_system_color_background_keeps_guest_encoding() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let mut info = class_info(&runtime, 0);
    info.hbr_background = 31;
    let class = register(&mut runtime, &mut host, info, Win16ClassName::Name(b"Color".to_vec()));
    assert_eq!(host.registrations.last().unwrap().0.background, Some(Win16ClassBackground::SystemColor(30)));
    let hwnd = window(&mut runtime, class, 1);
    assert_eq!(call(&mut runtime, &mut host, 129, hwnd, -10, None), 31);
}

#[test]
fn class_data_wndproc_remains_the_registered_procedure_after_window_subclassing() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Subclass", 4);
    let first = window(&mut runtime, class, 1);
    let second = window(&mut runtime, class, 2);
    let subclass = (class.info.lpfn_wnd_proc & 0xffff_0000) | 0x60;
    assert_eq!(call(&mut runtime, &mut host, 136, first, -4, Some(subclass)), class.info.lpfn_wnd_proc);
    assert_eq!(call(&mut runtime, &mut host, 135, first, -4, None), subclass);
    for hwnd in [first, second] {
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, -24, None), class.info.lpfn_wnd_proc);
    }
    assert_eq!(call(&mut runtime, &mut host, 135, second, -4, None), class.info.lpfn_wnd_proc);
    assert_eq!(runtime.win16.as_ref().unwrap().class_code_references(), vec![class.info.lpfn_wnd_proc]);
}

#[test]
fn class_data_unsupported_negative_fields_and_widths_report_gaps_without_mutation() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Unsupported", 4);
    let hwnd = window(&mut runtime, class, 1);
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, 0, Some(0x7654_3210)), 0);
    for index in [-32, -26, -24, -20, -18, -16, -14, -12, -10, -8, -1, i16::MIN] {
        gap(&mut runtime, &mut host, 130, hwnd, index, Some(0xffff));
        if index != -24 {
            gap(&mut runtime, &mut host, 132, hwnd, index, Some(u32::MAX));
        }
    }
    for index in [-32, -26, -20, -18, -14, -12, -10] {
        gap(&mut runtime, &mut host, 131, hwnd, index, None);
    }
    gap(&mut runtime, &mut host, 129, hwnd, -24, None);
    for index in [-16, -8, -1, i16::MIN] {
        gap(&mut runtime, &mut host, 129, hwnd, index, None);
        gap(&mut runtime, &mut host, 131, hwnd, index, None);
    }
    for (index, value) in [(-32, class.atom), (-26, class.info.style), (-20, 4), (-18, 6),
        (-14, 0), (-12, 0), (-10, 0)] {
        assert_eq!(call(&mut runtime, &mut host, 129, hwnd, index, None), u32::from(value));
    }
    assert_eq!(call(&mut runtime, &mut host, 131, hwnd, -24, None), class.info.lpfn_wnd_proc);
    assert_eq!(call(&mut runtime, &mut host, 131, hwnd, 0, None), 0x7654_3210);
}

#[test]
fn class_data_invalid_hwnds_return_zero_in_the_declared_register_width() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    for hwnd in [0, 1, 0x7777, 0xfffe, 0xffff] {
        for index in [0, 1, -24, -26, i16::MAX] {
            for (ordinal, value) in [(129, None), (130, Some(0xffff)),
                (131, None), (132, Some(u32::MAX))] {
                assert_eq!(call(&mut runtime, &mut host, ordinal, hwnd, index, value), 0);
            }
        }
    }
    assert!(host.registrations.is_empty());
}

#[test]
fn class_data_builtin_and_missing_class_storage_report_gaps() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let state = runtime.win16.as_mut().unwrap();
    let builtin = state.resolve_window_class_for_create(0,
        &Win16ClassName::Name(b"BUTTON".to_vec()), &mut host).unwrap().unwrap();
    let mut windows = Vec::new();
    for (native, class, initialize) in [
        (1, Some(builtin.host_class), true),
        (2, Some(Win16HostClass(0xdead_beef_1234_5678)), true),
        (3, None, true),
        (4, None, false),
    ] {
        let hwnd = state.allocate_window_handle(Win16HostWindow(native)).unwrap();
        if initialize {
            state.initialize_window_data(hwnd, class, builtin.instance, false, Some(8)).unwrap();
        }
        windows.push(hwnd);
    }
    assert_eq!(host.registrations.len(), 1);
    assert_eq!(host.registrations[0].0.system_class, Some(Win16HostSystemClass::Button));
    for hwnd in windows {
        for index in [0, 1, 4, -24, -26, -32] {
            for (ordinal, value) in [(129, None), (130, Some(0x1234)),
                (131, None), (132, Some(0x5678_1234))] {
                gap(&mut runtime, &mut host, ordinal, hwnd, index, value);
            }
        }
    }
    assert_eq!(host.registrations.len(), 1);
    assert!(host.unregistrations.is_empty());
}

#[test]
fn class_data_last_window_retirement_preserves_bytes_and_reused_hwnd_changes_class() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let first = named_class(&mut runtime, &mut host, b"Retained", 4);
    let second = named_class(&mut runtime, &mut host, b"Replacement", 4);
    let hwnd = window(&mut runtime, first, 1);
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, 0, Some(0x1234_5678)), 0);
    let state = runtime.win16.as_mut().unwrap();
    state.retire_window_handle(hwnd).unwrap();
    assert!(state.window_handles.is_empty());
    assert!(state.is_registered_class_atom(first.atom));
    state.next_window_handle = hwnd;
    let reused = window(&mut runtime, second, 2);
    assert_eq!(reused, hwnd);
    assert_eq!(call(&mut runtime, &mut host, 131, reused, 0, None), 0);
    assert_eq!(call(&mut runtime, &mut host, 129, reused, -32, None), u32::from(second.atom));
    assert_eq!(call(&mut runtime, &mut host, 132, reused, 0, Some(0x8765_4321)), 0);
    let recreated = window(&mut runtime, first, 3);
    assert_eq!(call(&mut runtime, &mut host, 131, recreated, 0, None), 0x1234_5678);
    assert_eq!(call(&mut runtime, &mut host, 131, reused, 0, None), 0x8765_4321);
}

#[test]
fn class_data_registration_failures_publish_no_class_or_storage() {
    for result in [HostResult::Refused, HostResult::Error] {
        let mut runtime = fixture();
        let mut host = ClassDataHost { registration_result: result, ..ClassDataHost::default() };
        let info = class_info(&runtime, 4);
        let state = runtime.win16.as_mut().unwrap();
        let registration = state.register_class(info, Win16ClassName::Name(b"Retry".to_vec()),
            None, &runtime.memory, &mut host);
        match result {
            HostResult::Refused => assert_eq!(registration.unwrap(), 0),
            HostResult::Error => assert_eq!(registration.unwrap_err().kind(), Kind::HostFailure),
            HostResult::Success => unreachable!(),
        }
        assert_eq!(state.window_classes.entries().count(), 0);
        assert!(state.class_code_references().is_empty());
        host.registration_result = HostResult::Success;
        let class = named_class(&mut runtime, &mut host, b"Retry", 4);
        let hwnd = window(&mut runtime, class, 1);
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, 0, None), 0);
        assert_eq!(runtime.win16.as_ref().unwrap().window_classes.entries().count(), 1);
    }
}

#[test]
fn class_data_cleanup_failure_retains_bytes_and_successful_reregistration_zeroes_them() {
    for module_cleanup in [false, true] {
        for failure in [HostResult::Refused, HostResult::Error] {
            let mut runtime = fixture();
            let mut host = ClassDataHost::default();
            let class = named_class(&mut runtime, &mut host, b"Cleanup", 4);
            let hwnd = window(&mut runtime, class, 1);
            assert_eq!(call(&mut runtime, &mut host, 132, hwnd, 0, Some(0xabcd_1234)), 0);
            host.unregistration_result = failure;
            let state = runtime.win16.as_mut().unwrap();
            if module_cleanup {
                // Automatic cleanup must not ask even a permissive host to
                // unregister while the runtime still owns a live window.
                state.release_module_classes(&[state.modules.main], &mut host).unwrap();
                assert!(host.unregistrations.is_empty());
                state.retire_window_handle(hwnd).unwrap();
            }
            let result = if module_cleanup {
                state.release_module_classes(&[state.modules.main], &mut host)
            } else {
                state.close_classes(&mut host)
            };
            if module_cleanup && matches!(failure, HostResult::Refused) {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), Kind::HostFailure);
            }
            assert!(state.is_registered_class_atom(class.atom));
            assert_eq!(state.class_code_references(), vec![class.info.lpfn_wnd_proc]);
            assert_eq!(state.window_classes.guest_class_extra_mut(class.class).unwrap(),
                &0xabcd_1234u32.to_le_bytes());
            if !module_cleanup {
                assert_eq!(call(&mut runtime, &mut host, 131, hwnd, 0, None), 0xabcd_1234);
                runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
            }
            host.unregistration_result = HostResult::Success;
            let state = runtime.win16.as_mut().unwrap();
            if module_cleanup {
                state.release_module_classes(&[state.modules.main], &mut host).unwrap();
            } else {
                state.close_classes(&mut host).unwrap();
            }
            assert!(!state.is_registered_class_atom(class.atom));
            assert_eq!(state.window_classes.entries().count(), 0);
            assert!(state.class_code_references().is_empty());
            assert_eq!(host.unregistrations, vec![class.class, class.class]);
            let replacement = named_class(&mut runtime, &mut host, b"Cleanup", 4);
            assert_ne!(replacement.class, class.class);
            let recreated = window(&mut runtime, replacement, 2);
            assert_eq!(call(&mut runtime, &mut host, 131, recreated, 0, None), 0);
        }
    }
}

#[path = "win16_dispatch_close_window_tests.rs"]
mod close_window_tests;
