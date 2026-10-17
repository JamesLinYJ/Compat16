//! OPENFILENAME hook and NE-template checks.
//!
//! Template bytes are decoded from the guest. The hook procedure is not
//! entered: no file-dialog window exists to own that callback.

use super::prepare::{CommonDialogHookTemplate, CommonDialogHookTemplateResolution};
use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::Runtime;
use guest_core::{GuestMemory, Selector};
use win16_abi::Access;
use win16_abi::commdlg_abi::{
    ChooseColor16, ChooseFont16, FindReplace16, OpenFileName16, PrintDlg16,
};
use win16_abi::{ExportLookupTarget, lookup_export};

const HOOK_BYTES: [u8; 5] = [0x31, 0xc0, 0xca, 0x0a, 0x00];

fn dialog_template_bytes() -> Vec<u8> {
    let mut bytes = 0_u32.to_le_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&0_i16.to_le_bytes());
    bytes.extend_from_slice(&0_i16.to_le_bytes());
    bytes.extend_from_slice(&20_i16.to_le_bytes());
    bytes.extend_from_slice(&10_i16.to_le_bytes());
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(b"File\0");
    bytes
}

fn add_dialog_resource(runtime: &mut Runtime, id: u16) {
    let payload = dialog_template_bytes();
    let state = runtime.win16.as_mut().unwrap();
    let record = state.modules.records.get_mut(&state.modules.main).unwrap();
    let offset = record.image.len();
    record.image.extend_from_slice(&payload);
    let definition = record.definition.as_mut().unwrap();
    definition.header.resource_table_offset = 0x100;
    definition.resource_types.push(formats::NeResourceType {
        id: formats::NeResourceId::Numeric(5),
        resources: vec![formats::NeResource {
            id: formats::NeResourceId::Numeric(id),
            file_offset: offset,
            byte_length: payload.len(),
            flags: 0,
            handle: 0,
            usage: 0,
        }],
    });
}

fn install_hook(runtime: &mut Runtime) -> u32 {
    let hook = (u32::from(runtime.cpu.regs.cs) << 16) | 0x80;
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(hook).unwrap();
    let physical = state.selectors.translate(pointer, Access::Execute, 5, &runtime.memory).unwrap();
    runtime.memory.write(physical, &HOOK_BYTES).unwrap();
    hook
}

fn write_at(runtime: &mut Runtime, far: u32, bytes: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
}

fn read_at(runtime: &Runtime, far: u32, bytes: &mut [u8]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state.selectors.read(&runtime.memory, pointer, bytes).unwrap();
}

struct OpenFileLayout {
    structure: u32,
    record: [u8; OpenFileName16::SIZE],
}

fn place_open_file(
    runtime: &mut Runtime,
    flags: u32,
    hook: u32,
    instance: u16,
    template: u32,
) -> OpenFileLayout {
    let data = u32::from(runtime.cpu.regs.ds) << 16;
    let structure = data;
    let file = data + OpenFileName16::SIZE as u32;
    let mut file_bytes = [0_u8; 16];
    file_bytes[..5].copy_from_slice(b"name\0");
    write_at(runtime, file, &file_bytes);
    let record = OpenFileName16 {
        structure_size: OpenFileName16::SIZE as u32,
        flags,
        hook,
        instance,
        template,
        file,
        max_file: file_bytes.len() as u32,
        ..OpenFileName16::default()
    }.encode();
    write_at(runtime, structure, &record);
    write_at(runtime, data + 200, &[0xa5]);
    OpenFileLayout { structure, record }
}

fn invoke(runtime: &mut Runtime, ordinal: u16, argument: Option<u32>) -> (u16, u16, u32) {
    let descriptor = lookup_export(b"COMMDLG", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let extra = argument.map_or(0, |_| 4);
    let return_to = (
        runtime.cpu.regs.cs,
        runtime.cpu.regs.ip(),
        u32::from(runtime.cpu.regs.sp()) + 4 + extra,
    );
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    if let Some(argument) = argument {
        bytes.extend_from_slice(&argument.to_le_bytes());
    }
    let pointer = state.selectors.pointer_from_raw(
        Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp(),
    ).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    return_to
}

fn dispatch(runtime: &mut Runtime) {
    let mut host = NoHost;
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
}

fn assert_returned_without_hook(
    runtime: &Runtime,
    return_to: (u16, u16, u32),
    layout: &OpenFileLayout,
    hook: u32,
) {
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), u32::from(runtime.cpu.regs.sp())),
        return_to,
    );
    assert_ne!(
        ((u32::from(runtime.cpu.regs.cs) << 16) | u32::from(runtime.cpu.regs.ip())),
        hook,
        "guest hook must not run before a file-dialog window exists",
    );
    assert_eq!(runtime.cpu.regs.ax(), 0);
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.callback_kinds.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
    let mut record = [0_u8; OpenFileName16::SIZE];
    read_at(runtime, layout.structure, &mut record);
    assert_eq!(record, layout.record);
    let mut canary = [0_u8; 1];
    read_at(runtime, layout.structure + 200, &mut canary);
    assert_eq!(canary, [0xa5]);
    let mut hook_bytes = [0_u8; 5];
    read_at(runtime, hook, &mut hook_bytes);
    assert_eq!(hook_bytes, HOOK_BYTES);
}

fn decoded_title(runtime: &mut Runtime, request: CommonDialogHookTemplate) -> Vec<u8> {
    let mut host = NoHost;
    let resolved = runtime.win16.as_mut().unwrap().resolve_common_dialog_hook_template(
        &runtime.memory, &mut host, request,
    ).unwrap();
    let CommonDialogHookTemplateResolution::Ready {
        hook: Some(_), template: Some(template),
    } = resolved else {
        panic!("template was not decoded");
    };
    match template.title {
        crate::Win16HostDialogAtom::String(title) => title,
        _ => panic!("template title was not the decoded ANSI string"),
    }
}

#[test]
fn open_and_save_hook_is_not_entered_before_a_dialog_exists() {
    for ordinal in [1_u16, 2] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FILE.NE").unwrap();
        let hook = install_hook(&mut runtime);
        let layout = place_open_file(&mut runtime, 0x20, hook, 0, 0);
        let return_to = invoke(&mut runtime, ordinal, Some(layout.structure));
        dispatch(&mut runtime);
        assert_returned_without_hook(&runtime, return_to, &layout, hook);
        let error_return = invoke(&mut runtime, 26, None);
        dispatch(&mut runtime);
        assert_eq!(
            (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), u32::from(runtime.cpu.regs.sp())),
            error_return,
        );
        assert_eq!(runtime.cpu.regs.ax(), 0);
        assert_eq!(runtime.cpu.regs.dx(), 0);
    }
}

#[test]
fn open_file_ne_template_is_decoded_without_entering_the_hook() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FILE.NE").unwrap();
    let instance = runtime.win16.as_ref().unwrap().modules.records
        [&runtime.win16.as_ref().unwrap().modules.main].instance;
    add_dialog_resource(&mut runtime, 11);
    let hook = install_hook(&mut runtime);
    assert_eq!(
        decoded_title(&mut runtime, CommonDialogHookTemplate {
            enable_hook: true,
            enable_template: true,
            enable_template_handle: false,
            hook,
            instance,
            template_name: 11,
        }),
        b"File",
    );
    let layout = place_open_file(&mut runtime, 0x20 | 0x40, hook, instance, 11);
    let return_to = invoke(&mut runtime, 1, Some(layout.structure));
    dispatch(&mut runtime);
    assert_returned_without_hook(&runtime, return_to, &layout, hook);
}

#[test]
fn open_file_template_handle_is_decoded_without_entering_the_hook() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FILE.NE").unwrap();
    let bytes = dialog_template_bytes();
    let mut host = NoHost;
    let handle = runtime.win16.as_mut().unwrap().global_alloc(
        2, bytes.len() as u32, &mut runtime.memory, &mut host,
    ).unwrap();
    assert_ne!(handle, 0);
    let far = runtime.win16.as_mut().unwrap().global_lock(handle, &runtime.memory).unwrap();
    write_at(&mut runtime, far, &bytes);
    runtime.win16.as_mut().unwrap().global_unlock(handle).unwrap();
    let hook = install_hook(&mut runtime);
    assert_eq!(
        decoded_title(&mut runtime, CommonDialogHookTemplate {
            enable_hook: true,
            enable_template: false,
            enable_template_handle: true,
            hook,
            instance: handle,
            template_name: 0xffff_ffff,
        }),
        b"File",
    );
    let layout = place_open_file(&mut runtime, 0x20 | 0x80, hook, handle, 0xffff_ffff);
    let return_to = invoke(&mut runtime, 1, Some(layout.structure));
    dispatch(&mut runtime);
    assert_returned_without_hook(&runtime, return_to, &layout, hook);
}

#[test]
fn open_file_missing_hook_and_template_return_sdk_errors() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FILE.NE").unwrap();
    let instance = runtime.win16.as_ref().unwrap().modules.records
        [&runtime.win16.as_ref().unwrap().modules.main].instance;
    let hook = install_hook(&mut runtime);
    let missing_hook = place_open_file(&mut runtime, 0x20, 0, 0, 0);
    let return_to = invoke(&mut runtime, 1, Some(missing_hook.structure));
    dispatch(&mut runtime);
    assert_returned_without_hook(&runtime, return_to, &missing_hook, hook);
    let error_return = invoke(&mut runtime, 26, None);
    dispatch(&mut runtime);
    assert_eq!(runtime.cpu.regs.ax(), 0x000b);
    assert_eq!(runtime.cpu.regs.dx(), 0);
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), u32::from(runtime.cpu.regs.sp())),
        error_return,
    );

    let missing_template = place_open_file(&mut runtime, 0x20 | 0x40, hook, instance, 99);
    let return_to = invoke(&mut runtime, 1, Some(missing_template.structure));
    dispatch(&mut runtime);
    assert_returned_without_hook(&runtime, return_to, &missing_template, hook);
    invoke(&mut runtime, 26, None);
    dispatch(&mut runtime);
    assert_eq!(runtime.cpu.regs.ax(), 0x0006);
}

#[test]
fn color_font_find_and_print_hooks_stay_false() {
    let families = [
        (5_u16, ChooseColor16 {
            structure_size: ChooseColor16::SIZE as u32,
            flags: 0x10,
            hook: 1,
            ..ChooseColor16::default()
        }.encode().to_vec()),
        (11, FindReplace16 {
            structure_size: FindReplace16::SIZE as u32,
            flags: 0x2300,
            hook: 1,
            ..FindReplace16::default()
        }.encode().to_vec()),
        (15, ChooseFont16 {
            structure_size: ChooseFont16::SIZE as u32,
            flags: 0x8,
            hook: 1,
            ..ChooseFont16::default()
        }.encode().to_vec()),
        (20, PrintDlg16 {
            structure_size: PrintDlg16::SIZE as u32,
            flags: 0x1000,
            print_hook: 1,
            ..PrintDlg16::default()
        }.encode().to_vec()),
    ];
    for (ordinal, bytes) in families {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FILE.NE").unwrap();
        let structure = u32::from(runtime.cpu.regs.ds) << 16;
        write_at(&mut runtime, structure, &bytes);
        let return_to = invoke(&mut runtime, ordinal, Some(structure));
        dispatch(&mut runtime);
        assert_eq!(
            (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), u32::from(runtime.cpu.regs.sp())),
            return_to,
        );
        assert_eq!(runtime.cpu.regs.ax(), 0);
        let state = runtime.win16.as_ref().unwrap();
        assert!(state.callback_kinds.is_empty());
        assert_eq!(state.common_dialog_state.last_extended_error, 0);
    }
}
