//! Class menu LONG values through real guest API/creation continuations.

use super::*;
use crate::{Win16HostMenu, Win16MenuTemplate, Win16MenuTemplateItem};
use formats::{NeResource, NeResourceId, NeResourceType};
use guest_core::PhysAddr;
use win16_abi::{AccessRights, exports::class_data::GCL_MENUNAME};

fn put_string(runtime: &mut Runtime, bytes: &[u8]) -> u32 {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x10).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
    pointer.far_value()
}

fn menu_name(runtime: &Runtime, class: Registered) -> Option<Win16ResourceName> {
    runtime.win16.as_ref().unwrap().window_classes.menu_resource_for_host_class(class.class)
}

fn add_menu(runtime: &mut Runtime, module: u16, name: NeResourceId, command: u16) {
    // Version/extension, one final ordinary command, ANSI text plus NUL.
    let mut payload = vec![0, 0, 0, 0, 0x80, 0];
    payload.extend_from_slice(&command.to_le_bytes());
    payload.extend_from_slice(b"Menu item\0");
    let record = runtime.win16.as_mut().unwrap().modules.records.get_mut(&module).unwrap();
    let offset = record.image.len();
    record.image.extend_from_slice(&payload);
    let definition = record.definition.as_mut().unwrap();
    definition.header.resource_table_offset = 0x100;
    if !definition.resource_types.iter().any(|entry| entry.id == NeResourceId::Numeric(4)) {
        definition.resource_types.push(NeResourceType { id: NeResourceId::Numeric(4), resources: vec![] });
    }
    definition.resource_types.iter_mut().find(|entry| entry.id == NeResourceId::Numeric(4))
        .unwrap().resources.push(NeResource { id: name, file_offset: offset,
            byte_length: payload.len(), flags: 0, handle: 0, usage: 0 });
}

fn menu_command(template: &Option<Win16MenuTemplate>) -> Option<u16> {
    template.as_ref().map(|template| match template.items.as_slice() {
        [Win16MenuTemplateItem::Command { id, text, .. }] => {
            assert_eq!(text, b"Menu item");
            *id
        }
        _ => panic!("expected one RT_MENU command"),
    })
}

fn begin_menu_creation(runtime: &mut Runtime, host: &mut CreationHost, class: Registered,
    instance: u16, style: u32, menu: u16, parent: u16,
) {
    let mut args = 0_u32.to_le_bytes().to_vec();
    for value in [instance, menu, parent, 50, 40, 3, 2] {
        args.extend_from_slice(&value.to_le_bytes());
    }
    args.extend_from_slice(&style.to_le_bytes());
    args.extend_from_slice(&0_u32.to_le_bytes());
    args.extend_from_slice(&u32::from(class.atom).to_le_bytes());
    host.return_to = Some(prepare_gate(runtime, 41, &args));
    assert_eq!(runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu,
        &mut runtime.memory, &mut runtime.dos, host, 0).unwrap(), None);
}

fn finish_menu_creation(runtime: &mut Runtime, host: &mut CreationHost) -> u16 {
    let window = selected_window(runtime);
    return_creation_callback(runtime, host, 1).unwrap();
    return_creation_callback(runtime, host, 0).unwrap();
    assert_eq!(project_creation(runtime, host).unwrap().0, u32::from(window));
    window
}

#[test]
fn class_menu_long_preserves_far_bits_copies_dbcs_and_clears_default() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = registered_class(&mut runtime, &mut host);
    let first = window(&mut runtime, class, 1);
    let second = window(&mut runtime, class, 2);
    assert_eq!(call(&mut runtime, &mut host, 131, first, GCL_MENUNAME, None), 0);
    for id in [7_u16, 0x8001, u16::MAX] {
        let previous = call(&mut runtime, &mut host, 131, second, GCL_MENUNAME, None);
        assert_eq!(call(&mut runtime, &mut host, 132, first, GCL_MENUNAME, Some(id.into())), previous);
        assert_eq!(call(&mut runtime, &mut host, 131, second, GCL_MENUNAME, None), u32::from(id));
        assert_eq!(menu_name(&runtime, class), Some(Win16ResourceName::Id(id)));
    }
    let pointer = put_string(&mut runtime, &[0x82, 0xa0, b'M', 0]);
    assert_eq!(call(&mut runtime, &mut host, 132, first, GCL_MENUNAME, Some(pointer)), 0xffff);
    assert_eq!(call(&mut runtime, &mut host, 131, second, GCL_MENUNAME, None), pointer);
    put_string(&mut runtime, b"reused\0");
    assert_eq!(menu_name(&runtime, class), Some(Win16ResourceName::Name(vec![0x82, 0xa0, b'M'])));
    assert_eq!(call(&mut runtime, &mut host, 132, second, GCL_MENUNAME, Some(pointer)), pointer);
    assert_eq!(menu_name(&runtime, class), Some(Win16ResourceName::Name(b"reused".to_vec())));
    assert_eq!(call(&mut runtime, &mut host, 132, second, GCL_MENUNAME, Some(0)), pointer);
    assert_eq!(menu_name(&runtime, class), None);
    assert_eq!(call(&mut runtime, &mut host, 131, first, GCL_MENUNAME, None), 0);
    assert!(host.diagnostics.is_empty());
}

#[test]
fn class_menu_invalid_or_unreadable_far_is_atomic_and_readback_never_dereferences_old_far() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = registered_class(&mut runtime, &mut host);
    let hwnd = window(&mut runtime, class, 1);
    let base = PhysAddr(0x88000);
    runtime.memory.write(base, b"Menu\0").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let readable = state.selectors.alloc_block(base, 5, AccessRights::read_only(), &runtime.memory).unwrap();
    let pointer = state.selectors.pointer_from_raw(readable.raw(), 0).unwrap().far_value();
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_MENUNAME, Some(pointer)), 0);
    runtime.win16.as_mut().unwrap().selectors.free_block(readable).unwrap();
    assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_MENUNAME, None), pointer);
    let state = runtime.win16.as_mut().unwrap();
    let unreadable = state.selectors.alloc_block(base, 5,
        AccessRights::new(false, true, false), &runtime.memory).unwrap();
    let short = state.selectors.alloc_block(base, 4, AccessRights::read_only(), &runtime.memory).unwrap();
    let unreadable = state.selectors.pointer_from_raw(unreadable.raw(), 0).unwrap().far_value();
    let short = state.selectors.pointer_from_raw(short.raw(), 0).unwrap().far_value();
    // Selector reuse is observable: invalidity must not rely on a freed raw
    // word remaining absent. A short view excludes the string's terminating NUL.
    for candidate in [0x0001_0000, 0xffff_ffff, unreadable, short, short | 0xffff] {
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_MENUNAME, Some(candidate)), 0);
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_MENUNAME, None), pointer);
        assert_eq!(menu_name(&runtime, class), Some(Win16ResourceName::Name(b"Menu".to_vec())));
    }
    assert!(host.diagnostics.is_empty());
}

#[test]
fn class_menu_creation_loads_replacement_numeric_and_named_resources() {
    let mut runtime = fixture();
    let mut class_host = ClassDataHost::default();
    let class = registered_class(&mut runtime, &mut class_host);
    let hwnd = window(&mut runtime, class, 1);
    let main = runtime.win16.as_ref().unwrap().modules.main;
    add_menu(&mut runtime, main, NeResourceId::Numeric(7), 101);
    add_menu(&mut runtime, main, NeResourceId::Name(b"CHANGED".to_vec()), 202);
    let pointer = put_string(&mut runtime, b"changed\0");
    for (sequence, replacement, command) in [(0, 7, 101), (1, pointer, 202)] {
        call(&mut runtime, &mut class_host, 132, hwnd, GCL_MENUNAME, Some(replacement));
        let mut host = CreationHost::new(0x2000 + sequence);
        begin_menu_creation(&mut runtime, &mut host, class, class.info.h_instance, 0, 0, 0);
        assert_eq!(menu_command(&host.creations[0].class_menu_template), Some(command));
        assert_eq!(host.creations[0].menu, None);
        finish_menu_creation(&mut runtime, &mut host);
    }
    assert!(class_host.diagnostics.is_empty());
}

#[test]
fn class_menu_explicit_menu_and_child_id_skip_missing_class_resource() {
    for child in [false, true] {
        let mut runtime = fixture();
        let mut class_host = ClassDataHost::default();
        let class = registered_class(&mut runtime, &mut class_host);
        let hwnd = window(&mut runtime, class, 1);
        call(&mut runtime, &mut class_host, 132, hwnd, GCL_MENUNAME, Some(0x7777));
        let explicit = Win16HostMenu(0xfeed_cafe_1234);
        let menu = if child { 77 } else {
            runtime.win16.as_mut().unwrap().guest_menus.intern(explicit).unwrap()
        };
        let mut host = CreationHost::new(0x3000);
        begin_menu_creation(&mut runtime, &mut host, class, class.info.h_instance,
            if child { 0x4000_0000 } else { 0 }, menu, if child { hwnd } else { 0 });
        let data = &host.creations[0];
        assert!(data.class_menu_template.is_none());
        assert_eq!(data.menu, (!child).then_some(explicit));
        assert_eq!(data.child_id, child.then_some(77));
        finish_menu_creation(&mut runtime, &mut host);
    }
}

#[test]
fn class_menu_nested_replacement_keeps_outer_creation_menu_snapshots() {
    let mut runtime = fixture();
    let mut class_host = ClassDataHost::default();
    let class = registered_class(&mut runtime, &mut class_host);
    let hwnd = window(&mut runtime, class, 1);
    let main = runtime.win16.as_ref().unwrap().modules.main;
    add_menu(&mut runtime, main, NeResourceId::Numeric(7), 101);
    add_menu(&mut runtime, main, NeResourceId::Numeric(8), 202);
    call(&mut runtime, &mut class_host, 132, hwnd, GCL_MENUNAME, Some(7));
    let mut outer = CreationHost::new(0x4000);
    begin_menu_creation(&mut runtime, &mut outer, class, class.info.h_instance, 0, 0, 0);
    let outer_window = selected_window(&runtime);
    let outer_stack = runtime.cpu.regs.sp();
    runtime.cpu.regs.set_sp(outer_stack - 12);
    assert_eq!(call(&mut runtime, &mut class_host, 132, outer_window, GCL_MENUNAME, Some(8)), 7);
    runtime.cpu.regs.set_sp(outer_stack - 34);
    let mut nested = CreationHost::new(0x5000);
    begin_menu_creation(&mut runtime, &mut nested, class, class.info.h_instance, 0, 0, 0);
    assert_eq!(menu_command(&outer.creations[0].class_menu_template), Some(101));
    assert_eq!(menu_command(&nested.creations[0].class_menu_template), Some(202));
    let nested_window = finish_menu_creation(&mut runtime, &mut nested);
    assert_eq!(runtime.cpu.regs.sp(), outer_stack);
    assert_eq!(selected_window(&runtime), outer_window);
    assert_eq!(finish_menu_creation(&mut runtime, &mut outer), outer_window);
    assert_ne!(nested_window, outer_window);
    assert_eq!(menu_command(&outer.creations[0].class_menu_template), Some(101));
    assert!(runtime.win16.as_ref().unwrap().window_handles.contains_key(&nested_window));
    assert_eq!(call(&mut runtime, &mut class_host, 132, hwnd, GCL_MENUNAME, Some(0)), 8);
    assert!(outer.creations[0].class_menu_template.is_some());
    assert!(nested.creations[0].class_menu_template.is_some());
    let mut cleared = CreationHost::new(0x6000);
    begin_menu_creation(&mut runtime, &mut cleared, class, class.info.h_instance, 0, 0, 0);
    assert!(cleared.creations[0].class_menu_template.is_none());
    finish_menu_creation(&mut runtime, &mut cleared);
}

#[test]
fn class_menu_custom_dialog_default_and_explicit_menu_keep_independent_prepared_templates() {
    use crate::{Win16HostDialogAtom as Atom, Win16HostDialogTemplate};
    use crate::win16_runtime::user_services_controls::Win16UserFamilyPreparation as Prepared;
    use win16_abi::{Win16UserFamilyRequest, Win16UserDialogRequest, Win16DialogTemplateRef};
    fn prepare(runtime: &mut Runtime, host: &mut ClassDataHost, instance: u16,
        explicit: Option<u16>,
    ) -> Win16HostDialogTemplate {
        let mut bytes = vec![0; 13]; // style, no items, rectangle
        if let Some(menu) = explicit { bytes.push(0xff); bytes.extend_from_slice(&menu.to_le_bytes()); }
        else { bytes.push(0); }
        bytes.extend_from_slice(b"MenuDialog\0\0"); // custom class, empty caption
        let template = put_string(runtime, &bytes);
        let prepared = runtime.win16.as_mut().unwrap().prepare_user_family(
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::Create {
                template: Win16DialogTemplateRef::FarAddress { instance, template },
                owner: 0, procedure: 0, modal: false, init_parameter: 0,
            }), &mut runtime.memory, host, Win16ReturnKind::Word).unwrap();
        let Prepared::WindowService { operation: crate::Win16HostUserServiceOperation::Dialog(
            crate::Win16HostDialogOperation::Create { template, .. }), .. } = prepared
            else { panic!("expected prepared custom dialog creation"); };
        template
    }
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let mut info = class_info(&runtime, 0);
    info.cb_wnd_extra = 30;
    let class = register(&mut runtime, &mut host, info, Win16ClassName::Name(b"MenuDialog".to_vec()));
    let hwnd = window(&mut runtime, class, 1);
    let main = runtime.win16.as_ref().unwrap().modules.main;
    add_menu(&mut runtime, main, NeResourceId::Numeric(7), 101);
    add_menu(&mut runtime, main, NeResourceId::Numeric(8), 202);
    add_menu(&mut runtime, main, NeResourceId::Numeric(99), 303);
    call(&mut runtime, &mut host, 132, hwnd, GCL_MENUNAME, Some(7));
    let prepared = prepare(&mut runtime, &mut host, class.info.h_instance, None);
    assert_eq!(menu_command(&prepared.menu_template), Some(101));
    call(&mut runtime, &mut host, 132, hwnd, GCL_MENUNAME, Some(8));
    let changed = prepare(&mut runtime, &mut host, class.info.h_instance, None);
    assert_eq!(menu_command(&changed.menu_template), Some(202));
    assert_eq!(menu_command(&prepared.menu_template), Some(101));
    let explicit = prepare(&mut runtime, &mut host, class.info.h_instance, Some(99));
    assert_eq!(explicit.menu, Atom::Ordinal(99));
    assert_eq!(menu_command(&explicit.menu_template), Some(303));
}

#[test]
fn class_menu_missing_resource_rejects_creation_but_remains_a_valid_default_value() {
    let mut runtime = fixture();
    let mut class_host = ClassDataHost::default();
    let class = registered_class(&mut runtime, &mut class_host);
    let hwnd = window(&mut runtime, class, 1);
    assert_eq!(call(&mut runtime, &mut class_host, 132, hwnd, GCL_MENUNAME, Some(99)), 0);
    let mut host = CreationHost::new(0x7000);
    begin_menu_creation(&mut runtime, &mut host, class, class.info.h_instance, 0, 0, 0);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert!(host.creations.is_empty(), "missing default must not enter native creation");
    assert!(runtime.win16.as_ref().unwrap().window_callbacks.is_empty());
    assert_eq!(call(&mut runtime, &mut class_host, 131, hwnd, GCL_MENUNAME, None), 99);
    assert_eq!(menu_name(&runtime, class), Some(Win16ResourceName::Id(99)));
}
