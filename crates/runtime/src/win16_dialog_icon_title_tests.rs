//! Guest icon titles use typed resources before the native dialog boundary.
use super::*;
use crate::win16_runtime::{test_support::tiny_ne_executable, user_services_dialog::parse_win16_dialog_template};
use crate::{Runtime, Win16HostDialogAtom as Atom, Win16HostIcon};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};

#[derive(Default)]
struct IconHost { selected: usize, created: usize, reject: bool }
impl DosHost for IconHost {
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

impl RuntimeHost for IconHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
    fn win16_select_icon_image(&mut self, group: &[u8]) -> Result<Option<u16>, RuntimeError> {
        assert_eq!(group, group_bytes());
        self.selected += 1;
        Ok(Some(9))
    }
    fn win16_create_icon(&mut self, image: &[u8]) -> Result<Option<Win16HostIcon>, RuntimeError> {
        assert_eq!(image, b"mock icon image");
        self.created += 1;
        Ok((!self.reject).then_some(Win16HostIcon(0x1234)))
    }
}
impl crate::RuntimeDdeHost for IconHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for IconHost {}
impl crate::RuntimeMidiHost for IconHost {}
impl crate::RuntimeNetbiosHost for IconHost {}

fn group_bytes() -> Vec<u8> {
    let mut group = vec![0; 20];
    group[2] = 1;
    group[4] = 1;
    group[18] = 9;
    group
}

fn dialog_bytes(icon: bool) -> Vec<u8> {
    dialog_bytes_with_title(icon, None)
}

fn dialog_bytes_with_title(icon: bool, name: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = 0_u32.to_le_bytes().to_vec();
    bytes.push(2);
    bytes.extend_from_slice(&[0; 8]); // dialog rectangle
    bytes.extend_from_slice(&[0; 3]); // no menu, standard class, empty title
    for index in 0..2_u16 {
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&(10 + index).to_le_bytes());
        bytes.extend_from_slice(&(if icon && index == 0 { 3_u32 } else { 0 }).to_le_bytes());
        bytes.push(0x82);
        if let Some(name) = name.filter(|_| index == 0) {
            bytes.extend_from_slice(name);
            bytes.push(0);
        } else {
            bytes.extend_from_slice(&[0xff, 7, 0]); // title ordinal 7
        }
        bytes.push(0); // no creation bytes
    }
    bytes
}

fn add_resource(runtime: &mut Runtime, kind: u16, id: u16, payload: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let record = state.modules.records.get_mut(&state.modules.main).unwrap();
    let offset = record.image.len();
    record.image.extend_from_slice(payload);
    let definition = record.definition.as_mut().unwrap();
    definition.header.resource_table_offset = 0x100;
    definition.resource_types.push(formats::NeResourceType {
        id: formats::NeResourceId::Numeric(kind),
        resources: vec![formats::NeResource {
            id: formats::NeResourceId::Numeric(id), file_offset: offset,
            byte_length: payload.len(), flags: 0, handle: 0, usage: 0,
        }],
    });
}

fn fixture() -> (Runtime, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\ICONS.NE").unwrap();
    let instance = runtime.win16.as_ref().unwrap().modules.records[
        &runtime.win16.as_ref().unwrap().modules.main].instance;
    add_resource(&mut runtime, 14, 7, &group_bytes());
    add_resource(&mut runtime, 3, 9, b"mock icon image");
    let mut strings = vec![0; 7];
    strings.extend_from_slice(&[3, 0x82, 0xa0, b'!']); // original DBCS bytes
    strings.extend_from_slice(&[0; 8]);
    add_resource(&mut runtime, 6, 1, &strings);
    (runtime, instance)
}

fn name_group(runtime: &mut Runtime, name: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    state.modules.records.get_mut(&state.modules.main).unwrap()
        .definition.as_mut().unwrap().resource_types[0].resources[0].id =
        formats::NeResourceId::Name(name.to_vec());
}

#[test]
fn dialog_icon_title_named_groups_keep_ansi_bytes_and_share_load_icon_cache() {
    for name in [b"NamedIcon".as_slice(), b"\x82\xa0Icon".as_slice()] {
        let (mut runtime, instance) = fixture();
        name_group(&mut runtime, name);
        let mut host = IconHost::default();
        let state = runtime.win16.as_mut().unwrap();
        for lookup in [name.to_vec(), name.to_ascii_uppercase()] {
            let mut template = parse_win16_dialog_template(
                &dialog_bytes_with_title(true, Some(&lookup))).unwrap();
            assert_eq!(template.items[0].title, Atom::String(lookup.clone()));
            assert!(state.resolve_dialog_template_titles(&mut template, instance, &mut host).unwrap());
            assert_eq!(template.items[0].initial_icon, Some(Win16HostIcon(0x1234)));
            assert_eq!(template.items[0].title, Atom::None);
            let handle = state.load_icon(instance, win16_abi::Win16ResourceName::Name(lookup),
                &mut host).unwrap();
            assert_eq!(state.guest_images.icon(handle), Some(Win16HostIcon(0x1234)));
            assert_eq!(template.items[1].title, Atom::String(vec![0x82, 0xa0, b'!']));
        }
        assert_eq!((host.selected, host.created), (1, 1));
    }
}

#[test]
fn dialog_icon_title_missing_named_groups_never_use_numeric_or_host_resources() {
    for instance_source in 0..3 {
        let (mut runtime, instance) = fixture();
        let mut host = IconHost::default();
        let mut template = parse_win16_dialog_template(
            &dialog_bytes_with_title(true, Some(b"MissingIcon"))).unwrap();
        let original = template.clone();
        let instance = match instance_source { 0 => instance, 1 => 0, _ => 0xffff };
        assert!(!runtime.win16.as_mut().unwrap().resolve_dialog_template_titles(
            &mut template, instance, &mut host).unwrap());
        assert_eq!(template, original);
        assert_eq!((host.selected, host.created), (0, 0));
    }
}

#[test]
fn dialog_icon_title_ordinal_wins_over_same_id_string_and_preserves_text_bytes() {
    let (mut runtime, instance) = fixture();
    let mut host = IconHost::default();
    let state = runtime.win16.as_mut().unwrap();
    let mut template = parse_win16_dialog_template(&dialog_bytes(true)).unwrap();
    assert!(template.items.iter().all(|item| item.initial_icon.is_none()));
    assert!(state.resolve_dialog_template_titles(&mut template, instance, &mut host).unwrap());
    assert_eq!(template.items[0].initial_icon, Some(Win16HostIcon(0x1234)));
    assert_eq!(template.items[0].title, Atom::None);
    assert_eq!(template.items[1].title, Atom::String(vec![0x82, 0xa0, b'!']));
    assert_eq!(template.items[1].initial_icon, None);
    let mut second = parse_win16_dialog_template(&dialog_bytes(true)).unwrap();
    assert!(state.resolve_dialog_template_titles(&mut second, instance, &mut host).unwrap());
    assert_eq!((host.selected, host.created), (1, 1)); // LoadIcon module cache
}

#[test]
fn dialog_icon_title_unsupported_routes_reject_before_icon_host_calls() {
    for case in 0..6 {
        let (mut runtime, instance) = fixture();
        let mut host = IconHost::default();
        let mut template = parse_win16_dialog_template(&dialog_bytes(true)).unwrap();
        match case {
            0 => template.class = Atom::String(b"CustomRoot".to_vec()),
            1 => template.items[1].class = Atom::String(b"CustomChild".to_vec()),
            2 => template.items[0].class = Atom::String(b"STATIC".to_vec()),
            3 => template.items[0].creation_data.push(1),
            4 => template.style |= 0x10, // DS_NOFAILCREATE
            _ => template.items[0].guest_class_name = Some(crate::Win16HostClassName::Atom(0x82)),
        }
        assert!(!runtime.win16.as_mut().unwrap().resolve_dialog_template_titles(
            &mut template, instance, &mut host).unwrap());
        assert_eq!((host.selected, host.created), (0, 0));
        assert!(template.items.iter().all(|item| item.initial_icon.is_none()));
    }
}

#[test]
fn dialog_icon_title_missing_and_rejected_resources_never_use_string_fallback() {
    for case in 0..3 {
        let (mut runtime, instance) = fixture();
        let mut host = IconHost { reject: case == 2, ..Default::default() };
        let state = runtime.win16.as_mut().unwrap();
        let record = state.modules.records.get_mut(&state.modules.main).unwrap();
        if case < 2 {
            record.definition.as_mut().unwrap().resource_types.retain(|entry|
                entry.id != formats::NeResourceId::Numeric(if case == 0 { 14 } else { 3 }));
        }
        let mut template = parse_win16_dialog_template(&dialog_bytes(true)).unwrap();
        assert!(!state.resolve_dialog_template_titles(&mut template, instance, &mut host).unwrap());
        assert_eq!(template.items[0].title, Atom::Ordinal(7));
        assert_eq!(template.items[0].initial_icon, None);
        assert_eq!(host.created, usize::from(case == 2));
    }
}

#[test]
fn dialog_icon_title_bad_group_reports_error_without_host_creation() {
    let (mut runtime, instance) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let record = state.modules.records.get_mut(&state.modules.main).unwrap();
    let offset = record.definition.as_ref().unwrap().resource_types[0].resources[0].file_offset;
    record.image[offset + 2] = 2; // cursor directory cannot masquerade as icon
    let mut host = IconHost::default();
    let mut template = parse_win16_dialog_template(&dialog_bytes(true)).unwrap();
    assert!(state.resolve_dialog_template_titles(&mut template, instance, &mut host).is_err());
    assert_eq!((host.selected, host.created), (0, 0));
}

#[test]
fn dialog_icon_title_non_icon_templates_keep_existing_title_semantics() {
    let (mut runtime, instance) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let mut host = IconHost::default();
    let mut template = parse_win16_dialog_template(&dialog_bytes(false)).unwrap();
    template.class = Atom::String(b"CustomRoot".to_vec());
    template.items[1].class = Atom::String(b"CustomChild".to_vec());
    template.items[1].title = Atom::String(b"unchanged".to_vec());
    template.items[1].creation_data = vec![1, 2];
    template.style |= 0x10;
    let unchanged = template.items[1].clone();
    assert!(state.resolve_dialog_template_titles(&mut template, instance, &mut host).unwrap());
    assert_eq!(template.items[0].title, Atom::String(vec![0x82, 0xa0, b'!']));
    assert_eq!(template.items[1], unchanged);
    assert_eq!((host.selected, host.created), (0, 0));
}

fn source(runtime: &mut Runtime, instance: u16, source: u8, host: &mut IconHost)
    -> Win16DialogTemplateRef
{
    let bytes = dialog_bytes(true);
    source_bytes(runtime, instance, source, host, &bytes)
}

fn source_bytes(runtime: &mut Runtime, instance: u16, source: u8, host: &mut IconHost,
    bytes: &[u8]) -> Win16DialogTemplateRef
{
    match source {
        0 => {
            add_resource(runtime, 5, 11, bytes);
            Win16DialogTemplateRef::Resource { instance, name: win16_abi::Win16ResourceName::Id(11) }
        }
        1 => {
            let state = runtime.win16.as_mut().unwrap();
            let handle = state.global_alloc(2, bytes.len() as u32, &mut runtime.memory, host).unwrap();
            assert_ne!(handle, 0);
            let far = state.global_lock(handle, &runtime.memory).unwrap();
            let pointer = state.selectors.pointer_from_far(far).unwrap();
            state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
            state.global_unlock(handle).unwrap();
            Win16DialogTemplateRef::GlobalHandle { instance, template: handle }
        }
        _ => {
            let far = u32::from(runtime.cpu.regs.ds) << 16;
            let state = runtime.win16.as_mut().unwrap();
            let pointer = state.selectors.pointer_from_far(far).unwrap();
            state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
            Win16DialogTemplateRef::FarAddress { instance, template: far }
        }
    }
}

#[test]
fn dialog_icon_title_named_resources_prepare_every_modal_and_modeless_source() {
    for modal in [false, true] {
        for source_id in 0..3 {
            let (mut runtime, instance) = fixture();
            let name = b"\x82\xa0Icon";
            name_group(&mut runtime, name);
            let mut host = IconHost::default();
            let reference = source_bytes(&mut runtime, instance, source_id, &mut host,
                &dialog_bytes_with_title(true, Some(name)));
            let prepared = runtime.win16.as_mut().unwrap().prepare_dialog_family(
                DialogRequest::Create { template: reference.clone(), owner: 0, procedure: 0,
                    modal, init_parameter: 0x5678 },
                &mut runtime.memory, &mut host, Win16ReturnKind::Word).unwrap();
            let Win16UserFamilyPreparation::WindowService { operation, continuation } = prepared
                else { panic!("named icon must reach native dialog creation"); };
            let Win16HostUserServiceOperation::Dialog(DialogOperation::Create {
                template, modal: actual_modal, init_parameter, ..
            }) = operation else { panic!("expected native dialog request"); };
            assert_eq!(actual_modal, modal);
            assert_eq!(init_parameter, 0x5678);
            assert_eq!(template.items[0].initial_icon, Some(Win16HostIcon(0x1234)));
            assert_eq!(template.items[0].title, Atom::None);
            let FamilyCompletion::DialogCreate { template_reference, .. } = continuation.completion
                else { panic!("lost dialog continuation"); };
            assert_eq!(template_reference, reference);
            assert_eq!((host.selected, host.created), (1, 1));
        }
    }
}

#[test]
fn dialog_icon_title_prepares_modal_modeless_resource_global_and_far_requests() {
    for modal in [false, true] {
        for source_id in 0..3 {
            let (mut runtime, instance) = fixture();
            let mut host = IconHost::default();
            let reference = source(&mut runtime, instance, source_id, &mut host);
            let prepared = runtime.win16.as_mut().unwrap().prepare_dialog_family(
                DialogRequest::Create { template: reference.clone(), owner: 0, procedure: 0,
                    modal, init_parameter: 0x5678 },
                &mut runtime.memory, &mut host, Win16ReturnKind::Word).unwrap();
            let Win16UserFamilyPreparation::WindowService { operation, continuation } = prepared
                else { panic!("valid icon resource must reach a real host operation"); };
            let Win16HostUserServiceOperation::Dialog(DialogOperation::Create {
                template, modal: actual_modal, init_parameter, ..
            }) = operation else { panic!("expected native dialog request"); };
            assert_eq!(actual_modal, modal);
            assert_eq!(init_parameter, 0x5678);
            assert_eq!(template.items[0].initial_icon, Some(Win16HostIcon(0x1234)));
            assert_eq!(template.items[0].title, Atom::None);
            assert_eq!(template.items[1].title, Atom::String(vec![0x82, 0xa0, b'!']));
            let FamilyCompletion::DialogCreate { template_reference, .. } = continuation.completion
                else { panic!("lost dialog continuation"); };
            assert_eq!(template_reference, reference);
            assert_eq!((host.selected, host.created), (1, 1));
            // Preparation does not invoke USER or invent a successful HWND.
        }
    }
}

#[test]
fn dialog_icon_title_failed_preparation_reports_not_invoked_for_every_source() {
    for modal in [false, true] {
        for source_id in 0..3 {
            let (mut runtime, instance) = fixture();
            let mut host = IconHost { reject: true, ..Default::default() };
            let reference = source(&mut runtime, instance, source_id, &mut host);
            let prepared = runtime.win16.as_mut().unwrap().prepare_dialog_family(
                DialogRequest::Create { template: reference.clone(), owner: 0, procedure: 0,
                    modal, init_parameter: 0 },
                &mut runtime.memory, &mut host, Win16ReturnKind::Word).unwrap();
            let Win16UserFamilyPreparation::Immediate { value, window_creation_observation, .. } = prepared
                else { panic!("rejected icon must not enter native USER"); };
            assert_eq!(value, if modal { u32::from(u16::MAX) } else { 0 });
            if modal { assert!(window_creation_observation.is_none()); }
            else {
                let observation = window_creation_observation.unwrap();
                assert_eq!(observation.native_api_return, crate::Win16NativeWindowApiReturn::NotInvoked);
                assert_eq!(observation.preflight_rejection,
                    Some(crate::Win16WindowCreationRejection::UnsupportedControlTitleResource));
                assert_eq!(observation.live_window, None);
                assert_eq!(observation.guest_window, 0);
                assert_eq!(observation.dialog_template, Some(reference));
            }
            assert_eq!((host.selected, host.created), (1, 1));
        }
    }
}

#[test]
fn dialog_icon_title_native_type_13_rejects_without_string_fallback() {
    for class in [Atom::Ordinal(0x82), Atom::String(b"STATIC".to_vec())] {
        let (mut runtime, instance) = fixture();
        let mut host = IconHost::default();
        let mut template = parse_win16_dialog_template(&dialog_bytes(true)).unwrap();
        template.items[0].class = class;
        template.items[0].style = 0x13;
        let original = template.clone();
        assert!(!runtime.win16.as_mut().unwrap().resolve_dialog_template_titles(
            &mut template, instance, &mut host).unwrap());
        assert_eq!(template, original);
        assert_eq!((host.selected, host.created), (0, 0));
    }
}
