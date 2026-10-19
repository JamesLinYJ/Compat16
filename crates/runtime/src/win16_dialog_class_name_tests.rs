//! Class resolution precedes control-specific resource interpretation.
use super::*;

#[test]
fn dialog_icon_title_standard_class_names_prepare_all_template_sources() {
    for (ordinal, name) in [
        (0x80, b"bUtToN".as_slice()),
        (0x81, b"EDIT"),
        (0x82, b"Static"),
        (0x83, b"LISTBOX"),
        (0x84, b"SCROLLBAR"),
        (0x85, b"COMBOBOX"),
    ] {
        for modal in [false, true] {
            for source_id in 0..3 {
                let (mut runtime, instance) = fixture();
                let icon_name = b"\x82\xa0Icon";
                name_group(&mut runtime, icon_name);
                let mut host = IconHost::default();
                let bytes =
                    dialog_bytes_with_classes(true, Some(icon_name), Some([b"sTaTiC", name]));
                let reference = source_bytes(&mut runtime, instance, source_id, &mut host, &bytes);
                let prepared = runtime
                    .win16
                    .as_mut()
                    .unwrap()
                    .prepare_dialog_family(
                        DialogRequest::Create {
                            template: reference,
                            owner: 0,
                            procedure: 0,
                            modal,
                            init_parameter: 0,
                        },
                        &mut runtime.memory,
                        &mut host,
                        Win16ReturnKind::Word,
                    )
                    .unwrap();
                let Win16UserFamilyPreparation::WindowService { operation, .. } = prepared else {
                    panic!("standard class names must reach dialog creation");
                };
                let Win16HostUserServiceOperation::Dialog(DialogOperation::Create {
                    template, ..
                }) = operation
                else {
                    panic!("expected native dialog request");
                };
                assert_eq!(template.items[0].class, Atom::Ordinal(0x82));
                assert_eq!(template.items[0].guest_class_name, None);
                assert_eq!(template.items[0].initial_icon, Some(Win16HostIcon(0x1234)));
                assert_eq!(template.items[0].title, Atom::None);
                assert_eq!(template.items[1].class, Atom::Ordinal(ordinal));
                assert_eq!(
                    template.items[1].title,
                    Atom::String(vec![0x82, 0xa0, b'!'])
                );
                assert_eq!((host.selected, host.created), (1, 1));
            }
        }
    }
}

fn register_static(
    runtime: &mut Runtime,
    host: &mut IconHost,
    instance: u16,
    global: bool,
) -> crate::Win16HostClass {
    let info = win16_abi::WndClass16 {
        style: if global { 0x4000 } else { 0 },
        lpfn_wnd_proc: (u32::from(runtime.cpu.regs.cs) << 16) | 0x20,
        h_instance: instance,
        ..win16_abi::WndClass16::default()
    };
    let atom = runtime
        .win16
        .as_mut()
        .unwrap()
        .register_class(
            info,
            win16_abi::Win16ClassName::Name(b"STATIC".to_vec()),
            None,
            &runtime.memory,
            host,
        )
        .unwrap();
    assert_ne!(atom, 0);
    host.classes.last().unwrap().class
}

#[test]
fn dialog_icon_title_registered_static_name_keeps_guest_class_and_title() {
    for local in [false, true] {
        let (mut runtime, instance) = fixture();
        let mut host = IconHost::default();
        let global_class = register_static(&mut runtime, &mut host, instance, true);
        let expected = if local {
            register_static(&mut runtime, &mut host, instance, false)
        } else {
            global_class
        };
        let bytes =
            dialog_bytes_with_classes(true, Some(b"Guest title"), Some([b"sTaTiC", b"BUTTON"]));
        let reference = source_bytes(&mut runtime, instance, 0, &mut host, &bytes);
        let prepared = runtime
            .win16
            .as_mut()
            .unwrap()
            .prepare_dialog_family(
                DialogRequest::Create {
                    template: reference,
                    owner: 0,
                    procedure: 0,
                    modal: false,
                    init_parameter: 0,
                },
                &mut runtime.memory,
                &mut host,
                Win16ReturnKind::Word,
            )
            .unwrap();
        let Win16UserFamilyPreparation::WindowService {
            operation,
            continuation,
        } = prepared
        else {
            panic!("registered STATIC must keep its guest route");
        };
        let Win16HostUserServiceOperation::Dialog(DialogOperation::Create { template, .. }) =
            operation
        else {
            panic!("expected native dialog request");
        };
        assert_eq!(template.items[0].class, Atom::GuestClass(expected));
        assert_eq!(
            template.items[0].guest_class_name,
            Some(crate::Win16HostClassName::Name(b"sTaTiC".to_vec()))
        );
        assert_eq!(
            template.items[0].title,
            Atom::String(b"Guest title".to_vec())
        );
        assert_eq!(template.items[0].initial_icon, None);
        assert_eq!((host.selected, host.created), (0, 0));
        let FamilyCompletion::DialogCreate { class_routes, .. } = continuation.completion else {
            panic!("expected class creation continuation");
        };
        assert_eq!(class_routes.len(), 1);
        assert_eq!(class_routes[0].host_class, expected);
        assert_eq!(class_routes[0].control_id, Some(10));
        assert!(!class_routes[0].root);
    }
}

#[test]
fn dialog_icon_title_unknown_class_is_rejected_before_image_preparation() {
    for modal in [false, true] {
        for source_id in 0..3 {
            let (mut runtime, instance) = fixture();
            let mut host = IconHost::default();
            let bytes =
                dialog_bytes_with_classes(true, None, Some([b"STATIC", b"UnregisteredChild"]));
            let reference = source_bytes(&mut runtime, instance, source_id, &mut host, &bytes);
            let prepared = runtime
                .win16
                .as_mut()
                .unwrap()
                .prepare_dialog_family(
                    DialogRequest::Create {
                        template: reference.clone(),
                        owner: 0,
                        procedure: 0,
                        modal,
                        init_parameter: 0,
                    },
                    &mut runtime.memory,
                    &mut host,
                    Win16ReturnKind::Word,
                )
                .unwrap();
            let Win16UserFamilyPreparation::Immediate {
                value,
                window_creation_observation,
                ..
            } = prepared
            else {
                panic!("unknown class must not enter native creation");
            };
            assert_eq!(value, if modal { u32::from(u16::MAX) } else { 0 });
            if let Some(observation) = window_creation_observation {
                assert!(!modal);
                assert_eq!(
                    observation.preflight_rejection,
                    Some(crate::Win16WindowCreationRejection::GuestClassUnavailable)
                );
                assert_eq!(
                    observation.native_api_return,
                    crate::Win16NativeWindowApiReturn::NotInvoked
                );
                assert_eq!(observation.dialog_template, Some(reference));
            } else {
                assert!(modal);
            }
            assert_eq!((host.selected, host.created), (0, 0));
        }
    }
}
