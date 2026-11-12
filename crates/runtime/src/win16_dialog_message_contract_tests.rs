//! Boundary results for IsDialogMessage, DefDlgProc, and dialog-procedure messages.
//!
//! WM_NEXTDLGCTL follows the published low-word rule: a nonzero low word is a
//! control HWND16, and a zero low word is a direction. The high word is not
//! the mode flag, so it never becomes a native pointer.

use crate::win16_runtime::test_support::{NoHost, tiny_ne_executable};
use crate::win16_runtime::user_services_controls::Win16UserFamilyPreparation;
use crate::win16_runtime::window_payloads::GuestWindowPayload;
use crate::win16_runtime::windows::{
    WindowCallbackContinuation, WindowCallbackFrame, WindowClassRoot,
};
use crate::{
    Runtime, Win16HostCallback, Win16HostDialogOperation, Win16HostMessage, Win16HostQueuedMessage,
    Win16HostUserServiceOperation, Win16HostWindow, Win16MessageParam, Win16ScalarMessage,
    Win16WindowInputMessage,
};
use win16_abi::{Win16ReturnKind, Win16UserDialogRequest, Win16UserFamilyRequest, user_abi::Msg16};

const WM_KEYDOWN: u16 = 0x0100;
const WM_INITDIALOG: u16 = 0x0110;
const WM_NEXTDLGCTL: u16 = 0x0028;
const DM_GETDEFID: u16 = 0x0400;
const DC_HASDEFID: u32 = 0x534B;
const VK_RETURN: u16 = 0x0D;
const VK_ESCAPE: u16 = 0x1B;

fn runtime() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\DIALOGMSG.NE").unwrap()
}

fn map_window(runtime: &mut Runtime, native: u64, dialog: bool) -> (u16, Win16HostWindow) {
    let token = Win16HostWindow(native);
    let state = runtime.win16.as_mut().unwrap();
    let hwnd = state.allocate_window_handle(token).unwrap();
    if dialog {
        state.initialize_dialog_window_data(hwnd, 0).unwrap();
    }
    (hwnd, token)
}

fn push_callback(
    runtime: &mut Runtime,
    hwnd: u16,
    native: Win16HostWindow,
    message: u16,
    w_param: u16,
    l_param: u32,
) {
    let saved = runtime.cpu.regs.clone();
    let state = runtime.win16.as_mut().unwrap();
    state.window_callbacks.push(WindowCallbackFrame::guest(
        crate::win16_runtime::CallbackFrameId(1),
        saved,
        GuestWindowPayload {
            message,
            w_param,
            l_param,
            allocation: None,
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        },
        None,
        0,
        WindowClassRoot::Unresolved,
        None,
        None,
        WindowCallbackContinuation::HostDialog {
            callback: Win16HostCallback(7),
            native_window: native,
            window: hwnd,
            destroyed: false,
        },
    ));
}

fn prepare(
    runtime: &mut Runtime,
    request: Win16UserFamilyRequest,
    return_kind: Win16ReturnKind,
) -> Win16UserFamilyPreparation {
    let state = runtime.win16.as_mut().unwrap();
    state
        .prepare_user_family(request, &mut runtime.memory, &mut NoHost, return_kind)
        .unwrap()
}

fn assert_immediate(prepared: Win16UserFamilyPreparation, value: u32) {
    match prepared {
        Win16UserFamilyPreparation::Immediate { value: actual, .. } => assert_eq!(actual, value),
        Win16UserFamilyPreparation::WindowService { .. } => {
            panic!("dialog call reached the host")
        }
        Win16UserFamilyPreparation::TerminateTask { .. } => panic!("dialog call ended the task"),
    }
}

fn is_message(prepared: Win16UserFamilyPreparation) -> Win16HostQueuedMessage {
    match prepared {
        Win16UserFamilyPreparation::WindowService {
            operation:
                Win16HostUserServiceOperation::Dialog(Win16HostDialogOperation::IsMessage {
                    message,
                    ..
                }),
            ..
        } => message,
        _ => panic!("IsDialogMessage was not forwarded"),
    }
}

fn default_message(prepared: Win16UserFamilyPreparation) -> Win16HostMessage {
    match prepared {
        Win16UserFamilyPreparation::WindowService {
            operation:
                Win16HostUserServiceOperation::Dialog(Win16HostDialogOperation::DefaultProcedure {
                    callback: Win16HostCallback(7),
                    message,
                    ..
                }),
            ..
        } => message,
        _ => panic!("DefDlgProc was not forwarded for the active callback"),
    }
}

fn next_control(input: Win16WindowInputMessage) -> (u16, Option<Win16HostWindow>, bool) {
    match input {
        Win16WindowInputMessage::NextDialogControl {
            direction,
            control,
            control_form,
        } => (direction, control, control_form),
        _ => panic!("expected WM_NEXTDLGCTL"),
    }
}

#[test]
fn next_dialog_control_low_word_keeps_direction_and_maps_control() {
    let mut runtime = runtime();
    assert!(Win16WindowInputMessage::accepts(WM_NEXTDLGCTL));
    assert!(!Win16WindowInputMessage::accepts(WM_INITDIALOG));
    assert!(!Win16WindowInputMessage::accepts(DM_GETDEFID));
    assert_eq!(
        Win16WindowInputMessage::next_dialog_guest_params(0xFFFF, 0, false),
        (0xFFFF, 0)
    );
    assert_eq!(
        Win16WindowInputMessage::next_dialog_guest_params(0, 0, true),
        (0, 1)
    );

    {
        let state = runtime.win16.as_mut().unwrap();
        let next = state.window_input_from_guest(WM_NEXTDLGCTL, 0, 0).unwrap();
        assert_eq!(next.message_id(), WM_NEXTDLGCTL);
        assert_eq!(next_control(next), (0, None, false));
        assert_eq!(
            state.window_input_to_guest(next).unwrap(),
            (WM_NEXTDLGCTL, 0, 0)
        );

        let previous = state
            .window_input_from_guest(WM_NEXTDLGCTL, 0xFFFF, 0x0001_0000)
            .unwrap();
        assert_eq!(next_control(previous), (0xFFFF, None, false));
        assert_eq!(
            state.window_input_to_guest(previous).unwrap(),
            (WM_NEXTDLGCTL, 0xFFFF, 0)
        );

        assert!(
            state
                .window_input_from_guest(WM_NEXTDLGCTL, 0xBEEF, 1)
                .is_none()
        );
        let null_control = state
            .window_input_from_guest(WM_NEXTDLGCTL, 0, 0xFFFF)
            .unwrap();
        assert_eq!(next_control(null_control), (0, None, true));
        assert_eq!(
            state.window_input_to_guest(null_control).unwrap(),
            (WM_NEXTDLGCTL, 0, 1)
        );
    }

    let (control, token) = map_window(&mut runtime, 40, false);
    let state = runtime.win16.as_mut().unwrap();
    let focused = state
        .window_input_from_guest(WM_NEXTDLGCTL, control, 0x0001_0001)
        .unwrap();
    assert_eq!(next_control(focused), (0, Some(token), true));
    assert_eq!(
        state.window_input_to_guest(focused).unwrap(),
        (WM_NEXTDLGCTL, control, 1)
    );
}

#[test]
fn is_dialog_message_rejects_unmapped_windows_and_forwards_keys() {
    let mut runtime = runtime();
    let (dialog, _) = map_window(&mut runtime, 20, true);

    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
                dialog: 0,
                message: Msg16 {
                    hwnd: dialog,
                    message: WM_KEYDOWN,
                    w_param: VK_RETURN,
                    ..Msg16::default()
                },
            }),
            Win16ReturnKind::Word,
        ),
        0,
    );
    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
                dialog,
                message: Msg16 {
                    hwnd: 0xBEEF,
                    message: WM_KEYDOWN,
                    w_param: VK_ESCAPE,
                    ..Msg16::default()
                },
            }),
            Win16ReturnKind::Word,
        ),
        0,
    );

    for (key, repeat) in [(VK_RETURN, 0x0001_0001_u32), (VK_ESCAPE, 0)] {
        let queued = is_message(prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
                dialog,
                message: Msg16 {
                    hwnd: dialog,
                    message: WM_KEYDOWN,
                    w_param: key,
                    l_param: repeat,
                    ..Msg16::default()
                },
            }),
            Win16ReturnKind::Word,
        ));
        assert_eq!(queued.message, WM_KEYDOWN);
        assert_eq!(queued.w_param, key);
        assert_eq!(queued.l_param, Win16MessageParam::Scalar(repeat));
    }

    let null_target = is_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
            dialog,
            message: Msg16 {
                hwnd: 0,
                message: WM_KEYDOWN,
                w_param: VK_RETURN,
                ..Msg16::default()
            },
        }),
        Win16ReturnKind::Word,
    ));
    assert!(null_target.window.is_none());
    assert_eq!(null_target.w_param, VK_RETURN);

    let default_id = (DC_HASDEFID << 16) | 1;
    let queued = is_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
            dialog,
            message: Msg16 {
                hwnd: dialog,
                message: DM_GETDEFID,
                w_param: 0,
                l_param: default_id,
                ..Msg16::default()
            },
        }),
        Win16ReturnKind::Word,
    ));
    assert_eq!(queued.message, DM_GETDEFID);
    assert_eq!(queued.w_param, 0);
    assert_eq!(queued.l_param, Win16MessageParam::GuestBits(default_id));
}

#[test]
fn is_dialog_message_marshals_next_dialog_control_or_returns_zero() {
    let mut runtime = runtime();
    let (dialog, _) = map_window(&mut runtime, 21, true);
    let (control, token) = map_window(&mut runtime, 22, false);

    let queued = is_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
            dialog,
            message: Msg16 {
                hwnd: dialog,
                message: WM_NEXTDLGCTL,
                w_param: 0xFFFF,
                l_param: 0x0001_0000,
                ..Msg16::default()
            },
        }),
        Win16ReturnKind::Word,
    ));
    assert_eq!(
        queued.l_param,
        Win16MessageParam::WindowInput(Win16WindowInputMessage::NextDialogControl {
            direction: 0xFFFF,
            control: None,
            control_form: false,
        })
    );

    let queued = is_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
            dialog,
            message: Msg16 {
                hwnd: control,
                message: WM_NEXTDLGCTL,
                w_param: control,
                l_param: 1,
                ..Msg16::default()
            },
        }),
        Win16ReturnKind::Word,
    ));
    assert_eq!(
        queued.l_param,
        Win16MessageParam::WindowInput(Win16WindowInputMessage::NextDialogControl {
            direction: 0,
            control: Some(token),
            control_form: true,
        })
    );

    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::IsMessage {
                dialog,
                message: Msg16 {
                    hwnd: dialog,
                    message: WM_NEXTDLGCTL,
                    w_param: 0xBEEF,
                    l_param: 1,
                    ..Msg16::default()
                },
            }),
            Win16ReturnKind::Word,
        ),
        0,
    );
}

#[test]
fn def_dlg_proc_returns_zero_without_a_dialog_callback() {
    let mut runtime = runtime();
    let (dialog, native) = map_window(&mut runtime, 30, true);
    let (plain, plain_native) = map_window(&mut runtime, 31, false);
    push_callback(&mut runtime, plain, plain_native, WM_NEXTDLGCTL, 0, 0);
    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
                dialog: plain,
                message: WM_NEXTDLGCTL,
                w_param: 0,
                l_param: 0,
            }),
            Win16ReturnKind::Dword,
        ),
        0,
    );

    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
                dialog,
                message: WM_KEYDOWN,
                w_param: VK_RETURN,
                l_param: 0,
            }),
            Win16ReturnKind::Dword,
        ),
        0,
    );
    push_callback(&mut runtime, dialog, native, WM_KEYDOWN, VK_ESCAPE, 0);
    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
                dialog,
                message: WM_KEYDOWN,
                w_param: VK_RETURN,
                l_param: 0,
            }),
            Win16ReturnKind::Dword,
        ),
        0,
    );
}

#[test]
fn def_dlg_proc_forwards_dialog_procedure_messages() {
    let mut runtime = runtime();
    let (dialog, native) = map_window(&mut runtime, 32, true);
    let (focus, focus_token) = map_window(&mut runtime, 33, false);

    push_callback(&mut runtime, dialog, native, WM_INITDIALOG, 0, 0xABCD);
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: WM_INITDIALOG,
            w_param: 0,
            l_param: 0xABCD,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::InitDialog {
            focus,
            focus_ancestry,
            init_parameter,
        } => {
            assert_eq!(focus, None);
            assert!(focus_ancestry.is_empty());
            assert_eq!(init_parameter, 0xABCD);
        }
        _ => panic!("WM_INITDIALOG was not translated"),
    }
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(&mut runtime, dialog, native, WM_INITDIALOG, focus, 7);
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: WM_INITDIALOG,
            w_param: focus,
            l_param: 7,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::InitDialog {
            focus: translated,
            init_parameter,
            ..
        } => {
            assert_eq!(translated, Some(focus_token));
            assert_eq!(init_parameter, 7);
        }
        _ => panic!("mapped WM_INITDIALOG focus was not translated"),
    }
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(&mut runtime, dialog, native, WM_INITDIALOG, 0xBEEF, 1);
    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
                dialog,
                message: WM_INITDIALOG,
                w_param: 0xBEEF,
                l_param: 1,
            }),
            Win16ReturnKind::Dword,
        ),
        0,
    );
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(
        &mut runtime,
        dialog,
        native,
        WM_NEXTDLGCTL,
        0xFFFF,
        0x0001_0000,
    );
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: WM_NEXTDLGCTL,
            w_param: 0xFFFF,
            l_param: 0x0001_0000,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::WindowInput(input) => {
            assert_eq!(next_control(input), (0xFFFF, None, false));
        }
        _ => panic!("WM_NEXTDLGCTL direction was not forwarded"),
    }
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(&mut runtime, dialog, native, WM_NEXTDLGCTL, focus, 1);
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: WM_NEXTDLGCTL,
            w_param: focus,
            l_param: 1,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::WindowInput(input) => {
            assert_eq!(next_control(input), (0, Some(focus_token), true));
        }
        _ => panic!("WM_NEXTDLGCTL control was not forwarded"),
    }
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(&mut runtime, dialog, native, WM_NEXTDLGCTL, 0xBEEF, 1);
    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
                dialog,
                message: WM_NEXTDLGCTL,
                w_param: 0xBEEF,
                l_param: 1,
            }),
            Win16ReturnKind::Dword,
        ),
        0,
    );
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(&mut runtime, dialog, native, WM_KEYDOWN, VK_RETURN, 0x11);
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: WM_KEYDOWN,
            w_param: VK_RETURN,
            l_param: 0x11,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::Scalar {
            kind: Win16ScalarMessage::KeyDown,
            w_param: VK_RETURN,
            l_param: 0x11,
        } => {}
        _ => panic!("Enter was not forwarded as WM_KEYDOWN"),
    }
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    push_callback(&mut runtime, dialog, native, WM_KEYDOWN, VK_ESCAPE, 0);
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: WM_KEYDOWN,
            w_param: VK_ESCAPE,
            l_param: 0,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::Scalar {
            kind: Win16ScalarMessage::KeyDown,
            w_param: VK_ESCAPE,
            l_param: 0,
        } => {}
        _ => panic!("Escape was not forwarded as WM_KEYDOWN"),
    }
    runtime.win16.as_mut().unwrap().window_callbacks.pop();

    let packed = (DC_HASDEFID << 16) | u32::from(focus);
    push_callback(&mut runtime, dialog, native, DM_GETDEFID, 0, packed);
    assert_immediate(
        prepare(
            &mut runtime,
            Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
                dialog,
                message: DM_GETDEFID,
                w_param: 0,
                l_param: packed,
            }),
            Win16ReturnKind::Dword,
        ),
        0,
    );
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dialog_procedures
        .insert(dialog, (0, 0));
    match default_message(prepare(
        &mut runtime,
        Win16UserFamilyRequest::Dialog(Win16UserDialogRequest::DefaultProcedure {
            dialog,
            message: DM_GETDEFID,
            w_param: 0,
            l_param: packed,
        }),
        Win16ReturnKind::Dword,
    )) {
        Win16HostMessage::GuestOpaque {
            message: DM_GETDEFID,
            w_param: 0,
            l_param,
        } => assert_eq!(l_param, packed),
        _ => panic!("DM_GETDEFID was not kept as numeric guest bits"),
    }
}
