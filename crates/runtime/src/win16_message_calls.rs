//! Win16 USER messages, timer registrations, focus, capture, and keyboard state.
//!
//! Guest timer callbacks are represented as guest FAR addresses and are never
//! installed as native Windows function pointers. Native queue/timer ownership
//! remains with the USER worker; this module owns only the Win16 ABI mapping.

use std::collections::BTreeMap;

use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ApiRequest, Win16ReturnKind};

use super::{Win16State, guest_ranges::GuestOutputRange, windows::WindowReturn};
use crate::win16_host_message_calls::Win16MessageCallContinuation;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostClass, Win16HostWindow,
    Win16MessageCall, Win16MessageParam, Win16ScalarMessage,
    Win16WindowInputMessage, Win16WindowOperation,
};

#[path = "win16_dialog_item_messages.rs"]
mod dialog_item_messages;
#[path = "win16_message_calls/send_message.rs"]
mod send_message;
#[path = "win16_message_calls/timers.rs"]
mod timers;
pub(super) use timers::{Win16TimerRegistration, Win16TimerRegistrations};
#[path = "win16_message_calls/dialog.rs"]
mod dialog;
pub(in crate::win16_runtime) use dialog_item_messages::prepare_dialog_item_send_message;
pub(in crate::win16_runtime) use send_message::{
    prepare_send_message, SendMessagePreparation,
};

const WM_COMMAND: u16 = 0x0111;
const WM_TIMER: u16 = 0x0113;
const WM_ACTIVATEAPP: u16 = 0x001c;
const WM_PARENTNOTIFY: u16 = 0x0210;
const WM_CTLCOLOR: u16 = 0x0019;
const WM_USER: u16 = 0x0400;
// Windows 3.1 SDK WINDOWS.H:3459. Unlike scalar messages, this synchronous
// request reads and writes owned geometry through the shared message codec.
const WM_NCCALCSIZE: u16 = 0x0083;
// Windows 3.1 WINDOWS.H, HWND_BROADCAST, special SendMessage target.
const HWND_BROADCAST: u16 = 0xffff;

impl Win16State {
    /// Dispatch one complete USER message/input request group. Native calls are
    /// yielded through the existing USER worker operation so synchronous
    /// guest WndProc callbacks can re-enter the runtime.
    pub(super) fn begin_user_message_request(
        &mut self,
        request: Win16ApiRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        match request {
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::SendDlgItemMessage {
                    dialog,
                    id,
                    message,
                    w_param,
                    l_param,
                },
            )) => self.begin_dialog_item_message(
                registers, memory, host, dialog, id, message, w_param, l_param, return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::SendMessage {
                    window,
                    message,
                    w_param,
                    l_param,
                },
            )) => {
                match prepare_send_message(
                    self, window, message, w_param, l_param, memory, host,
                )? {
                    SendMessagePreparation::Immediate { value, return_kind } =>
                        self.complete_return(
                            registers,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            value,
                            return_kind,
                        ),
                    SendMessagePreparation::Prepared { operation, continuation } =>
                        self.begin_window_operation(
                            registers, memory, host, operation, continuation, return_to,
                        ),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::PostMessage {
                    window,
                    message,
                    w_param,
                    l_param,
                },
            )) => {
                let Some((target, parameter, guest_class)) =
                    self.prepare_message_call(window, message, w_param, l_param, host, false)?
                else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        Win16ReturnKind::Word,
                    );
                };
                self.begin_message_call(
                    registers,
                    memory,
                    host,
                    Win16MessageCall::PostMessage {
                        window: target,
                        message,
                        w_param,
                        l_param: parameter,
                        guest_class,
                    },
                    Win16MessageCallContinuation::Boolean {
                        return_kind: Win16ReturnKind::Word,
                    },
                    return_to,
                )
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::PostAppMessage {
                    task,
                    message,
                    w_param,
                    l_param,
                },
            )) => {
                let _ = self.ensure_user_queue(host)?;
                let current = self.current_task_handle()?;
                if task != current {
                    if self.task_handles.values().any(|handle| *handle == task) {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            format!("Win16 PostAppMessage task 0x{task:04X} has no separate native USER queue")));
                    } else {
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::CompatibilityGap,
                            format!("Win16 PostAppMessage task 0x{task:04X} is not registered"),
                        ));
                    }
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        Win16ReturnKind::Word,
                    );
                }
                let Some((owner, bound_task, generation, queue)) = self.user_task_queue
                    .filter(|(_, bound_task, _, _)| *bound_task == task)
                else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                let sequence = self.next_app_notification_sequence;
                self.next_app_notification_sequence = sequence.checked_add(1).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 PostAppMessage source sequence is exhausted"))?;
                self.begin_post_guest_notification(registers, memory, host,
                    crate::Win16GuestNotification {
                        target: crate::Win16GuestNotificationTarget::Task {
                            owner, guest_htask: bound_task,
                            task_selector_generation: generation, queue,
                        },
                        source: crate::Win16GuestNotificationSource {
                            id: crate::WIN16_APP_MESSAGE_NOTIFICATION_SOURCE_ID,
                            generation,
                            sequence,
                        },
                        message, w_param, l_param,
                    }, return_to)
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::WaitMessage,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::WaitMessage,
                Win16MessageCallContinuation::WaitMessage {
                    return_kind: Win16ReturnKind::Void,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetTimer {
                    window,
                    timer_id,
                    interval,
                    callback,
                },
            )) => {
                let Some(native_window) = self
                    .window_handles
                    .get(&window)
                    .copied()
                    .filter(|_| window != 0)
                else {
                    if window != 0 {
                        return self.complete_return(
                            registers,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            0,
                            Win16ReturnKind::Word,
                        );
                    }
                    return self.begin_set_timer(
                        registers, memory, host, window, None, timer_id, interval, callback,
                        return_to,
                    );
                };
                self.begin_set_timer(
                    registers,
                    memory,
                    host,
                    window,
                    Some(native_window),
                    timer_id,
                    interval,
                    callback,
                    return_to,
                )
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::KillTimer { window, timer_id },
            )) => {
                let Some(registration) = self.timers.get(window, timer_id) else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        Win16ReturnKind::Word,
                    );
                };
                let native_window = self.window_handles.get(&window).copied();
                if window != 0 && native_window.is_none() {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        Win16ReturnKind::Word,
                    );
                }
                self.begin_message_call(
                    registers,
                    memory,
                    host,
                    Win16MessageCall::KillTimer {
                        window: native_window,
                        host_timer_id: registration.host_id,
                    },
                    Win16MessageCallContinuation::KillTimer {
                        guest_window: window,
                        guest_timer_id: timer_id,
                    },
                    return_to,
                )
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetFocus { window },
            )) => self.begin_focus_capture(registers, memory, host, window, true, return_to),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetCapture { window },
            )) => self.begin_focus_capture(registers, memory, host, window, false, return_to),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetFocus,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::GetFocus,
                Win16MessageCallContinuation::Window {
                    return_kind: Win16ReturnKind::Word,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetCapture,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::GetCapture,
                Win16MessageCallContinuation::Window {
                    return_kind: Win16ReturnKind::Word,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::ReleaseCapture,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::ReleaseCapture,
                Win16MessageCallContinuation::Boolean {
                    return_kind: Win16ReturnKind::Void,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::GetMessagePos,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::GetMessagePos,
                Win16MessageCallContinuation::Dword {
                    return_kind: Win16ReturnKind::Dword,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::GetMessageTime,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::GetMessageTime,
                Win16MessageCallContinuation::Dword {
                    return_kind: Win16ReturnKind::Dword,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::GetInputState,
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::GetInputState,
                Win16MessageCallContinuation::Boolean {
                    return_kind: Win16ReturnKind::Word,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::GetQueueStatus { flags },
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::GetQueueStatus { flags },
                Win16MessageCallContinuation::Dword {
                    return_kind: Win16ReturnKind::Dword,
                },
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::GetKeyboardState { output },
            )) => {
                self.begin_message_call(
                    registers,
                    memory,
                    host,
                    Win16MessageCall::GetKeyboardState,
                    Win16MessageCallContinuation::GetKeyboardState {
                        output_far: output,
                        output_range: None,
                    },
                    return_to,
                )
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::SetKeyboardState { state },
            )) => self.begin_message_call(
                registers,
                memory,
                host,
                Win16MessageCall::SetKeyboardState { state },
                Win16MessageCallContinuation::SetKeyboardState,
                return_to,
            ),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::CallWindowProc {
                    procedure,
                    window,
                    message,
                    w_param,
                    l_param,
                },
            )) => {
                // The native worker must not invoke a segmented guest address.
                // Execute the FAR procedure on the guest CPU using the checked
                // reentrant WndProc stack contract.
                self.begin_call_window_proc(
                    registers, memory, host, procedure, window, message, w_param, l_param,
                    return_to,
                )
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-message USER request reached the message-call bridge",
            )),
        }
    }

    fn prepare_message_call(
        &self,
        guest_window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        host: &mut impl RuntimeHost,
        send: bool,
    ) -> Result<
        Option<(
            crate::Win16HostWindow,
            Win16MessageParam,
            Option<Win16HostClass>,
        )>,
        RuntimeError,
    > {
        if message == super::messages::WM_PAINT && w_param != 0 && !send {
            // Posting a borrowed drawing context needs an asynchronous lease;
            // the synchronous paint bridge cannot promise that lifetime.
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "Win16 PostMessage with a paint HDC requires an asynchronous drawing-context lease"));
            return Ok(None);
        }
        let Some(&window) = self
            .window_handles
            .get(&guest_window)
            .filter(|_| guest_window != 0)
        else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("Win16 message target HWND 0x{guest_window:04X} is not mapped"),
            ));
            return Ok(None);
        };
        let guest_class = self
            .window_procedures
            .get(&guest_window)
            .map(|procedure| procedure.class);
        let parameter = if super::messages_mdi::is_mdi_message(message) {
            if send {
                // Synchronous MDI results carry opaque HWND/HMENU identities
                // and use MessageOutput::Mdi; they never enter the generic
                // scalar SendMessage host path.
                return Ok(None);
            }
            let Some(queued) = self.prepare_guest_dispatch_mdi_message(
                guest_window, message, w_param, l_param,
            )? else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 PostMessage MDI message 0x{message:04X} has invalid endpoint or guest parameters")));
                return Ok(None);
            };
            Win16MessageParam::Mdi(queued)
        } else if Win16WindowInputMessage::accepts(message) {
            let Some(input) = self.window_input_from_guest(message, w_param, l_param) else {
                let operation = if send { "SendMessage" } else { "PostMessage" };
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!(
                        "Win16 {operation} message 0x{message:04X} has an unmapped HWND parameter"
                    ),
                ));
                return Ok(None);
            };
            Win16MessageParam::WindowInput(input)
        } else if message == WM_COMMAND {
            let command = super::messages::unpack_win16_command(w_param, l_param);
            let control = if command.control == 0 {
                None
            } else if let Some(control) = self.window_handles.get(&command.control).copied() {
                Some(control)
            } else {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!(
                        "Win16 WM_COMMAND refers to unmapped control HWND 0x{:04X}",
                        command.control
                    ),
                ));
                return Ok(None);
            };
            Win16MessageParam::Command {
                control,
                notify: command.notify,
                control_parent: None,
            }
        } else if message == super::messages::WM_CHANGECBCHAIN {
            let Some(parameter) = self.clipboard_chain_param(w_param, l_param as u16) else {
                return Ok(None);
            };
            parameter
        } else if message == WM_ACTIVATEAPP {
            let other_task_queue = match self.activation_queue_for_task(l_param as u16) {
                Ok(queue) => queue,
                Err(error) => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_ACTIVATEAPP task identity was not mapped: {error}")));
                    return Ok(None);
                }
            };
            Win16MessageParam::ActivationApp(crate::Win16HostActivationApp {
                active: u16::from(w_param != 0),
                other_task_queue,
            })
        } else if message == WM_PARENTNOTIFY {
            let notification = match self.parent_notification_from_guest(w_param, l_param) {
                Ok(notification) => notification,
                Err(error) => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_PARENTNOTIFY layout was not mapped: {error}")));
                    return Ok(None);
                }
            };
            if !send && matches!(notification.data,
                crate::Win16HostParentNotificationData::Child { .. })
            {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 PostMessage WM_PARENTNOTIFY child HWND needs a lifetime-bound asynchronous lease"));
                return Ok(None);
            }
            Win16MessageParam::ParentNotification(notification)
        } else if message == WM_CTLCOLOR {
            if send {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "synchronous WM_CTLCOLOR bypassed its typed HDC lease and HBRUSH result route"));
            }
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "Win16 PostMessage WM_CTLCOLOR cannot retain its HDC lease until dequeue"));
            return Ok(None);
        } else if message == WM_TIMER && !send {
            // The host queues this through an opaque WPARAM token with a null
            // native LPARAM, then restores these guest bits on retrieval.
            // In particular, native DispatchMessage never sees a TIMERPROC FAR.
            Win16MessageParam::GuestBits(l_param)
        } else if Win16ScalarMessage::from_raw(message).is_some() {
            Win16MessageParam::Scalar(l_param)
        } else if message >= WM_USER
            && (guest_class.is_some() || self.dialog_procedures.contains_key(&guest_window))
        {
            Win16MessageParam::GuestBits(l_param)
        } else {
            let operation = if send { "SendMessage" } else { "PostMessage" };
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("{operation} message 0x{message:04X} needs parameter-family marshalling"),
            ));
            return Ok(None);
        };
        Ok(Some((window, parameter, guest_class)))
    }

    fn begin_set_timer(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_window: u16,
        native_window: Option<crate::Win16HostWindow>,
        requested_id: u16,
        interval: u16,
        callback: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if callback != 0 {
            self.check_guest_procedure(callback, memory)?;
        }
        let guest_timer_id = if requested_id != 0 {
            requested_id
        } else if let Some(id) = self.timers.allocate_guest_id(guest_window) {
            id
        } else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::ResourceExhausted,
                "Win16 USER has no free timer identifiers",
            ));
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        // The host field is an opaque timer-generation token, not the native
        // UINT_PTR. It lets the worker replace this Win16 timer only after a
        // new native generation has been installed successfully.
        let native_timer_id = self
            .timers
            .get(guest_window, guest_timer_id)
            .map(|entry| entry.host_id);
        let call = Win16MessageCall::SetTimer {
            window: native_window,
            timer_id: guest_timer_id,
            interval_ms: interval,
            native_timer_id,
            guest_callback: callback != 0,
        };
        self.begin_message_call(
            registers,
            memory,
            host,
            call,
            Win16MessageCallContinuation::SetTimer {
                guest_window,
                host_window: native_window,
                guest_timer_id,
                callback: (callback != 0).then_some(callback),
            },
            return_to,
        )
    }

    fn begin_focus_capture(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_window: u16,
        focus: bool,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(&window) = self
            .window_handles
            .get(&guest_window)
            .filter(|_| guest_window != 0)
        else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        let call = if focus {
            Win16MessageCall::SetFocus { window }
        } else {
            Win16MessageCall::SetCapture { window }
        };
        self.begin_message_call(
            registers,
            memory,
            host,
            call,
            Win16MessageCallContinuation::Window {
                return_kind: Win16ReturnKind::Word,
            },
            return_to,
        )
    }

    fn begin_message_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: Win16MessageCall,
        mut continuation: Win16MessageCallContinuation,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let keyboard_state_output = match &continuation {
            Win16MessageCallContinuation::GetKeyboardState { output_far, .. } => {
                let pointer = self
                    .selectors
                    .pointer_from_far(*output_far)
                    .map_err(crate::runtime_error)?;
                Some(GuestOutputRange::capture(self, memory, pointer, 256)?)
            }
            _ => None,
        };
        if let (
            Win16MessageCallContinuation::GetKeyboardState { output_range, .. },
            Some(range),
        ) = (&mut continuation, keyboard_state_output)
        {
            *output_range = Some(range);
        }
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::MessageCall(call),
            WindowReturn::MessageCall(continuation),
            return_to,
        )
    }

    fn check_guest_procedure(&self, procedure: u32, memory: &Memory) -> Result<(), RuntimeError> {
        let callback = self
            .selectors
            .pointer_from_far(procedure)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(callback, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        // SetTimer only registers the callback. The callback stack is checked
        // when WM_TIMER actually dispatches, against that call site's SS:SP.
        Ok(())
    }
}
