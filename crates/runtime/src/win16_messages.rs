//! Shared USER message marshalling: guest values become owned host payloads.

use guest_core::memory::Memory;
use guest_core::Registers;
use win16_abi::{CreateStruct16, Win16ClassName, Win16OutputBuffer,
    Win16ReturnKind, MAX_WIN16_STRING_BYTES};
use win16_abi::strings::read_ansi_z;
use super::Win16State;
use super::windows::WindowReturn;
use super::geometry::{WM_GETMINMAXINFO, guest_minmax_info, host_minmax_info};
use win16_abi::window_geometry::MinMaxInfo16;
use super::window_payloads::nonclient_payloads;
use super::window_payloads::window_position_payloads;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCreationData,
    Win16HostMessage, Win16HostMessageOutput, Win16HostMessageResult, Win16HostProcedure,
    Win16HostStaticIconOperation, Win16ScalarMessage, Win16WindowOperation, Win16MessageParam,
    Win16WindowInputMessage,
};

const WM_CREATE: u16 = 0x0001;
const WM_SETTEXT: u16 = 0x000c;
const WM_GETTEXT: u16 = 0x000d;
const WM_GETTEXTLENGTH: u16 = 0x000e;
pub(super) const WM_PAINT: u16 = 0x000f;
// Windows 3.1 SDK WINDOWSX.H:831-834: HFONT in WPARAM, BOOL in LOWORD(LPARAM).
pub(super) const WM_SETFONT: u16 = 0x0030;
const WM_ERASEBKGND: u16 = 0x0014;
const WM_NCCREATE: u16 = 0x0081;
const WM_GETDLGCODE: u16 = 0x0087;
const WM_INITDIALOG: u16 = 0x0110;
const WM_COMMAND: u16 = 0x0111;
const WM_CTLCOLOR: u16 = 0x0019;
pub(super) const WM_CHANGECBCHAIN: u16 = 0x030d;
const WM_NCCALCSIZE: u16 = 0x0083;
// Windows 3.1 Programmer's Reference, Vol. 3, PDF p. 179: WM_NCPAINT has no
// parameters, so no native update-region value is part of the guest payload.
pub(super) const WM_NCPAINT: u16 = 0x0085;
const WS_CHILD: u32 = 0x4000_0000;
const WM_USER: u16 = 0x0400;
// Windows 3.1 SDK WINDOWS.H, "Static Control Messages" (WINDOWS.H:4462-4463);
// the SDK collection manifest records include/ as derived from expanded files.
const STM_SETICON: u16 = WM_USER;
const STM_GETICON: u16 = WM_USER + 1;

pub(super) const fn is_static_icon_message(message: u16) -> bool {
    matches!(message, STM_SETICON | STM_GETICON)
}

pub(super) const fn is_window_text_message(message: u16) -> bool {
    matches!(message, WM_SETTEXT | WM_GETTEXT | WM_GETTEXTLENGTH)
}

/// Win16 WM_COMMAND repacks the native control notification: the native
/// `HIWORD(wParam)` code becomes `HIWORD(lParam)`, and the native control
/// HWND becomes a checked 16-bit guest handle in `LOWORD(lParam)`.
pub(super) struct Win16CommandParts {
    pub id: u16,
    pub notify: u16,
    pub control: u16,
}

pub(super) fn unpack_win16_command(w_param: u16, l_param: u32) -> Win16CommandParts {
    Win16CommandParts {
        id: w_param,
        notify: (l_param >> 16) as u16,
        control: l_param as u16,
    }
}

pub(super) fn pack_win16_command(id: u16, notify: u16, control: u16) -> (u16, u32) {
    (id, u32::from(control) | (u32::from(notify) << 16))
}

pub(super) enum MessageOutput {
    Control(super::standard_controls::ControlOutputPlan),
    ControlColor,
    None,
    OwnerDrawMeasure(super::guest_ranges::GuestOutputRange),
    Text(Option<GuestTextOutput>),
    MinMaxInfo(super::guest_ranges::GuestOutputRange),
    NonClientCalcSize(nonclient_payloads::MessageOutput),
    WindowPosition(window_position_payloads::MessageOutput),
    Mdi(Option<super::messages_mdi::MdiOutputPlan>),
}

pub(super) struct GuestTextOutput {
    pub(super) buffer: Win16OutputBuffer,
    pub(super) range: super::guest_ranges::GuestOutputRange,
}

impl Win16State {
    /// Prepare one explicit MDI default-procedure request. The endpoint is
    /// supplied by the API call path or verified MDIClient class identity;
    /// child roles are never inferred from a message number.
    pub(super) fn translate_mdi_message(
        &mut self,
        endpoint: crate::Win16MdiEndpoint,
        mdi_client: Option<(u16, crate::Win16HostWindow)>,
        message: u16,
        w_param: u16,
        l_param: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<(Win16HostMessage, MessageOutput)>, RuntimeError> {
        if !super::messages_mdi::is_mdi_message(message) {
            return Ok(None);
        }
        if matches!(endpoint, crate::Win16MdiEndpoint::Client) {
            let Some((guest, native)) = mdi_client else {
                return Ok(None);
            };
            if self.window_handles.get(&guest) != Some(&native)
                || self.window_system_classes.get(&guest)
                    != Some(&crate::Win16HostSystemClass::MdiClient)
            {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 MDI client message target is not a live MdiClient system-class window"));
                return Ok(None);
            }
        }
        let Some(prepared) = self.prepare_mdi_message(
            endpoint, mdi_client, message, w_param, l_param, memory, host,
        )? else {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("Win16 MDI message 0x{message:04X} has invalid endpoint or guest parameters")));
            return Ok(None);
        };
        Ok(Some((Win16HostMessage::Mdi(prepared.message),
            MessageOutput::Mdi(prepared.output))))
    }

    pub(super) fn clipboard_chain_param(&self, removed: u16, next: u16)
        -> Option<Win16MessageParam> {
        let resolve = |handle| if handle == 0 { Some(None) }
            else { self.window_handles.get(&handle).copied().map(Some) };
        Some(Win16MessageParam::ClipboardChainChange {
            removed: resolve(removed)?, next: resolve(next)?,
        })
    }

    pub(super) fn begin_def_window_proc(
        &mut self, registers: &mut Registers, window: u16, message: u16,
        w_param: u16, l_param: u32, memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_proc_operation(registers, memory, host, None, window,
            message, w_param, l_param, return_to)
    }

    pub(super) fn begin_native_window_proc(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        procedure: Win16HostProcedure,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_proc_operation(registers, memory, host, Some(procedure),
            window, message, w_param, l_param, return_to)
    }

    fn begin_window_proc_operation(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        procedure: Option<Win16HostProcedure>,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(&native) = self.window_handles.get(&window) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Dword);
        };
        // Standard Win16 control families overlap at WM_USER+n. Resolve the
        // retained procedure's family before interpreting either argument.
        // Guest procedures retain their application-defined message path.
        if let Some(procedure) = procedure.filter(|_| message >= WM_USER) {
            let identity = self.control_identity(window, Some(procedure), host)?;
            if let Some(identity) = identity {
                if identity.family == crate::Win16HostControlFamily::Static
                    && is_static_icon_message(message) {
                    return self.begin_static_icon_message(registers, memory, host, window,
                        message, w_param, Some(procedure), return_to);
                }
                if let Some((payload, output)) = self.prepare_control_message(window, message,
                    w_param, l_param, Some(procedure), identity, memory, host)? {
                    return self.begin_window_operation(registers, memory, host,
                        Win16WindowOperation::CallProcedure {
                            procedure, window: native, callback: None, message: payload,
                        }, WindowReturn::Message { output }, return_to);
                }
            } else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 native procedure message 0x{message:04X} has no control-family conversion; returned zero")));
            }
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Dword);
        }
        let Some((payload, output)) = self.translate_window_message(
            window, message, w_param, l_param, memory, host, procedure.is_some(),
        )? else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Dword);
        };
        let callback = self.active_window_callback(window, message, w_param, l_param);
        let operation = if let Some(procedure) = procedure {
            Win16WindowOperation::CallProcedure {
                procedure,
                window: native,
                callback,
                message: payload,
            }
        } else {
            Win16WindowOperation::Default {
                window: native,
                callback,
                message: payload,
            }
        };
        self.begin_window_operation(registers, memory, host, operation,
            WindowReturn::Message { output }, return_to)
    }

    pub(super) fn begin_static_icon_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_window: u16,
        message: u16,
        w_param: u16,
        procedure: Option<Win16HostProcedure>,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(&window) = self.window_handles.get(&guest_window) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Dword);
        };
        let operation = match message {
            STM_GETICON => Some(Win16HostStaticIconOperation::Get),
            STM_SETICON if w_param == 0 => Some(Win16HostStaticIconOperation::Set { icon: None }),
            STM_SETICON => self.guest_images.icon(w_param).map(|icon|
                Win16HostStaticIconOperation::Set { icon: Some(icon) }),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "non-static-icon message reached the typed icon path")),
        };
        let Some(operation) = operation else {
            // HICON16 values are guest tokens. An invalid token must never be
            // reinterpreted as a native HICON or passed to USER.
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Dword);
        };
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::StaticIcon { window, procedure, operation },
            WindowReturn::Icon { window: guest_window, message }, return_to)
    }

    pub(super) fn translate_window_message(
        &mut self,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        native_procedure: bool,
    ) -> Result<Option<(Win16HostMessage, MessageOutput)>, RuntimeError> {
        // Only this exact, innermost synchronous callback can recover native
        // notification provenance. New Send calls use their own message path.
        if let Some(notification) = self.active_guest_notification(
            window, message, w_param, l_param,
        ) {
            return Ok(Some((Win16HostMessage::GuestNotification(notification),
                MessageOutput::None)));
        }
        if self.active_window_callback(window, message, w_param, l_param).is_some() {
            if let Some(request_id) = self.window_callbacks.last()
                .and_then(|frame| frame.payload.common_dialog_request) {
                if let Some(notification) = self.common_dialog_callback_message(request_id) {
                    return Ok(Some((Win16HostMessage::FindReplaceNotification(notification),
                        MessageOutput::None)));
                }
            }
        }
        if message == 0x0233 {
            let Some(drop) = self.active_drop_files_message(
                window,
                message,
                w_param,
                l_param,
                memory,
            )? else {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "Win16 WM_DROPFILES forwarding has no exact active guest HGLOBAL owner",
                ));
                return Ok(None);
            };
            return Ok(Some((Win16HostMessage::DropFiles(drop), MessageOutput::None)));
        }
        if super::messages_mdi::is_mdi_message(message) {
            let client = if self.window_system_classes.get(&window)
                == Some(&crate::Win16HostSystemClass::MdiClient)
            {
                self.window_handles.get(&window).copied().map(|native| (window, native))
            } else {
                None
            };
            let Some(client) = client else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 MDI message 0x{message:04X} did not target a registered MdiClient; child semantics require DefMDIChildProc")));
                return Ok(None);
            };
            return self.translate_mdi_message(
                crate::Win16MdiEndpoint::Client, Some(client), message,
                w_param, l_param, memory, host,
            );
        }
        if crate::Win16OwnerDrawMessage::accepts(message)
        {
            let Some(item) = self.owner_draw_from_guest(message, w_param, l_param, memory)? else {
                if message == crate::win16_host_owner_draw::WM_COMPAREITEM {
                    // Zero means equal. A conversion failure cannot supply an
                    // ordering result without actually calling the comparator.
                    return Err(RuntimeError::new(Kind::InvalidInput,
                        "COMPAREITEM cannot resolve its guest item-window handle"));
                }
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "owner-draw message contains an unmapped guest handle"));
                return Ok(None);
            };
            let output = if message == crate::win16_host_owner_draw::WM_MEASUREITEM {
                let pointer = self.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
                let pointer = self.selectors.add_bytes(pointer,
                    win16_abi::owner_draw::measure_item_struct16_offsets::ITEM_WIDTH as u32)
                    .map_err(crate::runtime_error)?;
                MessageOutput::OwnerDrawMeasure(super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, win16_abi::owner_draw::MeasureItemStruct16::OUTPUT_SIZE,
                )?)
            } else { MessageOutput::None };
            return Ok(Some((Win16HostMessage::OwnerDraw(item), output)));
        }
        if Win16WindowInputMessage::accepts(message) {
            let Some(input) = self.window_input_from_guest(message, w_param, l_param) else {
                let operation = if native_procedure { "CallWindowProc" } else { "DefWindowProc" };
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 {operation} message 0x{message:04X} has an unmapped HWND parameter")));
                return Ok(None);
            };
            return Ok(Some((Win16HostMessage::WindowInput(input), MessageOutput::None)));
        }

        if message == WM_CTLCOLOR {
            // Windows 3.1 packs the color class into LPARAM; native USER has
            // seven distinct WM_CTLCOLOR* IDs and pointer-width HDC/HWND fields.
            let kind = (l_param >> 16) as u16;
            if kind > 6 {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 WM_CTLCOLOR type {kind} is outside the seven SDK control classes")));
                return Ok(None);
            }
            let dc = if w_param == 0 {
                None
            } else if let Some(dc) = self.guest_gdi.dc(w_param) {
                Some(dc)
            } else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 WM_CTLCOLOR refers to unmapped HDC16 0x{w_param:04X}")));
                return Ok(None);
            };
            let guest_control = l_param as u16;
            let control = if guest_control == 0 {
                None
            } else if let Some(control) = self.window_handles.get(&guest_control).copied() {
                Some(control)
            } else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 WM_CTLCOLOR refers to unmapped HWND16 0x{guest_control:04X}")));
                return Ok(None);
            };
            return Ok(Some((Win16HostMessage::ControlColor(crate::Win16HostControlColor {
                kind, dc, control,
            }), MessageOutput::ControlColor)));
        }

        if message == 0x001c {
            let other_task_queue = match self.activation_queue_for_task(l_param as u16) {
                Ok(queue) => queue,
                Err(error) => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_ACTIVATEAPP task identity was not mapped: {error}")));
                    return Ok(None);
                }
            };
            return Ok(Some((Win16HostMessage::ActivationApp(crate::Win16HostActivationApp {
                active: u16::from(w_param != 0),
                other_task_queue,
            }), MessageOutput::None)));
        }
        if message == 0x0210 {
            let notification = match self.parent_notification_from_guest(w_param, l_param) {
                Ok(notification) => notification,
                Err(error) => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_PARENTNOTIFY layout was not mapped: {error}")));
                    return Ok(None);
                }
            };
            return Ok(Some((Win16HostMessage::ParentNotification(notification),
                MessageOutput::None)));
        }
        // Validate the complete output range before any native side effect.
        let mut output = if message == WM_GETTEXT {
            MessageOutput::Text(if w_param == 0 {
                None
            } else {
                if l_param == 0 {
                    return Err(RuntimeError::new(Kind::GuestFault,
                        "Win16 WM_GETTEXT has a null output pointer for positive capacity"));
                }
                let pointer = self.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
                Some(GuestTextOutput {
                    buffer: Win16OutputBuffer { pointer, capacity: w_param },
                    range: super::guest_ranges::GuestOutputRange::capture(
                        self, memory, pointer, usize::from(w_param),
                    )?,
                })
            })
        } else if message == WM_GETMINMAXINFO {
            let pointer = self.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
            MessageOutput::MinMaxInfo(super::guest_ranges::GuestOutputRange::capture(
                self, memory, pointer, MinMaxInfo16::SIZE,
            )?)
        } else { MessageOutput::None };

        if matches!(message, WM_CREATE | WM_NCCREATE) {
            let mdi_callback = self.window_callbacks.last().and_then(|frame| {
                let is_current_mdi_create_callback = frame.payload.message == message
                    && matches!(frame.continuation,
                        super::windows::WindowCallbackContinuation::Host {
                            window: callback_window, ..
                        } if callback_window == window);
                is_current_mdi_create_callback
                    .then(|| frame.mdi_child_creation.clone())
                    .flatten()
            });
            if let Some(original) = mdi_callback {
                // Never downgrade a child created by WM_MDICREATE into a
                // generic Create callback when the guest changes LPARAM or
                // lpCreateParams. Only the exact active callback pair keeps
                // the checked native MCS provenance.
                if self.active_window_message(window, message, w_param, l_param).is_none() {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "Win16 MDI child default procedure did not receive its exact CREATESTRUCT16 callback tuple"));
                    return Ok(None);
                }
                let Some(data) = self.live_mdi_child_creation_data(&original, l_param, memory)? else {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "Win16 MDI child CREATESTRUCT16 no longer points to its checked nested MDICREATESTRUCT16"));
                    return Ok(None);
                };
                return Ok(Some((Win16HostMessage::MdiChildCreation {
                    non_client: message == WM_NCCREATE,
                    data,
                }, MessageOutput::None)));
            }
        }
        let payload = match message {
            WM_SETFONT => {
                let font = if w_param == 0 { None } else {
                    let Some(font) = self.guest_gdi.object(w_param) else { return Ok(None); };
                    Some(font)
                };
                Win16HostMessage::SetFont { font, redraw: l_param as u16 != 0 }
            }
            WM_CHANGECBCHAIN => {
                let Some(Win16MessageParam::ClipboardChainChange { removed, next }) =
                    self.clipboard_chain_param(w_param, l_param as u16) else {
                    return Ok(None);
                };
                Win16HostMessage::ClipboardChainChange { removed, next }
            }
            WM_COMMAND => {
                let command = unpack_win16_command(w_param, l_param);
                let control = if command.control == 0 {
                    None
                } else if let Some(control) = self.window_handles.get(&command.control).copied() {
                    Some(control)
                } else {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_COMMAND refers to unmapped control HWND 0x{:04X}",
                            command.control)));
                    return Ok(None);
                };
                Win16HostMessage::Command {
                    id: command.id,
                    notify: command.notify,
                    control,
                    control_parent: None,
                }
            }
            WM_PAINT => {
                let dc = if w_param == 0 { None } else {
                    let Some(dc) = self.guest_gdi.dc(w_param) else {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            format!("Win16 WM_PAINT refers to unmapped HDC 0x{w_param:04X}")));
                        return Ok(None);
                    };
                    Some(dc)
                };
                Win16HostMessage::Paint { dc }
            }
            WM_ERASEBKGND if w_param == 0 => Win16HostMessage::EraseBackground { dc: None },
            WM_ERASEBKGND => {
                let Some(dc) = self.guest_gdi.dc(w_param) else {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_ERASEBKGND refers to unmapped HDC 0x{w_param:04X}")));
                    return Ok(None);
                };
                Win16HostMessage::EraseBackground { dc: Some(dc) }
            }
            WM_CREATE | WM_NCCREATE => {
                let pointer = self.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
                let data = CreateStruct16::read_from(&self.selectors, memory, pointer)
                    .map_err(crate::runtime_error)?;
                if native_procedure && data.lp_create_params != 0 {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 CallWindowProc message 0x{message:04X} has non-null CREATESTRUCT lpCreateParams; native creation data was not forwarded")));
                    return Ok(None);
                }
                let class_name = if data.lpsz_class >> 16 == 0 {
                    Win16ClassName::Atom(data.lpsz_class as u16)
                } else {
                    Win16ClassName::Name(read_ansi_z(&self.selectors, memory,
                        data.lpsz_class, MAX_WIN16_STRING_BYTES).map_err(crate::runtime_error)?)
                };
                let Some(class) = self.resolve_window_class(data.h_instance, &class_name, host)?
                    else {
                        return Ok(None);
                    };
                let parent = if data.hwnd_parent == 0 { None } else {
                    let Some(&parent) = self.window_handles.get(&data.hwnd_parent)
                        else {
                            return Ok(None);
                        };
                    Some(parent)
                };
                let child = data.style & WS_CHILD != 0;
                let menu = if child || data.h_menu == 0 { None } else {
                    let Some(menu) = self.guest_menus.resolve(data.h_menu) else {
                        return Ok(None);
                    };
                    Some(menu)
                };
                let title = if data.lpsz_name == 0 { None } else {
                    Some(read_ansi_z(&self.selectors, memory, data.lpsz_name,
                        MAX_WIN16_STRING_BYTES).map_err(crate::runtime_error)?)
                };
                Win16HostMessage::Creation {
                    non_client: message == WM_NCCREATE,
                    data: Win16HostCreationData {
                        class: class.host_class, menu, title, style: data.style,
                        guest_instance: data.h_instance,
                        guest_class_name: match &class_name {
                            Win16ClassName::Name(name) => crate::Win16HostClassName::Name(name.clone()),
                            Win16ClassName::Atom(atom) => crate::Win16HostClassName::Atom(*atom),
                        },
                        guest_menu: data.h_menu,
                        class_menu_template: None,
                        create_parameter: data.lp_create_params,
                        creation_data: None,
                        // This route currently accepts registered guest
                        // classes; predefined MDIClient creation is separate.
                        mdi_client: None,
                        dialog_root: self.window_is_dialog(window),
                        ex_style: data.dw_ex_style, x: data.x, y: data.y,
                        width: data.cx, height: data.cy, parent,
                        child_id: child.then_some(data.h_menu),
                    },
                }
            }
            WM_SETTEXT => Win16HostMessage::SetText(if l_param == 0 { None } else {
                Some(read_ansi_z(&self.selectors, memory, l_param, MAX_WIN16_STRING_BYTES)
                    .map_err(crate::runtime_error)?)
            }),
            WM_GETTEXT => Win16HostMessage::GetText {
                capacity: w_param,
                buffer_is_null: l_param == 0,
            },
            WM_GETTEXTLENGTH => Win16HostMessage::GetTextLength,
            WM_GETDLGCODE => Win16HostMessage::GetDlgCode,
            WM_INITDIALOG => {
                let focus = if w_param == 0 {
                    None
                } else if let Some(focus) = self.window_handles.get(&w_param).copied() {
                    Some(focus)
                } else {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_INITDIALOG refers to unmapped focus HWND 0x{w_param:04X}")));
                    return Ok(None);
                };
                Win16HostMessage::InitDialog {
                    focus,
                    focus_ancestry: Vec::new(),
                    init_parameter: l_param,
                }
            }
            WM_GETMINMAXINFO => {
                let pointer = self.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
                let mut bytes = [0_u8; MinMaxInfo16::SIZE];
                self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
                Win16HostMessage::MinMaxInfo(host_minmax_info(MinMaxInfo16::decode(&bytes)))
            }
            WM_NCCALCSIZE => {
                let Some((data, output_state)) = nonclient_payloads::prepare_guest_message(
                    self, w_param, l_param, memory,
                )? else { return Ok(None); };
                output = MessageOutput::NonClientCalcSize(output_state);
                Win16HostMessage::NonClientCalcSize { w_param, data }
            }
            WM_NCPAINT => Win16HostMessage::NonClientPaint,
            _ if crate::is_multimedia_notification_message(message) => {
                // Keep MMSYSTEM's low-numbered MM_* family out of the general
                // Scalar/GuestBits table. Its exact typed default handler knows
                // which LPARAMs are guest WAVEHDR16/MIDIHDR16 FAR values.
                Win16HostMessage::MultimediaNotification { message, w_param, l_param }
            }
            window_position_payloads::WM_WINDOWPOSCHANGING
                | window_position_payloads::WM_WINDOWPOSCHANGED => {
                let changing = message == window_position_payloads::WM_WINDOWPOSCHANGING;
                let Some((data, output_state)) = window_position_payloads::prepare_guest_message(
                    self, changing, l_param, memory,
                )? else { return Ok(None); };
                if let Some(output_state) = output_state {
                    output = MessageOutput::WindowPosition(output_state);
                }
                Win16HostMessage::WindowPosition { changing, w_param, data }
            }
            _ if message >= WM_USER && (self.window_procedures.contains_key(&window)
                || self.dialog_procedures.contains_key(&window)) && !native_procedure => {
                // The current HWND is backed by a registered guest WndProc.
                // WM_USER+ parameters are application-defined, so keep the
                // guest LPARAM numeric instead of treating it as host memory.
                Win16HostMessage::GuestOpaque { message, w_param, l_param }
            }
            _ if message >= WM_USER => {
                let operation = if native_procedure { "CallWindowProc" } else { "DefWindowProc" };
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 {operation} message 0x{message:04X} needs a typed parameter family; guest LPARAM was not forwarded")));
                return Ok(None);
            }
            _ => match Win16ScalarMessage::from_raw(message) {
                Some(kind) => Win16HostMessage::Scalar { kind, w_param, l_param },
                None if native_procedure => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 CallWindowProc message 0x{message:04X} needs a typed parameter family; guest LPARAM was not forwarded")));
                    return Ok(None);
                }
                None => return Err(RuntimeError::new(Kind::CompatibilityGap,
                    format!("Win16 message 0x{message:04X} needs parameter/result translation"))),
            },
        };
        Ok(Some((payload, output)))
    }

    pub(super) fn finish_window_message_output(&mut self, output: MessageOutput,
        result: Option<Win16HostMessageResult>, memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        // An invalid native HWND returns failure without producing output.
        // A zero-capacity GETTEXT has no output bytes but keeps its native
        // return value; Win3.1 Vol. 3 PDF p. 139 also documents CB_ERR (-1) for a
        // combo box without an edit control, which must not write the buffer.
        let Some(result) = result else { return Ok(0); };
        if matches!(&result.output, Win16HostMessageOutput::WindowRetirements(_)) {
            return self.finish_window_retirement_output(&output, &result);
        }
        match (output, result.output) {
          (MessageOutput::Control(plan), Win16HostMessageOutput::Control(output)) => {
              let bytes = plan.encode(&output, result.value)?;
              super::guest_ranges::commit_guest_output(self, memory, &plan.range, &bytes)?;
          }
          (MessageOutput::ControlColor, Win16HostMessageOutput::ControlColor(brush)) => {
              if result.dialog_result.is_some() || result.value != 0 {
                  return Err(RuntimeError::new(Kind::InternalInvariant,
                      "Win16 control-color message returned an unrelated scalar or dialog result"));
              }
              return self.finish_control_color_brush(brush);
          }
          (MessageOutput::Control(_), Win16HostMessageOutput::None)
              if result.value >= u32::MAX - 1 => {}
          (MessageOutput::OwnerDrawMeasure(range),
              Win16HostMessageOutput::OwnerDrawMeasure { width, height }) => {
              let bytes = super::owner_draw_payloads::measure_output_bytes(width, height);
              super::guest_ranges::commit_guest_output(self, memory, &range, &bytes)?;
          }
          (MessageOutput::Text(Some(output)), Win16HostMessageOutput::Text(bytes)) => {
            if bytes.len() > usize::from(output.buffer.capacity)
                || bytes.len() > output.range.length()
                || bytes.last() != Some(&0)
                || usize::try_from(result.value).ok().and_then(|value| value.checked_add(1))
                    != Some(bytes.len())
                || bytes[..bytes.len().saturating_sub(1)].contains(&0) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "host window text result exceeds its guest buffer or lacks a terminator"));
            }
            super::guest_ranges::commit_guest_output_with_selectors(
                &self.selectors, memory, &output.range, &bytes,
            )?;
          }
          (MessageOutput::Text(Some(_)), Win16HostMessageOutput::None)
              if result.value == 0 || result.value == u32::MAX => {}
          (MessageOutput::Text(None), Win16HostMessageOutput::None)
              if result.value == 0 || result.value == u32::MAX => {}
          (MessageOutput::Text(None), Win16HostMessageOutput::Text(bytes))
              if bytes.is_empty() => {}
          (MessageOutput::MinMaxInfo(range), Win16HostMessageOutput::MinMaxInfo(data)) => {
            super::guest_ranges::commit_guest_output_with_selectors(
                &self.selectors, memory, &range, &guest_minmax_info(data).encode(),
            )?;
          }
          (MessageOutput::NonClientCalcSize(output),
              Win16HostMessageOutput::NonClientCalcSize(data)) => {
              nonclient_payloads::write_guest_result(self, output, data, memory)?;
              return Ok(u32::from(result.value as u16));
          }
          (MessageOutput::WindowPosition(output),
              Win16HostMessageOutput::WindowPosition(data)) => {
              window_position_payloads::write_guest_result(self, output, data, memory)?;
          }
          (MessageOutput::WindowPosition(_), Win16HostMessageOutput::None) => {}
          (MessageOutput::Mdi(output), Win16HostMessageOutput::Mdi(mdi_output)) => {
            if result.dialog_result.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "ordinary Win16 MDI message unexpectedly carried a DLGPROC result"));
            }
            return self.finish_mdi_message(output, Some(crate::Win16HostMdiMessageResult {
                value: result.value,
                output: mdi_output,
            }), memory);
          }
          (MessageOutput::None, Win16HostMessageOutput::None) => {}
          _ => return Err(RuntimeError::new(Kind::InternalInvariant,
              "native window message output does not match its guest destination")),
        }
        Ok(result.value)
    }

    pub(super) fn finish_window_retirement_output(
        &mut self,
        output: &MessageOutput,
        result: &Win16HostMessageResult,
    ) -> Result<u32, RuntimeError> {
        let Win16HostMessageOutput::WindowRetirements(batch) = &result.output else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "window retirement projection received a different output contract"));
        };
        if !matches!(output, MessageOutput::None) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native window retirement receipts conflict with the captured message output contract"));
        }
        self.retire_window_retirement_batch(batch)?;
        Ok(result.value)
    }

    fn finish_control_color_brush(
        &mut self,
        brush: crate::Win16HostControlColorBrush,
    ) -> Result<u32, RuntimeError> {
        control_color_brush_guest_handle(&mut self.guest_gdi, brush)
    }
}

pub(in crate::win16_runtime) fn control_color_brush_guest_handle(
    guest_gdi: &mut super::gdi::GuestGdiHandles,
    brush: crate::Win16HostControlColorBrush,
) -> Result<u32, RuntimeError> {
    // Guest GDI aliases cannot encode native pointers; preserve SDK 3.1
    // COLOR_*+1 values and allocate aliases only for typed ordinary brush IDs.
    match brush {
        crate::Win16HostControlColorBrush::Null => Ok(0),
        crate::Win16HostControlColorBrush::Brush(crate::Win16HostBrush::SystemColor(index))
            if index <= 20 => {
                // Windows 3.1 SDK WINDOWS.H defines COLOR_* as 0..=20;
                // its WM_CTLCOLOR return slot uses the COLOR_*+1 pseudo brush.
                Ok(u32::from(index + 1))
            }
        crate::Win16HostControlColorBrush::Brush(crate::Win16HostBrush::Object(object)) => {
            let handle = guest_gdi.existing_object(object)
                .or_else(|| guest_gdi.allocate_object(object))
                .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 control-color result has no guest HBRUSH16 alias"))?;
            Ok(u32::from(handle))
        }
        crate::Win16HostControlColorBrush::Brush(crate::Win16HostBrush::SystemColor(index)) => {
            Err(RuntimeError::new(Kind::InvalidInput,
                format!("Win16 control-color system brush index {index} exceeds COLOR_ENDCOLORS")))
        }
        crate::Win16HostControlColorBrush::Invalid(handle) => Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("native control-color result carried invalid HBRUSH16 0x{handle:04X}"),
        )),
    }
}
