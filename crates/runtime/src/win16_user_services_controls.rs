//! USER dialog-control and clipboard family marshalling.
//!
//! Every host operation contains copied data and opaque host identities only.
//! Guest output pointers remain in the runtime continuation and are validated
//! before the USER worker is entered.

use guest_core::memory::Memory;
use win16_abi::{
    Access, Rect16, Win16ReturnKind,
    Win16ClassName, Win16DialogTemplateRef, Win16SystemParametersInfoRequest,
    Win16UserDialogRequest as DialogRequest, Win16UserFamilyRequest,
};

use super::Win16State;
use super::guest_ranges::GuestOutputRange;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16CreationId,
    Win16HostDialogControlOperation as ControlOperation,
    Win16HostDialogOperation as DialogOperation,
    Win16HostRect,
    Win16HostUserServiceOperation, Win16HostUserServiceResult, Win16HostWindow,
};

#[path = "win16_user_services_clipboard.rs"]
pub(super) mod clipboard;
#[path = "win16_user_services_session.rs"]
pub(super) mod session;
#[path = "win16_dialog_message.rs"]
mod dialog_message;
#[path = "win16_user_services_controls_finish.rs"]
pub(in crate::win16_runtime) mod finish;
#[path = "win16_user_services_control_text.rs"]
mod control_text;
#[path = "win16_user_services_controls_dialog.rs"]
mod dialog_creation;
#[path = "win16_user_services_controls_writeback.rs"]
mod writeback;
pub(in crate::win16_runtime) use clipboard::GuestClipboardState;

#[derive(Clone, Debug)]
pub(super) enum ControlWriteBack {
    Window { parent: u16, native_parent: Win16HostWindow },
    Text { range: GuestOutputRange, capacity: u16 },
    IntegerTranslated { range: Option<GuestOutputRange> },
    DirectoryPath { range: Option<GuestOutputRange>, capacity: u16 },
    DirectorySelection { range: GuestOutputRange, capacity: u16 },
    Rect { range: GuestOutputRange },
}

pub(super) enum FamilyCompletion {
    DialogEnd,
    DialogDefaultProcedure { output: super::messages::MessageOutput },
    DialogCreate {
        creation: Win16CreationId,
        procedure: u32,
        instance: u16,
        modal: bool,
        class_routes: Vec<GuestDialogClassRoute>,
        template_reference: Win16DialogTemplateRef,
    },
    DialogIsMessage,
    Control { output: Option<ControlWriteBack> },
    Clipboard(clipboard::ClipboardCompletion),
    SystemParameters(super::user_services_system_parameters::Win16SpiContinuation),
    Session,
}

#[derive(Clone, Debug)]
pub(super) struct GuestDialogClassRoute {
    root: bool,
    control_id: Option<u16>,
    host_class: crate::Win16HostClass,
    guest_class_name: crate::Win16HostClassName,
}

/// Continuation owned by `WindowReturn::UserFamily` in the shared window
/// callback state machine. Keep this value intact while guest callbacks run.
pub(super) struct Win16UserFamilyContinuation {
    pub(super) return_kind: Win16ReturnKind,
    pub(super) completion: FamilyCompletion,
    pub(super) dialog_window: Option<Win16HostWindow>,
    pub(super) dialog_window_destroyed: bool,
}

impl Win16UserFamilyContinuation {
    /// The dialog root's registration is independent of custom child routes.
    /// An exact creation with no custom root uses the builtin dialog class.
    pub(super) fn pending_dialog_class_root(&self) -> super::windows::WindowClassRoot {
        use super::windows::WindowClassRoot;
        match &self.completion {
            FamilyCompletion::DialogCreate { class_routes, .. } => {
                let mut roots = class_routes.iter().filter(|route| route.root);
                let root = roots.next().map_or(WindowClassRoot::NoRegistration,
                    |route| WindowClassRoot::Class(route.host_class));
                if roots.next().is_some() { WindowClassRoot::Unresolved } else { root }
            }
            _ => WindowClassRoot::Unresolved,
        }
    }

    /// Custom root/control classes stay registered until the entire dialog
    /// creation continuation retires, including controls not yet created.
    pub(super) fn retains_window_class(&self, class: crate::Win16HostClass) -> bool {
        match &self.completion {
            FamilyCompletion::DialogCreate { class_routes, .. } =>
                class_routes.iter().any(|route| route.host_class == class),
            FamilyCompletion::DialogDefaultProcedure {
                output: super::messages::MessageOutput::Mdi(Some(
                    super::messages_mdi::MdiOutputPlan::Create(plan),
                )),
            } => plan.mdi.class == class,
            _ => false,
        }
    }

    pub(in crate::win16_runtime) fn take_clipboard_retirement_reservation(&self) -> usize {
        match &self.completion {
            FamilyCompletion::Clipboard(completion) =>
                completion.take_retirement_reservation(),
            _ => 0,
        }
    }

    /// The native dialog manager can synchronously call a DLGPROC while the
    /// CreateDialog/DialogBox host operation is still pending. Expose the
    /// guest callback and owning module to that callback bridge without
    /// coupling it to WndProc state.
    pub(super) fn pending_dialog_procedure(&self) -> Option<(u32, u16)> {
        match &self.completion {
            FamilyCompletion::DialogCreate { procedure, instance, .. } if *procedure != 0 => {
                Some((*procedure, *instance))
            }
            _ => None,
        }
    }

    pub(super) fn pending_dialog_creation(&self) -> Option<Win16CreationId> {
        match &self.completion {
            FamilyCompletion::DialogCreate { creation, .. } => Some(*creation),
            _ => None,
        }
    }

    pub(super) fn pending_dialog_instance(&self) -> Option<u16> {
        match &self.completion {
            FamilyCompletion::DialogCreate { instance, .. } => Some(*instance),
            _ => None,
        }
    }

    pub(super) fn validate_pending_dialog_class(
        &self,
        creation: Win16CreationId,
        data: &crate::Win16HostCreationData,
    ) -> bool {
        let FamilyCompletion::DialogCreate {
            creation: pending, instance, class_routes, ..
        } = &self.completion else { return false; };
        if *pending != creation || *instance != data.guest_instance { return false; }
        class_routes.iter().any(|route| {
            route.root == data.dialog_root
                && route.host_class == data.class
                && route.guest_class_name == data.guest_class_name
                && if route.root { data.child_id.is_none() }
                    else { route.control_id == data.child_id }
        })
    }

    /// Bind the synchronous native dialog callback stream to its pending
    /// CreateDialog/DialogBox operation. The opaque host identity prevents a
    /// destroyed modeless HWND from being re-aliased after USER returns.
    pub(super) fn bind_pending_dialog_window(&mut self, window: Win16HostWindow) -> bool {
        if self.pending_dialog_instance().is_none() || self.dialog_window_destroyed {
            return false;
        }
        match self.dialog_window {
            Some(active) => active == window,
            None => {
                self.dialog_window = Some(window);
                true
            }
        }
    }

    pub(super) fn pending_dialog_window(&self) -> Option<Win16HostWindow> {
        self.dialog_window
    }

    pub(super) fn pending_dialog_window_destroyed(&self) -> bool {
        self.dialog_window_destroyed
    }

    pub(super) fn mark_pending_dialog_window_destroyed(
        &mut self,
        window: Win16HostWindow,
    ) -> bool {
        if self.dialog_window != Some(window) {
            return false;
        }
        self.dialog_window_destroyed = true;
        true
    }
}

pub(super) enum Win16UserFamilyPreparation {
    TerminateTask { status: u16 },
    Immediate {
        value: u32,
        return_kind: Win16ReturnKind,
        window_creation_observation: Option<Win16WindowCreationObservation>,
    },
    WindowService {
        operation: Win16HostUserServiceOperation,
        continuation: Win16UserFamilyContinuation,
    },
}

#[derive(Clone, Debug)]
pub(super) struct Win16UserFamilyCompletion {
    pub value: u32,
    pub return_kind: Win16ReturnKind,
    /// A successful modeless dialog needs this FARPROC retained by the
    /// separate dialog-procedure table. Modal procedures die with the call.
    pub dialog_procedure: Option<(u16, u32, u16)>,
    pub window_creation_observation: Option<Win16WindowCreationObservation>,
}

#[derive(Clone, Debug)]
pub(super) struct Win16WindowCreationObservation {
    pub api: crate::Win16WindowCreationApi,
    pub native_api_return: crate::Win16NativeWindowApiReturn,
    pub preflight_rejection: Option<crate::Win16WindowCreationRejection>,
    pub class_instance: Option<u16>,
    pub window_class: Option<Win16ClassName>,
    pub live_window: Option<Win16HostWindow>,
    pub guest_window: u16,
    pub dialog_ncdestroy_observed: Option<bool>,
    pub dialog_template: Option<Win16DialogTemplateRef>,
}

impl Win16UserFamilyPreparation {
    fn immediate(value: u32, return_kind: Win16ReturnKind) -> Self {
        Self::Immediate {
            value,
            return_kind,
            window_creation_observation: None,
        }
    }

    fn window(
        operation: Win16HostUserServiceOperation,
        return_kind: Win16ReturnKind,
        completion: FamilyCompletion,
    ) -> Self {
        Self::WindowService {
        operation,
        continuation: Win16UserFamilyContinuation {
            return_kind,
            completion,
            dialog_window: None,
            dialog_window_destroyed: false,
        },
    }
}
}

impl Win16State {
    /// Prepare one decoded USER family request. Immediate cases never touch
    /// the host; callback-capable services are submitted through the shared
    /// worker so they retain the normal nested USER/message flow.
    pub(super) fn prepare_user_family(
        &mut self,
        request: Win16UserFamilyRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_kind: Win16ReturnKind,
    ) -> Result<Win16UserFamilyPreparation, RuntimeError> {
        match request {
            Win16UserFamilyRequest::Session(request) => {
                session::prepare(request, return_kind)
            }
            Win16UserFamilyRequest::SystemParametersInfo(request) => {
                self.prepare_spi(request, memory, host, return_kind)
            }
            Win16UserFamilyRequest::Dialog(request) => {
                self.prepare_dialog_family(request, memory, host, return_kind)
            }
            Win16UserFamilyRequest::Clipboard(request) => {
                self.prepare_clipboard_family(request, memory, host, return_kind)
            }
        }
    }

    fn prepare_spi(
        &self,
        request: Win16SystemParametersInfoRequest,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        return_kind: Win16ReturnKind,
    ) -> Result<Win16UserFamilyPreparation, RuntimeError> {
        use super::user_services_system_parameters::Win16SpiPreparation as Spi;
        match self.prepare_system_parameters_info(request, memory, host)? {
            Spi::Immediate(value) => Ok(Win16UserFamilyPreparation::immediate(value, return_kind)),
            Spi::Host { request, continuation } => Ok(Win16UserFamilyPreparation::window(
                Win16HostUserServiceOperation::SystemParameters(request), return_kind,
                FamilyCompletion::SystemParameters(continuation),
            )),
        }
    }

    fn prepare_dialog_family(
        &mut self,
        request: DialogRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_kind: Win16ReturnKind,
    ) -> Result<Win16UserFamilyPreparation, RuntimeError> {
        use DialogRequest as Request;
        use Win16UserFamilyPreparation as Prepared;

        let request_for_output = request.clone();
        let op = match request {
            Request::DefaultProcedure { dialog, message, w_param, l_param } => {
                let Some(native_dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                if !self.window_is_dialog(dialog) {
                    return Ok(Prepared::immediate(0, return_kind));
                }
                let Some(callback) = self.active_window_callback(
                    dialog, message, w_param, l_param,
                ) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let Some((translated, output)) = self.translate_window_message(
                    dialog, message, w_param, l_param, memory, host, false,
                )? else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::Dialog(DialogOperation::DefaultProcedure {
                        dialog: native_dialog,
                        callback,
                        message: translated,
                    }),
                    return_kind,
                    FamilyCompletion::DialogDefaultProcedure { output },
                ));
            }
            Request::Create { template, owner, procedure, modal, init_parameter } => {
                let template_reference = template.clone();
                if procedure != 0 {
                    self.validate_dialog_procedure(procedure, memory)?;
                }
                let instance = match &template {
                    Win16DialogTemplateRef::Resource { instance, .. }
                    | Win16DialogTemplateRef::GlobalHandle { instance, .. }
                    | Win16DialogTemplateRef::FarAddress { instance, .. } => *instance,
                };
                let owner = match self.dialog_window(owner) {
                    Some(owner) => Some(owner),
                    None if owner == 0 => None,
                    None => return Ok(dialog_create_not_invoked(
                        modal,
                        return_kind,
                        crate::Win16WindowCreationRejection::GuestOwnerUnavailable,
                        template_reference,
                    )),
                };
                let template = match template {
                    Win16DialogTemplateRef::Resource { instance, name } => {
                        self.dialog_template_from_resource(instance, &name, host)?
                    }
                    Win16DialogTemplateRef::GlobalHandle { template, .. } => {
                        self.dialog_template_from_global(template, memory)?
                    }
                    Win16DialogTemplateRef::FarAddress { template, .. } => {
                        self.dialog_template_from_far(memory, template)?
                    }
                };
                let Some(template) = template else {
                    return Ok(dialog_create_not_invoked(
                        modal,
                        return_kind,
                        crate::Win16WindowCreationRejection::GuestTemplateUnavailable,
                        template_reference,
                    ));
                };
                let mut template = template;
                if !matches!(&template.menu, crate::Win16HostDialogAtom::None) {
                    let resource = match &template.menu {
                        crate::Win16HostDialogAtom::Ordinal(id) => win16_abi::Win16ResourceName::Id(*id),
                        crate::Win16HostDialogAtom::String(bytes) => {
                            let name = bytes.strip_suffix(&[0]).unwrap_or(bytes);
                            win16_abi::Win16ResourceName::Name(name.to_vec())
                        }
                        crate::Win16HostDialogAtom::None | crate::Win16HostDialogAtom::GuestClass(_) => {
                            return Ok(dialog_create_not_invoked(modal, return_kind,
                                crate::Win16WindowCreationRejection::UnsupportedMenuResource,
                                template_reference));
                        }
                    };
                    let Some(menu_template) = self.resource_menu_template(instance, resource, host)? else {
                        host.report_diagnostic(&crate::Diagnostic::warning(Kind::CompatibilityGap,
                            "Win16 dialog menu resource could not be converted to an owned native menu tree"));
                        return Ok(dialog_create_not_invoked(modal, return_kind,
                            crate::Win16WindowCreationRejection::UnsupportedMenuResource,
                            template_reference));
                    };
                    template.menu_template = Some(menu_template);
                }
                // Resolve local/global registrations before interpreting control
                // styles. Only the predefined STATIC class owns SS_ICON; a
                // guest class with that name keeps its own title contract.
                if !self.resolve_dialog_template_classes(&mut template, instance, host)? {
                    host.report_diagnostic(&crate::Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "Win16 dialog template references a class unavailable in its local, global, or predefined namespace",
                    ));
                    return Ok(dialog_create_not_invoked(
                        modal,
                        return_kind,
                        crate::Win16WindowCreationRejection::GuestClassUnavailable,
                        template_reference,
                    ));
                }
                if !self.resolve_dialog_template_titles(&mut template, instance, host)? {
                    host.report_diagnostic(&crate::Diagnostic::warning(Kind::CompatibilityGap,
                        "Win16 dialog control title resource is missing or its typed image route is unsupported"));
                    return Ok(dialog_create_not_invoked(modal, return_kind,
                        crate::Win16WindowCreationRejection::UnsupportedControlTitleResource,
                        template_reference));
                }
                if let crate::Win16HostDialogAtom::GuestClass(class) = &template.class {
                    let Some(resolved) = self.window_classes.resolve_registered_host_class(*class) else {
                        return Ok(dialog_create_not_invoked(modal, return_kind,
                            crate::Win16WindowCreationRejection::GuestClassUnavailable,
                            template_reference));
                    };
                    // SDK 3.0's DLGTEMPLATE contract requires custom dialog
                    // classes to reserve the Win16 DLGWINDOWEXTRA area and
                    // call DefDlgProc from their WndProc. Guest storage stays
                    // separate from Win32's own dialog-manager bytes.
                    if resolved.wnd_proc == 0
                        || resolved.window_extra_bytes < 30
                    {
                        host.report_diagnostic(&crate::Diagnostic::warning(Kind::CompatibilityGap,
                            "custom Win16 dialog class lacks a valid WndProc or the 30-byte DLGWINDOWEXTRA contract"));
                        return Ok(dialog_create_not_invoked(modal, return_kind,
                            crate::Win16WindowCreationRejection::UnsupportedGuestClassRoute,
                            template_reference));
                    }
                }
                let creation = self.allocate_window_creation_identity()?;
                let class_routes = dialog_creation::guest_class_routes(&template)?;
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::Dialog(DialogOperation::Create {
                        creation, guest_instance: instance, owner, template, modal, init_parameter,
                    }),
                    return_kind,
                    FamilyCompletion::DialogCreate {
                        creation,
                        procedure,
                        instance,
                        modal,
                        class_routes,
                        template_reference,
                    },
                ));
            }
            Request::End { dialog, result } => {
                let Some(dialog) = self.window_handles.get(&dialog).copied() else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::Dialog(DialogOperation::End { dialog, result }),
                    return_kind, FamilyCompletion::DialogEnd,
                ));
            }
            Request::GetItem { dialog, id } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                ControlOperation::GetItem { dialog, id }
            }
            Request::NextGroupItem { dialog, control, previous } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let control = match self.window_handles.get(&control).copied() {
                    Some(control) => Some(control),
                    None if control == 0 => None,
                    None => return Ok(Prepared::immediate(0, return_kind)),
                };
                ControlOperation::GetNextGroupItem { dialog, control, previous }
            }
            Request::NextTabItem { dialog, control, previous } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let control = match self.window_handles.get(&control).copied() {
                    Some(control) => Some(control),
                    None if control == 0 => None,
                    None => return Ok(Prepared::immediate(0, return_kind)),
                };
                ControlOperation::GetNextTabItem { dialog, control, previous }
            }
            Request::SetItemText { dialog, id, text } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                ControlOperation::SetItemText { dialog, id, text }
            }
            Request::GetItemText { dialog, id, output, capacity } => {
                if capacity < 0 { return Ok(Prepared::immediate(0, return_kind)); }
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let capacity = capacity as u16;
                ControlOperation::GetItemText { dialog, id, capacity, buffer_is_null: output == 0 }
            }
            Request::SetItemInteger { dialog, id, value, signed } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                ControlOperation::SetItemInteger { dialog, id, value, signed }
            }
            Request::GetItemInteger { dialog, id, signed, translated_output } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                if translated_output != 0 {
                    self.checked_pointer(translated_output, Access::Write, 2, memory)?;
                }
                ControlOperation::GetItemInteger { dialog, id, signed }
            }
            Request::CheckButton { dialog, id, state } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                ControlOperation::CheckButton { dialog, id, state }
            }
            Request::IsButtonChecked { dialog, id } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                ControlOperation::IsButtonChecked { dialog, id }
            }
            Request::CheckRadioButton { dialog, first, last, checked } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                ControlOperation::CheckRadioButton { dialog, first, last, checked }
            }
            Request::DirectoryList {
                dialog, path_output, path_spec, list_id, path_id, file_type, combo_box,
            } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let (pointer, capacity) = if path_output == 0 {
                    (None, 0)
                } else {
                    let pointer = self.checked_pointer(path_output, Access::Write, 1, memory)?;
                    let capacity = self.selector_tail_capacity(pointer)?;
                    if capacity == 0 { return Ok(Prepared::immediate(0, return_kind)); }
                    self.preflight_text_write(memory, pointer, usize::from(capacity))?;
                    (Some(GuestOutputRange::capture(
                        self, memory, pointer, usize::from(capacity),
                    )?), capacity)
                };
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::DialogControl(ControlOperation::DirectoryList {
                        dialog, path_spec, path_capacity: capacity, list_id, path_id,
                        file_type, combo_box,
                    }),
                    return_kind,
                    FamilyCompletion::Control {
                        output: Some(ControlWriteBack::DirectoryPath { range: pointer, capacity }),
                    },
                ));
            }
            Request::DirectorySelect { dialog, output, capacity, control_id, combo_box } => {
                if capacity.is_some_and(|capacity| capacity <= 0) {
                    return Ok(Prepared::immediate(0, return_kind));
                }
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let pointer = self.checked_pointer(output, Access::Write, 1, memory)?;
                let capacity = match capacity {
                    Some(capacity) => capacity as u16,
                    None => self.selector_tail_capacity(pointer)?,
                };
                if capacity == 0 { return Ok(Prepared::immediate(0, return_kind)); }
                self.preflight_text_write(memory, pointer, usize::from(capacity))?;
                let range = GuestOutputRange::capture(
                    self, memory, pointer, usize::from(capacity),
                )?;
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::DialogControl(ControlOperation::DirectorySelect {
                        dialog, capacity, control_id, combo_box,
                    }),
                    return_kind,
                    FamilyCompletion::Control {
                        output: Some(ControlWriteBack::DirectorySelection { range, capacity }),
                    },
                ));
            }
            Request::AdjustWindowRect { rect, style, ex_style, menu } => {
                let pointer = self.checked_pointer(rect, Access::Read, Rect16::SIZE, memory)?;
                self.selectors.translate(pointer, Access::Write, Rect16::SIZE, memory)
                    .map_err(crate::runtime_error)?;
                let range = GuestOutputRange::capture(self, memory, pointer, Rect16::SIZE)?;
                let rect16 = self.read_rect16(memory, pointer)?;
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::DialogControl(ControlOperation::AdjustWindowRect {
                        rect: host_rect(rect16), style, ex_style, menu,
                    }),
                    return_kind,
                    FamilyCompletion::Control {
                        output: Some(ControlWriteBack::Rect { range }),
                    },
                ));
            }
            Request::MapDialogRect { dialog, rect } => {
                let Some(dialog) = self.dialog_window(dialog) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let pointer = self.checked_pointer(rect, Access::Read, Rect16::SIZE, memory)?;
                self.selectors.translate(pointer, Access::Write, Rect16::SIZE, memory)
                    .map_err(crate::runtime_error)?;
                let range = GuestOutputRange::capture(self, memory, pointer, Rect16::SIZE)?;
                let rect16 = self.read_rect16(memory, pointer)?;
                return Ok(Prepared::window(
                    Win16HostUserServiceOperation::DialogControl(ControlOperation::MapDialogRect {
                        dialog, rect: host_rect(rect16),
                    }),
                    return_kind,
                    FamilyCompletion::Control {
                        output: Some(ControlWriteBack::Rect { range }),
                    },
                ));
            }
            Request::IsMessage { dialog, message } => {
                return dialog_message::prepare(self, dialog, message, host, return_kind);
            }
        };

        let output = match &op {
            ControlOperation::GetItem { .. } => {
                let Request::GetItem { dialog, .. } = request_for_output else { unreachable!() };
                let ControlOperation::GetItem { dialog: native_parent, .. } = &op else {
                    unreachable!()
                };
                Some(ControlWriteBack::Window { parent: dialog, native_parent: *native_parent })
            }
            ControlOperation::GetNextGroupItem { .. } => {
                let Request::NextGroupItem { dialog, .. } = request_for_output else { unreachable!() };
                let ControlOperation::GetNextGroupItem { dialog: native_parent, .. } = &op else {
                    unreachable!()
                };
                Some(ControlWriteBack::Window { parent: dialog, native_parent: *native_parent })
            }
            ControlOperation::GetNextTabItem { .. } => {
                let Request::NextTabItem { dialog, .. } = request_for_output else { unreachable!() };
                let ControlOperation::GetNextTabItem { dialog: native_parent, .. } = &op else {
                    unreachable!()
                };
                Some(ControlWriteBack::Window { parent: dialog, native_parent: *native_parent })
            }
            ControlOperation::GetItemText { capacity, .. } => {
                if *capacity == 0 { None } else {
                    let Request::GetItemText { output, .. } = request_for_output else { unreachable!() };
                    let pointer = self.checked_pointer(output, Access::Write,
                        usize::from(*capacity), memory)?;
                    let range = GuestOutputRange::capture(
                        self, memory, pointer, usize::from(*capacity),
                    )?;
                    Some(ControlWriteBack::Text { range, capacity: *capacity })
                }
            }
            ControlOperation::GetItemInteger { .. } => {
                let Request::GetItemInteger { translated_output, .. } = request_for_output else { unreachable!() };
                let pointer = if translated_output == 0 { None } else {
                    Some(self.checked_pointer(translated_output, Access::Write, 2, memory)?)
                };
                let range = pointer.map(|pointer| GuestOutputRange::capture(self, memory, pointer, 2))
                    .transpose()?;
                Some(ControlWriteBack::IntegerTranslated { range })
            }
            _ => None,
        };
        Ok(Prepared::window(
            Win16HostUserServiceOperation::DialogControl(op), return_kind,
            FamilyCompletion::Control { output },
        ))
    }
}

fn host_rect(rect: Rect16) -> Win16HostRect {
    Win16HostRect {
        left: i32::from(rect.left),
        top: i32::from(rect.top),
        right: i32::from(rect.right),
        bottom: i32::from(rect.bottom),
    }
}


fn dialog_create_failure(modal: bool) -> u32 {
    if modal { u32::from(u16::MAX) } else { 0 }
}

fn dialog_create_not_invoked(
    modal: bool,
    return_kind: Win16ReturnKind,
    rejection: crate::Win16WindowCreationRejection,
    template_reference: Win16DialogTemplateRef,
) -> Win16UserFamilyPreparation {
    let value = dialog_create_failure(modal);
    let window_creation_observation = (!modal).then_some(Win16WindowCreationObservation {
        api: crate::Win16WindowCreationApi::CreateDialog,
        native_api_return: crate::Win16NativeWindowApiReturn::NotInvoked,
        preflight_rejection: Some(rejection),
        class_instance: None,
        window_class: None,
        live_window: None,
        guest_window: value as u16,
        dialog_ncdestroy_observed: None,
        dialog_template: Some(template_reference),
    });
    Win16UserFamilyPreparation::Immediate {
        value,
        return_kind,
        window_creation_observation,
    }
}

#[cfg(test)]
#[path = "win16_dialog_class_retention_tests.rs"]
mod dialog_class_retention_tests;

#[cfg(test)]
mod retained_class_tests {
    use super::*;

    #[test]
    fn class_data_unregister_class_dialog_creation_retains_exact_root_and_uncreated_control_class_tokens() {
        let root = crate::Win16HostClass(0x1000_0001);
        let control = crate::Win16HostClass(0x1000_0002);
        // Matching guest spelling does not establish native class identity.
        let class_name = crate::Win16HostClassName::Name(b"SharedDisplayName".to_vec());
        let mut continuation = Win16UserFamilyContinuation {
            return_kind: Win16ReturnKind::Word,
            completion: FamilyCompletion::DialogCreate {
                creation: Win16CreationId(1), procedure: 0x1234_0010,
                instance: 0x5678, modal: false,
                class_routes: vec![
                    GuestDialogClassRoute { root: true, control_id: None,
                        host_class: root, guest_class_name: class_name.clone() },
                    GuestDialogClassRoute { root: false, control_id: Some(10),
                        host_class: control, guest_class_name: class_name },
                ],
                template_reference: Win16DialogTemplateRef::FarAddress {
                    instance: 0x5678, template: 0x4321_0020,
                },
            },
            dialog_window: None, dialog_window_destroyed: false,
        };
        assert!(continuation.retains_window_class(root));
        assert!(continuation.retains_window_class(control));
        assert!(!continuation.retains_window_class(crate::Win16HostClass(0x1000_0003)));
        // A destroyed root does not retire pending child routes or completion
        // owners. The whole continuation remains authoritative until popped.
        continuation.dialog_window = Some(Win16HostWindow(1));
        continuation.dialog_window_destroyed = true;
        assert!(continuation.retains_window_class(root));
        assert!(continuation.retains_window_class(control));
        continuation.completion = FamilyCompletion::DialogEnd;
        assert!(!continuation.retains_window_class(root));
        assert!(!continuation.retains_window_class(control));
    }
}

#[cfg(test)]
#[path = "win16_dialog_icon_title_tests.rs"]
mod dialog_icon_title_tests;
