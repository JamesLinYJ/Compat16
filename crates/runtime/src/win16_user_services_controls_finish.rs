//! Completion of callback-capable USER family services.
//!
//! Kept separate from request decoding so each hand-written runtime unit stays
//! within the repository file-size limit.

use std::{error::Error, fmt};

use super::*;
use crate::Win16HostDialogResult as DialogResult;

#[derive(Debug)]
struct SessionApiFailureCause {
    failure: crate::Win16HostSessionApiFailure,
    os_error: std::io::Error,
}

impl SessionApiFailureCause {
    fn new(failure: crate::Win16HostSessionApiFailure) -> Self {
        Self {
            failure,
            os_error: std::io::Error::from_raw_os_error(failure.error_code as i32),
        }
    }
}

impl fmt::Display for SessionApiFailureCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed with Windows error code {}: {}",
            self.failure.phase.description(),
            self.failure.error_code,
            self.os_error,
        )
    }
}

impl Error for SessionApiFailureCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.os_error)
    }
}

fn report_session_api_failure(
    host: &mut impl RuntimeHost,
    context: &'static str,
    failure: crate::Win16HostSessionApiFailure,
) {
    let message = format!("Win16 USER {context} during {}", failure.phase.description());
    host.report_diagnostic(
        &crate::Diagnostic::warning(Kind::HostFailure, message)
            .with_cause(SessionApiFailureCause::new(failure)),
    );
}

impl Win16State {
    pub(super) fn resolve_dialog_template_titles(
        &mut self,
        template: &mut crate::Win16HostDialogTemplate,
        instance: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(module) = self.module_handle_for_instance(instance) else { return Ok(false); };
        let Some(record) = self.modules.records.get(&module) else { return Ok(false); };
        let Some(definition) = record.definition.as_ref() else { return Ok(false); };
        let strings = formats::NeStringTable::from_module(&record.image, definition)
            .map_err(crate::runtime_error)?;
        // The caller resolves class identities before interpreting titles.
        // This image route deliberately excludes guest class callbacks:
        // their child creation can invalidate the bounded native install plan.
        let icon_route = matches!(&template.class,
            crate::Win16HostDialogAtom::None | crate::Win16HostDialogAtom::Ordinal(0x8002))
            && template.style & 0x0010 == 0 // DS_NOFAILCREATE would hide install failure.
            && template.guest_class_name.is_none()
            && template.items.iter().all(|item|
                matches!(&item.class, crate::Win16HostDialogAtom::Ordinal(0x80..=0x85))
                    && item.guest_class_name.is_none());
        for item in &template.items {
            let static_class = matches!(&item.class, crate::Win16HostDialogAtom::Ordinal(0x82))
                || matches!(&item.class, crate::Win16HostDialogAtom::String(name)
                    if super::dialog_creation::standard_dialog_control_ordinal(name) == Some(0x82));
            // Bit 0x10 belongs to the native STATIC type mask. In particular,
            // 0x13 is not SS_ICON; do not reinterpret its ordinal as RT_STRING.
            if static_class && item.style & 0x1f == 0x13
                && matches!(&item.title, crate::Win16HostDialogAtom::Ordinal(_))
            {
                return Ok(false);
            }
            if static_class && item.style & 0x1f == 0x03
                && !matches!(&item.title, crate::Win16HostDialogAtom::None)
                && (!icon_route || !item.creation_data.is_empty()
                    || !matches!(&item.title, crate::Win16HostDialogAtom::Ordinal(_)
                        | crate::Win16HostDialogAtom::String(_)))
            {
                return Ok(false);
            }
        }
        for item in &mut template.items {
            if matches!(&item.class, crate::Win16HostDialogAtom::Ordinal(0x82))
                && item.style & 0x1f == 0x03
            {
                let name = match &item.title {
                    crate::Win16HostDialogAtom::None => continue,
                    crate::Win16HostDialogAtom::Ordinal(id) => win16_abi::Win16ResourceName::Id(*id),
                    crate::Win16HostDialogAtom::String(name) => win16_abi::Win16ResourceName::Name(name.clone()),
                    crate::Win16HostDialogAtom::GuestClass(_) => return Ok(false),
                };
                if !icon_route || !item.creation_data.is_empty() { return Ok(false); }
                // SS_ICON names and ordinals identify RT_GROUP_ICON, never
                // RT_STRING or a resource in the host executable. Keep ANSI
                // names in the guest resource namespace and reuse LoadIcon's
                // validated guest group/image selection and cache ownership.
                let handle = self.load_icon(instance, name, host)?;
                let Some(icon) = self.guest_images.icon(handle) else { return Ok(false); };
                item.initial_icon = Some(icon);
                item.title = crate::Win16HostDialogAtom::None;
                continue;
            }
            let crate::Win16HostDialogAtom::Ordinal(id) = &item.title else { continue; };
            let Some(bytes) = strings.get(*id).map_err(crate::runtime_error)? else {
                return Ok(false);
            };
            let mut owned = Vec::new();
            // NeStringTable returns the RT_STRING payload without a terminator;
            // keep this owned byte string unterminated because the native
            // UTF-16 template writer appends its own required zero word.
            owned.try_reserve_exact(bytes.len()).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "copy dialog control title string resource", error))?;
            owned.extend_from_slice(bytes);
            item.title = crate::Win16HostDialogAtom::String(owned);
        }
        Ok(true)
    }

    pub(in crate::win16_runtime) fn finish_user_family_service(
        &mut self,
        continuation: Win16UserFamilyContinuation,
        result: Win16HostUserServiceResult,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16UserFamilyCompletion, RuntimeError> {
        use FamilyCompletion as Completion;
        use Win16HostUserServiceResult as ResultValue;

        let pending_dialog_window = continuation.pending_dialog_window();
        let pending_dialog_window_destroyed = continuation.pending_dialog_window_destroyed();
        let pending_dialog_creation = continuation.pending_dialog_creation();
        let pending_dialog_class_root = continuation.pending_dialog_class_root();

        let value = match (continuation.completion, result) {
            (Completion::SystemParameters(spi), ResultValue::SystemParameters(result)) => {
                return self
                    .finish_system_parameters_info(spi, result, memory)
                    .map(|value| Win16UserFamilyCompletion {
                        value,
                        return_kind: continuation.return_kind,
                        dialog_procedure: None,
                        window_creation_observation: None,
                    });
            }
            (Completion::Session, ResultValue::Session(result)) => {
                // Preserve the guest BOOL result; host API failures are warnings with typed causes.
                if let Some(failure) = result.operation_failure {
                    report_session_api_failure(host, "session operation", failure);
                }
                u32::from(result.accepted)
            }
            (Completion::DialogEnd, ResultValue::Dialog(DialogResult::Ended(value))) => {
                u32::from(value)
            }
            (
                Completion::DialogDefaultProcedure { output },
                ResultValue::Dialog(DialogResult::DefaultResult(result)),
            ) => self.finish_window_message_output(output, result, memory)?,
            (
                Completion::DialogCreate { modal: true, .. },
                ResultValue::Dialog(DialogResult::ModalResult(result)),
            ) => {
                if let Some(window) = pending_dialog_window {
                    self.retire_dialog_window(window)?;
                }
                result.map_or(u32::from(u16::MAX), |value| value as u16 as u32)
            }
            (
                Completion::DialogCreate {
                    procedure,
                    instance,
                    modal: false,
                    template_reference,
                    ..
                },
                ResultValue::Dialog(DialogResult::Created { creation, menu }),
            ) => {
                let native_api_return = creation.native_api_return;
                let preflight_rejection = creation.preflight_rejection;
                let live_window = if pending_dialog_window_destroyed {
                    None
                } else {
                    creation.live_window
                };
                let window = if pending_dialog_window_destroyed {
                    if let Some(window) = pending_dialog_window {
                        self.retire_dialog_window(window)?;
                    }
                    None
                } else {
                    match live_window {
                        Some(window) => {
                            if pending_dialog_window.is_some_and(|pending| pending != window) {
                                return Err(RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "CreateDialog returned a different native window than its pending callback",
                                ));
                            }
                            let guest = self.map_window_handle(window, true)?;
                            let creation = pending_dialog_creation.ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "CreateDialog completion lost its exact creation identity",
                                )
                            })?;
                            self.associate_window_creation(guest, window, creation)?;
                            self.initialize_dialog_window_data(guest, instance)?;
                            self.record_window_class_root(guest, window, pending_dialog_class_root)?;
                            Some(guest)
                        }
                        None => {
                            if let Some(window) = pending_dialog_window {
                                self.retire_dialog_window(window)?;
                            }
                            None
                        }
                    }
                };
                if let (Some(_), Some(menu)) = (window, menu) {
                    self.guest_menus.intern(menu).ok_or_else(|| RuntimeError::new(
                        Kind::ResourceExhausted,
                        "guest menu handle table filled during dialog creation",
                    ))?;
                }
                let value = window.unwrap_or(0);
                let window_creation_observation = Some(Win16WindowCreationObservation {
                    api: crate::Win16WindowCreationApi::CreateDialog,
                    native_api_return,
                    preflight_rejection,
                    class_instance: None,
                    window_class: None,
                    live_window,
                    guest_window: value,
                    dialog_ncdestroy_observed: Some(pending_dialog_window_destroyed),
                    dialog_template: Some(template_reference),
                });
                return Ok(Win16UserFamilyCompletion {
                    value: u32::from(value),
                    return_kind: continuation.return_kind,
                    dialog_procedure: window.map(|window| (window, procedure, instance)),
                    window_creation_observation,
                });
            }
            (
                Completion::DialogIsMessage,
                ResultValue::Dialog(DialogResult::MessageHandled(handled)),
            ) => u32::from(handled),
            (Completion::Control { output }, ResultValue::DialogControl(result)) => {
                self.finish_dialog_control(output, result, memory)?
            }
            (Completion::Clipboard(completion), ResultValue::Clipboard(result)) => {
                self.finish_clipboard(completion, result, memory, host)?
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 USER family host result does not match its continuation",
                ));
            }
        };
        Ok(Win16UserFamilyCompletion {
            value,
            return_kind: continuation.return_kind,
            dialog_procedure: None,
            window_creation_observation: None,
        })
    }

    pub(super) fn resolve_dialog_template_classes(
        &self,
        template: &mut crate::Win16HostDialogTemplate,
        instance: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        fn resolve(
            atom: &mut crate::Win16HostDialogAtom,
            guest_identity: &mut Option<crate::Win16HostClassName>,
            instance: u16,
            standard_control: bool,
            state: &Win16State,
            host: &mut impl RuntimeHost,
        ) -> Result<bool, RuntimeError> {
            let class_name = match atom {
                crate::Win16HostDialogAtom::String(name) => {
                    crate::Win16HostClassName::Name(name.clone())
                }
                crate::Win16HostDialogAtom::Ordinal(atom) if standard_control
                    && (0x80..=0x85).contains(atom) => return Ok(true),
                crate::Win16HostDialogAtom::Ordinal(0x8002) if !standard_control => {
                    // WFW 3.1 WINDOWS.H defines WC_DIALOG as atom 0x8002.
                    // Keep that stock class atom native; it is not a guest
                    // class registration and has no guest WndProc route.
                    return Ok(true);
                }
                crate::Win16HostDialogAtom::Ordinal(atom) => {
                    crate::Win16HostClassName::Atom(*atom)
                }
                crate::Win16HostDialogAtom::None
                | crate::Win16HostDialogAtom::GuestClass(_) => return Ok(true),
            };
            let name = match &class_name {
                crate::Win16HostClassName::Name(name) => name,
                crate::Win16HostClassName::Atom(_) => &[] as &[u8],
            };
            let lookup = match &class_name {
                crate::Win16HostClassName::Name(name) => win16_abi::Win16ClassName::Name(name.clone()),
                crate::Win16HostClassName::Atom(atom) => win16_abi::Win16ClassName::Atom(*atom),
            };
            if let Some(class) = state.resolve_window_class(instance, &lookup, host)? {
                *guest_identity = Some(class_name);
                *atom = crate::Win16HostDialogAtom::GuestClass(class.host_class);
                return Ok(true);
            }
            if standard_control {
                if let Some(ordinal) = super::dialog_creation::standard_dialog_control_ordinal(name) {
                    *atom = crate::Win16HostDialogAtom::Ordinal(ordinal);
                    return Ok(true);
                }
            }
            Ok(false)
        }

        if !resolve(&mut template.class, &mut template.guest_class_name, instance, false, self, host)? {
            return Ok(false);
        }
        for item in &mut template.items {
            if !resolve(&mut item.class, &mut item.guest_class_name, instance, true, self, host)? {
                return Ok(false);
            }
        }
        if template.menu_template.is_none()
            && matches!(&template.menu, crate::Win16HostDialogAtom::None)
        {
            if let crate::Win16HostDialogAtom::GuestClass(class) = &template.class {
                if let Some(resource) = self.window_classes.menu_resource_for_host_class(*class) {
                    let owner = self.window_classes.resolve_registered_host_class(*class)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "custom dialog menu lost its exact guest class owner"))?.instance;
                    let Some(menu) = self.resource_menu_template(owner, resource, host)? else {
                        return Ok(false);
                    };
                    template.menu_template = Some(menu);
                }
            }
        }
        Ok(true)
    }
}
