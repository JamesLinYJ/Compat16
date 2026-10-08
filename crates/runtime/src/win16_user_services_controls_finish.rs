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
        &self,
        template: &mut crate::Win16HostDialogTemplate,
        instance: u16,
    ) -> Result<bool, RuntimeError> {
        let Some(module) = self.module_handle_for_instance(instance) else { return Ok(false); };
        let Some(record) = self.modules.records.get(&module) else { return Ok(false); };
        let Some(definition) = record.definition.as_ref() else { return Ok(false); };
        let strings = formats::NeStringTable::from_module(&record.image, definition)
            .map_err(crate::runtime_error)?;
        for item in &mut template.items {
            let crate::Win16HostDialogAtom::Ordinal(id) = &item.title else { continue; };
            // Win32's ordinal form for STATIC/SS_ICON names a native-module
            // resource, while this ID belongs to the guest NE module. Until
            // the host image lease is installed in the template route, do
            // not let native USER accidentally load a same-numbered host icon.
            if matches!(&item.class, crate::Win16HostDialogAtom::Ordinal(0x82))
                && item.style & 0x0f == 0x03
            {
                return Ok(false);
            }
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
                if result.cleanup.owner_retained {
                    let message = if result.request_attempted {
                        format!(
                            "shutdown-token cleanup remains pending after the Win16 USER session request (restore pending: {}, token close pending: {}, previous privilege state saved: {}, unreported failure receipt: {})",
                            result.cleanup.restore_pending,
                            result.cleanup.token_close_pending,
                            result.cleanup.previous_privilege_state_saved,
                            result.cleanup.failure_receipt_unreported,
                        )
                    } else {
                        format!(
                            "Win16 USER session request was not issued because shutdown-token cleanup remains pending (restore pending: {}, token close pending: {}, previous privilege state saved: {}, unreported failure receipt: {})",
                            result.cleanup.restore_pending,
                            result.cleanup.token_close_pending,
                            result.cleanup.previous_privilege_state_saved,
                            result.cleanup.failure_receipt_unreported,
                        )
                    };
                    host.report_diagnostic(&crate::Diagnostic::warning(Kind::HostFailure, message));
                }
                if let Some(failure) = result.operation_failure {
                    report_session_api_failure(host, "session operation", failure);
                }
                if let Some(failure) = result.privilege_restore_failure {
                    report_session_api_failure(host, "restore the host shutdown privilege", failure);
                }
                if let Some(failure) = result.token_close_failure {
                    report_session_api_failure(host, "close the host process token", failure);
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
                    let Some(menu) = self.resource_menu_template(instance, resource, host)? else {
                        return Ok(false);
                    };
                    template.menu_template = Some(menu);
                }
            }
        }
        Ok(true)
    }
}
