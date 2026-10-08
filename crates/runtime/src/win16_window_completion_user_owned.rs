//! State-owned projection for USER results that retain global-memory or HWND owners.

use std::sync::Arc;

use guest_core::memory::Memory;

use super::super::super::user_services_controls::{
    FamilyCompletion, Win16UserFamilyCompletion, Win16UserFamilyContinuation,
    Win16WindowCreationObservation,
    clipboard::ClipboardCompletion,
};
use super::super::operation_frame::{UserFamilyProjection, UserFamilyProjectionPhase};
use super::super::super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostUserServiceResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedFamily {
    Clipboard,
    DialogCreate,
}

#[derive(Debug)]
enum OwnedPhase {
    Ready,
    Attempted,
    Failed(Arc<RuntimeError>),
    PublishDialogProcedure(Win16UserFamilyCompletion),
    Complete {
        value: u32,
        observation: Option<Win16WindowCreationObservation>,
    },
}

/// One-shot effect journal attached to the exact returned USER completion.
#[derive(Debug)]
pub(in crate::win16_runtime) struct Win16UserOwnedProjection {
    family: OwnedFamily,
    phase: OwnedPhase,
}

impl Win16UserOwnedProjection {
    pub(in crate::win16_runtime) fn creation_observation(
        &self,
    ) -> Option<&Win16WindowCreationObservation> {
        if self.family != OwnedFamily::DialogCreate {
            return None;
        }
        match &self.phase {
            OwnedPhase::Complete { observation, .. } => observation.as_ref(),
            _ => None,
        }
    }
}

pub(in crate::win16_runtime::windows) fn finish_user_family_owned_projection(
    state: &mut Win16State,
    continuation: &Win16UserFamilyContinuation,
    result: &Win16HostUserServiceResult,
    owner: &mut UserFamilyProjection,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(u32, win16_abi::Win16ReturnKind), RuntimeError> {
    let family = owned_family(&continuation.completion).ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant,
        "state-owned USER projection received a completion outside its owner families",
    ))?;
    if !result_matches(family, &continuation.completion, result) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "state-owned USER result does not match its exact retained completion"));
    }
    if owner.owned_projection.is_none() {
        owner.owned_projection = Some(Win16UserOwnedProjection {
            family,
            phase: OwnedPhase::Ready,
        });
    }

    let value = {
        let projection = owner.owned_projection.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "state-owned USER projection lost its one-shot owner journal",
        ))?;
        if projection.family != family {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "state-owned USER owner journal changed completion family"));
        }

        let mut retained_continuation = if matches!(&projection.phase, OwnedPhase::Ready) {
            Some(clone_owned_continuation(continuation)?)
        } else {
            None
        };

        loop {
            let phase = std::mem::replace(&mut projection.phase, OwnedPhase::Attempted);
            match phase {
                OwnedPhase::Ready => {
                    let retained = retained_continuation.take().ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "ready USER owner has no exact retained effect input",
                    ))?;
                    match state.finish_user_family_service(
                        retained,
                        result.clone(),
                        memory,
                        host,
                    ) {
                        Ok(completion) => {
                            if completion.return_kind != continuation.return_kind {
                                let cause = Arc::new(RuntimeError::new(Kind::InternalInvariant,
                                    "USER family completion changed the captured Win16 return ABI"));
                                projection.phase = OwnedPhase::Failed(Arc::clone(&cause));
                                return Err(shared_error(cause));
                            }
                            if family == OwnedFamily::DialogCreate {
                                projection.phase = OwnedPhase::PublishDialogProcedure(completion);
                            } else {
                                projection.phase = OwnedPhase::Complete {
                                    value: completion.value,
                                    observation: None,
                                };
                            }
                        }
                        Err(error) => {
                            let cause = Arc::new(error);
                            projection.phase = OwnedPhase::Failed(Arc::clone(&cause));
                            return Err(shared_error(cause));
                        }
                    }
                }
                OwnedPhase::Attempted => {
                    projection.phase = OwnedPhase::Attempted;
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "state-owned USER completion re-entered an unresolved effect"));
                }
                OwnedPhase::Failed(cause) => {
                    projection.phase = OwnedPhase::Failed(Arc::clone(&cause));
                    return Err(shared_error(cause));
                }
                OwnedPhase::PublishDialogProcedure(completion) => {
                    if let Err(error) = publish_dialog_procedure(state, &completion) {
                        let cause = Arc::new(error);
                        projection.phase = OwnedPhase::Failed(Arc::clone(&cause));
                        return Err(shared_error(cause));
                    }
                    projection.phase = OwnedPhase::Complete {
                        value: completion.value,
                        observation: completion.window_creation_observation,
                    };
                }
                OwnedPhase::Complete { value, observation } => {
                    projection.phase = OwnedPhase::Complete { value, observation };
                    break value;
                }
            }
        }
    };

    owner.value = Some(value);
    owner.phase = UserFamilyProjectionPhase::Complete;
    Ok((value, continuation.return_kind))
}

fn owned_family(completion: &FamilyCompletion) -> Option<OwnedFamily> {
    match completion {
        FamilyCompletion::DialogCreate { .. } => Some(OwnedFamily::DialogCreate),
        FamilyCompletion::Clipboard(
            ClipboardCompletion::Empty { .. }
            | ClipboardCompletion::FormatAvailable { .. }
            | ClipboardCompletion::SetData { .. }
            | ClipboardCompletion::GetData { .. },
        ) => Some(OwnedFamily::Clipboard),
        _ => None,
    }
}

fn result_matches(
    family: OwnedFamily,
    completion: &FamilyCompletion,
    result: &Win16HostUserServiceResult,
) -> bool {
    match (family, completion, result) {
        (
            OwnedFamily::DialogCreate,
            FamilyCompletion::DialogCreate { modal: true, .. },
            Win16HostUserServiceResult::Dialog(crate::Win16HostDialogResult::ModalResult(_)),
        ) => true,
        (
            OwnedFamily::DialogCreate,
            FamilyCompletion::DialogCreate { modal: false, .. },
            Win16HostUserServiceResult::Dialog(crate::Win16HostDialogResult::Created { .. }),
        ) => true,
        (
            OwnedFamily::Clipboard,
            FamilyCompletion::Clipboard(
                ClipboardCompletion::Empty { .. }
                | ClipboardCompletion::FormatAvailable { .. }
                | ClipboardCompletion::SetData { .. }
                | ClipboardCompletion::GetData { .. },
            ),
            Win16HostUserServiceResult::Clipboard(_),
        ) => true,
        _ => false,
    }
}

fn clone_owned_continuation(
    continuation: &Win16UserFamilyContinuation,
) -> Result<Win16UserFamilyContinuation, RuntimeError> {
    let completion = match &continuation.completion {
        FamilyCompletion::DialogCreate {
            creation,
            procedure,
            instance,
            modal,
            class_routes,
            template_reference,
        } => FamilyCompletion::DialogCreate {
            creation: *creation,
            procedure: *procedure,
            instance: *instance,
            modal: *modal,
            class_routes: class_routes.clone(),
            template_reference: template_reference.clone(),
        },
        FamilyCompletion::Clipboard(completion @ (
            ClipboardCompletion::Empty { .. }
            | ClipboardCompletion::FormatAvailable { .. }
            | ClipboardCompletion::SetData { .. }
            | ClipboardCompletion::GetData { .. }
        )) => FamilyCompletion::Clipboard(completion.clone()),
        _ => return Err(RuntimeError::new(Kind::InternalInvariant,
            "state-owned USER completion cannot retain this family input")),
    };
    Ok(Win16UserFamilyContinuation {
        return_kind: continuation.return_kind,
        completion,
        dialog_window: continuation.dialog_window,
        dialog_window_destroyed: continuation.dialog_window_destroyed,
    })
}

fn publish_dialog_procedure(
    state: &mut Win16State,
    completion: &Win16UserFamilyCompletion,
) -> Result<(), RuntimeError> {
    let Some((window, procedure, instance)) = completion.dialog_procedure else {
        return Ok(());
    };
    match state.dialog_procedures.get(&window) {
        Some(existing) if *existing == (procedure, instance) => Ok(()),
        Some(_) => Err(RuntimeError::new(Kind::InternalInvariant,
            "dialog procedure table conflicts with the exact completed creation")),
        None => {
            state.dialog_procedures.insert(window, (procedure, instance));
            Ok(())
        }
    }
}

fn shared_error(cause: Arc<RuntimeError>) -> RuntimeError {
    super::super::super::callback_lifo::shared_runtime_error(cause)
}
