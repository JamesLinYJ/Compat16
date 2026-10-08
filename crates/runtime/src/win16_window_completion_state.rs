//! State-wide USER result projection while the exact source frame stays parked.

use super::super::user_services_controls::{FamilyCompletion, clipboard::ClipboardCompletion};
use super::*;

impl Win16State {
    pub(super) fn window_completion_needs_state_projection(
        &self,
        frame_id: u64,
    ) -> Result<bool, RuntimeError> {
        let completion = self
            .window_operations
            .last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "state-wide USER projection has no exact top completion",
                )
            })?;
        let has_window_retirements = match &completion.result {
            Win16WindowResult::Message(Some(result)) => matches!(
                &result.output,
                crate::Win16HostMessageOutput::WindowRetirements(_),
            ),
            Win16WindowResult::UserService(crate::Win16HostUserServiceResult::Dialog(
                crate::Win16HostDialogResult::DefaultResult(Some(result)),
            )) => matches!(
                &result.output,
                crate::Win16HostMessageOutput::WindowRetirements(_),
            ),
            _ => false,
        };
        let state_owned = match &completion.continuation {
            WindowReturn::CommonDialog(_) | WindowReturn::ShellExecution(_) => true,
            WindowReturn::Message { output }
                if matches!(output, super::super::messages::MessageOutput::Mdi(_))
                    || has_window_retirements =>
            {
                true
            }
            WindowReturn::UserFamily(continuation) => {
                matches!(
                    &continuation.completion,
                    FamilyCompletion::DialogCreate { .. }
                        | FamilyCompletion::Clipboard(
                            ClipboardCompletion::Empty { .. }
                                | ClipboardCompletion::FormatAvailable { .. }
                                | ClipboardCompletion::SetData { .. }
                                | ClipboardCompletion::GetData { .. }
                        ),
                ) || (has_window_retirements
                    && matches!(
                        &continuation.completion,
                        FamilyCompletion::DialogDefaultProcedure { .. },
                    ))
            }
            _ => false,
        };
        Ok(state_owned || matches!(&completion.result, Win16WindowResult::DispatchedMdi { .. },))
    }

    pub(super) fn project_state_owned_window_completion(
        &mut self,
        frame_id: u64,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        let frame = self
            .window_operations
            .last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "state-wide USER projection changed its exact top frame",
                )
            })?;
        let completion = frame.completion.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "state-wide USER projection lost its cached result",
            )
        })?;
        if completion.journal.phase != WindowOperationCompletionPhase::Received
            || !completion.journal.owns_return(&completion.continuation)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "state-wide USER projection has an inconsistent continuation or phase",
            ));
        }
        // The source frame and its CPU/native owners remain in the LIFO. Only
        // its actual completion carrier is borrowed into this local owner so
        // global-memory operations can use the same runtime state. Projection
        // has no CPU entry and cannot run a guest callback or pop this frame.
        let mut completion = frame.completion.take().expect("completion checked above");
        // Keep every projection failure inside this closure. The carrier has
        // been taken from its source frame and must be restored below even
        // when an arm uses `?` or returns an error before finishing projection.
        let result = (|| { match (
            &completion.continuation,
            &completion.result,
            &mut completion.journal.projection,
        ) {
            (
                WindowReturn::CommonDialog(continuation),
                Win16WindowResult::CommonDialog(result),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::CommonDialog(owner)),
            ) => super::completion_common_dialog::finish_common_dialog_projection(
                self,
                continuation,
                result,
                owner,
                memory,
                host,
            ),
            (
                WindowReturn::ShellExecution(continuation),
                Win16WindowResult::ShellExecution(result),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::ShellExecution(owner)),
            ) => super::super::compat_shell_execution::finish_shell_execution_projection(
                self,
                continuation,
                result,
                owner,
                memory,
                host,
            ),
            (
                WindowReturn::Message {
                    output: super::super::messages::MessageOutput::Mdi(output),
                },
                Win16WindowResult::Message(result),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::Message(_)),
            ) => {
                let result = match result {
                    Some(result) if result.dialog_result.is_some() => Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "ordinary Win16 MDI operation returned a DLGPROC result",
                    )),
                    Some(result) => match &result.output {
                        crate::Win16HostMessageOutput::Mdi(output) => {
                            Ok(Some(crate::Win16HostMdiMessageResult {
                                value: result.value,
                                output: output.clone(),
                            }))
                        }
                        _ => Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "typed MDI window operation returned a non-MDI output",
                        )),
                    },
                    None => Ok(None),
                };
                result.and_then(|result| {
                    self.finish_mdi_message(output.clone(), result, memory)
                        .map(|value| (value, Win16ReturnKind::Dword))
                })
            }
            (
                WindowReturn::Message { output },
                Win16WindowResult::Message(Some(result)),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::Message(owner)),
            ) if matches!(
                &result.output,
                crate::Win16HostMessageOutput::WindowRetirements(_),
            ) =>
            {
                let value = self.finish_window_retirement_output(output, result)?;
                owner.value = Some(value);
                owner.phase = super::operation_frame::MessageProjectionPhase::Complete;
                Ok((value, Win16ReturnKind::Dword))
            }
            (
                WindowReturn::UserFamily(continuation),
                Win16WindowResult::UserService(crate::Win16HostUserServiceResult::Dialog(
                    crate::Win16HostDialogResult::DefaultResult(Some(result)),
                )),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::UserFamily(owner)),
            ) if matches!(
                &result.output,
                crate::Win16HostMessageOutput::WindowRetirements(_),
            ) =>
            {
                let FamilyCompletion::DialogDefaultProcedure { output } = &continuation.completion
                else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "window retirement receipt came from a non-default dialog procedure",
                    ));
                };
                let value = self.finish_window_retirement_output(output, result)?;
                owner.value = Some(value);
                owner.phase = super::operation_frame::UserFamilyProjectionPhase::Complete;
                Ok((value, continuation.return_kind))
            }
            (
                WindowReturn::UserFamily(continuation),
                Win16WindowResult::UserService(result),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::UserFamily(owner)),
            ) => super::completion_native_api::finish_user_family_owned_projection(
                self,
                continuation,
                result,
                owner,
                memory,
                host,
            ),
            (
                WindowReturn::DispatchMessage { mdi_output },
                Win16WindowResult::DispatchedMdi {
                    result,
                    retirements,
                },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::DispatchMessage(phase)),
            ) => (|| {
                let value = self.finish_mdi_message_with_retirements(
                    mdi_output.clone(),
                    Some(result.clone()),
                    Some(&retirements),
                    memory,
                )?;
                super::completion_driver::cache_simple_return(phase, value, Win16ReturnKind::Dword)
            })(),
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "state-wide USER result does not match its retained continuation",
            )),
        } })();
        if let Ok((value, return_kind)) = result {
            if let WindowProjectionJournal::Api(WindowApiProjectionJournal::UserFamily(owner)) =
                &completion.journal.projection
                && let Some(observation) = owner.owned_projection.as_ref().and_then(
                    super::completion_native_api::Win16UserOwnedProjection::creation_observation,
                )
            {
                completion.journal.creation_observation = Some(observation.clone());
            }
            completion.journal.phase =
                WindowOperationCompletionPhase::GuestProjected { value, return_kind };
        }
        let frame = self
            .window_operations
            .last_mut()
            .filter(|frame| frame.id == frame_id)
            .expect("state-wide projection retains its source frame");
        assert!(
            frame.completion.is_none(),
            "state-wide projection does not replace its carrier"
        );
        frame.completion = Some(completion);
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.retain_window_completion_failure(frame_id, error),
        }
    }
}
