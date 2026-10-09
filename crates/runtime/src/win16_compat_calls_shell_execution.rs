//! Checked runtime continuations for the public Win16 SHELL API family.

use std::sync::Arc;

use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ReturnKind, Win16ShellExecutionRequest};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostShellActivation,
    Win16HostShellExecutionOperation, Win16HostShellExecutionResult, Win16HostShellFailure,
    Win16WindowOperation, Win16WindowTarget,
};

use super::external_application::{ExternalApplicationKind, ExternalApplicationState};
use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes},
    windows::WindowReturn,
};

pub(in crate::win16_runtime) struct Win16ShellExecutionContinuation {
    pub(super) kind: Win16ShellExecutionContinuationKind,
    pub(super) return_kind: Win16ReturnKind,
}

impl Win16ShellExecutionContinuation {
    pub(super) fn terminal_external_application(
        &self,
    ) -> Option<(u16, ExternalApplicationKind)> {
        match self.kind {
            Win16ShellExecutionContinuationKind::WinExec { identity } => {
                Some((identity, ExternalApplicationKind::Activation))
            }
            Win16ShellExecutionContinuationKind::Execute { identity } => {
                Some((identity, ExternalApplicationKind::Activation))
            }
            Win16ShellExecutionContinuationKind::FindExecutable { identity, .. } => {
                Some((identity, ExternalApplicationKind::Association))
            }
            Win16ShellExecutionContinuationKind::About { .. } => None,
            Win16ShellExecutionContinuationKind::DragAcceptFiles => None,
        }
    }
}

pub(super) enum Win16ShellExecutionContinuationKind {
    WinExec { identity: u16 },
    DragAcceptFiles,
    Execute {
        identity: u16,
    },
    FindExecutable {
        identity: u16,
        output_far: u32,
        cleared_output: GuestOutputRange,
    },
    About {
        app_delimiter: Option<GuestOutputRange>,
    },
}

/// Completion-local journal. The surrounding WindowOperationCompletion owns
/// this value, so the same native result is projected at most once even if a
/// later terminal cleanup has to retain the frame.
#[derive(Debug)]
pub(in crate::win16_runtime) struct ShellExecutionProjection {
    state: ShellExecutionProjectionState,
}

#[derive(Debug)]
enum ShellExecutionProjectionState {
    Ready,
    Attempted,
    Failed(std::sync::Arc<RuntimeError>),
    Complete { value: u32, return_kind: Win16ReturnKind },
}

impl ShellExecutionProjection {
    pub(in crate::win16_runtime) fn new() -> Self {
        Self { state: ShellExecutionProjectionState::Ready }
    }
}

pub(in crate::win16_runtime) fn finish_shell_execution_projection(
    state: &mut Win16State,
    continuation: &Win16ShellExecutionContinuation,
    result: &Win16HostShellExecutionResult,
    projection: &mut ShellExecutionProjection,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    match &projection.state {
        ShellExecutionProjectionState::Complete { value, return_kind } => {
            return Ok((*value, *return_kind));
        }
        ShellExecutionProjectionState::Failed(cause) => {
            return Err(super::callback_lifo::shared_runtime_error(Arc::clone(cause)));
        }
        ShellExecutionProjectionState::Attempted => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "shell execution projection was re-entered while its first attempt remained unresolved",
            ));
        }
        ShellExecutionProjectionState::Ready => {}
    }

    // The retained WindowOperationCompletion owns the original result and
    // these exact output leases. An attempt can have committed a native owner
    // or guest bytes before a later step fails, so retries reuse the saved
    // result and report the saved error instead of repeating those effects.
    projection.state = ShellExecutionProjectionState::Attempted;
    match project_shell_execution_result(state, continuation, result, memory, host) {
        Ok((value, return_kind)) => {
            projection.state = ShellExecutionProjectionState::Complete { value, return_kind };
            Ok((value, return_kind))
        }
        Err(error) => {
            let cause = Arc::new(error);
            projection.state = ShellExecutionProjectionState::Failed(Arc::clone(&cause));
            Err(super::callback_lifo::shared_runtime_error(cause))
        }
    }
}

fn project_shell_execution_result(
    state: &mut Win16State,
    continuation: &Win16ShellExecutionContinuation,
    result: &Win16HostShellExecutionResult,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    let reserved_identity = continuation.terminal_external_application();
    let return_kind = continuation.return_kind;
    let value = match (&continuation.kind, result) {
        (
            Win16ShellExecutionContinuationKind::WinExec { identity },
            Win16HostShellExecutionResult::WinExec(Ok(activation)),
        ) => {
            let application_state = match activation {
                Win16HostShellActivation::ProcessStarted { process } => {
                    ExternalApplicationState::ProcessStarted { process: *process }
                }
                Win16HostShellActivation::NativeActivationReceipt => {
                    ExternalApplicationState::NativeActivationReceipt
                }
            };
            state.commit_external_application(
                *identity,
                ExternalApplicationKind::Activation,
                application_state,
            )?;
            u32::from(*identity)
        }
        (
            Win16ShellExecutionContinuationKind::WinExec { identity },
            Win16HostShellExecutionResult::WinExec(Err(failure)),
        ) => {
            rollback_expected_api_failure(state, *identity, ExternalApplicationKind::Activation,
                RuntimeError::new(Kind::HostFailure, "native WinExec process creation failed"))?;
            u32::from(failure.code)
        }
        (
            Win16ShellExecutionContinuationKind::DragAcceptFiles,
            Win16HostShellExecutionResult::DragAcceptFiles(accepted),
        ) => {
            if !accepted {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "Win16 DragAcceptFiles did not receive a live mapped native HWND",
                ));
            }
            0
        }
        (
            Win16ShellExecutionContinuationKind::Execute { identity },
            Win16HostShellExecutionResult::Execute(Ok(activation)),
        ) => {
            let application_state = match activation {
                Win16HostShellActivation::ProcessStarted { process } => {
                    ExternalApplicationState::ProcessStarted { process: *process }
                }
                Win16HostShellActivation::NativeActivationReceipt => {
                    ExternalApplicationState::NativeActivationReceipt
                }
            };
            state.commit_external_application(
                *identity,
                ExternalApplicationKind::Activation,
                application_state,
            )?;
            u32::from(*identity)
        }
        (
            Win16ShellExecutionContinuationKind::Execute { identity },
            Win16HostShellExecutionResult::Execute(Err(error)),
        ) => {
            match error {
                Win16HostShellFailure::ComInitialization { hresult } => {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        format!("Win16 ShellExecute could not initialize the native USER worker COM STA (HRESULT 0x{:08X}); returning ShellExecute failure", *hresult as u32),
                    ));
                }
                Win16HostShellFailure::Preparation(cause) => {
                    host.report_diagnostic(&Diagnostic::warning(
                        cause.kind(),
                        format!("Win16 ShellExecute host preparation failed: {cause}"),
                    ));
                }
                _ => {}
            }
            let guest_error = match error {
                Win16HostShellFailure::ComInitialization { .. } => 31,
                _ => match shell_error(error) {
                    Some(value) => value,
                    None => {
                        let primary = shell_failure_runtime_error_ref(
                            "Win16 ShellExecute received a non-API host failure",
                            error,
                        );
                        return Err(rollback_preserving_primary(
                            state,
                            *identity,
                            ExternalApplicationKind::Activation,
                            primary,
                        ));
                    }
                },
            };
            rollback_expected_api_failure(
                state,
                *identity,
                ExternalApplicationKind::Activation,
                shell_failure_runtime_error_ref("Win16 ShellExecute failed", error),
            )?;
            u32::from(guest_error)
        }
        (
            Win16ShellExecutionContinuationKind::FindExecutable {
                identity,
                cleared_output,
                ..
            },
            Win16HostShellExecutionResult::FindExecutable(Err(error)),
        ) => {
            if let Err(primary) = cleared_output.is_live(state, memory) {
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }
            if matches!(error, Win16HostShellFailure::HostContractViolation) {
                let primary = shell_failure_runtime_error_ref(
                    "Win16 FindExecutable violated its native output contract",
                    error,
                );
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }
            if matches!(error, Win16HostShellFailure::ExecutableInputNotRepresentable(_)) {
                let primary = shell_failure_runtime_error_ref(
                    "Win16 FindExecutable input cannot be represented by the host code page",
                    error,
                );
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }
            if matches!(error, Win16HostShellFailure::ExecutablePathNotRepresentable(_)) {
                let primary = shell_failure_runtime_error_ref(
                    "Win16 FindExecutable path cannot be represented in its guest contract",
                    error,
                );
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }
            if let Win16HostShellFailure::Preparation(cause) = error {
                host.report_diagnostic(&Diagnostic::warning(
                    cause.kind(),
                    format!("Win16 FindExecutable host preparation failed: {cause}"),
                ));
            }
            let Some(guest_error) = shell_error(error) else {
                let primary = shell_failure_runtime_error_ref(
                    "Win16 FindExecutable received a non-API host failure",
                    error,
                );
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            };
            rollback_expected_api_failure(
                state,
                *identity,
                ExternalApplicationKind::Association,
                shell_failure_runtime_error_ref("Win16 FindExecutable failed", error),
            )?;
            u32::from(guest_error)
        }
        (
            Win16ShellExecutionContinuationKind::FindExecutable {
                identity,
                output_far,
                cleared_output,
            },
            Win16HostShellExecutionResult::FindExecutable(Ok(path)),
        ) => {
            if let Err(primary) = cleared_output.is_live(state, memory) {
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }
            if path.is_empty() || path.contains(&0) {
                let primary = RuntimeError::new(
                    Kind::InternalInvariant,
                    "FindExecutable succeeded without a valid NUL-free path",
                );
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }

            // The host result stays parked in the completion, so retain an
            // owned path for the association record before committing guest
            // output. This allocation is fallible and occurs before effects.
            let mut association_path = Vec::new();
            if let Err(error) = association_path.try_reserve_exact(path.len()) {
                let primary = RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain Win16 FindExecutable association path",
                    error,
                );
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }
            association_path.extend_from_slice(path);

            let output_result = (|| {
                let output_length = path.len().checked_add(1).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "FindExecutable output length overflow",
                    )
                })?;
                let output = checked_output_range(state, *output_far, output_length, memory)?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(output_length).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve FindExecutable guest output",
                        error,
                    )
                })?;
                bytes.extend_from_slice(path);
                bytes.push(0);
                commit_guest_writes(state, memory, vec![(output, bytes)])
            })();
            if let Err(primary) = output_result {
                return Err(rollback_preserving_primary(
                    state,
                    *identity,
                    ExternalApplicationKind::Association,
                    primary,
                ));
            }

            // This alias records only the returned association path, never
            // guest code. Resolving it may have started a DDE server, which
            // the pending identity rollback cannot reverse.
            state.commit_external_application(
                *identity,
                ExternalApplicationKind::Association,
                ExternalApplicationState::AssociationIdentity {
                    path: association_path,
                },
            )?;
            u32::from(*identity)
        }
        (
            Win16ShellExecutionContinuationKind::About { app_delimiter },
            Win16HostShellExecutionResult::About(shown),
        ) => {
            if *shown {
                if let Some(output) = app_delimiter.as_ref() {
                    // The modal substitute commits this NUL after return;
                    // retain the exact range and never capture the FAR value
                    // again after a failed projection.
                    super::guest_ranges::commit_guest_output(state, memory, output, &[0])?;
                }
                1
            } else {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::HostFailure,
                    "Win16 ShellAbout failed; returning the Win16 DialogBoxParam failure value",
                ));
                u16::MAX as u32
            }
        }
        _ => {
            if let Some((identity, kind)) = reserved_identity {
                return Err(rollback_preserving_primary(
                    state,
                    identity,
                    kind,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 Shell continuation received the wrong native result",
                    ),
                ));
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 Shell continuation received the wrong native result",
            ));
        }
    };
    if matches!(continuation.kind, Win16ShellExecutionContinuationKind::Execute { .. }) {
        host.observe_win16_io(&crate::Win16IoEvent::ShellExecuteResult { value });
    } else if matches!(continuation.kind, Win16ShellExecutionContinuationKind::WinExec { .. }) {
        let native_error = match result {
            Win16HostShellExecutionResult::WinExec(Err(failure)) => failure.native_error,
            _ => None,
        };
        host.observe_win16_io(&crate::Win16IoEvent::WinExecResult {
            value: value as u16,
            native_error,
        });
    }
    Ok((value, return_kind))
}

impl Win16State {
    pub(in crate::win16_runtime) fn begin_shell_execution_request(
        &mut self,
        request: Win16ShellExecutionRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match request {
            Win16ShellExecutionRequest::WinExec { command_line, show } => {
                let owner = self.current_task_owner()?;
                let directory = self.kernel_file_system.current_directory_text(owner)?;
                host.observe_win16_io(&crate::Win16IoEvent::WinExecRequest {
                    command_line: &command_line,
                    directory: &directory,
                    show,
                });
                let identity = match self.reserve_external_application(ExternalApplicationKind::Activation) {
                    Ok(identity) => identity,
                    Err(error) if error.kind() == Kind::ResourceExhausted => {
                        return self.complete_return(registers, return_to.0, return_to.1,
                            return_to.2, 8, return_kind);
                    }
                    Err(error) => return Err(error),
                };
                self.begin_reserved_shell_operation(
                    registers, memory, host,
                    Win16WindowOperation::ShellExecution(Win16HostShellExecutionOperation::WinExec {
                        command_line, directory, show,
                    }),
                    identity, ExternalApplicationKind::Activation,
                    WindowReturn::ShellExecution(Win16ShellExecutionContinuation {
                        kind: Win16ShellExecutionContinuationKind::WinExec { identity },
                        return_kind,
                    }),
                    return_to,
                )
            }
            Win16ShellExecutionRequest::Execute {
                owner,
                operation,
                file,
                parameters,
                directory,
                show,
            } => {
                host.observe_win16_io(&crate::Win16IoEvent::ShellExecuteRequest {
                    file: &file, parameters: parameters.as_deref(), directory: directory.as_deref(),
                });
                let identity =
                    match self.reserve_external_application(ExternalApplicationKind::Activation) {
                        Ok(identity) => identity,
                        Err(error) if error.kind() == Kind::ResourceExhausted => {
                            return self.complete_return(
                                registers,
                                return_to.0,
                                return_to.1,
                                return_to.2,
                                8,
                                return_kind,
                            );
                        }
                        Err(error) => return Err(error),
                    };
                let operation = Win16HostShellExecutionOperation::Execute {
                    owner: window_target(self, owner),
                    operation,
                    file,
                    parameters,
                    directory,
                    show,
                };
                self.begin_reserved_shell_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::ShellExecution(operation),
                    identity,
                    ExternalApplicationKind::Activation,
                    WindowReturn::ShellExecution(Win16ShellExecutionContinuation {
                        kind: Win16ShellExecutionContinuationKind::Execute { identity },
                        return_kind,
                    }),
                    return_to,
                )
            }
            Win16ShellExecutionRequest::FindExecutable {
                file,
                directory,
                output_far,
            } => {
                let output = checked_output_range(self, output_far, 1, memory)?;
                commit_guest_writes(self, memory, vec![(output.clone(), vec![0])])?;
                let identity =
                    match self.reserve_external_application(ExternalApplicationKind::Association) {
                        Ok(identity) => identity,
                        Err(error) if error.kind() == Kind::ResourceExhausted => {
                            return self.complete_return(
                                registers,
                                return_to.0,
                                return_to.1,
                                return_to.2,
                                8,
                                return_kind,
                            );
                        }
                        Err(error) => return Err(error),
                    };
                let operation =
                    Win16HostShellExecutionOperation::FindExecutable { file, directory };
                self.begin_reserved_shell_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::ShellExecution(operation),
                    identity,
                    ExternalApplicationKind::Association,
                    WindowReturn::ShellExecution(Win16ShellExecutionContinuation {
                        kind: Win16ShellExecutionContinuationKind::FindExecutable {
                            identity,
                            output_far,
                            cleared_output: output,
                        },
                        return_kind,
                    }),
                    return_to,
                )
            }
            Win16ShellExecutionRequest::About {
                owner,
                app_far,
                app,
                other_stuff,
                icon,
            } => {
                let icon = if icon == 0 {
                    None
                } else {
                    let Some(icon) = self.guest_images.icon(icon) else {
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::CompatibilityGap,
                            "Win16 ShellAbout received an unmapped guest icon handle",
                        ));
                        return self.complete_return(
                            registers,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            u16::MAX as u32,
                            return_kind,
                        );
                    };
                    Some(icon)
                };
                let app_delimiter = match app.iter().position(|byte| *byte == b'#') {
                    Some(index) => Some(checked_output_range(
                        self,
                        far_add_in_segment(app_far, index)?,
                        1,
                        memory,
                    )?),
                    None => None,
                };
                let operation = Win16HostShellExecutionOperation::About {
                    owner: window_target(self, owner),
                    app,
                    other_stuff,
                    icon,
                };
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::ShellExecution(operation),
                    WindowReturn::ShellExecution(Win16ShellExecutionContinuation {
                        kind: Win16ShellExecutionContinuationKind::About { app_delimiter },
                        return_kind,
                    }),
                    return_to,
                )
            }
        }
    }

    fn begin_reserved_shell_operation(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        operation: Win16WindowOperation,
        identity: u16,
        kind: ExternalApplicationKind,
        continuation: WindowReturn,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let source = operation.native_operation_kind();
        if let Err(error) = self.push_window_operation(registers.clone(), return_to, continuation) {
            return Err(rollback_preserving_primary(self, identity, kind, error));
        }
        self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 Shell operation disappeared before native begin",
        ))?.native_source = Some(source);
        self.mark_window_begin_pending(source)?;
        let step = match host.win16_window_begin(operation) {
            Ok(step) => step,
            Err(error) => {
                if !matches!(
                    self.window_operations.last().and_then(|frame| frame.continuation()),
                    Some(WindowReturn::ShellExecution(_))
                ) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 Shell start failed after its continuation frame changed",
                    ));
                }
                let error = std::sync::Arc::new(error);
                self.mark_window_begin_rejected(std::sync::Arc::clone(&error))?;
                match self.rollback_external_application(identity, kind) {
                    Ok(()) => {
                        if let Some(frame) = self.window_operations.last_mut() {
                            frame.terminal_resources_retired = true;
                        }
                        return Err(super::callback_lifo::shared_runtime_error(error));
                    }
                    Err(cleanup) => {
                        let combined = super::external_application::combine_rollback_failure(
                            super::callback_lifo::shared_runtime_error(error),
                            cleanup,
                        );
                        let combined = std::sync::Arc::new(combined);
                        if let Some(frame) = self.window_operations.last_mut() {
                            frame.terminal_error = Some(std::sync::Arc::clone(&combined));
                        }
                        return Err(super::callback_lifo::shared_runtime_error(combined));
                    }
                }
            }
        };
        // Once the worker accepted the operation, keep the reserved identity
        // even if continuation processing reports a runtime invariant: the
        // native API may already have activated an application.
        self.advance_window_operation(registers, memory, host, step)?;
        Ok(None)
    }
}

fn rollback_preserving_primary(
    state: &mut Win16State,
    identity: u16,
    kind: ExternalApplicationKind,
    primary: RuntimeError,
) -> RuntimeError {
    match state.rollback_external_application(identity, kind) {
        Ok(()) => primary,
        Err(cleanup) => super::external_application::combine_rollback_failure(primary, cleanup),
    }
}

fn rollback_expected_api_failure(
    state: &mut Win16State,
    identity: u16,
    kind: ExternalApplicationKind,
    primary: RuntimeError,
) -> Result<(), RuntimeError> {
    if let Err(cleanup) = state.rollback_external_application(identity, kind) {
        return Err(super::external_application::combine_rollback_failure(
            primary, cleanup,
        ));
    }
    Ok(())
}

fn shell_failure_runtime_error_ref(
    operation: &'static str,
    failure: &Win16HostShellFailure,
) -> RuntimeError {
    let kind = match failure {
        Win16HostShellFailure::Preparation(cause) => cause.kind(),
        Win16HostShellFailure::HostContractViolation => Kind::InternalInvariant,
        Win16HostShellFailure::ExecutableInputNotRepresentable(_)
        | Win16HostShellFailure::ExecutablePathNotRepresentable(_) => Kind::CompatibilityGap,
        Win16HostShellFailure::Api(_) | Win16HostShellFailure::ComInitialization { .. } => {
            Kind::HostFailure
        }
    };
    RuntimeError::with_source(kind, operation, failure.clone())
}

fn checked_output_range(
    state: &Win16State,
    output_far: u32,
    length: usize,
    memory: &Memory,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state
        .selectors
        .pointer_from_far(output_far)
        .map_err(crate::runtime_error)?;
    // These are ordinary FAR buffers: validate the whole extent in the one
    // descriptor before capture, rather than treating it as a huge pointer.
    state
        .selectors
        .translate(pointer, Access::Write, length, memory)
        .map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, length)
}

fn far_add_in_segment(far: u32, displacement: usize) -> Result<u32, RuntimeError> {
    let displacement = u16::try_from(displacement).map_err(|error| {
        RuntimeError::with_source(
            Kind::GuestFault,
            "ShellAbout app string offset exceeds a FAR segment",
            error,
        )
    })?;
    let offset = (far as u16).checked_add(displacement).ok_or_else(|| {
        RuntimeError::new(
            Kind::GuestFault,
            "ShellAbout app string delimiter exceeds its FAR segment",
        )
    })?;
    Ok((far & 0xffff_0000) | u32::from(offset))
}

pub(super) fn window_target(state: &Win16State, owner: u16) -> Win16WindowTarget {
    if owner == 0 {
        Win16WindowTarget::Null
    } else {
        state
            .window_handles
            .get(&owner)
            .copied()
            .map(Win16WindowTarget::Mapped)
            .unwrap_or(Win16WindowTarget::Invalid)
    }
}

fn shell_error(error: &Win16HostShellFailure) -> Option<u16> {
    match error {
        Win16HostShellFailure::Api(error) if *error <= 32 => Some(*error),
        Win16HostShellFailure::Preparation(cause) if cause.kind() == Kind::ResourceExhausted => {
            Some(8)
        }
        Win16HostShellFailure::Api(_)
        | Win16HostShellFailure::ComInitialization { .. }
        | Win16HostShellFailure::Preparation(_) => Some(31),
        Win16HostShellFailure::HostContractViolation
        | Win16HostShellFailure::ExecutableInputNotRepresentable(_)
        | Win16HostShellFailure::ExecutablePathNotRepresentable(_) => None,
    }
}
