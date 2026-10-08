//! Route typed DDE callback carriers on their exact runtime origin.

use super::*;
use dos_kernel::DosKernel;
use x86_cpu::Cpu;
use crate::Win16HostDdeStep;

impl Win16State {
    /// Route a native callback reply without turning CallbackFrameComplete
    /// into a fake window/API result. WindowWait IDs are runtime frame IDs;
    /// foreground operation IDs remain a distinct host-token type.
    pub(in crate::win16_runtime) fn route_dde_callback_step(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        origin: Win16DdeCallbackOrigin,
        step: Win16HostDdeStep,
    ) -> Result<(), RuntimeError> {
        match origin {
            Win16DdeCallbackOrigin::CallbackFollowUp { callback_id, .. } => {
                self.resume_callback_owned_dde_follow_up(
                    callback_id,
                    Some(step),
                    cpu,
                    dos,
                    memory,
                    host,
                )
            }
            Win16DdeCallbackOrigin::Foreground(expected) => {
                let Some(frame) = self.window_operations.last() else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "foreground DDE callback resumed without its runtime window frame"));
                };
                let Some(WindowReturn::Dde(continuation)) = frame.result.as_ref() else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "foreground DDE callback resumed under a non-DDE continuation"));
                };
                if continuation.host_operation() != Some(expected) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "foreground DDE callback resumed under a different native operation"));
                }
                match step {
                    Win16HostDdeStep::SourceRetired { proof, result } => {
                        if !proof.has_valid_identity() || proof.operation != expected {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "DDE callback returned a foreign normal source-retirement proof"));
                        }
                        {
                            let frame = self.window_operations.last_mut().ok_or_else(|| {
                                RuntimeError::new(Kind::InternalInvariant,
                                    "DDE source-retirement proof has no retained runtime frame")
                            })?;
                            let Some(WindowReturn::Dde(continuation)) = frame.result.as_mut() else {
                                return Err(RuntimeError::new(Kind::InternalInvariant,
                                    "DDE source-retirement proof reached a non-DDE continuation"));
                            };
                            continuation.cache_normal_source_retirement(
                                Arc::clone(&proof), result.clone(),
                            )?;
                        }
                        self.advance_window_operation(&mut cpu.regs, memory, host,
                            Win16WindowStep::DdeSourceRetired {
                                proof,
                                result: Box::new(Win16WindowStep::Complete(
                                    Win16WindowResult::Dde(result),
                                )),
                            })
                    }
                    Win16HostDdeStep::Complete(result) => {
                        let cached = self.window_operations.last().and_then(|frame| {
                            let Some(WindowReturn::Dde(continuation)) = frame.result.as_ref() else {
                                return None;
                            };
                            continuation.cached_native_completion(expected)
                        });
                        if cached != Some(&result) {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "raw DDE Complete reached routing without the same cached native result"));
                        }
                        let retired = self.retire_cached_dde_completion_source(expected, host)?;
                        self.route_dde_callback_step(
                            cpu, dos, memory, host, origin, retired,
                        )
                    }
                    Win16HostDdeStep::Callback(callback) => {
                        if callback.parent.is_some_and(|actual| actual != expected) {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "DDE callback reply changed its foreground parent operation"));
                        }
                        self.advance_window_operation(&mut cpu.regs, memory, host,
                        Win16WindowStep::DdeCallback(callback))
                    }
                    Win16HostDdeStep::CallbackFrameComplete { .. } => Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "foreground DDE operation returned an unsolicited callback-frame completion")),
                }
            }
            Win16DdeCallbackOrigin::WindowWait { operation } => {
                if self.window_operations.last().map(|frame| frame.id) != Some(operation) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "unsolicited DDE callback resumed under a different runtime window wait"));
                }
                match step {
                    Win16HostDdeStep::CallbackFrameComplete { .. } => {
                        // The callback frame was checked by the DDE callback
                        // continuation. Resume the exact pending USER/DDE wait.
                        let next = host.win16_window_resume(None)?;
                        self.advance_window_operation(&mut cpu.regs, memory, host, next)
                    }
                    Win16HostDdeStep::Callback(callback) if callback.parent.is_none() =>
                        self.advance_window_operation(&mut cpu.regs, memory, host,
                            Win16WindowStep::DdeCallback(callback)),
                    _ => Err(RuntimeError::new(Kind::InternalInvariant,
                        "unsolicited DDE wait returned an API completion or foreground callback")),
                }
            }
            Win16DdeCallbackOrigin::GuestExecution { frame } => match step {
                Win16HostDdeStep::CallbackFrameComplete { frame: actual } if actual == frame =>
                    self.queue_dde_guest_context_restore(frame),
                _ => Err(RuntimeError::new(Kind::InternalInvariant,
                    "guest-execution DDE callback did not acknowledge its exact native frame")),
            },
        }
    }
}
