//! Win16 teardown after the guest CPU has stopped.

use super::Win16TaskExecutionEnded;
use crate::machine::Runtime;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Runtime {
    pub(super) fn finish_win16_teardown(
        &mut self,
        mut result: Result<u8, RuntimeError>,
        host: &mut impl RuntimeHost,
        instruction_limit: u64,
    ) -> Result<u8, RuntimeError> {
        let mut cleanup_error = None;
        let mut prerequisites_complete = true;
        if result.is_err() {
            if let Some(state) = self.win16.as_mut() {
                state.pending_kernel_diagnostic_effects.clear();
            }
        }

        match self.win16.as_mut() {
            Some(state) => {
                if let Err(error) = state.close_mci_runtime(host) {
                    remember_cleanup(
                        &mut cleanup_error,
                        error.with_context("Win16 MCI quiescence before callback teardown"),
                    );
                    prerequisites_complete = false;
                }
            }
            None => {
                remember_cleanup(
                    &mut cleanup_error,
                    RuntimeError::new(Kind::InternalInvariant, "Win16 teardown has no task state"),
                );
                prerequisites_complete = false;
            }
        }

        // MCI can hold guest callbacks and module references while a native
        // owner is blocked. Do not retire those callback dependencies unless
        // every MCI native owner first reached a confirmed quiescent state.
        if prerequisites_complete {
            match self.win16.as_mut() {
                Some(state) => {
                    if let Err(error) = state.close_dde_runtime(&mut self.memory, host) {
                        remember_cleanup(
                            &mut cleanup_error,
                            error.with_context("Win16 DDE cleanup"),
                        );
                        prerequisites_complete = false;
                    }
                }
                None => {
                    remember_cleanup(
                        &mut cleanup_error,
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 teardown has no task state",
                        ),
                    );
                    prerequisites_complete = false;
                }
            }
        }

        if prerequisites_complete {
            if result.is_ok() && !self.process_frames.is_empty() {
                result = Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 task returned with suspended DOS child process frames",
                ));
            }
            if result.is_err() || !self.process_frames.is_empty() {
                if let Err(error) = self.abort_child_processes(host) {
                    remember_cleanup(
                        &mut cleanup_error,
                        error.with_context("DOS child process cleanup"),
                    );
                    prerequisites_complete = false;
                }
            }
        }
        if prerequisites_complete && !self.process_frames.is_empty() {
            remember_cleanup(
                &mut cleanup_error,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DOS child recovery frames remain after child teardown",
                ),
            );
            prerequisites_complete = false;
        }

        // Child recovery has restored the Win16 address space. Stop WAVE
        // producers while that space and every callback source are still
        // owned; logical callback retirement follows native quiescence.
        if prerequisites_complete {
            if let Some(state) = self.win16.as_mut() {
                if let Err(error) = state.quiesce_wave_producers(&mut self.memory, host) {
                    remember_cleanup(
                        &mut cleanup_error,
                        error.with_context("Win16 WAVE quiescence before callback teardown"),
                    );
                    prerequisites_complete = false;
                }
            }
        }

        if prerequisites_complete {
            if let Err(error) = self.dos.close_all_handles_checked(host) {
                remember_cleanup(
                    &mut cleanup_error,
                    crate::runtime_error(dos_kernel::DosError::HostOperation(error))
                        .with_context("DOS handle cleanup"),
                );
                prerequisites_complete = false;
            }
        }
        if prerequisites_complete {
            if let Err(error) = self.dos.release_jft_storage(&mut self.memory) {
                remember_cleanup(
                    &mut cleanup_error,
                    crate::runtime_error(error).with_context("DOS JFT storage cleanup"),
                );
                prerequisites_complete = false;
            }
        }
        if prerequisites_complete {
            if let Some(state) = self.win16.as_mut() {
                if let Err(error) = state.release_all_dos_caller_address_spaces(
                    &mut self.dos,
                    &mut self.memory,
                    host,
                ) {
                    remember_cleanup(
                        &mut cleanup_error,
                        error.with_context("DOS caller-address-space cleanup"),
                    );
                    prerequisites_complete = false;
                }
            }
        }
        if prerequisites_complete {
            if let Some(state) = self.win16.as_mut() {
                let remaining = instruction_limit.saturating_sub(self.instructions);
                let cleanup =
                    state.close_pe32_dispatcher(&mut self.cpu, &mut self.memory, host, remaining);
                let boundaries = state.pe32_dispatch.take_charged_boundaries();
                match self.instructions.checked_add(boundaries) {
                    Some(instructions) => self.instructions = instructions,
                    None => {
                        remember_cleanup(
                            &mut cleanup_error,
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "PE32 cleanup charged-boundary counter overflowed",
                            ),
                        );
                    }
                }
                if let Err(error) = cleanup {
                    let error = error.with_context("PE32 loader cleanup");
                    host.report_diagnostic(error.diagnostic());
                    remember_cleanup(&mut cleanup_error, error);
                    // PE32 code/provider pins remain live when detach fails;
                    // later module and process-view retirement depends on them.
                    prerequisites_complete = false;
                }
            }
        }
        // `close_pe32_dispatcher` above can run guest detach callbacks on this
        // CPU. Seal the terminal proof only after that final CPU-capable
        // teardown call has returned.
        let ended = Win16TaskExecutionEnded::after_cpu_execution_boundary();
        if prerequisites_complete {
            if let Some(state) = self.win16.as_mut() {
                if let Err(error) =
                    state.retire_failed_legacy_cpu_captures(&ended, &mut self.dos, &mut self.memory)
                {
                    remember_cleanup(&mut cleanup_error, error);
                    prerequisites_complete = false;
                } else if let Err(error) = state.close_remaining_task_resources(
                    &ended,
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                    host,
                ) {
                    remember_cleanup(&mut cleanup_error, error);
                    prerequisites_complete = false;
                } else if let Err(error) = state
                    .retire_legacy_cpu_frames_after_task_execution_ended(
                        &ended,
                        &mut self.cpu,
                        &mut self.dos,
                        &mut self.memory,
                    )
                {
                    remember_cleanup(
                        &mut cleanup_error,
                        error.with_context("Win16 terminal legacy CPU frame-owner cleanup"),
                    );
                    prerequisites_complete = false;
                }
            }
        }
        if prerequisites_complete {
            if let Some(state) = self.win16.as_mut() {
                // Callback payloads can outlive their frames while exact CPU
                // selector leases pin the allocation. Retry after those real
                // owners retired, before releasing the task's process views.
                match state.retry_retired_window_payloads() {
                    Ok(true) => {}
                    Ok(false) => {
                        let error = state.retained_window_payload_error()
                            .map(super::super::callback_lifo::shared_runtime_error)
                            .unwrap_or_else(|| RuntimeError::new(
                                Kind::InternalInvariant,
                                "Win16 terminal callback payloads remain owned without a retained cause",
                            ));
                        remember_cleanup(&mut cleanup_error, error);
                        prerequisites_complete = false;
                    }
                    Err(error) => {
                        remember_cleanup(
                            &mut cleanup_error,
                            error.with_context("Win16 terminal callback payload cleanup"),
                        );
                        prerequisites_complete = false;
                    }
                }
            }
        }
        if prerequisites_complete {
            if let Some(state) = self.win16.as_mut() {
                if let Err(error) = state.release_process_views(&mut self.dos, &mut self.memory) {
                    remember_cleanup(
                        &mut cleanup_error,
                        error.with_context("Win16 process-view cleanup"),
                    );
                }
            }
        }

        match cleanup_error {
            None => result,
            Some(cleanup) => Err(match result {
                Ok(_) => cleanup,
                Err(operation) => operation.with_cleanup(
                    "Win16 runtime operation and task cleanup both failed",
                    cleanup,
                ),
            }),
        }
    }
}

fn remember_cleanup(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        None => error,
        Some(operation) => {
            operation.with_cleanup("multiple prerequisite teardown operations failed", error)
        }
    });
}
