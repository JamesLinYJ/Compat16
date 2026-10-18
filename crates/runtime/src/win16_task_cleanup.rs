//! Release resources owned by a completed Win16 task.

use super::Win16State;
use dos_kernel::DosKernel;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16WindowTerminalSourceTop};
use guest_core::memory::Memory;

impl Win16State {
    pub(super) fn finish_task(
        &mut self,
        _memory: &mut Memory,
        _host: &mut impl RuntimeHost,
        status: u16,
    ) -> Result<Option<u8>, RuntimeError> {
        self.request_toolhelp_task_termination(status, None)?;
        Ok(None)
    }

    pub(super) fn finalize_task_termination(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        status: u16,
    ) -> Result<u8, RuntimeError> {
        host.observe_win16_io(&crate::Win16IoEvent::TaskExit { status });
        let task = self.current_task_handle()?;
        self.retire_toolhelp_task_callbacks(task, cpu, dos, memory)?;
        self.retire_user_hooks_for_task_end();
        self.pending_kernel_diagnostic_effects.clear();
        // Stop native MCI publication while its accepted notifications and
        // callback roots stay owned for the outer terminal source retirement.
        self.quiesce_mci_producers(host)?;
        // Stop DDE publication before leaving the guest service gate. Runtime
        // callback frames and their storage stay owned until the outer unwind
        // restores their checked CPU continuations and retires native sources.
        self.quiesce_dde_callback_owners(host)?;
        Ok(status as u8)
    }

    pub(super) fn close_remaining_task_resources(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        // This is shared by normal exit and fatal guest termination. Mark
        // installed hooks retired before unwinding, retaining active nodes
        // until their checked callback continuations have been aborted.
        self.retire_user_hooks_for_task_end();
        match self.close_remaining_task_resources_once(ended, cpu, dos, memory, host) {
            Ok(()) => Ok(()),
            Err(primary) if self.can_retire_task_selector_views() => {
                if let Err(retire) = self.release_all_selector_backing(dos, memory) {
                    return Err(primary.with_cleanup(
                        "retiring exact process-owned selector views after native producers quiesced",
                        retire,
                    ));
                }
                match self.close_remaining_task_resources_once(ended, cpu, dos, memory, host) {
                    Ok(()) => Ok(()),
                    Err(retry) => Err(primary.with_cleanup(
                        "retrying Win16 task cleanup after exact process-owned selector retirement",
                        retry,
                    )),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn close_remaining_task_resources_once(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failures = None;
        // Selectors and aliases are task-owned. Retire them before later USER
        // cleanup can return, and again if this function is retried.
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            self.release_winmem32_on_task_exit()
                .map_err(|error| error.with_context("WINMEM32 task-exit cleanup")),
        );
        // SOUND opens devices in the shared WAVE host. Retire its sessions and
        // playback leases while guest memory and producer callbacks remain live.
        let sound_retired = match self.retire_sound(memory, host) {
            Ok(()) => true,
            Err(error) => {
                remember(
                    &mut failures,
                    "multiple Win16 task cleanup failures",
                    Err(error.with_context("Win16 SOUND cleanup")),
                );
                match self.retire_sound(memory, host) {
                    Ok(()) => true,
                    Err(error) => {
                        remember(
                            &mut failures,
                            "multiple Win16 task cleanup failures",
                            Err(error.with_context("retry Win16 SOUND cleanup")),
                        );
                        false
                    }
                }
            }
        };
        let wave_quiet = if sound_retired {
            match self.quiesce_wave_producers(memory, host)
                .map_err(|error| error.with_context("Win16 WAVE producer quiescence"))
            {
                Ok(()) => true,
                Err(error) => {
                    remember(&mut failures, "multiple Win16 task cleanup failures", Err(error));
                    match self.quiesce_wave_producers(memory, host)
                        .map_err(|error| error.with_context("retry Win16 WAVE producer quiescence"))
                    {
                        Ok(()) => true,
                        Err(error) => {
                            remember(&mut failures,
                                "multiple Win16 task cleanup failures", Err(error));
                            false
                        }
                    }
                }
            }
        } else {
            false
        };
        // Reset every actual MIDI host owner now, while retaining callback
        // contexts and prepared storage for the later exact source ACK.
        let midi_quiet = match self.quiesce_midi_producers(host)
            .map_err(|error| error.with_context("Win16 MIDI producer quiescence"))
        {
            Ok(()) => true,
            Err(error) => {
                remember(&mut failures, "multiple Win16 task cleanup failures", Err(error));
                false
            }
        };
        let mci_quiescence = self.quiesce_mci_producers(host)
            .map_err(|error| error.with_context("Win16 MCI producer quiescence"));
        let mci_quiet = mci_quiescence.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            mci_quiescence,
        );
        // Network sources share USER's source stack. Stop native publication
        // before Abort, then retain their accepted source owners for exact-top
        // retirement; full network cleanup follows that retirement below.
        let network_quiescence = self.quiesce_network_producers(host)
            .map_err(|error| error.with_context("Win16 network producer quiescence"));
        let network_quiet = network_quiescence.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            network_quiescence,
        );
        let network_print_quiescence = self.quiesce_network_print_producers(host)
            .map_err(|error| error.with_context("Win16 network-print producer quiescence"));
        let network_print_quiet = network_print_quiescence.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            network_print_quiescence,
        );
        let netbios_cleanup = self.close_netbios_runtime(host)
            .map_err(|error| error.with_context("Win16 NetBIOS cleanup"));
        let netbios_retired = netbios_cleanup.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            netbios_cleanup,
        );
        let acm_cleanup = self.retire_all_acm(host)
            .map_err(|error| error.with_context("Win16 ACM cleanup"));
        let acm_retired = acm_cleanup.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            acm_cleanup,
        );
        let buffer_cleanup = self.retire_mmio_guest_buffers(memory, host)
            .map_err(|error| error.with_context("Win16 MMIO buffer cleanup"));
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            buffer_cleanup,
        );
        let multimedia_cleanup = self
            .retire_multimedia_services(host)
            .map_err(|error| error.with_context("Win16 multimedia cleanup"));
        let multimedia_retired = multimedia_cleanup.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            multimedia_cleanup,
        );
        let mixer_cleanup = self.mixer.retire_all(host)
            .map_err(|error| error.with_context("Win16 mixer cleanup"));
        let mixer_retired = mixer_cleanup.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            mixer_cleanup,
        );
        // COMM ports are owned by the task that opened them. Retire the host
        // token and the event-word allocation while the guest heap is live.
        // A failed close stays in the table for a later retry.
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            self.retire_comm_ports(host)
                .map_err(|error| error.with_context("Win16 COMM port cleanup")),
        );
        let automation_cleanup = self.close_automation(memory, host)
            .map_err(|error| error.with_context("Win16 Automation cleanup"));
        let automation_retired = automation_cleanup.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            automation_cleanup,
        );
        let files_cleanup = self.close_files(host)
            .map_err(|error| error.with_context("Win16 file cleanup"));
        let files_retired = files_cleanup.is_ok();
        remember(
            &mut failures,
            "multiple Win16 task cleanup failures",
            files_cleanup,
        );

        // The USER terminal receipt is acquired only after every producer
        // barrier and shared-lane owner above has supplied its real proof.
        let producer_barriers_ready = wave_quiet && midi_quiet && mci_quiet && sound_retired
            && network_quiet && network_print_quiet
            && netbios_retired && acm_retired && multimedia_retired && mixer_retired
            && automation_retired && files_retired;
        let windows_closed = if self.window_teardown_state == super::WindowTeardownState::Closed {
            // Closed is published only after the exact shared-source loop and
            // close_windows complete. A later family cleanup retry must resume
            // that family rather than re-enter NativeQuiescent-only retirement.
            if self.window_abort_receipt.is_none()
                || !self.window_operations.is_empty()
                || !self.window_callbacks.is_empty()
                || !self.native_function_callbacks.is_empty()
                || !self.callback_kinds.is_empty()
                || !self.callback_frame_ids.is_empty()
                || !self.window_handles.is_empty()
            {
                remember(&mut failures, "multiple Win16 task cleanup failures", Err(
                    RuntimeError::new(Kind::InternalInvariant,
                        "closed USER phase retains callback, operation, or window owners"),
                ));
                false
            } else {
                true
            }
        } else if producer_barriers_ready {
            let terminal = (|| {
                // Seal the exact native COM owner before USER Abort so a
                // nested STA callback receives a real typed failure and can
                // return through its existing native stack.
                self.seal_com_owners_for_teardown(host)?;
                self.quiesce_window_callback_owner(host)?;
                self.unwind_callbacks_for_teardown(ended, cpu, dos, memory, host)?;
                self.clear_toolhelp_callbacks_after_task_end(cpu, dos, memory)?;
                loop {
                    let terminal_step =
                        self.retire_window_operations_for_teardown(ended, cpu, dos, memory, host)?;
                    let mci_sources_ready =
                        self.retire_mci_notifications_after_windows_abort(host)?;
                    match terminal_step {
                        super::windows::WindowTerminalRetirementStep::WindowFrameRetired
                        | super::windows::WindowTerminalRetirementStep::DdeFrameRetired => {}
                        super::windows::WindowTerminalRetirementStep::AllRuntimeFramesRetired => {
                            if !mci_sources_ready {
                                return Err(RuntimeError::new(Kind::HostFailure,
                                    "MCI notification still awaits USER source retirement after the terminal source stack drained"));
                            }
                            break;
                        }
                        super::windows::WindowTerminalRetirementStep::BlockedBySource(top) => {
                            let receipt = self.window_abort_receipt.clone().ok_or_else(|| {
                                RuntimeError::new(Kind::InternalInvariant,
                                    "USER source-top step lost its cached abort receipt")
                            })?;
                            let wave_owner = self.owns_terminal_wave_post_source(&top)?;
                            let midi_owner = self.owns_terminal_midi_post_source(&top);
                            let network_owner = self.owns_terminal_network_post_source(&top)?;
                            let network_print_owner = self.owns_terminal_network_print_post_source(&top)?;
                            let mci_owner = self.owns_terminal_mci_post_source(&top)?;
                            match (wave_owner, midi_owner, network_owner, network_print_owner, mci_owner) {
                                (true, false, false, false, false) => {
                                    if !self.retire_wave_terminal_post_source(&receipt, &top, host)? {
                                        return Err(terminal_source_blocker(&top));
                                    }
                                }
                                (false, true, false, false, false) => {
                                    if !self.retire_midi_terminal_post_source(&receipt, &top, host)? {
                                        return Err(terminal_source_blocker(&top));
                                    }
                                }
                                (false, false, true, false, false) => {
                                    if !self.retire_network_terminal_post_source(&receipt, &top, host)? {
                                        return Err(terminal_source_blocker(&top));
                                    }
                                }
                                (false, false, false, true, false) => {
                                    if !self.retire_network_print_terminal_post_source(&receipt, &top, host)? {
                                        return Err(terminal_source_blocker(&top));
                                    }
                                }
                                (false, false, false, false, true) => {
                                    if !self.retire_mci_terminal_post_source(&receipt, &top, host)? {
                                        return Err(terminal_source_blocker(&top));
                                    }
                                }
                                _ => return Err(terminal_source_blocker(&top)),
                            }
                        }
                    }
                }
                self.close_windows(host)
            })();
            match terminal {
                Ok(()) => true,
                Err(error) => {
                    remember(
                        &mut failures,
                        "multiple Win16 task cleanup failures",
                        Err(error.with_context("Win16 terminal USER cleanup")),
                    );
                    false
                }
            }
        } else {
            false
        };
        if windows_closed {
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.finish_com_owners_for_teardown(host)
                    .map_err(|error| error.with_context("Win16 COM owner retirement")),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.drain_native_drop_retirements(host)
                    .map_err(|error| error.with_context(
                        "Win16 native WM_DROPFILES retirement receipts before HGLOBAL cleanup",
                    )),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.retire_all_queued_drop_file_leases()
                    .map_err(|error| error.with_context("Win16 queued HDROP cleanup")),
            );
            // If an earlier exact retirement failed transiently, retry it
            // after terminal lease cleanup. The host receipt remains at the
            // FIFO head until this separate transport ACK succeeds.
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.drain_native_drop_retirements(host)
                    .map_err(|error| error.with_context(
                        "Win16 native WM_DROPFILES retirement receipts after HGLOBAL cleanup",
                    )),
            );
        }
        let mut final_media_retired = false;
        let mut dde_retired = false;
        let mut network_retired = false;
        let mut network_print_retired = false;
        let mut mci_retired = false;
        if windows_closed {
            let dde_cleanup = self.close_dde_runtime(memory, host)
                .map_err(|error| error.with_context("Win16 DDE cleanup"));
            dde_retired = dde_cleanup.is_ok();
            remember(&mut failures, "multiple Win16 task cleanup failures", dde_cleanup);
            let network_cleanup = self.close_network(memory, host)
                .map_err(|error| error.with_context("Win16 network cleanup"));
            network_retired = network_cleanup.is_ok();
            remember(&mut failures, "multiple Win16 task cleanup failures", network_cleanup);
            let network_print_cleanup = if let Some(owner) = self.tasks.current() {
                self.cleanup_network_print_task(owner, host)
            } else {
                Ok(())
            }.map_err(|error| error.with_context("Win16 network-print cleanup"));
            network_print_retired = network_print_cleanup.is_ok();
            remember(&mut failures, "multiple Win16 task cleanup failures", network_print_cleanup);
            let mci_cleanup = self.retire_mci_notifications_after_windows_abort(host)
                .and_then(|sources_ready| {
                    if !sources_ready {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "MCI notification still awaits USER source retirement after windows closed"));
                    }
                    self.close_mci_runtime(host)
                })
                .map_err(|error| error.with_context("Win16 MCI cleanup"));
            mci_retired = mci_cleanup.is_ok();
            remember(&mut failures, "multiple Win16 task cleanup failures", mci_cleanup);
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.retry_retained_callback_buffers()
                    .map_err(|error| error.with_context("Win16 callback-buffer cleanup")),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.close_classes(host)
                    .map_err(|error| error.with_context("Win16 class cleanup")),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.retire_all_common_dialogs()
                    .map_err(|error| error.with_context("Win16 common-dialog cleanup")),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.retire_all_clipboard_data()
                    .map_err(|error| error.with_context("Win16 clipboard cleanup")),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.close_gdi(memory, host)
                    .map_err(|error| error.with_context("Win16 GDI cleanup")),
            );
            remember(
                &mut failures,
                "multiple Win16 task cleanup failures",
                self.close_images(host)
                    .map_err(|error| error.with_context("Win16 image cleanup")),
            );
            let wave_cleanup = self.close_wave_runtime(memory, host)
                .map_err(|error| error.with_context("Win16 WAVE cleanup"));
            let midi_cleanup = self.close_all_midi(memory, host)
                .map_err(|error| error.with_context("Win16 MIDI cleanup"));
            final_media_retired = wave_cleanup.is_ok() && midi_cleanup.is_ok();
            remember(&mut failures, "multiple Win16 task cleanup failures", wave_cleanup);
            remember(&mut failures, "multiple Win16 task cleanup failures", midi_cleanup);
        }
        // Producers and guest windows have been quiesced before the exact
        // host task queue is retired. Carrier tombstones remain tied to their
        // native queue records until USER removes them or the worker exits.
        if windows_closed && final_media_retired && dde_retired
            && network_retired && network_print_retired && mci_retired && failures.is_none()
        {
            if let Some(owner) = self.tasks.current() {
                let file_system_cleanup = self.kernel_file_system.retire_task(owner, host)
                    .map_err(|error| error.with_context("Win16 KERNEL file-system cleanup"));
                remember(&mut failures, "multiple Win16 task cleanup failures", file_system_cleanup);
                let global_notify_cleanup = self.global_notify.retire_task(owner);
                remember(&mut failures, "multiple Win16 task cleanup failures", global_notify_cleanup);
            }
        }
        if windows_closed && final_media_retired && dde_retired
            && network_retired && network_print_retired && mci_retired && failures.is_none()
        {
            if let Some((owner, task, generation, queue)) = self.user_task_queue {
                match host.win16_retire_task_queue(owner, task, generation, queue) {
                    Ok(true) => {
                        self.user_task_queue = None;
                        self.user_queue.take();
                    }
                    Ok(false) => remember(&mut failures,
                        "multiple Win16 task cleanup failures",
                        Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 task USER queue retirement did not match its exact owner, HTASK, selector generation, and queue incarnation")
                            .with_context("Win16 USER queue retirement"))),
                    Err(error) => remember(&mut failures,
                        "multiple Win16 task cleanup failures",
                        Err(error.with_context("Win16 USER queue retirement"))),
                }
            } else {
                self.user_queue.take();
            }
        }
        failures.map_or(Ok(()), Err)
    }
}

fn remember(
    failures: &mut Option<RuntimeError>,
    context: &'static str,
    result: Result<(), RuntimeError>,
) {
    let Err(error) = result else {
        return;
    };
    *failures = Some(match failures.take() {
        None => error,
        Some(primary) => primary.with_cleanup(context, error),
    });
}

fn terminal_source_blocker(top: &Win16WindowTerminalSourceTop) -> RuntimeError {
    let source = match top {
        Win16WindowTerminalSourceTop::User { operation, worker_generation, .. } =>
            format!("USER operation {} in worker generation {}", operation.0, worker_generation),
        Win16WindowTerminalSourceTop::Dde { operation } =>
            format!("DDE operation {}", operation.0),
    };
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("Win16 terminal source has no unique retained owner: {source}"),
    )
}
