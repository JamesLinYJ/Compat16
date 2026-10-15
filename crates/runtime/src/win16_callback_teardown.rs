//! Producer quiescence and exact LIFO cancellation for terminal Win16 exit.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use x86_cpu::Cpu;

use super::{CallbackKind, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    /// Prove every callback producer stopped before cancelling any entered
    /// guest continuation. DDE and active MCI owners stay retained until their
    /// host boundary supplies an explicit cancellation receipt.
    pub(in crate::win16_runtime) fn quiesce_callback_owners_for_teardown(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.callback_owners_quiesced {
            return Ok(());
        }
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(callback_teardown_invariant(
                "Win16 callback kind and frame identity stacks have different depths",
            ));
        }

        self.quiesce_acm_callback_owners(cpu, memory, host)?;
        self.quiesce_window_callback_owner(host)?;

        self.quiesce_mci_producers(host)?;
        if !self.mci.callback_producers_stopped() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 MCI has a native yield continuation without a cancellation receipt",
            ));
        }
        self.quiesce_dde_callback_owners(host)?;

        self.callback_owners_quiesced = true;
        Ok(())
    }

    /// Retire one exact top continuation. Source-bound asynchronous callbacks
    /// are ACKed only after their saved CPU context and guest buffers retire.
    pub(in crate::win16_runtime) fn cancel_top_callback_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.callback_owners_quiesced {
            return Err(callback_teardown_invariant(
                "callback cancellation started before producer quiescence",
            ));
        }
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(callback_teardown_invariant(
                "Win16 callback kind and frame identity stacks have different depths",
            ));
        }

        if self
            .retire_acknowledged_dde_context_after_task_execution_ended(ended, cpu, dos, memory)?
        {
            return Ok(true);
        }
        let Some(kind) = self.callback_kinds.last().copied() else {
            if !self.callback_frame_ids.is_empty() {
                return Err(callback_teardown_invariant(
                    "Win16 callback identity stack has an entry without a kind",
                ));
            }
            if let Some(retirement) = self
                .pending_asynchronous_source_retirements()
                .first()
                .copied()
            {
                self.finish_pending_asynchronous_callback_retirement(host, retirement)?;
                return Ok(true);
            }
            if let Some((callback_id, source_bound)) =
                self.callback_scheduler.next_pre_entry_cleanup()
            {
                if source_bound {
                    return self.retry_wave_pre_entry_cleanup(callback_id);
                }
                let _ = self.retry_asynchronous_pre_entry_cleanup(callback_id)?;
                return Ok(true);
            }
            return Ok(false);
        };

        let _callback_id = self.require_callback_top(kind)?;
        match kind {
            CallbackKind::ClassicDde => {
                self.cancel_classic_dde_callback_for_teardown(ended, cpu, dos, memory, host)?
            }
            CallbackKind::Ole1 => {
                self.cancel_ole1_callback_for_teardown(ended, cpu, dos, memory, host)?
            }
            CallbackKind::UserHook => {
                self.cancel_user_hook_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::Font => {
                self.cancel_font_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::GdiObject => {
                self.cancel_object_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::AcmEnumeration => {
                if !self.cancel_acm_callback_frame(ended, cpu, dos, memory, host)? {
                    return Err(callback_teardown_invariant(
                        "top ACM callback kind has no cancellable family frame",
                    ));
                }
            }
            CallbackKind::WindowEnumeration => {
                self.cancel_window_enumeration(ended, cpu, dos, memory)?
            }
            CallbackKind::LineDda => {
                self.cancel_line_dda_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::Window => {
                match self.cancel_window_callback_for_teardown(ended)? {
                    super::windows::WindowCallbackPayloadCleanup::Released
                    | super::windows::WindowCallbackPayloadCleanup::RetainedTransferred => {}
                    super::windows::WindowCallbackPayloadCleanup::RetainedInFrame => {
                        // A retained payload keeps the exact callback frame at
                        // the shared LIFO top. Report no progress so the outer
                        // unwind exits instead of retrying in a tight loop;
                        // final validation then returns the retained-owner
                        // failure without issuing a source ACK.
                        return Ok(false);
                    }
                }
            }
            CallbackKind::NativeFunction => {
                self.cancel_native_function_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::Dde => {
                self.cancel_dde_callback_after_abort(ended, cpu, dos, memory, host)?
            }
            CallbackKind::Module => self.cancel_module_callback_for_teardown(ended, cpu, dos, memory)?,
            CallbackKind::Resource => self.cancel_resource_callback_for_teardown(ended, cpu, dos, memory)?,
            CallbackKind::Asynchronous => {
                if self.callback_scheduler.asynchronous_top_source_bound() {
                    let (callback_id, callback_token) = self
                        .callback_scheduler
                        .asynchronous_top_identity()
                        .ok_or_else(|| {
                            callback_teardown_invariant(
                                "source-bound callback has no exact asynchronous frame identity",
                            )
                        })?;
                    self.prepare_wave_callback_terminal_retirement(callback_id, callback_token)?;
                }
                let retirement = self.cancel_asynchronous_callback_for_teardown(ended, cpu, dos, memory)?;
                if retirement.source_bound || retirement.midi_source.is_some() {
                    self.finish_pending_asynchronous_callback_retirement(host, retirement)?;
                }
            }
            CallbackKind::Mci => {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "MCI callback frame awaits an explicit native yield cancellation receipt",
                ));
            }
            CallbackKind::FileCdr => {
                self.cancel_file_cdr_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::ToolhelpNotify => {
                self.cancel_toolhelp_notify_callback_for_teardown(ended, cpu, dos, memory)?
            }
            CallbackKind::ToolhelpInterrupt => {
                self.cancel_toolhelp_interrupt_callback_for_teardown(
                    ended, cpu, dos, memory,
                )?
            }
        }
        Ok(true)
    }

    fn finish_pending_asynchronous_callback_retirement(
        &mut self,
        host: &mut impl RuntimeHost,
        retirement: super::callback_scheduler::AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        if !retirement.source_bound {
            return Err(callback_teardown_invariant(
                "terminal callback retirement has no typed WAVE or MIDI source identity",
            ));
        }
        if retirement.midi_source.is_some() {
            return self.finish_midi_asynchronous_callback_retirement(host, retirement);
        }

        if retirement.terminal_cancelled
            && self.finish_terminal_wave_callback_retirement(retirement)?
        {
            // WAVE consumed this exact scheduler source with its cached
            // producer-quiescence proof before removing its own source row.
            return Ok(());
        }

        if retirement.source_acknowledged {
            if self.has_exact_netbios_callback_retirement(retirement) {
                self.complete_asynchronous_source_retirement(
                    retirement.callback_id,
                    retirement.callback_token,
                )?;
                return self.complete_netbios_callback_frame(retirement);
            }
            return self.complete_asynchronous_source_retirement(
                retirement.callback_id,
                retirement.callback_token,
            );
        }

        if self.finish_netbios_callback_retirement(retirement, host)? {
            self.mark_pending_asynchronous_source_acknowledged(retirement)?;
            self.complete_asynchronous_source_retirement(
                retirement.callback_id,
                retirement.callback_token,
            )?;
            return self.complete_netbios_callback_frame(retirement);
        }

        if !retirement.source_acknowledged {
            self.finish_pending_wave_callback_retirement(retirement)?;
            self.mark_pending_asynchronous_source_acknowledged(retirement)?;
        }
        self.complete_asynchronous_source_retirement(
            retirement.callback_id,
            retirement.callback_token,
        )
    }

    pub(in crate::win16_runtime) fn unwind_callbacks_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.quiesce_callback_owners_for_teardown(cpu, memory, host)?;
        self.discard_stopped_toolhelp_interrupt_events_after_execution_ended(ended);
        while self.cancel_top_callback_for_teardown(ended, cpu, dos, memory, host)? {}
        self.validate_callback_retirement_complete()
    }

    fn validate_callback_retirement_complete(&self) -> Result<(), RuntimeError> {
        if !self.window_callbacks.is_empty() {
            if let Some(error) = self.retained_window_payload_error() {
                return Err(super::callback_lifo::shared_runtime_error(error));
            }
        }
        if !self.callback_kinds.is_empty()
            || !self.callback_frame_ids.is_empty()
            || !self.font_callbacks.is_empty()
            || !self.object_callbacks.is_empty()
            || !self.acm.callback_frames_are_empty()
            || !self.line_dda_callbacks.is_empty()
            || !self.window_enumerations.is_empty()
            || !self.window_callbacks.is_empty()
            || !self.native_function_callbacks.is_empty()
            || !self.dde_callbacks.is_empty()
            || !self.module_callbacks.is_empty()
            || !self.resource_callbacks.is_empty()
            || !self.toolhelp_notify_frames.is_empty()
            || !self.toolhelp_interrupt_frames.is_empty()
            || !self.toolhelp_interrupt_retained_selector_owners.is_empty()
            || !self.toolhelp_interrupt_retained_stacks.is_empty()
            || self.toolhelp_interrupt_stopped_event.is_some()
            || !self.toolhelp_interrupt_handles.is_empty()
            || self.kernel_file_system.has_active_callback()
            || !self.mci.callback_producers_stopped()
            || self.callback_scheduler.has_active_frames()
            || self.callback_scheduler.has_pending_cleanup()
            || self.callback_scheduler.has_pending_source_retirement()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                self.callback_retirement_state(),
            ));
        }
        Ok(())
    }

    /// Observe retained ownership without changing cancellation or ACK order.
    /// A blocked payload can leave both central and family frames live, so
    /// reporting an empty central stack would hide the actual retirement phase.
    fn callback_retirement_state(&self) -> String {
        let window = self.window_callbacks.last().map_or_else(
            || "none".to_owned(),
            |frame| {
                let allocation = frame.payload.allocation.map_or_else(
                    || "none".to_owned(),
                    |owner| format!("0x{:04X}/{}", owner.raw().0, owner.generation()),
                );
                let selector = frame.payload_selector.map_or_else(
                    || "none".to_owned(),
                    |owner| format!("0x{:04X}/{}", owner.raw().0, owner.generation()),
                );
                let pins = frame.payload_retained.map_or_else(
                    || "unobserved".to_owned(),
                    |counts| format!("aliases={},pages={},internal={}",
                        counts.selector_aliases, counts.page_locks, counts.internal_pins),
                );
                format!("callback={},allocation={},selector={},pins=[{}],locked={},cleaned={},returned={},setup_error={},payload_error={},cleanup_error={},cpu_selector_owner={}",
                    frame.callback_id.0, allocation, selector, pins,
                    frame.payload_allocation_locked, frame.payload_cleaned,
                    frame.payload_result.is_some(), frame.setup_error.is_some(),
                    frame.payload_error.is_some(), frame.payload_cleanup_error.is_some(),
                    frame.payload_selector.is_some_and(|selector|
                        self.legacy_cpu_frame_owns_selector(selector)))
            },
        );
        format!("Win16 callback retirement incomplete: central_kinds={},central_ids={},font={},gdi_object={},acm_live={},line_dda={},window_enum={},window={},window_property={},dde={},module={},resource={},toolhelp={},file_callback={},mci_stopped={},scheduler_active={},scheduler_cleanup={},scheduler_source_retirement={},operations={},operation_cpu_owners={}; top_window=[{}]",
            self.callback_kinds.len(), self.callback_frame_ids.len(),
            self.font_callbacks.len(), self.object_callbacks.len(), !self.acm.callback_frames_are_empty(),
            self.line_dda_callbacks.len(), self.window_enumerations.len(),
            self.window_callbacks.len(), self.native_function_callbacks.len(),
            self.dde_callbacks.len(), self.module_callbacks.len(),
            self.resource_callbacks.len(), self.toolhelp_notify_frames.len(),
            self.kernel_file_system.has_active_callback(),
            self.mci.callback_producers_stopped(),
            self.callback_scheduler.has_active_frames(),
            self.callback_scheduler.has_pending_cleanup(),
            self.callback_scheduler.has_pending_source_retirement(),
            self.window_operations.len(),
            self.window_operations.iter().filter(|frame| frame.cpu_call_owner.is_some()).count(),
            window)
    }
}

fn callback_teardown_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
