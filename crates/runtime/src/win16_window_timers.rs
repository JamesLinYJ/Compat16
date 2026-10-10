//! Checked guest entry for native and posted WM_TIMER callback events.
//!
//! The USER worker's TIMERPROC is a host-owned trampoline. This module turns
//! its typed event into a Win16 FAR call only after resolving the guest timer
//! generation or a guest-post sidecar; native function pointers never cross
//! this boundary.

use guest_core::{Registers, memory::Memory};

use super::super::window_payloads::GuestWindowPayload;
use super::{
    Win16State, WindowCallbackContinuation, WindowCallbackEntryPhase,
    WindowCallbackFrame, WindowCallbackSetupJournal, WindowCallbackSetupPhase,
    WindowClassRoot, WNDPROC_STACK_BYTES,
};
use crate::{
    RuntimeError, Win16HostCallback, Win16HostWindow,
    Win16HostWindowOperationId, Win16NativeCallbackSource,
};

const WM_TIMER: u16 = 0x0113;

impl Win16State {
    /// Enter a timer callback supplied by the host-owned TIMERPROC trampoline.
    /// `Some(host_timer_id)` identifies a SetTimer generation, including one
    /// retired after KillTimer; `None` is reserved for a verified guest-post
    /// sidecar whose LPARAM is a guest FAR value.
    pub(in crate::win16_runtime) fn begin_host_timer_callback(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        callback: Win16HostCallback,
        host_window: Option<Win16HostWindow>,
        host_timer_id: Option<u64>,
        guest_w_param: u16,
        guest_l_param: u32,
        time: u32,
        operation_id: Win16HostWindowOperationId,
        source: Win16NativeCallbackSource,
    ) -> Result<bool, RuntimeError> {
        let (guest_window, guest_timer_id, timer_proc, window_proc) =
            if let Some(host_timer_id) = host_timer_id {
                let Some((guest_window, guest_timer_id, registration)) =
                    self.timers.registration_for_host(host_timer_id)
                else {
                    return Ok(false);
                };
                // A queued native TIMERPROC can outlive KillTimer, window
                // destruction, or removal of the live guest handle mapping.
                if registration.host_window != host_window {
                    return Ok(false);
                }
                let window_proc = if registration.callback.is_none() && guest_window != 0 {
                    // A TIMERPROC retains its FAR target after KillTimer, but
                    // fallback dispatch may only select a live procedure from
                    // this timer's exact original HWND generation.
                    self.timer_window_procedure(guest_window, registration.host_window)
                } else {
                    None
                };
                (guest_window, guest_timer_id, registration.callback, window_proc)
            } else {
                let guest_window = match host_window {
                    Some(native) => match self.window_handles.iter().find_map(|(guest, found)|
                        (*found == native).then_some(*guest)) {
                        Some(guest) => guest,
                        None => return Ok(false),
                    },
                    None => 0,
                };
                let window_proc = if guest_l_param == 0 && guest_window != 0 {
                    self.timer_window_procedure(guest_window, host_window)
                } else {
                    None
                };
                (guest_window, guest_w_param, (guest_l_param != 0).then_some(guest_l_param),
                    window_proc)
            };

        let (procedure, instance, stack_l_param, stack_w_param, class_root) =
            if let Some(procedure) = timer_proc {
                // TIMERPROC(HWND, UINT, UINT_PTR, DWORD) is FAR PASCAL; its
                // DWORD time value occupies the WndProc LPARAM stack slot.
                (procedure, None, time, guest_timer_id, WindowClassRoot::NoRegistration)
            } else if let Some((procedure, instance, class_root)) = window_proc {
                if guest_window == 0 { return Ok(false); }
                (procedure, Some(instance), guest_l_param, guest_timer_id, class_root)
            } else {
                return Ok(false);
            };

        let payload = GuestWindowPayload {
            message: WM_TIMER,
            w_param: stack_w_param,
            l_param: stack_l_param,
            allocation: None,
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        };
        let callback_id = self.reserve_window_callback_frame()?;
        self.publish_window_callback_frame(WindowCallbackFrame {
            callback_id,
            saved: registers.clone(),
            payload_allocation_locked: false,
            guest_drop_global: None,
            guest_drop_generation: None,
            payload_selector: None,
            payload,
            guest_return_value: None,
            payload_result: None,
            payload_error: None,
            payload_cleanup_error: None,
            payload_retained: None,
            payload_cleaned: false,
            setup_error: None,
            entry_phase: WindowCallbackEntryPhase::Preparing,
            setup: WindowCallbackSetupJournal::preparing(),
            window_tree_retired: false,
            clipboard_retired: false,
            trace_observed: false,
            native_resume_error: None,
            guest_notification: None,
            mdi_child_creation: None,
            callback_address: procedure,
            class_root,
            host_operation: Some(operation_id),
            native_source: Some(source),
            continuation: WindowCallbackContinuation::HostTimer { callback },
        })?;

        let setup = (|| {
            self.check_window_callback(registers, procedure, memory)?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::ProcedureValidated,
            );
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::PayloadPrepared,
            );
            let payload = &self.window_callbacks.last().ok_or_else(|| RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "pre-entry TIMERPROC frame disappeared before stack setup",
            ))?.payload;
            self.write_window_callback_stack(registers, guest_window, payload, memory)?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::CallbackStackWritten,
            );
            Ok(())
        })();
        if let Err(error) = setup {
            return Err(self.fail_preparing_window_callback(callback_id, error));
        }

        let frame = self.window_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "pre-entry TIMERPROC frame disappeared before guest entry",
        ))?;
        debug_assert_eq!(frame.callback_id, callback_id);
        frame.entry_phase = WindowCallbackEntryPhase::GuestCallback;
        registers.set_sp(registers.sp() - WNDPROC_STACK_BYTES);
        registers.cs = (procedure >> 16) as u16;
        registers.set_ip(procedure as u16);
        if let Some(instance) = instance {
            registers.set_ax(instance);
            registers.ds = registers.ss;
            registers.es = registers.ss;
        }
        frame.setup.last_completed = WindowCallbackSetupPhase::GuestEntryCommitted;
        Ok(true)
    }

    fn timer_window_procedure(
        &self, window: u16, native: Option<Win16HostWindow>,
    ) -> Option<(u32, u16, WindowClassRoot)> {
        let native = native?;
        if self.window_handles.get(&window) != Some(&native) { return None; }
        if let Some(&(address, instance)) = self.dialog_procedures.get(&window) {
            return (address != 0).then(|| (address, instance, self.window_class_root(window)));
        }
        self.window_procedures.get(&window).map(|procedure|
            (procedure.address, procedure.instance, WindowClassRoot::Class(procedure.class)))
    }
}
