//! Callback return dispatch while the live CPU and source owners are available.

use super::win16_dde_callback::Win16DdeCallbackFollowUpDispatch;
use super::*;
use crate::Win16HostDdeStep;

impl Win16State {
    pub(super) fn push_callback_kind(
        &mut self,
        kind: CallbackKind,
        callback_id: CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        if callback_id.0 == 0
            || self.callback_frame_ids.contains(&callback_id)
            || self.callback_kinds.len() != self.callback_frame_ids.len()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 callback binding has an invalid or duplicate frame identity",
            ));
        }
        self.callback_kinds.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 callback kind binding",
                error,
            )
        })?;
        self.callback_frame_ids.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 callback identity binding",
                error,
            )
        })?;
        self.callback_kinds.push(kind);
        self.callback_frame_ids.push(callback_id);
        self.callback_owners_quiesced = false;
        Ok(())
    }

    pub(super) fn require_callback_top(
        &self,
        kind: CallbackKind,
    ) -> Result<CallbackFrameId, RuntimeError> {
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 callback kind and identity stacks have different depths",
            ));
        }
        match (self.callback_kinds.last(), self.callback_frame_ids.last()) {
            (Some(found_kind), Some(callback_id)) if *found_kind == kind && callback_id.0 != 0 => {
                Ok(*callback_id)
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "requested Win16 callback is not the exact shared LIFO top",
            )),
        }
    }

    pub(super) fn retire_callback_binding(
        &mut self,
        kind: CallbackKind,
        callback_id: CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        super::retire_callback_binding_from_stacks(
            &mut self.callback_kinds,
            &mut self.callback_frame_ids,
            kind,
            callback_id,
        )
    }

    pub(crate) fn finish_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        dos: &mut dos_kernel::DosKernel,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(kind) = self.callback_kinds.last().copied() else {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 callback gate has no active call",
            ));
        };
        self.require_callback_top(kind)?;
        let callback_transfer =
            if matches!(kind, CallbackKind::Window | CallbackKind::NativeFunction) {
                match cpu
                    .control_transfer()
                    .filter(|transfer| transfer.is_call_return())
                {
                    Some(transfer) => Some(transfer),
                    _ => {
                        return Err(RuntimeError::new(
                            Kind::GuestFault,
                            "Win16 USER callback gate has no exact guest return transfer marker",
                        ));
                    }
                }
            } else {
                None
            };
        if let Some(transfer) = callback_transfer {
            // Store the instruction/checked-adapter return on its exact operation owner
            // before callback cleanup can retire the top callback frame.
            self.record_window_callback_return(kind, transfer)?;
        }

        let finished = match kind {
            CallbackKind::Font => self.finish_font_callback(cpu, dos, memory),
            CallbackKind::GdiObject => self.finish_object_callback(cpu, dos, memory),
            CallbackKind::AcmEnumeration => self.finish_acm_enumeration(cpu, dos, memory, host),
            CallbackKind::LineDda => self.finish_line_dda_callback(cpu, dos, memory),
            CallbackKind::WindowEnumeration => {
                self.finish_window_enumeration(cpu, dos, memory, host)
            }
            CallbackKind::UserHook => self.finish_user_hook_callback(cpu, dos, memory),
            CallbackKind::Ole1 => self.finish_ole1_callback(cpu, dos, memory, host),
            CallbackKind::Window => self.finish_window_callback(&mut cpu.regs, memory, host),
            CallbackKind::NativeFunction => {
                self.finish_native_function_callback(cpu, dos, memory, host)
            }
            CallbackKind::Dde => match self.finish_dde_callback(cpu, dos, memory, host)? {
                Win16DdeCallbackFinish::Resume { origin, step } => {
                    self.resume_dde_callback_origin(origin, step, cpu, dos, memory, host)
                }
                Win16DdeCallbackFinish::FollowUp { callback_id } => self
                    .resume_callback_owned_dde_follow_up(callback_id, None, cpu, dos, memory, host),
            },
            CallbackKind::ClassicDde => {
                self.finish_classic_dde_guest_callback(cpu, dos, memory, host)
            }
            CallbackKind::Mci => self.finish_mci_callback(cpu, memory, host),
            CallbackKind::Module => self.finish_module_callback(cpu, dos, memory, host),
            CallbackKind::Resource => self.finish_resource_callback(cpu, dos, memory, host),
            CallbackKind::Asynchronous => {
                let retirement = self.finish_asynchronous_guest_callback(cpu, dos, memory)?;
                if retirement.source_bound || retirement.midi_source.is_some() {
                    self.validate_asynchronous_callback_retirement(retirement)?;
                    let retire_netbios_source = if let Some(identity) = retirement.midi_source {
                        if !retirement.source_acknowledged {
                            self.finish_midi_notification_target(host, identity)?;
                            self.mark_asynchronous_callback_source_acknowledged(retirement)?;
                        }
                        false
                    } else if retirement.source_acknowledged {
                        self.has_exact_netbios_callback_retirement(retirement)
                    } else if self.finish_netbios_callback_retirement(retirement, host)? {
                        self.mark_asynchronous_callback_source_acknowledged(retirement)?;
                        true
                    } else {
                        self.finish_pending_wave_callback_retirement(retirement)?;
                        self.mark_asynchronous_callback_source_acknowledged(retirement)?;
                        false
                    };
                    // Retire the paired callback family frame only after the
                    // exact source ACK has succeeded. A NetBIOS tombstone is
                    // removed last, after its callback ID leaves the stack.
                    self.complete_asynchronous_callback_retirement(dos, memory, retirement)?;
                    if retire_netbios_source {
                        self.complete_netbios_callback_frame(retirement)?;
                    }
                }
                Ok(())
            }
            CallbackKind::FileCdr => self.finish_file_cdr_callback(cpu, dos, memory),
            CallbackKind::ToolhelpNotify => {
                self.finish_toolhelp_notify_callback_frame(cpu, dos, memory)
            }
            CallbackKind::ToolhelpInterrupt => {
                self.finish_toolhelp_interrupt_callback(cpu, dos, memory)
            }
        };
        match finished {
            Ok(()) => self.drive_pending_window_completion(cpu, memory, dos, host),
            Err(error) => Err(error),
        }
    }

    pub(in crate::win16_runtime) fn resume_dde_callback_origin(
        &mut self,
        origin: Win16DdeCallbackOrigin,
        step: Win16HostDdeStep,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        match origin {
            Win16DdeCallbackOrigin::CallbackFollowUp { callback_id, .. } => self
                .resume_callback_owned_dde_follow_up(
                    callback_id,
                    Some(step),
                    cpu,
                    dos,
                    memory,
                    host,
                ),
            origin => self.route_dde_callback_step(cpu, dos, memory, host, origin, step),
        }
    }

    pub(in crate::win16_runtime) fn resume_callback_owned_dde_follow_up(
        &mut self,
        callback_id: CallbackFrameId,
        resumed_step: Option<Win16HostDdeStep>,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        match Win16State::drive_callback_owned_dde_follow_up(
            self,
            callback_id,
            resumed_step,
            cpu,
            dos,
            memory,
            host,
        )? {
            Win16DdeCallbackFollowUpDispatch::GuestEntered => Ok(()),
            Win16DdeCallbackFollowUpDispatch::Resume { origin, step } => {
                self.resume_dde_callback_origin(origin, step, cpu, dos, memory, host)
            }
            Win16DdeCallbackFollowUpDispatch::StartedFailure { failure } => {
                Err(RuntimeError::with_source(
                    failure.cause.kind(),
                    "native DDE WILDCONNECT readback remains on its exact callback owner",
                    std::sync::Arc::clone(&failure.cause),
                ))
            }
        }
    }
}
