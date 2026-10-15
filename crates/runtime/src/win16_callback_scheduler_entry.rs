//! Preflight and transactional entry for typed asynchronous callback ABIs.

use guest_core::memory::Memory;
use super::{
    AsynchronousCallbackBeginFailure, AsynchronousCallbackPhase, Win16AsynchronousCallbackArgument,
    Win16AsynchronousCallbackFrame, Win16State,
};
use super::super::callback_entry::{
    Win16CallbackEntry, Win16CallbackEntryFrame, Win16GuestCallbackAbi,
};
use super::super::callback_scheduler_registration::validate_guest_callback_registration;
use super::super::far_callback::{Win16FarCallbackArgument, Win16FarCallbackReturn};
use crate::{DiagnosticKind as Kind, RuntimeError, Win16GuestCallbackToken, Win16HostMidiNotificationId};

impl Win16State {
    pub(super) fn begin_asynchronous_guest_callback_entry_from_source(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        callback: Win16GuestCallbackToken,
        entry: Win16CallbackEntry,
        source_bound: bool,
        midi_source: Option<Win16HostMidiNotificationId>,
    ) -> Result<Option<super::super::CallbackFrameId>, AsynchronousCallbackBeginFailure> {
        let Some(registration) = self.callback_scheduler.resolve(callback) else {
            return Ok(None);
        };
        match (&registration.abi, &entry) {
            (Win16GuestCallbackAbi::FarCall { return_kind, .. }, Win16CallbackEntry::FarCall { .. })
                if *return_kind == Win16FarCallbackReturn::Void => {}
            (Win16GuestCallbackAbi::FarCall { .. }, Win16CallbackEntry::FarCall { .. }) => {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "asynchronous Win16 FAR callbacks require a void return ABI",
                ).into());
            }
        }

        let Win16CallbackEntry::FarCall { arguments } = &entry;
        for value in arguments {
            let Win16AsynchronousCallbackArgument::GuestFarPointer {
                far,
                access,
                bytes,
                selector_generation,
                allow_null,
            } = value else {
                continue;
            };
            if *far == 0 && *allow_null {
                continue;
            }
            if *far != 0 && selector_generation.is_none() {
                return Err(RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 callback FAR pointer has no captured selector generation",
                ).into());
            }
            let pointer = self.selectors.pointer_from_far(*far)
                .map_err(crate::runtime_error)?;
            if selector_generation.is_some_and(|generation| {
                pointer.selector().generation() != generation
            }) {
                return Err(RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 callback FAR pointer selector generation changed",
                ).into());
            }
            let extent = usize::try_from(*bytes).map_err(|_| RuntimeError::new(
                Kind::GuestFault,
                "Win16 callback FAR pointer extent exceeds host address width",
            ))?;
            self.selectors.translate(pointer, *access, extent, memory)
                .map_err(crate::runtime_error)?;
        }
        // Reserve every central owner before temporary guest buffers, the
        // callback stack frame, or live CPU registers can change.
        self.callback_scheduler.active.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain asynchronous Win16 callback frame", error)
        })?;
        self.callback_scheduler.pending_cleanup.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain asynchronous callback rollback owner", error)
        })?;
        self.callback_scheduler.pending_source_retirements.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain asynchronous callback source-retirement receipt", error)
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let owned_count = arguments.iter().filter(|argument| matches!(
            argument, Win16AsynchronousCallbackArgument::OwnedBytes { .. }
        )).count();
        let argument_count = arguments.len();
        self.reserve_retained_callback_buffer_capacity(owned_count)?;
        let mut buffers = Vec::new();
        buffers.try_reserve(owned_count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain asynchronous callback guest buffers",
            error,
        ))?;
        let mut far_arguments = Vec::new();
        far_arguments.try_reserve(argument_count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain asynchronous callback arguments",
            error,
        ))?;

        if let Err(error) = validate_guest_callback_registration(
            &self.selectors, memory, registration,
        ) {
            return Err(self.retain_failed_pre_entry_cleanup(
                callback_id, callback, registration, buffers, source_bound, error,
            ));
        }

        let active_call = match entry {
            Win16CallbackEntry::FarCall { arguments } => {
                for value in arguments {
                    match value {
                        Win16AsynchronousCallbackArgument::Word(value) => {
                            far_arguments.push(Win16FarCallbackArgument::Word(value));
                        }
                        Win16AsynchronousCallbackArgument::Dword(value) => {
                            far_arguments.push(Win16FarCallbackArgument::Dword(value));
                        }
                        Win16AsynchronousCallbackArgument::GuestFarPointer {
                            far, access, bytes, allow_null, ..
                        } => {
                            if far == 0 && allow_null {
                                far_arguments.push(Win16FarCallbackArgument::Dword(0));
                            } else {
                                far_arguments.push(Win16FarCallbackArgument::GuestPointer {
                                    far, access, bytes,
                                });
                            }
                        }
                        Win16AsynchronousCallbackArgument::OwnedBytes { bytes, access } => {
                            let (buffer, far, length) =
                                match self.allocate_callback_buffer(memory, &bytes) {
                                    Ok(buffer) => buffer,
                                    Err((error, partial)) => {
                                        if let Some(partial) = partial { buffers.push(partial); }
                                        return Err(self.retain_failed_pre_entry_cleanup(
                                            callback_id, callback, registration, buffers,
                                            source_bound, error,
                                        ));
                                    }
                                };
                            buffers.push(buffer);
                            far_arguments.push(Win16FarCallbackArgument::GuestPointer {
                                far, access, bytes: length,
                            });
                        }
                    }
                }
                let Win16GuestCallbackAbi::FarCall { convention, return_kind } = registration.abi;
                match self.enter_guest_far_callback_checked(
                    cpu,
                    dos,
                    memory,
                    registration.procedure,
                    &far_arguments,
                    convention,
                    return_kind,
                ) {
                    Ok(frame) => Win16CallbackEntryFrame::FarCall(frame),
                    Err(error) => return Err(self.retain_failed_pre_entry_cleanup(
                        callback_id, callback, registration, buffers, source_bound, error,
                    )),
                }
            }
        };

        self.callback_scheduler.active.push(Win16AsynchronousCallbackFrame {
            callback_id,
            callback_token: callback,
            registration,
            active_call,
            buffers,
            phase: AsynchronousCallbackPhase::Guest,
            return_failure: None,
            source_bound,
            midi_source,
            source_acknowledged: false,
        });
        self.push_callback_kind(super::super::CallbackKind::Asynchronous, callback_id)?;
        Ok(Some(callback_id))
    }
}
