//! Win16 WAVE open, callback registration, and guest handle publication.

use super::*;
use guest_core::{OwnerId, Selector};

impl Win16State {
    pub(super) fn wave_open(
        &mut self,
        direction: Win16WaveDirection,
        output_handle: u32,
        device: u16,
        format_far: u32,
        callback_far: u32,
        instance: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let supported_flags =
            CALLBACK_TYPEMASK | WAVE_FORMAT_QUERY | WAVE_ALLOWSYNC | WAVE_FORMAT_DIRECT;
        if flags & !supported_flags != 0 {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let callback_kind = flags & CALLBACK_TYPEMASK;
        let query_only = flags & WAVE_FORMAT_QUERY != 0;
        let callback = if query_only {
            None
        } else {
            match callback_kind {
                CALLBACK_NULL => None,
                CALLBACK_FUNCTION => {
                    if callback_far == 0 {
                        return Ok(MMSYSERR_INVALPARAM);
                    }
                    let task = current_wave_task_identity(self)?;
                    match self.register_guest_callback(
                        memory,
                        callback_far,
                        Win16FarCallbackConvention::Pascal,
                        Win16FarCallbackReturn::Void,
                    ) {
                        Ok(token) => Some(WaveCallbackRoute::Function {
                            callback: token,
                            task,
                        }),
                        Err(error) if is_guest_api_failure(&error) => {
                            return Ok(MMSYSERR_INVALPARAM);
                        }
                        Err(error) => return Err(error),
                    }
                }
                CALLBACK_WINDOW => {
                    let Ok(window_handle) = u16::try_from(callback_far) else {
                        return Ok(MMSYSERR_INVALPARAM);
                    };
                    let Some(window) = self.window_handles.get(&window_handle).copied() else {
                        return Ok(MMSYSERR_INVALPARAM);
                    };
                    let task = current_wave_task_identity(self)?;
                    let Some(queue) = self.ensure_user_queue(host)? else {
                        self.warn_wave_unsupported(
                            host,
                            "Win16 WAVE CALLBACK_WINDOW has no exact bound USER task queue",
                        );
                        return Ok(MMSYSERR_NOTSUPPORTED);
                    };
                    Some(WaveCallbackRoute::Window {
                        window,
                        guest_hwnd: window_handle,
                        task,
                        queue,
                    })
                }
                CALLBACK_TASK => {
                    let Ok(task) = u16::try_from(callback_far) else {
                        return Ok(MMSYSERR_INVALPARAM);
                    };
                    let owner = self
                        .task_handles
                        .iter()
                        .find_map(|(owner, handle)| (*handle == task).then_some(*owner));
                    let Some(owner) = owner.filter(|_| task != 0) else {
                        return Ok(MMSYSERR_INVALPARAM);
                    };
                    let identity = match wave_task_identity(self, owner, task) {
                        Ok(identity) => identity,
                        Err(error) => {
                            return if is_guest_api_failure(&error) {
                                Ok(MMSYSERR_INVALPARAM)
                            } else {
                                Err(error)
                            };
                        }
                    };
                    // The current task uses the same exact queue identity as
                    // GetMessage and dispatch; binding only in the host would
                    // leave the runtime's notification validation cache empty.
                    let queue = if self.tasks.current() == Some(owner) {
                        self.ensure_user_queue(host)?
                    } else {
                        host.win16_initialize_user_queue()?;
                        host.win16_bind_task_queue(
                            identity.owner,
                            identity.guest_htask,
                            identity.task_selector_generation,
                        )?
                    };
                    let Some(queue) = queue
                    else {
                        self.warn_wave_unsupported(
                            host,
                            "Win16 WAVE CALLBACK_TASK has no exact bound USER task queue",
                        );
                        return Ok(MMSYSERR_NOTSUPPORTED);
                    };
                    Some(WaveCallbackRoute::Task {
                        task: identity,
                        queue,
                    })
                }
                CALLBACK_EVENT => {
                    self.warn_wave_unsupported(
                        host,
                        "Win16 WAVE callback event mode is not translated",
                    );
                    return Ok(MMSYSERR_NOTSUPPORTED);
                }
                _ => return Ok(MMSYSERR_INVALFLAG),
            }
        };
        let format = match read_wave_format(self, memory, format_far) {
            Ok(WaveFormatRead::Null) => None,
            Ok(WaveFormatRead::Format(format)) => Some(format),
            Err(error) if is_guest_api_failure(&error) => {
                self.unregister_wave_callback(callback);
                return Ok(MMSYSERR_INVALPARAM);
            }
            Err(error) => {
                self.unregister_wave_callback(callback);
                return Err(error);
            }
        };
        let output = if query_only || output_handle == 0 {
            None
        } else {
            match self.capture_wave_output(memory, output_handle, 2) {
                Ok(output) => Some(output),
                Err(error) if is_guest_api_failure(&error) => {
                    self.unregister_wave_callback(callback);
                    return Ok(MMSYSERR_INVALPARAM);
                }
                Err(error) => {
                    self.unregister_wave_callback(callback);
                    return Err(error);
                }
            }
        };
        let reserved_guest_handle = if !query_only && output.is_some() {
            if self.wave_audio.devices.try_reserve(1).is_err() {
                self.unregister_wave_callback(callback);
                return Ok(MMSYSERR_NOMEM);
            }
            let Some(handle) = self.wave_audio.allocate_guest_handle() else {
                self.unregister_wave_callback(callback);
                return Ok(MMSYSERR_NOMEM);
            };
            Some(handle)
        } else {
            None
        };
        let reserved_generation = if reserved_guest_handle.is_some() {
            match self.wave_audio.allocate_device_generation() {
                Ok(generation) => Some(generation),
                Err(error) => {
                    self.unregister_wave_callback(callback);
                    return Err(error);
                }
            }
        } else {
            None
        };
        // A native Open or QUERY may create an owner the runtime never receives.
        self.wave_audio.owner_barrier_required = true;
        let result = host.win16_wave(Win16HostWaveOperation::Open {
            direction: host_direction(direction),
            device_id: device,
            output_handle_present: output.is_some(),
            format,
            flags: if query_only {
                flags & !CALLBACK_TYPEMASK
            } else if matches!(
                callback,
                Some(WaveCallbackRoute::Window { .. } | WaveCallbackRoute::Task { .. })
            ) {
                // Use an owned host callback sink so native completions wake
                // a blocked GetMessage; the runtime later posts the guest
                // WINDOW/TASK notification through USER.
                (flags & !CALLBACK_TYPEMASK) | CALLBACK_FUNCTION
            } else {
                flags
            },
        });
        let result = match result {
            Ok(Win16HostWaveResult::Opened { result, device }) => (result, device),
            Ok(_) => {
                self.unregister_wave_callback(callback);
                return Err(wave_invariant("WAVE open returned the wrong result"));
            }
            Err(error) => {
                self.unregister_wave_callback(callback);
                return Err(error);
            }
        };
        if query_only {
            if result.1.is_some() {
                self.unregister_wave_callback(callback);
                return Err(wave_invariant("WAVE format query allocated a device"));
            }
            return Ok(result.0);
        }
        if result.0 != MMSYSERR_NOERROR {
            if result.1.is_some() {
                return Err(wave_invariant("failed WAVE open returned a live device"));
            }
            self.unregister_wave_callback(callback);
            return Ok(result.0);
        }
        let Some(host_device) = result.1 else {
            self.unregister_wave_callback(callback);
            return Err(wave_invariant(
                "successful WAVE open returned no device identity",
            ));
        };
        let Some(output) = output else {
            // Passing NULL for the output handle should produce the ordinary
            // WinMM parameter failure, never a successful untracked device.
            self.unregister_wave_callback(callback);
            return Err(wave_invariant(
                "WAVE open succeeded without a guest output pointer",
            ));
        };
        let guest_handle = reserved_guest_handle
            .ok_or_else(|| wave_invariant("successful WAVE open has no reserved guest handle"))?;
        let generation = reserved_generation
            .ok_or_else(|| wave_invariant("successful WAVE open has no reserved generation"))?;
        self.wave_audio.devices.push(WaveDeviceRecord {
            guest_handle,
            direction,
            host: host_device,
            generation,
            callback,
            instance,
            closing: false,
            reset_result: None,
            reset_failure_result: None,
            close_result: None,
            last_received_sequence: 0,
            close_event_sequence: None,
            producer_quiescence_sequence: None,
        });
        let mut writes = Vec::new();
        writes.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WAVE open result write",
                error,
            )
        })?;
        writes.push((output, wave_bytes(guest_handle.to_le_bytes())?));
        commit_guest_writes(self, memory, writes)?;
        Ok(MMSYSERR_NOERROR)
    }
}

fn current_wave_task_identity(
    state: &Win16State,
) -> Result<WaveTaskIdentity, RuntimeError> {
    let owner = state.tasks.current().ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant, "Win16 has no current task for WAVE callback")
    })?;
    let guest_htask = state.task_handles.get(&owner).copied().ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 current WAVE callback task has no guest HTASK",
        )
    })?;
    wave_task_identity(state, owner, guest_htask)
}

fn wave_task_identity(
    state: &Win16State,
    owner: OwnerId,
    guest_htask: u16,
) -> Result<WaveTaskIdentity, RuntimeError> {
    let task = state.tasks.info(owner).map_err(crate::runtime_error)?;
    if matches!(task.state,
        win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited)
    {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "Win16 WAVE callback task is already terminating",
        ));
    }
    if state.task_handles.get(&owner) != Some(&guest_htask) {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "Win16 WAVE callback task identity is no longer registered",
        ));
    }
    let selector = state
        .selectors
        .reference(Selector(guest_htask))
        .map_err(crate::runtime_error)?;
    Ok(WaveTaskIdentity {
        owner,
        guest_htask,
        task_selector_generation: selector.generation(),
    })
}
