//! Native WinMM WAVE device open and stable callback-owner registration.

use super::*;

impl Win16WaveHost {
    pub(super) fn open(
        &mut self,
        direction: Win16HostWaveDirection,
        device_id: u16,
        output_handle_present: bool,
        format: Option<Win16HostWaveFormatSpec>,
        flags: u32,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        let query = flags & WAVE_FORMAT_QUERY != 0;
        if !query && !output_handle_present {
            return Ok(Win16HostWaveResult::Opened {
                result: MMSYSERR_INVALPARAM,
                device: None,
            });
        }
        let callback_kind = flags & CALLBACK_TYPEMASK;
        if callback_kind != CALLBACK_NULL_WIN16 && callback_kind != CALLBACK_FUNCTION_WIN16 {
            return Ok(Win16HostWaveResult::Opened {
                result: MMSYSERR_INVALPARAM,
                device: None,
            });
        }
        // WinMM's default mapper performs installed ACM conversion. Keep the
        // complete owned guest format alive across the real native call.
        let mut native_format = format
            .as_ref()
            .map(WaveFormatStorage::from_spec)
            .transpose()?;
        let format_pointer = native_format
            .as_mut()
            .map_or(ptr::null_mut(), WaveFormatStorage::as_mut_wfx);
        let callback_function = callback_kind == CALLBACK_FUNCTION_WIN16 && !query;
        // Callback delivery needs the USER worker's real wake channel. Keep
        // query/null-callback operations usable when that worker is absent,
        // but preserve its startup cause before allocating a callback owner.
        if callback_function {
            if let Some(error) = &self.wake_start_error {
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "native WAVE callback delivery has no USER wake channel",
                    Arc::clone(error),
                ));
            }
        }
        if output_handle_present {
            self.devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native WAVE device table",
                    error,
                )
            })?;
        }
        // Reserve an identity and retirement owner even for QUERY. The normal
        // API returns no handle there, but retaining these before the native
        // call keeps an unexpected non-null output safe instead of orphaning
        // a handle after WinMM has observed it.
        let device_token = Win16HostWaveDevice(self.allocate_identity()?);
        retired::reserve_slot()?;
        let mut callback = if callback_function {
            Some(Box::new(CallbackContext::new(
                direction,
                Arc::clone(&self.event_sequences),
                Arc::clone(&self.callback_wake),
            )))
        } else {
            None
        };
        let callback_instance = callback.as_mut().map_or(0, |context| {
            (&mut **context as *mut CallbackContext) as usize
        });
        let callback_proc = if callback_function {
            match direction {
                Win16HostWaveDirection::Input => callback::wave_in_callback as *const () as usize,
                Win16HostWaveDirection::Output => callback::wave_out_callback as *const () as usize,
            }
        } else {
            CALLBACK_NULL as usize
        };
        let native_device_id = if device_id == u16::MAX {
            WAVE_MAPPER
        } else {
            u32::from(device_id)
        };
        let native_flags = flags & (WAVE_FORMAT_QUERY | WAVE_ALLOWSYNC | WAVE_FORMAT_DIRECT)
            | if callback_function {
                CALLBACK_FUNCTION
            } else {
                CALLBACK_NULL
            };
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let (result, native_handle) = unsafe {
            native::open_native(
                direction,
                native_device_id,
                output_handle_present,
                format_pointer,
                callback_proc,
                callback_instance,
                native_flags,
            )
        };
        if result != MMSYSERR_NOERROR {
            if !native_handle_is_null(&native_handle) {
                let device = WaveDevice {
                    token: device_token,
                    direction,
                    native: native_handle,
                    callback,
                    callback_function,
                    closing: true,
                    native_closed: false,
                    close_event_delivered: false,
                    close_event_sequence: None,
                    owner_thread: std::thread::current().id(),
                    retirement_slot_reserved: true,
                    buffers: Vec::new(),
                };
                if let Err(cleanup_error) = retired::dispose_or_retain(device) {
                    return Err(retired::operation_and_cleanup_error(
                        retired::wave_result_error("open WAVE device", result),
                        cleanup_error,
                    ));
                }
            } else {
                retired::release_reservation()?;
            }
            return Ok(Win16HostWaveResult::Opened {
                result,
                device: None,
            });
        }
        if query {
            if !native_handle_is_null(&native_handle) {
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let close_result = unsafe { native::close_native(&native_handle) };
                if close_result != MMSYSERR_NOERROR {
                    let device = WaveDevice {
                        token: device_token,
                        direction,
                        native: native_handle,
                        callback,
                        callback_function,
                        closing: true,
                        native_closed: false,
                        close_event_delivered: false,
                        close_event_sequence: None,
                        owner_thread: std::thread::current().id(),
                        retirement_slot_reserved: true,
                        buffers: Vec::new(),
                    };
                    retired::retain(
                        device,
                        std::thread::current().id(),
                        Some(retired::wave_result_error(
                            "close unexpected WAVE query handle",
                            close_result,
                        )),
                    );
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "WinMM format query unexpectedly opened a device that could not be closed",
                    ));
                }
                retired::release_reservation()?;
                return Err(wave_invariant(
                    "WinMM format query unexpectedly returned a device handle",
                ));
            }
            retired::release_reservation()?;
            return Ok(Win16HostWaveResult::Opened {
                result,
                device: None,
            });
        }
        if native_handle_is_null(&native_handle) {
            retired::release_reservation()?;
            return Err(wave_invariant(
                "WinMM succeeded but returned a null device handle",
            ));
        }
        self.devices.push(WaveDevice {
            token: device_token,
            direction,
            native: native_handle,
            callback,
            callback_function,
            closing: false,
            native_closed: false,
            close_event_delivered: false,
            close_event_sequence: None,
            owner_thread: std::thread::current().id(),
            retirement_slot_reserved: true,
            buffers: Vec::new(),
        });
        Ok(Win16HostWaveResult::Opened {
            result,
            device: Some(device_token),
        })
    }
}
