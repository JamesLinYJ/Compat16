//! Tokenized PlaySound leases sharing the WAVE owner lifetime.

use super::*;

pub(super) fn play_wave(
    host: &mut Win16WaveHost,
    source: Win16SoundSource,
    flags: u32,
) -> Result<ResultValue, RuntimeError> {
    let asynchronous = flags & SND_ASYNC != 0;
    let memory = flags & SND_MEMORY != 0;
    let (native_source, retained_source) = match source {
        Win16SoundSource::Stop => (None, None),
        Win16SoundSource::MemoryWave(bytes) => {
            if bytes.is_empty() || !memory {
                return Ok(ResultValue::PlayWave {
                    result: false,
                    lease: None,
                    retired_lease: None,
                });
            }
            let source = super::PlaySoundSourceOwner::Bytes(bytes);
            let pointer = match &source {
                super::PlaySoundSourceOwner::Bytes(bytes) => bytes.as_ptr().cast::<u16>(),
                super::PlaySoundSourceOwner::WidePath { .. } => unreachable!(),
            };
            (Some(pointer), Some(source))
        }
        Win16SoundSource::FileOrAlias(bytes) => {
            if memory {
                return Ok(ResultValue::PlayWave {
                    result: false,
                    lease: None,
                    retired_lease: None,
                });
            }
            let source = wide_terminated(&host.text_codec, bytes)?;
            let pointer = source.as_ptr();
            (
                Some(pointer),
                Some(super::PlaySoundSourceOwner::WidePath { _units: source }),
            )
        }
    };
    let token = if asynchronous && native_source.is_some() {
        Some(Win16SoundLease(host.allocate_identity()?))
    } else {
        None
    };
    if token.is_some() && retained_source.is_none() {
        return Err(wave_invariant(
            "accepted asynchronous PlaySound has no owned source buffer",
        ));
    }

    // The process ledger owns the bytes while native playback is live. This
    // same lock serializes PlaySound calls and their exact owner-generation
    // changes across every WindowsHost instance in the process.
    let mut process = super::lock_play_sound_process();
    let generation = if token.is_some() {
        let generation = process.next_generation;
        process.next_generation = generation.checked_add(1).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "PlaySound generations exhausted")
        })?;
        Some(generation)
    } else {
        None
    };
    // SAFETY: filenames are owned, NUL-terminated UTF-16; memory data remains
    // an unchanged owned RIFF/WAVE byte vector. Async input moves into the
    // process ledger without reallocating.
    let accepted =
        unsafe { PlaySoundW(native_source.unwrap_or(ptr::null()), ptr::null_mut(), flags) != 0 };
    if !accepted {
        return Ok(ResultValue::PlayWave {
            result: false,
            lease: None,
            retired_lease: None,
        });
    }

    let retired_lease = host.sound.active_play_sound.take().map(|lease| lease.token);
    process.active_owner = match (token, generation, retained_source) {
        (Some(token), Some(generation), Some(source)) => {
            let host_identity = Arc::clone(&host.identity_source);
            let owner_thread = thread::current().id();
            host.sound.active_play_sound = Some(PlaySoundLeaseRecord {
                token,
                host_identity: Arc::clone(&host_identity),
                generation,
            });
            Some(ProcessPlaySoundOwner {
                host_identity,
                token,
                generation,
                _retained_source: source,
                owner_thread,
                orphaned: false,
            })
        }
        (None, None, _) => None,
        _ => {
            return Err(wave_invariant(
                "accepted PlaySound could not retain its exact process owner",
            ));
        }
    };
    Ok(ResultValue::PlayWave {
        result: true,
        lease: token,
        retired_lease,
    })
}

pub(super) fn stop_play_wave(
    host: &mut Win16WaveHost,
    token: Win16SoundLease,
) -> Result<ResultValue, RuntimeError> {
    let mut process = super::lock_play_sound_process();
    let Some(lease) = host.sound.active_play_sound.as_ref() else {
        return Ok(not_owned_play_wave());
    };
    if lease.token != token {
        return Ok(not_owned_play_wave());
    }
    if !process_owner_matches(&process, &host.identity_source, lease) {
        host.sound.active_play_sound = None;
        return Ok(not_owned_play_wave());
    }
    if stop_native_play_sound() {
        process.active_owner = None;
        host.sound.active_play_sound = None;
        Ok(ResultValue::PlayWaveStopped {
            result: true,
            status: Win16SoundStopStatus::Stopped,
        })
    } else {
        Ok(ResultValue::PlayWaveStopped {
            result: false,
            status: Win16SoundStopStatus::Pending,
        })
    }
}

fn not_owned_play_wave() -> ResultValue {
    ResultValue::PlayWaveStopped {
        result: false,
        status: Win16SoundStopStatus::NotOwned,
    }
}

fn process_owner_matches(
    process: &PlaySoundProcessState,
    host_identity: &Arc<AtomicU64>,
    lease: &PlaySoundLeaseRecord,
) -> bool {
    process.active_owner.as_ref().is_some_and(|owner| {
        Arc::ptr_eq(&owner.host_identity, host_identity)
            && Arc::ptr_eq(&owner.host_identity, &lease.host_identity)
            && owner.token == lease.token
            && owner.generation == lease.generation
    })
}

fn retired_owner_matches(owner: &ProcessPlaySoundOwner, lease: &PlaySoundLeaseRecord) -> bool {
    Arc::ptr_eq(&owner.host_identity, &lease.host_identity)
        && owner.token == lease.token
        && owner.generation == lease.generation
}

fn stop_native_play_sound() -> bool {
    // SAFETY: NULL is the documented PlaySound stop request; no source buffer
    // is passed or exposed.
    unsafe { PlaySoundW(ptr::null(), ptr::null_mut(), 0) != 0 }
}

fn wide_terminated(
    codec: &super::super::GuestTextCodec,
    mut bytes: Vec<u8>,
) -> Result<Vec<u16>, RuntimeError> {
    if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
        bytes.truncate(end);
    }
    codec.to_wide_z(&bytes)
}

pub(super) fn cleanup(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    let mut process = super::lock_play_sound_process();
    let Some(lease) = host.sound.active_play_sound.as_ref() else {
        return Ok(());
    };
    if !process_owner_matches(&process, &host.identity_source, lease) {
        host.sound.active_play_sound = None;
        return Ok(());
    }
    if !stop_native_play_sound() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "PlaySound did not confirm release of its owned source buffer",
        ));
    }
    process.active_owner = None;
    host.sound.active_play_sound = None;
    Ok(())
}

pub(super) fn producer_barrier(host: &Win16WaveHost) -> Result<(), RuntimeError> {
    retry_retired_play_sounds()?;
    let current_thread = thread::current().id();
    let process = super::lock_play_sound_process();
    let Some(owner) = process.active_owner.as_ref() else {
        return Ok(());
    };
    if owner.owner_thread != current_thread {
        return Ok(());
    }
    let belongs_to_host = Arc::ptr_eq(&owner.host_identity, &host.identity_source);
    Err(RuntimeError::new(
        Kind::HostFailure,
        format!(
            "PlaySound lease {:?} generation {} remains live on the current owner thread at the WAVE/SOUND producer barrier (current host owns it: {belongs_to_host})",
            owner.token, owner.generation,
        ),
    ))
}

pub(super) fn retain_on_drop(state: &mut SoundState) {
    let Some(lease) = state.active_play_sound.take() else {
        return;
    };
    let mut process = super::lock_play_sound_process();
    let Some(owner) = process.active_owner.as_mut() else {
        return;
    };
    if retired_owner_matches(owner, &lease) {
        owner.orphaned = true;
    }
}

pub(super) fn retry_retired_play_sounds() -> Result<(), RuntimeError> {
    let current_thread = thread::current().id();
    let mut process = super::lock_play_sound_process();
    let Some(owner) = process.active_owner.as_ref() else {
        return Ok(());
    };
    if !owner.orphaned || owner.owner_thread != current_thread {
        return Ok(());
    }
    if stop_native_play_sound() {
        process.active_owner = None;
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::HostFailure,
            "retry PlaySound stop for a process-owned source failed",
        ))
    }
}
