//! Guest pointer/resource translation for Win16 sndPlaySound and PlaySound.

use guest_core::memory::Memory;
use guest_core::Selector;
use win16_abi::{Win16ResourceName, Win16SoundPlayApi, strings::read_ansi_z};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16SoundHostOperation as Op, Win16SoundHostResult as HostResult,
    Win16SoundLease, Win16SoundSource};

const SND_MEMORY: u32 = 0x0004;
const SND_ASYNC: u32 = 0x0001;
const SND_RESOURCE: u32 = 0x0004_0000;
const MAX_WAVE_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn play_wave_api(
    state: &mut Win16State,
    api: Win16SoundPlayApi,
    sound_name: u32,
    module: u16,
    flags: u32,
    memory: &Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    let (source, native_flags) = if sound_name == 0 {
        (Win16SoundSource::Stop, flags)
    } else if api == Win16SoundPlayApi::PlaySound && flags & SND_RESOURCE != 0 {
        let Some(bytes) = state.resource_wave(sound_name, module, memory, host)? else {
            return Ok(0);
        };
        (Win16SoundSource::MemoryWave(bytes), (flags & !SND_RESOURCE) | SND_MEMORY)
    } else if flags & SND_MEMORY != 0 {
        let Some(bytes) = state.memory_wave(sound_name, memory)? else { return Ok(0); };
        (Win16SoundSource::MemoryWave(bytes), flags)
    } else {
        let name = read_ansi_z(&state.selectors, memory, sound_name,
            win16_abi::MAX_WIN16_STRING_BYTES).map_err(crate::runtime_error)?;
        (Win16SoundSource::FileOrAlias(name), flags)
    };

    let is_stop = matches!(&source, Win16SoundSource::Stop);
    let is_async = flags & SND_ASYNC != 0;
    if !is_stop {
        // Reserve before the native call so any returned lease can be retained
        // until the owner confirms its retirement, even if flags were rejected.
        state.sound.play_wave_leases.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 PlaySound lease tracking", error))?;
    }
    let reply = host.win16_sound(Op::PlayWave { source, flags: native_flags });
    if is_async
        && !is_stop
        && !matches!(&reply, Err(error) if error.kind() == Kind::CompatibilityGap)
    {
        // Async PlaySound retains a process-owned source without opening a
        // WAVE device; include it in the same pre-USER barrier.
        state.require_wave_owner_barrier();
    }
    match reply {
        Ok(HostResult::PlayWave { result, lease, retired_lease }) => {
            if result {
                if !is_stop && is_async && lease.is_none() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "successful asynchronous PlaySound returned no playback lease"));
                }
                if !is_async && lease.is_some() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "synchronous PlaySound returned a live playback lease"));
                }
                update_leases(state, lease, retired_lease, is_stop)?;
            } else if lease.is_some() || retired_lease.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "failed native PlaySound call changed its owned lease"));
            }
            Ok(u32::from(result))
        }
        Ok(_) => Err(RuntimeError::new(Kind::InternalInvariant,
            "PlaySound returned the wrong host result")),
        Err(error) if error.kind() == Kind::CompatibilityGap => {
            host.report_diagnostic(&crate::Diagnostic::warning(Kind::CompatibilityGap,
                "shared WAVE owner does not provide PlaySound lease operations yet"));
            Ok(0)
        }
        Err(error) => Err(error),
    }
}

impl Win16State {
    fn memory_wave(&self, raw_far: u32, memory: &Memory) -> Result<Option<Vec<u8>>, RuntimeError> {
        let pointer = self.selectors.pointer_from_raw(Selector((raw_far >> 16) as u16), raw_far as u16)
            .map_err(crate::runtime_error)?;
        let header = self.read_text_bytes(memory, pointer, 12)?;
        if &header[..4] != b"RIFF" || &header[8..12] != b"WAVE" { return Ok(None); }
        let riff_bytes = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let Some(total) = riff_bytes.checked_add(8).and_then(|size| usize::try_from(size).ok())
            .filter(|size| (12..=MAX_WAVE_BYTES).contains(size)) else {
            return Ok(None);
        };
        self.read_text_bytes(memory, pointer, total).map(Some)
    }

    fn resource_wave(
        &mut self,
        raw_far: u32,
        module: u16,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let name = if raw_far >> 16 == 0 {
            Win16ResourceName::Id(raw_far as u16)
        } else {
            Win16ResourceName::Name(read_ansi_z(&self.selectors, memory, raw_far,
                win16_abi::MAX_WIN16_STRING_BYTES).map_err(crate::runtime_error)?)
        };
        let info = self.find_resource(module, &name,
            &Win16ResourceName::Name(b"WAVE".to_vec()), host)?;
        if info == 0 { return Ok(None); }
        let Some(metadata) = self.resource_metadata(module, info) else { return Ok(None); };
        if metadata.length > MAX_WAVE_BYTES { return Ok(None); }
        let Some(record) = self.modules.records.get(&metadata.key.module) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND WAVE resource module disappeared after checked lookup"));
        };
        let Some(end) = metadata.offset.checked_add(metadata.length) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND WAVE resource extent overflowed its module"));
        };
        let Some(bytes) = record.image.get(metadata.offset..end) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "checked SOUND WAVE resource exceeds its owned NE image"));
        };
        if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return Ok(None);
        }
        let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
            .checked_add(8).and_then(|size| usize::try_from(size).ok());
        let Some(total) = declared.filter(|size| (12..=bytes.len()).contains(size)) else {
            return Ok(None);
        };
        let mut owned = Vec::new();
        owned.try_reserve_exact(total).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "copy SOUND WAVE resource to owned storage", error))?;
        owned.extend_from_slice(&bytes[..total]);
        Ok(Some(owned))
    }
}

fn update_leases(
    state: &mut Win16State,
    next: Option<Win16SoundLease>,
    retired: Option<Win16SoundLease>,
    stop_requested: bool,
) -> Result<(), RuntimeError> {
    if next.is_some() && next == retired {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native PlaySound returned the same token as both current and retired"));
    }
    if stop_requested && next.is_some() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "successful null PlaySound request returned a live lease"));
    }
    if let Some(retired) = retired {
        state.sound.play_wave_leases.retain(|known| *known != retired);
    }
    if let Some(next) = next {
        if !state.sound.play_wave_leases.contains(&next) {
            // Lease capacity was reserved before the native call.
            state.sound.play_wave_leases.push(next);
        }
    }
    Ok(())
}
