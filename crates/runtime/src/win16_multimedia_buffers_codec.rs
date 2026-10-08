//! Checked decoding of Win16 WAVE format headers and sample ranges.

use std::error::Error;
use std::fmt;

use guest_core::{memory::Memory, GuestMemory};
use win16_abi::{Access, SegmentedPointer};
use zerocopy::FromBytes;

#[path = "win16_wave_format_wire.rs"]
mod wire;

use self::wire::{PcmWaveFormat16, WaveFormat14, WaveFormatEx18};
use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWaveFormatShape, Win16HostWaveFormatSpec,
};

const WAVEFORMAT_BYTES: usize = 14;
const PCMWAVEFORMAT_BYTES: usize = 16;
const WAVEFORMATEX_BYTES: usize = 18;
const PCM_FORMAT_TAG: u16 = 1;

pub(super) enum WaveFormatRead {
    Null,
    Format(Win16HostWaveFormatSpec),
}

pub(super) fn read_wave_format(
    state: &Win16State,
    memory: &Memory,
    format_far: u32,
) -> Result<WaveFormatRead, RuntimeError> {
    if format_far == 0 {
        return Ok(WaveFormatRead::Null);
    }
    let pointer = state
        .selectors
        .pointer_from_far(format_far)
        .map_err(crate::runtime_error)?;
    let common_bytes = read_single_far_bytes(state, memory, pointer, WAVEFORMAT_BYTES)?;
    let common = WaveFormat14::read_from_bytes(&common_bytes).map_err(|_| {
        wire_size_mismatch("Win16 WAVEFORMAT", WAVEFORMAT_BYTES, common_bytes.len())
    })?;
    let tag = common.format_tag.get();
    if tag == PCM_FORMAT_TAG {
        // SDK 3.1 defines PCM as PCMWAVEFORMAT (16 bytes). Modern WAVEFORMATEX
        // documentation says PCM cbSize is implicitly zero and should be
        // ignored, so bytes after PCMWAVEFORMAT are not guessed as an extension.
        let bytes = read_single_far_bytes(state, memory, pointer, PCMWAVEFORMAT_BYTES)?;
        let pcm = PcmWaveFormat16::read_from_bytes(&bytes).map_err(|_| {
            wire_size_mismatch("Win16 PCMWAVEFORMAT", PCMWAVEFORMAT_BYTES, bytes.len())
        })?;
        return Ok(WaveFormatRead::Format(Win16HostWaveFormatSpec {
            format_tag: tag,
            channels: pcm.base.channels.get(),
            samples_per_second: pcm.base.samples_per_second.get(),
            average_bytes_per_second: pcm.base.average_bytes_per_second.get(),
            block_align: pcm.base.block_align.get(),
            bits_per_sample: pcm.bits_per_sample.get(),
            extension: Vec::new(),
            shape: Win16HostWaveFormatShape::PcmWaveFormat,
        }));
    }

    // Win16 SDK 3.1 exposes only the 14-byte WAVEFORMAT and PCM's 16-byte
    // PCMWAVEFORMAT. The generic ACM bridge therefore accepts non-PCM input
    // only when it carries the later WAVEFORMATEX cbSize contract; guessing a
    // codec's private tail length from bytes after WAVEFORMAT is unsafe.
    let fixed_bytes = read_single_far_bytes(state, memory, pointer, WAVEFORMATEX_BYTES)?;
    let extended = WaveFormatEx18::read_from_bytes(&fixed_bytes).map_err(|_| {
        wire_size_mismatch("Win16 WAVEFORMATEX", WAVEFORMATEX_BYTES, fixed_bytes.len())
    })?;
    let cb_size = extended.extra_bytes.get();
    let total = WAVEFORMATEX_BYTES
        .checked_add(usize::from(cb_size))
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "Win16 WAVEFORMATEX size overflow"))?;
    let bytes = read_single_far_bytes(state, memory, pointer, total)?;
    let extension = copy_owned_bytes(&bytes[WAVEFORMATEX_BYTES..])?;
    Ok(WaveFormatRead::Format(Win16HostWaveFormatSpec {
        format_tag: tag,
        channels: extended.base.base.channels.get(),
        samples_per_second: extended.base.base.samples_per_second.get(),
        average_bytes_per_second: extended.base.base.average_bytes_per_second.get(),
        block_align: extended.base.base.block_align.get(),
        bits_per_sample: extended.base.bits_per_sample.get(),
        extension,
        shape: Win16HostWaveFormatShape::WaveFormatEx { cb_size },
    }))
}

pub(super) fn read_wave_data(
    state: &Win16State,
    memory: &Memory,
    data_far: u32,
    length: u32,
) -> Result<Vec<u8>, RuntimeError> {
    if data_far == 0 && length != 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 WAVE data pointer is null for a nonempty buffer",
        ));
    }
    let Some(pointer) = state.guest_pointer(data_far)? else {
        return Ok(Vec::new());
    };
    state.read_text_bytes(memory, pointer, length as usize)
}

fn read_single_far_bytes(
    state: &Win16State,
    memory: &Memory,
    pointer: SegmentedPointer,
    length: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let address = state
        .selectors
        .translate(pointer, Access::Read, length, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve checked Win16 WAVE format bytes",
            error,
        )
    })?;
    bytes.resize(length, 0);
    memory
        .read(address, &mut bytes)
        .map_err(crate::runtime_error)?;
    Ok(bytes)
}

fn copy_owned_bytes(source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(source.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve owned Win16 WAVE format extension",
            error,
        )
    })?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}

fn wire_size_mismatch(record: &'static str, expected: usize, actual: usize) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        format!("decode {record} wire record"),
        WaveFormatSizeMismatch {
            record,
            expected,
            actual,
        },
    )
}

#[derive(Debug)]
struct WaveFormatSizeMismatch {
    record: &'static str,
    expected: usize,
    actual: usize,
}

impl fmt::Display for WaveFormatSizeMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} needs {} bytes, received {}",
            self.record, self.expected, self.actual
        )
    }
}

impl Error for WaveFormatSizeMismatch {}

const _: () = assert!(core::mem::size_of::<WaveFormat14>() == WAVEFORMAT_BYTES);
const _: () = assert!(core::mem::size_of::<PcmWaveFormat16>() == PCMWAVEFORMAT_BYTES);
const _: () = assert!(core::mem::size_of::<WaveFormatEx18>() == WAVEFORMATEX_BYTES);
