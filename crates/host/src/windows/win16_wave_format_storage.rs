//! Owned WAVEFORMATEX storage for native WinMM WAVE open and query calls.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWaveFormatShape, Win16HostWaveFormatSpec,
};
use windows_sys::Win32::Media::Audio::{WAVE_FORMAT_PCM, WAVEFORMATEX};

pub(super) const WAVEFORMATEX_FIXED_BYTES: usize = 18;

/// `Vec<u8>` is aligned sufficiently because windows-sys declares WAVEFORMATEX
/// packed to byte alignment. The exact cbSize tail immediately follows its
/// 18-byte fixed prefix. Keep this owner alive for each borrowed native pointer.
pub(super) struct WaveFormatStorage {
    bytes: Vec<u8>,
}

impl WaveFormatStorage {
    /// Own an exact Win16 WAVE format image in a host WAVEFORMATEX buffer.
    pub(super) fn from_spec(spec: &Win16HostWaveFormatSpec) -> Result<Self, RuntimeError> {
        validate_wave_format_spec(spec)?;
        Self::encode_spec(spec)
    }

    /// The raw pointer is valid only while this storage remains borrowed for a
    /// synchronous WinMM QUERY/OPEN call; never store it in a
    /// WAVEHDR, device record, runtime DTO, or guest-visible object.
    pub(super) fn as_mut_wfx(&mut self) -> *mut WAVEFORMATEX {
        debug_assert!(self.bytes.len() >= WAVEFORMATEX_FIXED_BYTES);
        // SAFETY: WAVEFORMATEX is pack(1), this Vec is contiguous, and its
        // allocation remains owned and stable until the caller returns.
        self.bytes.as_mut_ptr().cast()
    }

    fn encode_spec(spec: &Win16HostWaveFormatSpec) -> Result<Self, RuntimeError> {
        let cb_size = match spec.shape {
            Win16HostWaveFormatShape::PcmWaveFormat => 0,
            Win16HostWaveFormatShape::WaveFormatEx { cb_size } => cb_size,
        };
        let total = WAVEFORMATEX_FIXED_BYTES
            .checked_add(spec.extension.len())
            .ok_or_else(|| storage_invariant("WAVEFORMATEX extension length overflow"))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(total).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve owned WAVEFORMATEX", error)
        })?;
        bytes.extend_from_slice(&spec.format_tag.to_le_bytes());
        bytes.extend_from_slice(&spec.channels.to_le_bytes());
        bytes.extend_from_slice(&spec.samples_per_second.to_le_bytes());
        bytes.extend_from_slice(&spec.average_bytes_per_second.to_le_bytes());
        bytes.extend_from_slice(&spec.block_align.to_le_bytes());
        bytes.extend_from_slice(&spec.bits_per_sample.to_le_bytes());
        bytes.extend_from_slice(&cb_size.to_le_bytes());
        bytes.extend_from_slice(&spec.extension);
        Ok(Self { bytes })
    }
}

pub(super) fn validate_wave_format_spec(
    spec: &Win16HostWaveFormatSpec,
) -> Result<(), RuntimeError> {
    let valid = match spec.shape {
        Win16HostWaveFormatShape::PcmWaveFormat => {
            spec.format_tag == WAVE_FORMAT_PCM as u16 && spec.extension.is_empty()
        }
        Win16HostWaveFormatShape::WaveFormatEx { cb_size } => {
            usize::from(cb_size) == spec.extension.len()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(storage_invariant(
            "Win16 WAVE source shape disagrees with its owned fields",
        ))
    }
}

fn storage_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
