//! Fixed little-endian wire layouts for Win16 waveform format headers.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Windows 3.1 `WAVEFORMAT`: the shared prefix is 14 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub(super) struct WaveFormat14 {
    pub(super) format_tag: U16,
    pub(super) channels: U16,
    pub(super) samples_per_second: U32,
    pub(super) average_bytes_per_second: U32,
    pub(super) block_align: U16,
}

/// Windows 3.1 `PCMWAVEFORMAT`: WAVEFORMAT plus 16-bit sample width.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub(super) struct PcmWaveFormat16 {
    pub(super) base: WaveFormat14,
    pub(super) bits_per_sample: U16,
}

/// Modern WAVEFORMATEX fixed prefix, retained only for its explicit cbSize
/// contract. The bytes after this record remain opaque to the runtime.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub(super) struct WaveFormatEx18 {
    pub(super) base: PcmWaveFormat16,
    pub(super) extra_bytes: U16,
}
