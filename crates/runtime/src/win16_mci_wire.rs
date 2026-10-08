//! Fixed Win16 MCI_SET records selected by the open device family.
//!
//! The guest records use 16-bit ABI alignment and are not host MCI structs.
//! The byte-aligned wrappers keep the Win16 field offsets explicit without
//! unaligned integer reads or runtime-defined pointer widths. Layout follows
//! SDK 3.1 MMSYSTEM.H `MCI_WAVE_SET_PARMS` and `MCI_SEQ_SET_PARMS`.

use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct WaveSet {
    pub(super) callback: U32,
    pub(super) time_format: U32,
    pub(super) audio: U32,
    pub(super) input: U16,
    pub(super) input_reserved: U16,
    pub(super) output: U16,
    pub(super) output_reserved: U16,
    pub(super) format_tag: U16,
    pub(super) format_reserved: U16,
    pub(super) channels: U16,
    pub(super) channels_reserved: U16,
    pub(super) samples_per_second: U32,
    pub(super) average_bytes_per_second: U32,
    pub(super) block_align: U16,
    pub(super) block_reserved: U16,
    pub(super) bits_per_sample: U16,
    pub(super) bits_reserved: U16,
}

const _: () = {
    assert!(core::mem::size_of::<WaveSet>() == 44);
    assert!(core::mem::align_of::<WaveSet>() == 1);
    assert!(core::mem::offset_of!(WaveSet, input) == 12);
    assert!(core::mem::offset_of!(WaveSet, output) == 16);
    assert!(core::mem::offset_of!(WaveSet, format_tag) == 20);
    assert!(core::mem::offset_of!(WaveSet, channels) == 24);
    assert!(core::mem::offset_of!(WaveSet, samples_per_second) == 28);
    assert!(core::mem::offset_of!(WaveSet, average_bytes_per_second) == 32);
    assert!(core::mem::offset_of!(WaveSet, block_align) == 36);
    assert!(core::mem::offset_of!(WaveSet, bits_per_sample) == 40);
};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct SequencerSet {
    pub(super) callback: U32,
    pub(super) time_format: U32,
    pub(super) audio: U32,
    pub(super) tempo: U32,
    pub(super) port: U32,
    pub(super) slave: U32,
    pub(super) master: U32,
    pub(super) offset: U32,
}

const _: () = {
    assert!(core::mem::size_of::<SequencerSet>() == 32);
    assert!(core::mem::align_of::<SequencerSet>() == 1);
    assert!(core::mem::offset_of!(SequencerSet, tempo) == 12);
    assert!(core::mem::offset_of!(SequencerSet, offset) == 28);
};

/// SDK 3.1 overlay MCI_SAVE/MCI_LOAD layout: callback and filename FAR DWORDs
/// followed by the four signed 16-bit Win16 RECT coordinates. The modern host
/// RECT is a different layout and cannot decode this guest record directly.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct OverlayFile {
    pub(super) callback: U32,
    pub(super) filename: U32,
    pub(super) left: I16,
    pub(super) top: I16,
    pub(super) right: I16,
    pub(super) bottom: I16,
}

const _: () = {
    assert!(core::mem::size_of::<OverlayFile>() == 16);
    assert!(core::mem::align_of::<OverlayFile>() == 1);
    assert!(core::mem::offset_of!(OverlayFile, left) == 8);
    assert!(core::mem::offset_of!(OverlayFile, bottom) == 14);
};

pub(super) fn read<T: FromBytes + KnownLayout + Immutable>(
    bytes: &[u8],
) -> Result<&T, zerocopy::CastError<&[u8], T>> {
    T::ref_from_bytes(bytes)
}
