//! Bounded decode reuse; instruction fetches still validate every current byte.

use super::{DecodedInstruction, MAX_INSTRUCTION_LENGTH};

const CACHE_SLOTS: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct Entry {
    cs: u16,
    ip: u32,
    bits: u32,
    protected_eip32: bool,
    pub(super) bytes: [u8; MAX_INSTRUCTION_LENGTH],
    pub(super) decoded: DecodedInstruction,
}

/// A small direct-mapped table avoids heap allocation and unbounded growth.
/// This is decoder-specific rather than a general cache: hits require the
/// existing checked, byte-ordered fetch path, including self-modifying code,
/// page/segment faults, remapping, and provider read side effects.
pub(crate) struct DecodeCache {
    entries: [Option<Entry>; CACHE_SLOTS],
}

impl Default for DecodeCache {
    fn default() -> Self {
        Self { entries: [None; CACHE_SLOTS] }
    }
}

impl DecodeCache {
    fn slot(cs: u16, ip: u32) -> usize {
        (ip ^ ip.rotate_right(6) ^ u32::from(cs).rotate_left(3)) as usize
            & (CACHE_SLOTS - 1)
    }

    pub(super) fn lookup(
        &self,
        cs: u16,
        ip: u32,
        bits: u32,
        protected_eip32: bool,
    ) -> Option<Entry> {
        self.entries[Self::slot(cs, ip)].filter(|entry| {
            entry.cs == cs && entry.ip == ip && entry.bits == bits
                && entry.protected_eip32 == protected_eip32
        })
    }

    pub(super) fn insert(
        &mut self,
        cs: u16,
        bits: u32,
        protected_eip32: bool,
        bytes: [u8; MAX_INSTRUCTION_LENGTH],
        decoded: DecodedInstruction,
    ) {
        self.entries[Self::slot(cs, decoded.start_ip)] = Some(Entry {
            cs, ip: decoded.start_ip, bits, protected_eip32, bytes, decoded,
        });
    }
}
