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
    // Keep derived JIT IR out of the byte-fetch entries: interpreter hits
    // should neither copy JIT metadata nor enlarge their hot cache lines.
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    integer_ir: [Option<Option<compat16_jit::Instruction>>; CACHE_SLOTS],
    // Test fixtures can retain this CPU/cache while suppressing both lookup
    // and insertion. Normal construction always enables reuse.
    #[cfg(test)]
    pub(crate) bypass: bool,
}

impl Default for DecodeCache {
    fn default() -> Self {
        Self {
            entries: [None; CACHE_SLOTS],
            #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
            integer_ir: [None; CACHE_SLOTS],
            #[cfg(test)]
            bypass: false,
        }
    }
}

impl DecodeCache {
    // Consulted only immediately after successful checked decode. Replacing
    // an entry clears its derived IR, so rewritten bytes, remapping and code
    // width changes retain the decoder's existing invalidation contract.
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn integer_ir(&self, cs: u16, ip: u32) -> Option<Option<compat16_jit::Instruction>> {
        #[cfg(test)]
        if self.bypass { return None; }
        let slot = Self::slot(cs, ip);
        self.entries[slot]
            .filter(|entry| entry.cs == cs && entry.ip == ip)
            .and_then(|_| self.integer_ir[slot])
    }

    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn set_integer_ir(&mut self, cs: u16, ip: u32, ir: Option<compat16_jit::Instruction>) {
        #[cfg(test)]
        if self.bypass { return; }
        let slot = Self::slot(cs, ip);
        if let Some(entry) = self.entries[slot].as_ref()
            && entry.cs == cs && entry.ip == ip
        {
            self.integer_ir[slot] = Some(ir);
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

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
        let slot = Self::slot(cs, decoded.start_ip);
        self.entries[slot] = Some(Entry {
            cs, ip: decoded.start_ip, bits, protected_eip32, bytes, decoded,
        });
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        { self.integer_ir[slot] = None; }
    }
}
