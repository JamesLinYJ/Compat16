//! Raw x87 register, tag, pointer, and exception state.

/// The 80-bit x87 register payload, kept as its architectural raw fields.
///
/// `sign_exponent` stores sign in bit 15 and the biased exponent in bits
/// 14:0. `significand` contains the explicit integer bit in bit 63.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Ext80 {
    pub significand: u64,
    pub sign_exponent: u16,
}

impl Ext80 {
    pub(crate) fn from_le_bytes(bytes: [u8; 10]) -> Self {
        Self {
            significand: u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            sign_exponent: u16::from_le_bytes([bytes[8], bytes[9]]),
        }
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 10] {
        let mut bytes = [0; 10];
        bytes[..8].copy_from_slice(&self.significand.to_le_bytes());
        bytes[8..].copy_from_slice(&self.sign_exponent.to_le_bytes());
        bytes
    }

    pub(crate) fn tag(self) -> X87Tag {
        let exponent = self.sign_exponent & 0x7fff;
        if exponent == 0 && self.significand == 0 {
            X87Tag::Zero
        } else if exponent == 0 || exponent == 0x7fff || self.significand & (1 << 63) == 0 {
            X87Tag::Special
        } else {
            X87Tag::Valid
        }
    }
}

/// Two-bit tag values used by the physical x87 register file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum X87Tag {
    Valid = 0,
    Zero = 1,
    Special = 2,
    Empty = 3,
}

impl X87Tag {
    pub(crate) fn from_bits(bits: u16) -> Self {
        match bits & 3 {
            0 => Self::Valid,
            1 => Self::Zero,
            2 => Self::Special,
            _ => Self::Empty,
        }
    }
}

pub(crate) const X87_EXCEPTION_FLAGS: u16 = 0x003f;
pub(crate) const X87_STACK_FAULT: u16 = 1 << 6;
pub(crate) const X87_EXCEPTION_SUMMARY: u16 = 1 << 7;
pub(crate) const X87_C0: u16 = 1 << 8;
pub(crate) const X87_C1: u16 = 1 << 9;
pub(crate) const X87_C2: u16 = 1 << 10;
pub(crate) const X87_TOP_MASK: u16 = 7 << 11;
pub(crate) const X87_C3: u16 = 1 << 14;
pub(crate) const X87_BUSY: u16 = 1 << 15;

/// Modeled x87 environment and raw physical register stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct X87State {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u16,
    pub registers: [Ext80; 8],
    /// Last x87 instruction pointer offset, stored at its non-64-bit width.
    pub instruction_pointer: u32,
    pub instruction_segment: u16,
    /// Last x87 data pointer offset, stored at its non-64-bit width.
    pub data_pointer: u32,
    pub data_segment: u16,
    /// Last x87 opcode, limited to the architectural 11-bit value.
    pub opcode: u16,
}

impl Default for X87State {
    fn default() -> Self {
        Self {
            control_word: 0x037f,
            status_word: 0,
            tag_word: 0xffff,
            registers: [Ext80::default(); 8],
            instruction_pointer: 0,
            instruction_segment: 0,
            data_pointer: 0,
            data_segment: 0,
            opcode: 0,
        }
    }
}

impl X87State {
    pub(crate) fn reset(&mut self) {
        let registers = self.registers;
        *self = Self::default();
        // The architectural tags make these values unobservable, but the
        // processor does not clear the physical data-register payloads.
        self.registers = registers;
    }

    pub(crate) fn top(&self) -> u8 {
        ((self.status_word & X87_TOP_MASK) >> 11) as u8
    }

    pub(crate) fn set_top(&mut self, top: u8) {
        self.status_word = (self.status_word & !X87_TOP_MASK) | (u16::from(top & 7) << 11);
    }

    /// Map an ST(i) index to its physical x87 register index.
    pub(crate) fn physical_register(&self, st_index: u8) -> usize {
        usize::from(self.top().wrapping_add(st_index) & 7)
    }

    pub(crate) fn tag(&self, physical_index: usize) -> X87Tag {
        let shift = (physical_index & 7) * 2;
        X87Tag::from_bits(self.tag_word >> shift)
    }

    pub(crate) fn set_tag(&mut self, physical_index: usize, tag: X87Tag) {
        let shift = (physical_index & 7) * 2;
        self.tag_word = (self.tag_word & !(3 << shift)) | (u16::from(tag as u8) << shift);
    }

    /// Read a non-empty ST(i) register without converting or rounding it.
    pub(crate) fn read_st(&self, st_index: u8) -> Option<Ext80> {
        let physical = self.physical_register(st_index);
        (self.tag(physical) != X87Tag::Empty).then_some(self.registers[physical])
    }

    /// Write an ST(i) register and derive its tag from the raw Ext80 class.
    pub(crate) fn write_st(&mut self, st_index: u8, value: Ext80) {
        let physical = self.physical_register(st_index);
        self.registers[physical] = value;
        self.set_tag(physical, value.tag());
    }

    pub(crate) fn empty_st(&mut self, st_index: u8) {
        let physical = self.physical_register(st_index);
        self.set_tag(physical, X87Tag::Empty);
    }

    /// Record sticky exception flags and return any currently unmasked flags.
    ///
    /// `stack_fault` sets SF; `stack_overflow` updates C1 only when present,
    /// where `Some(true)` means overflow and `Some(false)` means underflow.
    pub(crate) fn record_exceptions(
        &mut self,
        flags: u16,
        stack_fault: bool,
        stack_overflow: Option<bool>,
    ) -> u16 {
        self.status_word |= flags & X87_EXCEPTION_FLAGS;
        if stack_fault {
            self.status_word |= X87_STACK_FAULT;
        }
        if let Some(overflow) = stack_overflow {
            if overflow {
                self.status_word |= X87_C1;
            } else {
                self.status_word &= !X87_C1;
            }
        }
        self.refresh_exception_summary();
        self.pending_unmasked_exceptions()
    }

    /// Load the x87 control word and refresh ES/B for sticky flags that become
    /// newly masked or unmasked. Environment restore copies its saved words
    /// verbatim and intentionally does not use this instruction-side setter.
    pub(crate) fn set_control_word(&mut self, control_word: u16) {
        self.control_word = control_word;
        self.refresh_exception_summary();
    }

    fn refresh_exception_summary(&mut self) {
        let pending = self.pending_unmasked_exceptions();
        if pending != 0 {
            self.status_word |= X87_EXCEPTION_SUMMARY | X87_BUSY;
        } else {
            self.status_word &= !(X87_EXCEPTION_SUMMARY | X87_BUSY);
        }
    }

    /// Return exception flag bits currently unmasked by the control word.
    pub(crate) fn pending_unmasked_exceptions(&self) -> u16 {
        (self.status_word & X87_EXCEPTION_FLAGS) & !(self.control_word & X87_EXCEPTION_FLAGS)
    }

    pub(crate) fn clear_exceptions(&mut self) {
        self.status_word &= !(X87_EXCEPTION_FLAGS | X87_STACK_FAULT | X87_EXCEPTION_SUMMARY | X87_BUSY);
    }
}
