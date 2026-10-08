use crate::{DeviceAction, DeviceError, DispatchOutcome};
use guest_core::{GuestMemory, MemoryError, PhysAddr};
use guest_core::Registers;

const BDA_BASE: u32 = 0x0400;
const BUFFER_START_OFFSET: u16 = 0x001e;
const QUEUE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeyStroke {
    pub ascii: u8,
    pub scan: u8,
}

impl KeyStroke {
    pub fn bios_word(self) -> u16 { u16::from_le_bytes([self.ascii, self.scan]) }
}

#[derive(Clone, Debug)]
pub struct BiosKeyboard {
    queue: [KeyStroke; QUEUE_LEN],
    head: usize,
    tail: usize,
    shift_flags: u8,
}

impl Default for BiosKeyboard {
    fn default() -> Self { Self::new() }
}

impl BiosKeyboard {
    pub fn new() -> Self {
        Self { queue: [KeyStroke::default(); QUEUE_LEN], head: 0, tail: 0, shift_flags: 0 }
    }

    pub fn push(&mut self, key: KeyStroke) -> bool {
        let next = (self.tail + 1) % QUEUE_LEN;
        if next == self.head { return false; }
        self.queue[self.tail] = key;
        self.tail = next;
        true
    }

    pub fn pop(&mut self) -> Option<KeyStroke> {
        if self.head == self.tail { return None; }
        let key = self.queue[self.head];
        self.head = (self.head + 1) % QUEUE_LEN;
        Some(key)
    }

    pub fn peek(&self) -> Option<KeyStroke> {
        (self.head != self.tail).then_some(self.queue[self.head])
    }

    pub fn len(&self) -> usize { (self.tail + QUEUE_LEN - self.head) % QUEUE_LEN }
    pub fn is_empty(&self) -> bool { self.head == self.tail }
    pub fn shift_flags(&self) -> u8 { self.shift_flags }
    pub fn set_shift_flags(&mut self, flags: u8) { self.shift_flags = flags; }

    pub(super) fn dispatch_int16(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        outcome: &mut DispatchOutcome,
    ) -> Result<(), DeviceError> {
        match regs.ah() {
            0x00 | 0x10 => {
                if let Some(key) = self.pop() {
                    regs.set_al(key.ascii);
                    regs.set_ah(key.scan);
                } else {
                    outcome.actions.push(DeviceAction::AwaitKeyboard);
                }
            }
            0x01 | 0x11 => {
                if let Some(key) = self.peek() {
                    regs.set_al(key.ascii);
                    regs.set_ah(key.scan);
                    regs.eflags &= !(1 << 6);
                } else {
                    regs.eflags |= 1 << 6;
                }
            }
            0x02 => regs.set_al(self.shift_flags()),
            // IBM's Sept. 1991 PS/2 BIOS reference defines AH=09 as a feature
            // bitmap. Bit 5 advertises the AH=10/11/12 enhanced-keyboard
            // functions implemented here; keyboard-ID and typematic controls
            // (bits 4 and 3..0) are not provided.
            0x09 => regs.set_al(1 << 5),
            // IBM defines AH=0A only when keyboard-ID support is advertised
            // by AH=09 bit 4. This machine has no configured hardware ID, so
            // leave registers unchanged instead of inventing one.
            0x0a => {}
            // IBM PS/2 BIOSes return the conventional and extended shift
            // states in AL and AH. The low byte is this keyboard's tracked
            // BIOS shift state. AH maps BDA 40:18 and 40:96 bits into the
            // documented extended-state layout; reserved flags are omitted.
            0x12 => {
                let flags_2 = memory.read_u8(PhysAddr(BDA_BASE + 0x18))?;
                let flags_3 = memory.read_u8(PhysAddr(BDA_BASE + 0x96))?;
                let extended = (flags_2 & 0x73)
                    | ((flags_2 & 0x04) << 5)
                    | (flags_3 & 0x0c);
                regs.set_ax(u16::from(self.shift_flags()) | (u16::from(extended) << 8));
            }
            0x05 => {
                let key = KeyStroke {
                    ascii: crate::bios::low_byte(regs.ecx),
                    scan: crate::bios::high_byte(regs.ecx),
                };
                regs.set_al(if self.push(key) { 0 } else { 1 });
            }
            // Keyboard extensions also use this vector for installation
            // probes. An unclaimed function preserves the frame, as the
            // empty BIOS/TSR chain does; it does not advertise an extension.
            _ => return Ok(()),
        }
        self.sync_bda(memory)?;
        Ok(())
    }

    /// Mirror the ring indices and contents into the BIOS data area layout.
    /// The BIOS ring reserves one slot to distinguish empty from full.
    pub fn sync_bda(&self, memory: &mut impl GuestMemory) -> Result<(), MemoryError> {
        let mut bytes = [0u8; 0x26]; // 041Ah..043Fh inclusive.
        let head_offset = BUFFER_START_OFFSET + (self.head * 2) as u16;
        let tail_offset = BUFFER_START_OFFSET + (self.tail * 2) as u16;
        bytes[0..2].copy_from_slice(&head_offset.to_le_bytes());
        bytes[2..4].copy_from_slice(&tail_offset.to_le_bytes());
        for (index, key) in self.queue.iter().enumerate() {
            let offset = 4 + index * 2;
            bytes[offset..offset + 2].copy_from_slice(&key.bios_word().to_le_bytes());
        }
        memory.validate_write(PhysAddr(BDA_BASE + 0x17), 1)?;
        memory.validate_write(PhysAddr(BDA_BASE + 0x1a), bytes.len())?;
        memory.write_u8(PhysAddr(BDA_BASE + 0x17), self.shift_flags)?;
        memory.write(PhysAddr(BDA_BASE + 0x1a), &bytes)
    }
}

#[cfg(test)]
#[path = "keyboard_tests.rs"]
mod tests;
