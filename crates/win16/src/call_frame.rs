//! Checked decoding of 16-bit Windows export arguments from a guest stack.
//!
//! The frame begins at the guest stack pointer on callee entry, where the
//! near/far return address is at the top of the stack. Argument values are
//! returned in declaration order, regardless of their physical stack order.
//!
//! ABI basis: *Microsoft Windows 3.0 SDK Programmer's Reference, Volume 2*,
//! §13.1.2, Table 13.2 (Standard C versus Pascal push order and stack cleanup),
//! and §14, `Arg` / `parmB` (byte parameters occupy word slots; the high byte
//! is not normalized). Microsoft specifies Pascal as the default convention
//! required for functions called by Windows. The original Microsoft manual is
//! transcribed at <https://www.pcjs.org/documents/books/mspl13/win/w3sdkr2/>.

use crate::{Access, SegmentedPointer, SelectorTable, Win16Error};
use guest_core::{GuestMemory, Registers};

/// Architectural register state presented to a Win16 register-context export.
///
/// This is a value snapshot of the guest CPU context at export entry. It keeps
/// the full 32-bit general registers and flags along with all segment selectors;
/// register-context exports are not normalized into stack arguments or reduced
/// to only the registers currently known to one service.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Win16RegisterContext {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub eflags: u32,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub ss: u16,
    pub fs: u16,
    pub gs: u16,
}

impl From<&Registers> for Win16RegisterContext {
    fn from(registers: &Registers) -> Self {
        Self {
            eax: registers.eax,
            ebx: registers.ebx,
            ecx: registers.ecx,
            edx: registers.edx,
            esi: registers.esi,
            edi: registers.edi,
            ebp: registers.ebp,
            esp: registers.esp,
            eip: registers.eip,
            eflags: registers.eflags,
            cs: registers.cs,
            ds: registers.ds,
            es: registers.es,
            ss: registers.ss,
            fs: registers.fs,
            gs: registers.gs,
        }
    }
}

impl Win16RegisterContext {
    /// Replace the active architectural state with this context snapshot.
    pub fn apply_to(self, registers: &mut Registers) {
        registers.eax = self.eax;
        registers.ebx = self.ebx;
        registers.ecx = self.ecx;
        registers.edx = self.edx;
        registers.esi = self.esi;
        registers.edi = self.edi;
        registers.ebp = self.ebp;
        registers.esp = self.esp;
        registers.eip = self.eip;
        registers.eflags = self.eflags;
        registers.cs = self.cs;
        registers.ds = self.ds;
        registers.es = self.es;
        registers.ss = self.ss;
        registers.fs = self.fs;
        registers.gs = self.gs;
    }
}

/// Stack order and ownership of argument cleanup for a Win16 function call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16CallingConvention {
    /// Arguments are pushed left-to-right; the callee removes them on return.
    Pascal,
    /// Arguments are pushed right-to-left; the caller removes them after return.
    Cdecl,
}

/// Encoded scalar type of a Win16 stack argument.
///
/// Byte parameters occupy a two-byte stack slot. Their value is the low byte;
/// the high byte is ignored because Win16 callers do not have to clear it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ArgumentKind {
    Byte,
    Word,
    Dword,
}

impl ArgumentKind {
    const fn slot_bytes(self) -> usize {
        match self {
            Self::Byte | Self::Word => 2,
            Self::Dword => 4,
        }
    }
}

/// A decoded scalar, retaining the declared width and raw guest bits.
///
/// A dword may encode a Win16 far pointer. It remains a guest value here; use
/// `SelectorTable::pointer_from_far` when the service contract requires pointer
/// validation. Signedness and pointer meaning belong to the export signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16Argument {
    Byte(u8),
    Word(u16),
    Dword(u32),
}

/// Width of the return address present at the top of the entry stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReturnAddressWidth {
    Near,
    Far,
}

impl ReturnAddressWidth {
    const fn bytes(self) -> u32 {
        match self {
            Self::Near => 2,
            Self::Far => 4,
        }
    }
}

/// Number of argument bytes removed by each side of a Win16 call.
///
/// The near/far return address is not included: the CPU's `RET`/`RETF` logic
/// removes it independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct StackCleanup {
    pub callee_pop_bytes: u16,
    pub caller_pop_bytes: u16,
}

/// Guest call entry state and checked argument decoder for one Win16 stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win16CallFrame {
    entry_stack: SegmentedPointer,
    return_address: ReturnAddressWidth,
}

impl Win16CallFrame {
    /// `entry_stack` points to the first byte of the return address on entry.
    pub const fn new(entry_stack: SegmentedPointer, return_address: ReturnAddressWidth) -> Self {
        Self { entry_stack, return_address }
    }

    pub const fn entry_stack(self) -> SegmentedPointer { self.entry_stack }

    pub const fn return_address_width(self) -> ReturnAddressWidth { self.return_address }

    /// Reads the declared arguments and returns them in source/declaration order.
    ///
    /// This method reads only guest memory through `SelectorTable`; it never
    /// forms or exposes a host pointer. It validates the return-address range
    /// and every complete argument slot, including the unused high byte of a
    /// byte argument. Stack offsets do not wrap or silently advance SS to an
    /// adjacent selector.
    pub fn decode_arguments(
        self,
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        convention: Win16CallingConvention,
        signature: &[ArgumentKind],
    ) -> Result<Vec<Win16Argument>, Win16Error> {
        self.decode_arguments_iter(selectors, memory, convention, signature.iter().copied())
    }

    /// Decodes a declaration-order signature without materializing its kinds.
    ///
    /// The iterator and its clones must yield the same signature. As with
    /// `decode_arguments`, the complete frame's 16-bit stack range is checked
    /// before memory access, then slots are read in physical stack order.
    pub(crate) fn decode_arguments_iter<I>(
        self,
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        convention: Win16CallingConvention,
        signature: I,
    ) -> Result<Vec<Win16Argument>, Win16Error>
    where
        I: Iterator<Item = ArgumentKind> + Clone + ExactSizeIterator + DoubleEndedIterator,
    {
        let argument_bytes = argument_bytes(signature.clone())?;
        let frame_bytes = self.return_address.bytes()
            .checked_add(argument_bytes)
            .ok_or(Win16Error::InvalidRange)?;
        self.check_stack_range(frame_bytes)?;

        selectors.translate(
            self.entry_stack,
            Access::Read,
            self.return_address.bytes() as usize,
            memory,
        )?;

        let mut decoded = vec![None; signature.len()];
        let mut stack_offset = self.return_address.bytes();
        match convention {
            Win16CallingConvention::Pascal => {
                for (index, kind) in signature.enumerate().rev() {
                    decoded[index] = Some(self.read_argument(
                        selectors, memory, kind, stack_offset,
                    )?);
                    stack_offset = stack_offset
                        .checked_add(kind.slot_bytes() as u32)
                        .ok_or(Win16Error::InvalidRange)?;
                }
            }
            Win16CallingConvention::Cdecl => {
                for (index, kind) in signature.enumerate() {
                    decoded[index] = Some(self.read_argument(selectors, memory, kind, stack_offset)?);
                    stack_offset = stack_offset
                        .checked_add(kind.slot_bytes() as u32)
                        .ok_or(Win16Error::InvalidRange)?;
                }
            }
        }

        decoded.into_iter().collect::<Option<Vec<_>>>().ok_or(Win16Error::InvalidRange)
    }

    /// Computes which side removes the argument slots after this call returns.
    pub fn cleanup(
        self,
        convention: Win16CallingConvention,
        signature: &[ArgumentKind],
    ) -> Result<StackCleanup, Win16Error> {
        let argument_bytes = argument_bytes(signature.iter().copied())?;
        self.cleanup_argument_bytes(convention, argument_bytes)
    }

    /// Computes stack ownership for a dynamically sized argument area.
    ///
    /// This is used by variadic Win16 calls whose count is decoded from the
    /// fixed part of the frame before the complete parameter list is known.
    /// `argument_bytes` excludes the near/far return address.
    pub fn cleanup_argument_bytes(
        self,
        convention: Win16CallingConvention,
        argument_bytes: u32,
    ) -> Result<StackCleanup, Win16Error> {
        let frame_bytes = self.return_address.bytes()
            .checked_add(argument_bytes)
            .ok_or(Win16Error::InvalidRange)?;
        self.check_stack_range(frame_bytes)?;
        let bytes = u16::try_from(argument_bytes).map_err(|_| Win16Error::InvalidRange)?;
        Ok(match convention {
            Win16CallingConvention::Pascal => StackCleanup { callee_pop_bytes: bytes, caller_pop_bytes: 0 },
            Win16CallingConvention::Cdecl => StackCleanup { callee_pop_bytes: 0, caller_pop_bytes: bytes },
        })
    }

    fn read_argument(
        self,
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        kind: ArgumentKind,
        stack_offset: u32,
    ) -> Result<Win16Argument, Win16Error> {
        let offset = u32::from(self.entry_stack.offset())
            .checked_add(stack_offset)
            .ok_or(Win16Error::InvalidRange)?;
        let argument_end = stack_offset
            .checked_add(kind.slot_bytes() as u32)
            .ok_or(Win16Error::InvalidRange)?;
        let offset = u16::try_from(offset).map_err(|_| Win16Error::StackOffsetWrap {
            offset: self.entry_stack.offset(),
            length: argument_end,
        })?;
        let pointer = SegmentedPointer::new(self.entry_stack.selector(), offset);
        let mut bytes = [0_u8; 4];
        selectors.read(memory, pointer, &mut bytes[..kind.slot_bytes()])?;

        Ok(match kind {
            ArgumentKind::Byte => Win16Argument::Byte(bytes[0]),
            ArgumentKind::Word => Win16Argument::Word(u16::from_le_bytes([bytes[0], bytes[1]])),
            ArgumentKind::Dword => Win16Argument::Dword(u32::from_le_bytes(bytes)),
        })
    }

    fn check_stack_range(self, length: u32) -> Result<(), Win16Error> {
        let end = u32::from(self.entry_stack.offset())
            .checked_add(length)
            .ok_or(Win16Error::InvalidRange)?;
        if end > 0x1_0000 {
            return Err(Win16Error::StackOffsetWrap {
                offset: self.entry_stack.offset(),
                length,
            });
        }
        Ok(())
    }
}

fn argument_bytes(mut signature: impl Iterator<Item = ArgumentKind>) -> Result<u32, Win16Error> {
    signature.try_fold(0_u32, |bytes, kind| {
        bytes.checked_add(kind.slot_bytes() as u32).ok_or(Win16Error::InvalidRange)
    })
}

#[cfg(test)]
#[path = "call_frame_tests.rs"]
mod tests;
