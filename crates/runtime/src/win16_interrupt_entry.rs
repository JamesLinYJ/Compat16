//! Checked Win16 interrupt entry, firmware chaining and resume ownership.

use dos_kernel::{DosAction, DosKernel};
use guest_core::{GuestMemory, PhysAddr, Registers, Selector};
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, SelectorRef};
use x86_cpu::Cpu;

use super::{dos_interrupts, Win16State};
use crate::win16_loader::Win16Segments;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, runtime_error};

// This bounds runtime ownership metadata, not the guest interrupt ABI.
const MAX_ACTIVE_INTERRUPT_FRAMES: usize = 65_536;
const INTERRUPT_FRAME_BYTES: usize = 6;
const FLAGS_BYTE_OFFSET: usize = 4;

/// Exact descriptor identities retain the interrupted code until its IRET.
/// The saved SP distinguishes nested returns to the same instruction.
#[derive(Clone, Copy)]
pub(super) struct InterruptResume {
    pub(super) code: SelectorRef,
    pub(super) stack: SelectorRef,
    offset: u16,
    stack_pointer: u16,
}

impl Win16State {
    pub(super) fn begin_software_interrupt(
        &mut self,
        vector: u8,
        cpu: &mut Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let target = match dos_interrupts::resolve_interrupt_target(self, vector, memory)? {
            dos_interrupts::ProtectedInterruptTarget::Empty => {
                if matches!(vector, 0x25 | 0x26) {
                    self.reject_absolute_disk_interrupt(cpu, memory)?;
                    return Ok(());
                }
                if vector == 0x27 {
                    unsupported_protected_dos(&mut cpu.regs);
                    return Ok(());
                }
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    format!("Win16 interrupt {vector:02X}h has no configured guest handler")));
            }
            dos_interrupts::ProtectedInterruptTarget::Guest(pointer)
                | dos_interrupts::ProtectedInterruptTarget::FirmwareService { entry: pointer, .. } => pointer,
        };
        if self.interrupt_returns.len() == MAX_ACTIVE_INTERRUPT_FRAMES {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 active interrupt frame limit reached"));
        }
        let reference = |raw| self.selectors.reference(Selector(raw)).map_err(|error|
            RuntimeError::with_source(Kind::GuestFault,
                "Win16 interrupt resume selector is not allocated", error));
        let resume = InterruptResume {
            code: reference(cpu.regs.cs)?,
            stack: reference(cpu.regs.ss)?,
            offset: cpu.regs.ip(),
            stack_pointer: cpu.regs.sp(),
        };
        let context = Win16Segments { selectors: &self.selectors, memory_len: memory.len() };
        // The CPU validates the complete six-byte destination before writing
        // FLAGS, CS and IP. Only successful entry creates an ownership record.
        cpu.enter_interrupt16(target.selector().raw().0, target.offset(), memory, &context)
            .map_err(runtime_error)?;
        self.interrupt_returns.push(resume);
        Ok(())
    }

    fn reject_absolute_disk_interrupt(
        &self,
        cpu: &mut Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        // INT 25h/26h return through RETF, leaving one FLAGS word for the
        // caller to pop even on failure. NTVDM's PMIntr25/26 likewise leaves
        // this word with the returned status flags (dpmi/dxdisk.asm).
        // A service shortcut must reproduce that stack contract.
        let mut returned = cpu.regs.clone();
        unsupported_protected_dos(&mut returned);
        let stack_pointer = returned.sp().wrapping_sub(2);
        let pointer = self.selectors.pointer_from_raw(Selector(returned.ss), stack_pointer)
            .map_err(runtime_error)?;
        self.selectors.write(memory, pointer, &(returned.eflags as u16).to_le_bytes())
            .map_err(runtime_error)?;
        returned.set_sp(stack_pointer);
        cpu.regs = returned;
        Ok(())
    }

    pub(super) fn retire_interrupt_return(&mut self, regs: &Registers) -> Result<(), RuntimeError> {
        if let Some(index) = self.interrupt_returns.iter().rposition(|entry|
            entry.code.raw().0 == regs.cs && entry.offset == regs.ip()
                && entry.stack.raw().0 == regs.ss && entry.stack_pointer == regs.sp()) {
            let entry = self.interrupt_returns[index];
            let code = self.selectors.reference(Selector(regs.cs)).map_err(runtime_error)?;
            let stack = self.selectors.reference(Selector(regs.ss)).map_err(runtime_error)?;
            if code != entry.code || stack != entry.stack {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 IRET resume descriptor was freed or replaced"));
            }
            self.interrupt_returns.truncate(index);
        }
        Ok(())
    }
}

/// Run a typed service at a checked ROM selector alias. Both software INT and
/// PUSHF/CALL FAR reach this entry with an ordinary 16-bit interrupt frame.
/// The caller executes the ROM IRET after this method returns Continue.
pub(super) fn call_firmware_service(
    state: &mut Win16State,
    dos: &mut DosKernel,
    vector: u8,
    regs: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<DosAction, RuntimeError> {
    let frame = ProtectedServiceFrame::prepare(state, regs, memory)?;
    let action = match vector {
        0x20 => {
            unsupported_protected_dos(regs);
            DosAction::Continue
        }
        0x21 => dos_interrupts::dispatch_int21(state, dos, regs, memory, host)?,
        0x13 => {
            // This configuration has no BIOS block devices. Its shared disk
            // service returns absence/status without accessing ES:BX, so it
            // is also valid at a protected-selector firmware entry. DOS
            // directory drives continue through their separate file APIs.
            devices::disk_bios::dispatch(regs, memory).map_err(runtime_error)?;
            DosAction::Continue
        }
        0x2a => match crate::network::int2a(regs) {
            DosAction::Unhandled => return Ok(DosAction::Continue),
            action => action,
        },
        0x2f => {
            // AX=4310 returns a real-mode XMS entry point. It cannot be
            // exposed as a protected selector without a real-mode call bridge.
            if regs.ax() == 0x4310 {
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "Win16 XMS entry query requires a real-mode call bridge"));
            }
            match crate::multiplex::dispatch(regs) {
                crate::multiplex::MultiplexOutcome::Handled => DosAction::Continue,
                crate::multiplex::MultiplexOutcome::Unclaimed => return Ok(DosAction::Continue),
                crate::multiplex::MultiplexOutcome::MissingDosService => return Err(RuntimeError::new(
                    Kind::CompatibilityGap, "DOS internal multiplex service is not implemented")),
            }
        }
        _ => return Err(RuntimeError::new(Kind::CompatibilityGap,
            format!("Win16 interrupt {vector:02X}h requires a protected-mode service bridge"))),
    };
    if !matches!(action, DosAction::Exit(_)) { frame.store_status(regs, memory)?; }
    Ok(action)
}

fn unsupported_protected_dos(regs: &mut Registers) {
    // SDK 3.1 Vol.1 section 20.2.1, printed p.402: INT 20/25/26/27 fail
    // in protected mode. The SDK supplies no exact return-register contract;
    // apply this runtime's normal unsupported-DOS policy without terminating
    // a task or touching DOS handle ownership. Registered guest hooks still
    // execute normally instead of being replaced with this fallback.
    regs.set_ax(dos_kernel::DosErrorCode::InvalidFunction as u16);
    regs.set_carry(true);
}

struct ProtectedServiceFrame {
    flag_addresses: [PhysAddr; 2],
    saved_flags: u16,
}

impl ProtectedServiceFrame {
    fn prepare(state: &Win16State, regs: &Registers, memory: &Memory) -> Result<Self, RuntimeError> {
        let stack = state.selectors.reference(Selector(regs.ss)).map_err(runtime_error)?;
        let mut addresses = [PhysAddr(0); INTERRUPT_FRAME_BYTES];
        for (index, address) in addresses.iter_mut().enumerate() {
            // Each WORD begins at a 16-bit SP offset; its high byte must not
            // wrap across the segment boundary (Intel INT/IRET #SS rule).
            let word_offset = regs.sp().wrapping_add((index & !1) as u16);
            let offset = u32::from(word_offset) + (index & 1) as u32;
            let narrow = u16::try_from(offset).map_err(|_| RuntimeError::new(
                Kind::GuestFault, "Win16 interrupt frame crosses the stack segment limit"))?;
            let pointer = SegmentedPointer::new(stack, narrow);
            *address = state.selectors.translate(pointer, Access::Read, 1, memory)
                .map_err(runtime_error)?;
            if index >= FLAGS_BYTE_OFFSET {
                state.selectors.translate(pointer, Access::Write, 1, memory)
                    .map_err(runtime_error)?;
            }
        }
        // These are scalar FLAGS bytes, resolved separately to preserve the
        // 16-bit stack addressing rules; no host-layout structure is cast.
        let flag_addresses = [addresses[FLAGS_BYTE_OFFSET], addresses[FLAGS_BYTE_OFFSET + 1]];
        let saved_flags = u16::from_le_bytes([
            memory.read_u8(flag_addresses[0]).map_err(runtime_error)?,
            memory.read_u8(flag_addresses[1]).map_err(runtime_error)?,
        ]);
        Ok(Self { flag_addresses, saved_flags })
    }

    fn store_status(self, regs: &Registers, memory: &mut Memory) -> Result<(), RuntimeError> {
        let mask = crate::interrupts::STATUS_FLAGS;
        let flags = (self.saved_flags & !mask) | ((regs.eflags as u16) & mask);
        for (address, byte) in self.flag_addresses.into_iter().zip(flags.to_le_bytes()) {
            memory.write_u8(address, byte).map_err(runtime_error)?;
        }
        Ok(())
    }
}
