//! Reusable root stamps and narrow transfers for runtime-owned legacy checkpoints.
//!
//! The runtime must independently validate its logical owner, activation, selector
//! generations, backing memory and every guest-supplied target field. CPU stamps
//! are not guest capabilities and never replace those checks.

use std::sync::Arc;

use crate::{
    ControlTransfer, Cpu, CpuCallResumeError, CpuContext, LegacyStackPointerTarget,
    legacy_continuation::validate_legacy_context, system::CpuSystem,
};

/// Reusable CPU-origin and execution-root identity, independent of saved words.
/// Ordinary scheduler context restoration does not revoke this stamp. Runtime
/// ownership evidence must distinguish unrelated logical executions on one CPU.
#[derive(Clone, Debug)]
pub struct LegacyCpuCheckpointStamp {
    origin: Arc<u8>,
    root: CpuSystem,
}

impl PartialEq for LegacyCpuCheckpointStamp {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.origin, &other.origin) && same_root(&self.root, &other.root)
    }
}
impl Eq for LegacyCpuCheckpointStamp {}

/// The only saved register words a narrow checkpoint may change. All upper
/// halves and all unlisted registers remain live. AX is supplied separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyCheckpointRegisters {
    pub cs: u16,
    pub ip: u16,
    pub ss: u16,
    pub sp: u16,
    pub bp: u16,
    pub si: u16,
    pub di: u16,
    pub ds: u16,
    pub stack_pointer: LegacyStackPointerTarget,
}

/// A one-use, exact-boundary transfer. This contains a snapshot for validation,
/// never for whole-context restoration.
pub struct PreparedLegacyCheckpointTransfer {
    stamp: LegacyCpuCheckpointStamp,
    generation: u64,
    sequence: u64,
    transfer_sequence: Option<u64>,
    expected: CpuContext,
    target: LegacyCheckpointRegisters,
    ax: u16,
    next_sequence: u64,
}

impl Cpu {
    pub fn legacy_checkpoint_stamp(&self) -> Result<LegacyCpuCheckpointStamp, CpuCallResumeError> {
        self.check_legacy_boundary()?;
        validate_legacy_context(&self.capture_context())?;
        Ok(LegacyCpuCheckpointStamp {
            origin: Arc::clone(&self.call_continuation_origin),
            root: self.system,
        })
    }

    /// Prepare only after the runtime validates the target and its own roots.
    /// Runtime memory writes may occur between prepare and commit, but no CPU
    /// mutation or execution may intervene. With that invariant commit cannot
    /// fail: sequence capacity and every CPU precondition are checked here.
    pub fn prepare_legacy_checkpoint_transfer(
        &self,
        stamp: &LegacyCpuCheckpointStamp,
        target: LegacyCheckpointRegisters,
        ax: u16,
    ) -> Result<PreparedLegacyCheckpointTransfer, CpuCallResumeError> {
        self.check_checkpoint_stamp(stamp)?;
        if target.stack_pointer == LegacyStackPointerTarget::OnePast16BitSegment && target.sp != 0 {
            return Err(CpuCallResumeError::InvalidLegacyTransferTarget);
        }
        let next_sequence = self
            .next_call_boundary_sequence()
            .ok_or(CpuCallResumeError::BoundarySequenceExhausted)?;
        Ok(PreparedLegacyCheckpointTransfer {
            stamp: stamp.clone(),
            generation: self.call_continuation_generation,
            sequence: self.call_boundary_sequence,
            transfer_sequence: self.control_transfer_sequence,
            expected: self.capture_context(),
            target,
            ax,
            next_sequence,
        })
    }

    /// Commit a nonlocal transfer. No return event is manufactured, and enclosing
    /// call/parked continuations are neither consumed nor generation-invalidated.
    pub fn commit_legacy_checkpoint_transfer(
        &mut self,
        prepared: PreparedLegacyCheckpointTransfer,
    ) -> Result<(), CpuCallResumeError> {
        self.commit_checkpoint(prepared, false)
    }

    /// Commit the runtime-validated initial ABI return and publish its provenance.
    pub fn commit_legacy_checkpoint_return(
        &mut self,
        prepared: PreparedLegacyCheckpointTransfer,
    ) -> Result<(), CpuCallResumeError> {
        self.commit_checkpoint(prepared, true)
    }

    fn check_checkpoint_stamp(
        &self,
        stamp: &LegacyCpuCheckpointStamp,
    ) -> Result<(), CpuCallResumeError> {
        if !Arc::ptr_eq(&self.call_continuation_origin, &stamp.origin) {
            return Err(CpuCallResumeError::WrongCpu);
        }
        self.check_legacy_boundary()?;
        validate_legacy_context(&self.capture_context())?;
        if !same_root(&stamp.root, &self.system) {
            return Err(CpuCallResumeError::ExecutionRootChanged);
        }
        Ok(())
    }

    fn commit_checkpoint(
        &mut self,
        prepared: PreparedLegacyCheckpointTransfer,
        adapter_return: bool,
    ) -> Result<(), CpuCallResumeError> {
        self.check_checkpoint_stamp(&prepared.stamp)?;
        if self.call_continuation_generation != prepared.generation
            || self.call_boundary_sequence != prepared.sequence
            || self.control_transfer_sequence != prepared.transfer_sequence
            || self.capture_context() != prepared.expected
        {
            return Err(CpuCallResumeError::PreparedStateChanged);
        }
        let target = prepared.target;
        self.regs.cs = target.cs;
        self.regs.set_ip(target.ip);
        self.regs.ss = target.ss;
        self.regs.set_sp(target.sp);
        self.regs.set_bp(target.bp);
        self.regs.set_si(target.si);
        self.regs.set_di(target.di);
        self.regs.ds = target.ds;
        self.regs.set_ax(prepared.ax);
        self.call_boundary_sequence = prepared.next_sequence;
        self.control_transfer = adapter_return.then_some(ControlTransfer::AdapterReturn);
        self.control_transfer_sequence = adapter_return.then_some(prepared.next_sequence);
        Ok(())
    }
}

fn same_root(a: &CpuSystem, b: &CpuSystem) -> bool {
    a.architectural_context_initialized == b.architectural_context_initialized
        && a.cr0 == b.cr0
        && a.cr3 == b.cr3
        && a.cpl == b.cpl
        && a.gdtr == b.gdtr
        && a.idtr == b.idtr
        && a.ldtr == b.ldtr
        && a.task == b.task
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registers;

    fn target() -> LegacyCheckpointRegisters {
        LegacyCheckpointRegisters {
            cs: 0x1234,
            ip: 0x2345,
            ss: 0x3456,
            sp: 0x4567,
            bp: 0x5678,
            si: 0x6789,
            di: 0x789a,
            ds: 0x89ab,
            stack_pointer: LegacyStackPointerTarget::RegisterValue,
        }
    }

    #[test]
    fn checkpoint_restores_only_narrow_words_and_preserves_live_effects() {
        let mut cpu = Cpu::new(Registers::default());
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        cpu.regs = Registers {
            eax: 0x1111_ffff,
            ebx: 0x2222_ffff,
            ecx: 0x3333_ffff,
            edx: 0x4444_ffff,
            esp: 0x5555_ffff,
            ebp: 0x6666_ffff,
            esi: 0x7777_ffff,
            edi: 0x8888_ffff,
            eip: 0x9999_ffff,
            eflags: 0x402,
            cs: 1,
            ss: 2,
            ds: 3,
            es: 4,
            fs: 5,
            gs: 6,
        };
        cpu.pending_x87_irq13 = true;
        cpu.pending_non_maskable_interrupt = true;
        cpu.non_maskable_interrupt_blocked = true;
        cpu.system.cr2 = 0xdead_beef;
        cpu.x87.control_word = 0x027f;
        let mut expected = cpu.capture_context();
        let t = target();
        expected.registers.cs = t.cs;
        expected.registers.set_ip(t.ip);
        expected.registers.ss = t.ss;
        expected.registers.set_sp(t.sp);
        expected.registers.set_bp(t.bp);
        expected.registers.set_si(t.si);
        expected.registers.set_di(t.di);
        expected.registers.ds = t.ds;
        expected.registers.set_ax(0x8001);
        let generation = cpu.call_continuation_generation;
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, t, 0x8001)
            .unwrap();
        cpu.commit_legacy_checkpoint_transfer(prepared).unwrap();
        assert!(cpu.capture_context() == expected);
        assert_eq!(cpu.call_continuation_generation, generation);
        assert_eq!(cpu.control_transfer(), None);
        assert_eq!(cpu.legacy_checkpoint_stamp().unwrap(), stamp);
    }

    #[test]
    fn checkpoint_stamp_survives_owned_context_restores_and_repeated_transfers() {
        let mut cpu = Cpu::new(Registers::default());
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        let context = cpu.capture_context();
        for ax in [0, 1, 0xffff] {
            cpu.restore_context(&context).unwrap();
            assert_eq!(cpu.legacy_checkpoint_stamp().unwrap(), stamp);
            let prepared = cpu
                .prepare_legacy_checkpoint_transfer(&stamp, target(), ax)
                .unwrap();
            cpu.commit_legacy_checkpoint_transfer(prepared).unwrap();
            assert_eq!(cpu.regs.ax(), ax);
        }
    }

    #[test]
    fn checkpoint_prepared_transfer_rejects_changes_atomically() {
        let mut cpu = Cpu::new(Registers::default());
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, target(), 3)
            .unwrap();
        let context = cpu.capture_context();
        cpu.restore_context(&context).unwrap();
        let before = cpu.capture_context();
        assert_eq!(
            cpu.commit_legacy_checkpoint_transfer(prepared),
            Err(CpuCallResumeError::PreparedStateChanged)
        );
        assert!(cpu.capture_context() == before);
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, target(), 3)
            .unwrap();
        cpu.regs.es = 42;
        let before = cpu.capture_context();
        assert_eq!(
            cpu.commit_legacy_checkpoint_transfer(prepared),
            Err(CpuCallResumeError::PreparedStateChanged)
        );
        assert!(cpu.capture_context() == before);
    }

    #[test]
    fn checkpoint_rejects_wrong_origin_roots_and_initialized_mode() {
        let mut cpu = Cpu::new(Registers::default());
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        let other = Cpu::new(Registers::default());
        assert!(matches!(
            other.prepare_legacy_checkpoint_transfer(&stamp, target(), 0),
            Err(CpuCallResumeError::WrongCpu)
        ));
        cpu.system.cr3 = 0x1000;
        assert!(matches!(
            cpu.prepare_legacy_checkpoint_transfer(&stamp, target(), 0),
            Err(CpuCallResumeError::ExecutionRootChanged)
        ));
        cpu.system.cr3 = 0;
        cpu.reset_real_mode_segments_from_visible_registers()
            .unwrap();
        assert!(matches!(
            cpu.prepare_legacy_checkpoint_transfer(&stamp, target(), 0),
            Err(CpuCallResumeError::LegacyContextAlreadyInitialized)
        ));
    }

    #[test]
    fn checkpoint_initial_return_provenance_and_stack_endpoint_are_checked() {
        let mut cpu = Cpu::new(Registers::default());
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        let mut t = target();
        t.stack_pointer = LegacyStackPointerTarget::OnePast16BitSegment;
        assert!(matches!(
            cpu.prepare_legacy_checkpoint_transfer(&stamp, t, 0),
            Err(CpuCallResumeError::InvalidLegacyTransferTarget)
        ));
        t.sp = 0;
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, t, 0)
            .unwrap();
        cpu.commit_legacy_checkpoint_return(prepared).unwrap();
        assert_eq!(cpu.control_transfer(), Some(ControlTransfer::AdapterReturn));
        assert_eq!(
            cpu.control_transfer_sequence,
            Some(cpu.call_boundary_sequence)
        );
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, t, 0xffff)
            .unwrap();
        cpu.commit_legacy_checkpoint_transfer(prepared).unwrap();
        assert_eq!(cpu.control_transfer(), None);
        assert_eq!(cpu.control_transfer_sequence, None);
    }

    #[test]
    fn checkpoint_sequence_exhaustion_is_atomic() {
        let mut cpu = Cpu::new(Registers::default());
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        cpu.call_boundary_sequence = u64::MAX;
        let before = cpu.capture_context();
        assert!(matches!(
            cpu.prepare_legacy_checkpoint_transfer(&stamp, target(), 0),
            Err(CpuCallResumeError::BoundarySequenceExhausted)
        ));
        assert!(cpu.capture_context() == before);
    }

    #[test]
    fn checkpoint_keeps_enclosing_callback_ticket_valid_after_actual_far_return() {
        use crate::{
            CallEffectPolicy, CallResumeBoundary, LegacyBindingTransfer, LegacyCpuBinding,
            LegacyRegisterTransfer,
        };
        use guest_core::{GuestMemory, MemoryError, PhysAddr};
        struct Binding;
        impl LegacyCpuBinding for Binding {
            type Proof = ();
            type Error = std::convert::Infallible;
            fn capture(&self, _: &Registers) -> Result<(), Self::Error> {
                Ok(())
            }
            fn revalidate(
                &self,
                _: &(),
                _: &(),
                _: &LegacyBindingTransfer<'_, ()>,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }
        struct Memory([u8; 64]);
        impl GuestMemory for Memory {
            fn len(&self) -> u32 {
                64
            }
            fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
                self.validate_read(address, bytes.len())?;
                bytes
                    .copy_from_slice(&self.0[address.0 as usize..address.0 as usize + bytes.len()]);
                Ok(())
            }
            fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
                self.validate_write(address, bytes.len())?;
                self.0[address.0 as usize..address.0 as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            }
        }
        let mut cpu = Cpu::new(Registers {
            esp: 32,
            ..Registers::default()
        });
        let caller = cpu.capture_legacy_call_continuation(&Binding).unwrap();
        let stamp = cpu.legacy_checkpoint_stamp().unwrap();
        let t = LegacyCheckpointRegisters {
            cs: 0,
            ip: 8,
            ss: 0,
            sp: 32,
            bp: 0,
            si: 0,
            di: 0,
            ds: 0,
            stack_pointer: LegacyStackPointerTarget::RegisterValue,
        };
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, t, 0)
            .unwrap();
        cpu.commit_legacy_checkpoint_transfer(prepared).unwrap();
        assert_eq!(cpu.regs.ax(), 0);
        let mut memory = Memory([0; 64]);
        memory.0[8] = 0xcb; // Actual guest RETF.
        memory.0[32] = 16;
        struct LegacySegments;
        impl crate::SegmentResolver for LegacySegments {
            fn resolve(
                &self,
                segment: u16,
                offset: u32,
                address32: bool,
            ) -> Result<PhysAddr, crate::CpuError> {
                crate::RealModeSegments.resolve(segment, offset, address32)
            }
        }
        cpu.step_with_context(&mut memory, &mut guest_core::io::NoPorts, &LegacySegments)
            .unwrap();
        assert_eq!(cpu.control_transfer(), Some(ControlTransfer::FarReturn));
        let prepared = cpu
            .prepare_legacy_call_resume(
                &caller,
                CallEffectPolicy::PreserveX87,
                CallResumeBoundary::GuestCallReturn {
                    transfer: ControlTransfer::FarReturn,
                },
                LegacyRegisterTransfer {
                    registers: cpu.regs.clone(),
                    stack_pointer: LegacyStackPointerTarget::RegisterValue,
                },
                &Binding,
            )
            .unwrap();
        cpu.commit_legacy_call_resume(prepared, &Binding).unwrap();
        assert_eq!(cpu.regs.ip(), 16);
    }
}
