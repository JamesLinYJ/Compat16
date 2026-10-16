//! KERNEL stack switching through guest metadata and a checked CPU boundary.

#[path = "win16_stack_switch/writes.rs"]
mod writes;

use dos_kernel::DosKernel;
use guest_core::{Selector, memory::Memory};
use win16_abi::task_database::{
    INSTANCE_DATA_OLD_STACK_POINTER_OFFSET, INSTANCE_DATA_STACK_TOP_OFFSET,
    TASK_DATABASE_STACK_POINTER_OFFSET,
};
use win16_abi::{Access, SegmentedPointer, SelectorRef, Win16RegisterContext};
use x86_cpu::{Cpu, LegacyCheckpointRegisters, LegacyStackPointerTarget};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};
use writes::StackWrites;

impl Win16State {
    pub(super) fn switch_stack_to(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        stack_selector: u16,
        stack_pointer: u16,
        stack_top: u16,
    ) -> Result<(), RuntimeError> {
        let (cs, ip, returned_sp) = self.far_return(&cpu.regs, memory, 6)?;
        let old_ss = cpu.regs.ss;
        let old_stack = self.checked_stack(old_ss, dos, memory)?;
        let new_stack = self.checked_stack(stack_selector, dos, memory)?;
        // KERNEL31 copies words below BP's saved DS, from high to low.
        // The API's six argument bytes and FAR return are already consumed.
        let argument_end = u32::from(
            cpu.regs
                .bp()
                .checked_sub(2)
                .ok_or_else(|| fault("SwitchStackTo has no caller BP frame"))?,
        );
        let argument_bytes = argument_end
            .checked_sub(returned_sp)
            .ok_or_else(|| fault("SwitchStackTo caller BP precedes its stack arguments"))?
            & !1;
        let argument_start = argument_end - argument_bytes;
        let saved_sp = returned_sp
            .checked_sub(2)
            .ok_or_else(|| fault("SwitchStackTo cannot save the caller BP"))?;
        let bottom = if stack_pointer == 0 {
            0x10000
        } else {
            u32::from(stack_pointer)
        };
        let return_frame = bottom
            .checked_sub(argument_bytes + 6)
            .filter(|start| *start >= u32::from(stack_top).max(16))
            .ok_or_else(|| fault("SwitchStackTo arguments exceed the alternate stack bounds"))?;
        let mut payload = bytes((argument_bytes + 6) as usize)?;
        payload[..2].copy_from_slice(&ip.to_le_bytes());
        payload[2..4].copy_from_slice(&cs.to_le_bytes());
        if argument_bytes != 0 {
            self.selectors
                .read(
                    memory,
                    SegmentedPointer::new(old_stack, argument_start as u16),
                    &mut payload[4..4 + argument_bytes as usize],
                )
                .map_err(crate::runtime_error)?;
        }
        // The final zero WORD terminates the new frame's saved-DS/BP chain.
        let new_sp = return_frame + 4;
        let target = target(cpu, cs, ip, stack_selector, new_sp, stack_pointer);
        let prepared = self.prepare_stack_return(cpu, memory, dos, target)?;
        let mut writes = StackWrites::new()?;
        writes.add(
            &self.selectors,
            memory,
            SegmentedPointer::new(old_stack, saved_sp as u16),
            &cpu.regs.bp().to_le_bytes(),
        )?;
        let mut previous = [0_u8; 4];
        previous[..2].copy_from_slice(&(saved_sp as u16).to_le_bytes());
        previous[2..].copy_from_slice(&old_ss.to_le_bytes());
        writes.add(
            &self.selectors,
            memory,
            SegmentedPointer::new(new_stack, INSTANCE_DATA_OLD_STACK_POINTER_OFFSET as u16),
            &previous,
        )?;
        let mut bounds = [0_u8; 6];
        bounds[..2].copy_from_slice(&stack_top.to_le_bytes());
        bounds[2..4].copy_from_slice(&stack_pointer.to_le_bytes());
        bounds[4..].copy_from_slice(&stack_pointer.to_le_bytes());
        writes.add(
            &self.selectors,
            memory,
            SegmentedPointer::new(new_stack, INSTANCE_DATA_STACK_TOP_OFFSET as u16),
            &bounds,
        )?;
        writes.add(
            &self.selectors,
            memory,
            SegmentedPointer::new(new_stack, return_frame as u16),
            &payload,
        )?;
        self.stage_task_stack(memory, &mut writes, stack_selector, new_sp as u16)?;
        writes.publish(memory)?;
        cpu.commit_legacy_checkpoint_return(prepared)
            .map_err(cpu_error)?;
        self.retire_far_return(cs, u32::from(ip), old_ss);
        Ok(())
    }

    pub(super) fn switch_stack_back(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        context: Win16RegisterContext,
    ) -> Result<(), RuntimeError> {
        if context != Win16RegisterContext::from(&cpu.regs) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "SwitchStackBack register snapshot changed before dispatch",
            ));
        }
        let (cs, ip, _) = self.far_return(&cpu.regs, memory, 0)?;
        let current_ss = cpu.regs.ss;
        let current_stack = self.checked_stack(current_ss, dos, memory)?;
        let mut previous = [0_u8; 4];
        self.selectors
            .read(
                memory,
                SegmentedPointer::new(current_stack, INSTANCE_DATA_OLD_STACK_POINTER_OFFSET as u16),
                &mut previous,
            )
            .map_err(crate::runtime_error)?;
        let saved_sp = u16::from_le_bytes([previous[0], previous[1]]);
        let saved_ss = u16::from_le_bytes([previous[2], previous[3]]);
        let old_stack = self.checked_stack(saved_ss, dos, memory)?;
        let mut saved_bp = [0_u8; 2];
        self.selectors
            .read(
                memory,
                SegmentedPointer::new(old_stack, saved_sp),
                &mut saved_bp,
            )
            .map_err(crate::runtime_error)?;
        let return_frame = saved_sp
            .checked_sub(2)
            .ok_or_else(|| fault("SwitchStackBack has no space for its FAR return"))?;
        let target = target(
            cpu,
            cs,
            ip,
            saved_ss,
            u32::from(saved_sp) + 2,
            u16::from_le_bytes(saved_bp),
        );
        let prepared = self.prepare_stack_return(cpu, memory, dos, target)?;
        let mut writes = StackWrites::new()?;
        writes.add(
            &self.selectors,
            memory,
            SegmentedPointer::new(current_stack, INSTANCE_DATA_OLD_STACK_POINTER_OFFSET as u16),
            &[0; 4],
        )?;
        self.stage_task_stack(memory, &mut writes, saved_ss, saved_sp)?;
        let mut return_address = [0_u8; 4];
        return_address[..2].copy_from_slice(&ip.to_le_bytes());
        return_address[2..].copy_from_slice(&cs.to_le_bytes());
        writes.add(
            &self.selectors,
            memory,
            SegmentedPointer::new(old_stack, return_frame),
            &return_address,
        )?;
        writes.publish(memory)?;
        // Narrow transfers leave DX, all upper register halves, flags, x87 and
        // pending CPU events live. In particular Back preserves the AX:DX result.
        cpu.commit_legacy_checkpoint_return(prepared)
            .map_err(cpu_error)?;
        self.retire_far_return(cs, u32::from(ip), current_ss);
        Ok(())
    }

    fn checked_stack(
        &mut self,
        raw: u16,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<SelectorRef, RuntimeError> {
        let reference = self
            .selectors
            .reference(Selector(raw))
            .map_err(crate::runtime_error)?;
        let descriptor = self
            .selectors
            .describe(reference)
            .map_err(crate::runtime_error)?;
        if !descriptor.rights.readable()
            || !descriptor.rights.writable()
            || descriptor.rights.executable()
            || self
                .selector_backing_lease(reference, dos, memory)?
                .is_none()
        {
            return Err(fault(
                "Win16 stack selector has no writable process-owned data backing",
            ));
        }
        Ok(reference)
    }

    fn prepare_stack_return(
        &mut self,
        cpu: &Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        target: LegacyCheckpointRegisters,
    ) -> Result<x86_cpu::PreparedLegacyCheckpointTransfer, RuntimeError> {
        let code = self
            .selectors
            .reference(Selector(target.cs))
            .map_err(crate::runtime_error)?;
        if self.selector_backing_lease(code, dos, memory)?.is_none() {
            return Err(fault(
                "Win16 stack return has no process-owned code backing",
            ));
        }
        self.selectors
            .translate(
                SegmentedPointer::new(code, target.ip),
                Access::Execute,
                1,
                memory,
            )
            .map_err(crate::runtime_error)?;
        let stack = self.checked_stack(target.ss, dos, memory)?;
        let end = if target.stack_pointer == LegacyStackPointerTarget::OnePast16BitSegment {
            0x10000
        } else {
            u32::from(target.sp)
        };
        let probe = end
            .checked_sub(1)
            .ok_or_else(|| fault("Win16 stack return has no room for another push"))?;
        self.selectors
            .translate(
                SegmentedPointer::new(stack, probe as u16),
                Access::Write,
                1,
                memory,
            )
            .map_err(crate::runtime_error)?;
        let stamp = cpu.legacy_checkpoint_stamp().map_err(cpu_error)?;
        cpu.prepare_legacy_checkpoint_transfer(&stamp, target, cpu.regs.ax())
            .map_err(cpu_error)
    }

    fn stage_task_stack(
        &self,
        memory: &Memory,
        writes: &mut StackWrites,
        ss: u16,
        sp: u16,
    ) -> Result<(), RuntimeError> {
        let task = self.current_task_handle()?;
        let pointer = self
            .selectors
            .pointer_from_raw(Selector(task), TASK_DATABASE_STACK_POINTER_OFFSET as u16)
            .map_err(crate::runtime_error)?;
        let mut value = [0_u8; 4];
        value[..2].copy_from_slice(&sp.to_le_bytes());
        value[2..].copy_from_slice(&ss.to_le_bytes());
        writes.add(&self.selectors, memory, pointer, &value)
    }
}

fn target(cpu: &Cpu, cs: u16, ip: u16, ss: u16, sp: u32, bp: u16) -> LegacyCheckpointRegisters {
    LegacyCheckpointRegisters {
        cs,
        ip,
        ss,
        sp: sp as u16,
        bp,
        si: cpu.regs.si(),
        di: cpu.regs.di(),
        ds: cpu.regs.ds,
        stack_pointer: if sp == 0x10000 {
            LegacyStackPointerTarget::OnePast16BitSegment
        } else {
            LegacyStackPointerTarget::RegisterValue
        },
    }
}

fn bytes(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut value = Vec::new();
    value.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 stack argument copy",
            error,
        )
    })?;
    value.resize(length, 0);
    Ok(value)
}

fn cpu_error(error: x86_cpu::CpuCallResumeError) -> RuntimeError {
    RuntimeError::with_source(Kind::GuestFault, "Win16 stack-switch CPU transfer", error)
}

fn fault(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::GuestFault, message)
}
