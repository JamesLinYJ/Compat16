//! Win16 initial-task register call and checked guest-memory bootstrap.

use guest_core::{GuestMemory, PhysAddr, Registers, Selector};
use guest_core::memory::Memory;
use win16_abi::{prepare_local_heap_init, Access, SegmentedPointer, Win16RegisterContext};
use win16_abi::task_database::{
    INSTANCE_DATA_STACK_BOTTOM_OFFSET, INSTANCE_DATA_STACK_MINIMUM_OFFSET,
    INSTANCE_DATA_STACK_TOP_OFFSET, TASK_DATABASE_ERROR_MODE_OFFSET,
};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

// INSTANCEDATA is the Win16 DGROUP header (external private-layout comparison).
const STACK_GUARD_BYTES: u32 = 150;
const PSP_COMMAND_LENGTH: u16 = 0x80;
const PSP_COMMAND_TEXT: u16 = 0x81;
const DEFAULT_CMD_SHOW: u32 = 1;

struct TaskPatch {
    address: PhysAddr,
    original: Vec<u8>,
    replacement: Vec<u8>,
}

impl Win16State {
    pub(super) fn set_error_mode(
        &self,
        mode: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let handle = self.current_task_handle()?;
        let pointer = self.selectors.pointer_from_raw(
            Selector(handle), TASK_DATABASE_ERROR_MODE_OFFSET as u16,
        ).map_err(crate::runtime_error)?;
        let address = self.selectors.translate(pointer, Access::Write, 2, memory)
            .map_err(crate::runtime_error)?;

        // SetErrorMode is process-wide. The single guest task's TDB tracks the
        // requested Win16 flags, while AX reports Windows' previous process mode.
        let previous = host.win16_set_error_mode(mode)?;
        memory.write(address, &mode.to_le_bytes()).map_err(crate::runtime_error)?;
        Ok(previous)
    }

    pub(super) fn init_task(
        &mut self,
        context: Win16RegisterContext,
        registers: &mut Registers,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let stack = self.selectors.pointer_from_raw(Selector(context.ss), context.esp as u16)
            .map_err(crate::runtime_error)?;
        // The application calls KERNEL.91 with a far CALL. Decode only its
        // continuation here; register-context exports have no Pascal arguments.
        let mut continuation = [0_u8; 4];
        self.selectors.read(memory, stack, &mut continuation)
            .map_err(crate::runtime_error)?;
        let return_ip = u16::from_le_bytes([continuation[0], continuation[1]]);
        let return_cs = u16::from_le_bytes([continuation[2], continuation[3]]);
        let return_pointer = self.selectors.pointer_from_raw(Selector(return_cs), return_ip)
            .map_err(crate::runtime_error)?;
        self.selectors.address_within(return_pointer, Access::Execute, 1, memory.len())
            .map_err(crate::runtime_error)?;
        let returned_sp = u32::from(context.esp as u16).checked_add(4)
            .filter(|offset| *offset <= 0x1_0000)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 InitTask far return exceeds the 16-bit stack"))?;
        let sentinel_sp = returned_sp.checked_sub(2).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "Win16 InitTask has no room for its BP sentinel"))? as u16;

        let mut command = [0_u8; 128];
        self.selectors.read(memory,
            SegmentedPointer::new(self.psp_selector, PSP_COMMAND_LENGTH), &mut command)
            .map_err(crate::runtime_error)?;
        let command_length = usize::from(command[0]);
        if command_length > 126 || command[command_length + 1] != b'\r' {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 InitTask PSP command tail is malformed"));
        }
        let leading_space = command[1..1 + command_length].iter()
            .take_while(|byte| **byte == b' ' || **byte == b'\t')
            .count();
        let command_offset = if command_length == 0 {
            PSP_COMMAND_LENGTH
        } else {
            PSP_COMMAND_TEXT + leading_space as u16
        };
        let command_terminator = if command_length == 0 {
            None
        } else {
            let search_start = 1 + leading_space;
            let carriage_return = command[search_start..=command_length + 1]
                .iter()
                .position(|byte| *byte == b'\r')
                .map(|offset| search_start + offset)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::GuestFault,
                        "Win16 InitTask PSP command tail has no carriage return",
                    )
                })?;
            let offset = usize::from(PSP_COMMAND_LENGTH) + carriage_return;
            Some(u16::try_from(offset).map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 InitTask PSP command terminator offset is invalid",
                    error,
                )
            })?)
        };

        let stack_min = returned_sp as u16;
        let stack_reserve = context.ebx as u16;
        let stack_top = u32::from(stack_min)
            .saturating_sub(u32::from(stack_reserve))
            .checked_add(STACK_GUARD_BYTES)
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 InitTask stack metadata exceeds the 16-bit segment"))?;
        let dgroup = self.selectors.reference(Selector(context.ds))
            .map_err(crate::runtime_error)?;
        let mut patches = Vec::new();
        patches.try_reserve_exact(11).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 InitTask memory patches", error))?;
        if let Some(offset) = command_terminator {
            self.stage_task_patch(memory, &mut patches,
                SegmentedPointer::new(self.psp_selector, offset), &[0])?;
        }
        self.stage_task_patch(memory, &mut patches,
            SegmentedPointer::new(dgroup, INSTANCE_DATA_STACK_TOP_OFFSET as u16), &stack_top.to_le_bytes())?;
        self.stage_task_patch(memory, &mut patches,
            SegmentedPointer::new(dgroup, INSTANCE_DATA_STACK_MINIMUM_OFFSET as u16), &stack_min.to_le_bytes())?;
        self.stage_task_patch(memory, &mut patches,
            SegmentedPointer::new(dgroup, INSTANCE_DATA_STACK_BOTTOM_OFFSET as u16), &stack_min.to_le_bytes())?;

        let heap_reserve = context.ecx as u16;
        if heap_reserve != 0 {
            let segment = self.selectors.describe(self.instance_selector)
                .map_err(crate::runtime_error)?;
            let segment_bytes = usize::try_from(segment.limit + 1).map_err(|error|
                RuntimeError::with_source(Kind::InternalInvariant,
                    "Win16 instance segment length is invalid", error))?;
            let plan = prepare_local_heap_init(segment_bytes, 0, heap_reserve)
                .map_err(|error| RuntimeError::with_source(Kind::GuestFault,
                    "Win16 InitTask local heap cannot be initialized", error))?;
            for write in plan.writes() {
                self.stage_task_patch(memory, &mut patches,
                    SegmentedPointer::new(self.instance_selector, write.offset()), write.bytes())?;
            }
        }
        self.stage_task_patch(memory, &mut patches,
            SegmentedPointer::new(stack.selector(), sentinel_sp), &[0, 0])?;
        commit_task_patches(memory, &patches)?;

        let mut returned = context;
        returned.eax = u32::from(self.psp_selector.raw().0);
        returned.ebx = u32::from(command_offset);
        returned.ecx = u32::from(stack_top);
        returned.edx = DEFAULT_CMD_SHOW;
        returned.esi = 0;
        returned.edi = u32::from(self.instance_handle);
        returned.es = self.psp_selector.raw().0;
        returned.cs = return_cs;
        returned.eip = u32::from(return_ip);
        returned.esp = (context.esp & !0xffff) | u32::from(sentinel_sp);
        returned.apply_to(registers);
        self.retire_far_return(return_cs, u32::from(return_ip), context.ss);
        Ok(())
    }

    fn stage_task_patch(
        &self,
        memory: &Memory,
        patches: &mut Vec<TaskPatch>,
        pointer: SegmentedPointer,
        replacement: &[u8],
    ) -> Result<(), RuntimeError> {
        let address = self.selectors.translate(pointer, Access::Write, replacement.len(), memory)
            .map_err(crate::runtime_error)?;
        let end = address.0.checked_add(replacement.len() as u32).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "Win16 InitTask write range overflows"))?;
        if patches.iter().any(|patch| {
            let previous_end = patch.address.0 + patch.replacement.len() as u32;
            address.0 < previous_end && patch.address.0 < end
        }) {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 InitTask stack, instance header, and local heap overlap"));
        }
        let mut original = Vec::new();
        original.try_reserve_exact(replacement.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "allocate Win16 InitTask rollback data", error))?;
        original.resize(replacement.len(), 0);
        memory.read(address, &mut original).map_err(crate::runtime_error)?;
        let mut replacement_copy = Vec::new();
        replacement_copy.try_reserve_exact(replacement.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "allocate Win16 InitTask patch data", error))?;
        replacement_copy.extend_from_slice(replacement);
        patches.push(TaskPatch { address, original, replacement: replacement_copy });
        Ok(())
    }
}

fn commit_task_patches(memory: &mut Memory, patches: &[TaskPatch]) -> Result<(), RuntimeError> {
    for (index, patch) in patches.iter().enumerate() {
        if let Err(write_error) = memory.write(patch.address, &patch.replacement) {
            for previous in patches[..=index].iter().rev() {
                if let Err(rollback_error) = memory.write(previous.address, &previous.original) {
                    return Err(RuntimeError::with_source(Kind::InternalInvariant,
                        format!("Win16 InitTask write failed ({write_error}) and rollback failed"),
                        rollback_error));
                }
            }
            return Err(RuntimeError::with_source(Kind::GuestFault,
                "Win16 InitTask could not commit guest-memory changes", write_error));
        }
    }
    Ok(())
}
