//! Stack-frame walking over checked Win16 guest selectors.

use guest_core::{memory::Memory, Registers, Selector};
use win16_abi::{
    toolhelp_abi::StackTraceEntry16,
    Access,
};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const FRAME_FAR: u16 = 0;
const FRAME_NEAR: u16 = 1;

impl Win16State {
    /// Seed stack walking from the real current-task CPU snapshot. Inactive
    /// task contexts are unavailable because this runtime has no task switcher.
    pub(super) fn toolhelp_stack_trace_first(
        &self,
        output: u32,
        task: u16,
        registers: &Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some((_pointer, _dw_size)) = self.toolhelp_stack_trace_output(output, memory)? else {
            return Ok(0);
        };
        let current_task = self.current_task_handle()?;
        if task == 0 || task == current_task {
            return self.toolhelp_stack_trace_csip_first(
                output,
                registers.ss,
                registers.cs,
                registers.ip(),
                registers.bp(),
                memory,
            );
        }
        if !self.task_handles.values().any(|handle| *handle == task) {
            return Ok(0);
        }
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            "TOOLHELP StackTraceFirst cannot inspect an inactive task because its saved stack context is not retained",
        ).with_context(format!("task 0x{task:04X}")));
        Ok(0)
    }

    /// Seed a caller-specified guest frame for subsequent StackTraceNext calls.
    pub(super) fn toolhelp_stack_trace_csip_first(
        &self,
        output: u32,
        stack_segment: u16,
        code_segment: u16,
        instruction_pointer: u16,
        base_pointer: u16,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_stack_trace_output(output, memory)? else {
            return Ok(0);
        };
        let Ok(code) = self.selectors.pointer_from_raw(Selector(code_segment), instruction_pointer)
        else { return Ok(0); };
        if self.selectors.translate(code, Access::Execute, 1, memory).is_err() {
            return Ok(0);
        }
        let Ok(frame) = self.selectors.pointer_from_raw(Selector(stack_segment), base_pointer)
        else { return Ok(0); };
        if self.selectors.translate(frame, Access::Read, 2, memory).is_err() {
            return Ok(0);
        }
        let task = self.current_task_handle()?;
        let (module, segment) = self.toolhelp_stack_trace_module_segment(code_segment);
        let value = StackTraceEntry16 {
            task,
            stack_segment,
            base_pointer,
            code_segment,
            instruction_pointer,
            module,
            segment,
            flags: FRAME_FAR,
        };
        self.selectors.write(memory, pointer, &value.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    /// Walk one BP-linked frame.
    ///
    /// A far prolog increments BP before pushing it, so the saved word is odd
    /// and the return is CS:IP. A near prolog pushes BP unchanged, so the
    /// saved word is even and the return is an IP in the same CS. `mov bp, sp`
    /// leaves the live frame pointer even; an odd live BP is not a frame.
    pub(super) fn toolhelp_stack_trace_next(
        &self,
        output: u32,
        memory: &mut Memory,
        _host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size, mut entry)) =
            self.toolhelp_stack_trace_read_entry(output, memory)? else {
            return Ok(0);
        };
        let Some(walked) = self.toolhelp_stack_trace_walk(&entry, memory)? else {
            return Ok(0);
        };
        entry.code_segment = walked.code_segment;
        entry.instruction_pointer = walked.instruction_pointer;
        entry.base_pointer = walked.base_pointer;
        entry.flags = walked.flags;
        (entry.module, entry.segment) =
            self.toolhelp_stack_trace_module_segment(entry.code_segment);
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    fn toolhelp_stack_trace_walk(
        &self, entry: &StackTraceEntry16, memory: &Memory,
    ) -> Result<Option<WalkedFrame>, RuntimeError> {
        let bp = entry.base_pointer;
        if bp == 0 || bp & 1 != 0 || usize::from(bp) + 2 > 0x1_0000 {
            return Ok(None);
        }
        let Ok(frame) = self.selectors.pointer_from_raw(Selector(entry.stack_segment), bp) else {
            return Ok(None);
        };
        if self.selectors.translate(frame, Access::Read, 2, memory).is_err() {
            return Ok(None);
        }
        let mut saved_bp_bytes = [0_u8; 2];
        if self.selectors.read(memory, frame, &mut saved_bp_bytes).is_err() {
            return Ok(None);
        }
        let saved_bp = u16::from_le_bytes(saved_bp_bytes);
        if saved_bp == 0 {
            return Ok(None);
        }
        let far_frame = saved_bp & 1 != 0;
        let next_bp = saved_bp & !1;
        if next_bp == 0 || next_bp <= bp || usize::from(next_bp) + 2 > 0x1_0000 {
            return Ok(None);
        }
        let Ok(next_frame) = self.selectors.pointer_from_raw(Selector(entry.stack_segment), next_bp)
        else { return Ok(None); };
        if self.selectors.translate(next_frame, Access::Read, 2, memory).is_err() {
            return Ok(None);
        }
        let frame_len = if far_frame { 6 } else { 4 };
        if usize::from(bp) + frame_len > 0x1_0000
            || self.selectors.translate(frame, Access::Read, frame_len, memory).is_err()
        {
            return Ok(None);
        }
        let mut frame_bytes = [0_u8; 6];
        if self.selectors.read(memory, frame, &mut frame_bytes[..frame_len]).is_err() {
            return Ok(None);
        }
        let return_ip = u16::from_le_bytes([frame_bytes[2], frame_bytes[3]]);
        let return_cs = if far_frame {
            u16::from_le_bytes([frame_bytes[4], frame_bytes[5]])
        } else {
            entry.code_segment
        };
        let Ok(code) = self.selectors.pointer_from_raw(Selector(return_cs), return_ip) else {
            return Ok(None);
        };
        if self.selectors.translate(code, Access::Execute, 1, memory).is_err() {
            return Ok(None);
        }
        Ok(Some(WalkedFrame {
            code_segment: return_cs,
            instruction_pointer: return_ip,
            base_pointer: next_bp,
            flags: if far_frame { FRAME_FAR } else { FRAME_NEAR },
        }))
    }

    fn toolhelp_stack_trace_output(
        &self,
        raw: u32,
        memory: &Memory,
    ) -> Result<Option<(win16_abi::SegmentedPointer, u32)>, RuntimeError> {
        let Ok(pointer) = self.selectors.pointer_from_far(raw) else { return Ok(None); };
        if self.selectors.translate(pointer, Access::Read, 4, memory).is_err() {
            return Ok(None);
        }
        let mut size = [0_u8; 4];
        self.selectors.read(memory, pointer, &mut size).map_err(crate::runtime_error)?;
        let dw_size = u32::from_le_bytes(size);
        // dwSize is a version. A larger caller structure is accepted; only the
        // known prefix is written, and the caller's dwSize is preserved.
        if dw_size < StackTraceEntry16::SIZE as u32
            || self.selectors.translate(pointer, Access::Write, StackTraceEntry16::SIZE, memory).is_err()
        {
            return Ok(None);
        }
        Ok(Some((pointer, dw_size)))
    }

    fn toolhelp_stack_trace_read_entry(
        &self,
        raw: u32,
        memory: &Memory,
    ) -> Result<Option<(win16_abi::SegmentedPointer, u32, StackTraceEntry16)>, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_stack_trace_output(raw, memory)? else {
            return Ok(None);
        };
        let mut bytes = [0_u8; StackTraceEntry16::SIZE];
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        let (_, entry) = StackTraceEntry16::decode(&bytes);
        Ok(Some((pointer, dw_size, entry)))
    }

    fn toolhelp_stack_trace_module_segment(&self, code_segment: u16) -> (u16, u16) {
        let Some(module) = self.modules.by_handle(code_segment) else { return (0, 0); };
        let segment = self.modules.records.get(&module)
            .and_then(|record| record.loaded.as_ref())
            .and_then(|loaded| loaded.segments.iter()
                .find(|segment| segment.selector.0 == code_segment))
            .map_or(0, |segment| segment.number);
        (module, segment)
    }
}

struct WalkedFrame {
    code_segment: u16,
    instruction_pointer: u16,
    base_pointer: u16,
    flags: u16,
}
