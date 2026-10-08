//! Guest-thread continuation for GDI LineDDA callbacks.
//!
//! The host asks Windows to enumerate the native DDA points into owned data.
//! This module then runs the guest FAR callback on the emulated CPU, in order,
//! before returning to the original Win16 caller.

use dos_kernel::DosKernel;
use guest_core::{memory::Memory, Registers, Selector};
use win16_abi::{Access, SegmentedPointer, Win16ReturnKind};

use super::{CallbackKind, Win16State};
use super::far_callback::{
    Win16FarCallbackArgument as CallbackArgument, Win16FarCallbackConvention,
    Win16FarCallbackFrame, Win16FarCallbackReturn,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16DrawingOperation as DrawingOperation,
    Win16DrawingPoint, Win16DrawingResult as DrawingResult,
};
use x86_cpu::Cpu;

const CALLBACK_STACK_BYTES: u16 = 12; // FAR return, x/y WORDs, LPARAM DWORD.
const MAX_CALLBACK_POINTS: usize = 65_536;

pub(super) struct LineDdaCallbackFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    callback: u32,
    data: u32,
    return_value: u32,
    return_kind: Win16ReturnKind,
    points: Vec<Win16DrawingPoint>,
    next_index: usize,
    active_call: Option<Win16FarCallbackFrame>,
}

impl Win16State {
    pub(super) fn begin_line_dda(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        x_start: i16,
        y_start: i16,
        x_end: i16,
        y_end: i16,
        callback: u32,
        data: u32,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        if callback == 0 {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, return_kind);
        }
        let callback_pointer = self.selectors.pointer_from_far(callback)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(callback_pointer, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        self.preflight_callback_stack(&cpu.regs, memory)?;

        let result = host.win16_gdi(DrawingOperation::LineDda {
            x_start: i32::from(x_start),
            y_start: i32::from(y_start),
            x_end: i32::from(x_end),
            y_end: i32::from(y_end),
        })?;
        let DrawingResult::LineDda { success, points } = result else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 host drawing returned the wrong result for LineDDA"));
        };
        if !success || points.is_empty() {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, return_kind);
        }
        if points.len() > MAX_CALLBACK_POINTS {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native LineDDA exceeded the Win16 endpoint point bound"));
        }
        if points.iter().any(|point| {
            i16::try_from(point.x).is_err() || i16::try_from(point.y).is_err()
        }) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native LineDDA returned a point outside signed Win16 coordinates"));
        }

        let callback_id = self.reserve_callback_frame_id()?;
        self.line_dda_callbacks.push(LineDdaCallbackFrame {
            callback_id, saved: cpu.regs.clone(), return_to, callback, data,
            return_value: u32::from(success), return_kind,
            points, next_index: 0, active_call: None,
        });
        self.push_callback_kind(CallbackKind::LineDda, callback_id)?;
        self.schedule_line_dda_callback(cpu, dos, memory)?;
        Ok(None)
    }

    pub(crate) fn finish_line_dda_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::LineDda)?;
        if self.line_dda_callbacks.last().is_none_or(|frame| frame.callback_id != callback_id) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 LineDDA callback identity changed before guest return"));
        }
        let mut active_call = self.line_dda_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take()).ok_or_else(|| RuntimeError::new(
                Kind::GuestFault, "Win16 callback gate has no active LineDDA call"))?;
        if let Err(error) = self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active_call) {
            self.line_dda_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
            return Err(error);
        }
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.line_dda_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
            return Err(error);
        }
        let frame = self.line_dda_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 LineDDA callback frame disappeared"))?;
        if frame.next_index < frame.points.len() {
            self.line_dda_callbacks.last_mut().expect("frame checked").active_call = None;
            return self.schedule_line_dda_callback(cpu, dos, memory);
        }

        self.line_dda_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
        let frame = self.line_dda_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 LineDDA callback frame disappeared"))?;
        let saved = frame.saved.clone();
        let return_to = frame.return_to;
        let return_value = frame.return_value;
        let return_kind = frame.return_kind;
        cpu.regs = saved.clone();
        self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
            return_to.2, return_value, return_kind)?;
        let frame = self.line_dda_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 LineDDA callback frame disappeared"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::LineDda, callback_id) {
            self.line_dda_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_line_dda_callback_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::LineDda)?;
        let frame = self.line_dda_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "top LineDDA callback has no family frame"))?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "top LineDDA callback identity differs from its family frame"));
        }
        if let Some(mut active_call) = self.line_dda_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended, CallbackKind::LineDda, callback_id, cpu, dos, memory, &mut active_call,
            ) {
                self.line_dda_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
            self.line_dda_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
        }
        let frame = self.line_dda_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "LineDDA callback frame disappeared during teardown"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::LineDda, callback_id) {
            self.line_dda_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn line_dda_code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(self.line_dda_callbacks.len().saturating_mul(3));
        for frame in &self.line_dda_callbacks {
            references.push(frame.callback);
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }

    fn preflight_callback_stack(
        &self,
        registers: &Registers,
        memory: &Memory,
    ) -> Result<SegmentedPointer, RuntimeError> {
        let stack_pointer = registers.sp().checked_sub(CALLBACK_STACK_BYTES).ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault, "Win16 LineDDA callback stack underflow")
        })?;
        let pointer = self.selectors.pointer_from_raw(Selector(registers.ss), stack_pointer)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Write,
            usize::from(CALLBACK_STACK_BYTES), memory).map_err(crate::runtime_error)?;
        Ok(pointer)
    }

    fn schedule_line_dda_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self.line_dda_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 LineDDA callback frame is missing"))?;
        let point = frame.points.get(frame.next_index).copied().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "Win16 LineDDA point is missing")
        })?;
        let callback = frame.callback;
        let data = frame.data;
        let saved = frame.saved.clone();
        cpu.regs = saved;
        let active_call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            callback,
            &[
                CallbackArgument::Word(point.x as i16 as u16),
                CallbackArgument::Word(point.y as i16 as u16),
                CallbackArgument::Dword(data),
            ],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Void,
        )?;
        let frame = self.line_dda_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 LineDDA callback frame disappeared"))?;
        frame.next_index += 1;
        frame.active_call = Some(active_call);
        Ok(())
    }
}
