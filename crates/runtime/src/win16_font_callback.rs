//! Guest execution frames for GDI font enumeration callbacks.
//!
//! Native GDI enumeration finishes before these frames are scheduled. The
//! copied records are serialized into guest-owned memory one at a time; the
//! normal instruction loop executes every guest callback and nested API call.

use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers};
use guest_core::memory::Memory;
use win16_abi::{Access, AllocationFlags, GlobalHandle, SegmentedPointer, Win16Error, Win16ReturnKind};
use win16_abi::gdi_abi::{TextMetric16, TEXTMETRIC16_SIZE};

use super::{CallbackKind, Win16State};
use x86_cpu::Cpu;
use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostFontRecord};

const LOGFONT16_BYTES: usize = 50;
const NEWTEXTMETRIC16_BYTES: usize = 41;
const FONT_RECORD_BYTES: usize = LOGFONT16_BYTES + NEWTEXTMETRIC16_BYTES;
const CALLBACK_STACK_BYTES: u16 = 18; // FAR return, two FAR pointers, WORD, DWORD.

pub(super) struct FontCallbackFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    callback: u32,
    parameter: i32,
    records: Vec<Win16HostFontRecord>,
    next_index: usize,
    last_result: u16,
    allocation: Option<GlobalHandle>,
    allocation_locked: bool,
    data: SegmentedPointer,
    active_call: Option<Win16FarCallbackFrame>,
}

fn narrow(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn encode_font(record: &Win16HostFontRecord) -> [u8; FONT_RECORD_BYTES] {
    let mut bytes = [0_u8; FONT_RECORD_BYTES];
    for (index, value) in record.logfont_dimensions.iter().enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&narrow(*value).to_le_bytes());
    }
    bytes[10..18].copy_from_slice(&record.logfont_styles);
    bytes[18..50].copy_from_slice(&record.face_name);
    let metric = LOGFONT16_BYTES;
    bytes[metric..metric + TEXTMETRIC16_SIZE].copy_from_slice(&TextMetric16::from_host(
        record.textmetric_dimensions, record.textmetric_styles, record.textmetric_extra,
    ).encode());
    if let Some([flags, em, cell, average]) = record.newtextmetric_extra {
        bytes[metric + 31..metric + 35].copy_from_slice(&flags.to_le_bytes());
        for (index, value) in [em, cell, average].into_iter().enumerate() {
            let at = metric + 35 + index * 2;
            bytes[at..at + 2].copy_from_slice(&(value.min(u32::from(u16::MAX)) as u16).to_le_bytes());
        }
    }
    bytes
}

impl Win16State {
    pub(super) fn font_code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(self.font_callbacks.len().saturating_mul(3));
        for frame in &self.font_callbacks {
            references.push(frame.callback);
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }

    pub(super) fn begin_enum_fonts(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        dc: u16,
        face_name: Option<&[u8]>,
        callback: u32,
        parameter: i32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(native_dc) = self.guest_gdi.dc(dc) else {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        let records = host.win16_enum_fonts(native_dc, face_name)?;
        if records.is_empty() {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        }
        let target = self.selectors.pointer_from_far(callback).map_err(crate::runtime_error)?;
        self.selectors.translate(target, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        if cpu.regs.sp() < CALLBACK_STACK_BYTES {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 font callback has insufficient guest stack space"));
        }
        let callback_id = self.reserve_callback_frame_id()?;
        let allocation = match self.heap.alloc(memory, OwnerId(1),
            FONT_RECORD_BYTES as u32, AllocationFlags::fixed().with_zero_init()) {
            Ok(handle) => handle,
            Err(Win16Error::OutOfMemory | Win16Error::HandleTableFull) => {
                return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Word);
            }
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let data = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => {
                self.heap.free(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
                return Err(crate::runtime_error(error));
            }
        };
        self.font_callbacks.push(FontCallbackFrame {
            callback_id, saved: cpu.regs.clone(), return_to, callback, parameter, records,
            next_index: 0, last_result: 0, allocation: Some(allocation),
            allocation_locked: true, data, active_call: None,
        });
        self.push_callback_kind(CallbackKind::Font, callback_id)?;
        self.schedule_font_callback(cpu, dos, memory)?;
        Ok(None)
    }

    fn schedule_font_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self.font_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 font callback frame is missing"))?;
        let record = frame.records.get(frame.next_index).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 font callback record is missing"))?;
        let bytes = encode_font(record);
        self.selectors.write(memory, frame.data, &bytes).map_err(crate::runtime_error)?;
        let metric = self.selectors.add_bytes(frame.data, LOGFONT16_BYTES as u32)
            .map_err(crate::runtime_error)?;
        let callback = frame.callback;
        let parameter = frame.parameter as u32;
        let font_type = record.font_type;
        let data_far = frame.data.far_value();
        let metric_far = metric.far_value();
        let saved = frame.saved.clone();
        cpu.regs = saved;
        let active_call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            callback,
            &[
                Win16FarCallbackArgument::GuestPointer {
                    far: data_far,
                    access: Access::Read,
                    bytes: LOGFONT16_BYTES as u32,
                },
                Win16FarCallbackArgument::GuestPointer {
                    far: metric_far,
                    access: Access::Read,
                    bytes: NEWTEXTMETRIC16_BYTES as u32,
                },
                Win16FarCallbackArgument::Word(font_type),
                Win16FarCallbackArgument::Dword(parameter),
            ],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )?;
        let frame = self.font_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 font callback frame disappeared"))?;
        frame.next_index += 1;
        frame.active_call = Some(active_call);
        Ok(())
    }

    pub(crate) fn finish_font_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Font)?;
        if self.font_callbacks.last().is_none_or(|frame| frame.callback_id != callback_id) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 font callback identity changed before guest return"));
        }
        let mut active_call = self.font_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take()).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 callback gate has no active call"))?;
        let callback_result = match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active_call) {
            Ok(value) => value,
            Err(error) => {
                self.font_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
        };
        let continue_enumeration = {
            let frame = self.font_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 font callback frame disappeared"))?;
            frame.last_result = callback_result as u16;
            frame.last_result != 0 && frame.next_index < frame.records.len()
        };
        if continue_enumeration {
            if let Err(error) = self.release_guest_far_callback_owner(
                &mut active_call, dos, memory,
            ) {
                self.font_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
            self.font_callbacks.last_mut().expect("frame checked").active_call = None;
            return self.schedule_font_callback(cpu, dos, memory);
        }
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.font_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
            return Err(error);
        }
        self.font_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);

        let (allocation, allocation_locked, saved, return_to, last_result) = {
            let frame = self.font_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 font callback frame disappeared"))?;
            (frame.allocation, frame.allocation_locked, frame.saved.clone(),
                frame.return_to, frame.last_result)
        };
        if let Some(allocation) = allocation {
            if allocation_locked {
                self.heap.unlock(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
                self.font_callbacks.last_mut().expect("frame checked").allocation_locked = false;
            }
            self.heap.free(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
            self.font_callbacks.last_mut().expect("frame checked").allocation = None;
        }

        cpu.regs = saved;
        self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
            return_to.2, u32::from(last_result), Win16ReturnKind::Word)?;
        let frame = self.font_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 font callback frame disappeared"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::Font, callback_id) {
            self.font_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_font_callback_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Font)?;
        let frame = self.font_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "top font callback has no family frame"))?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "top font callback identity differs from its family frame"));
        }
        if let Some(mut active_call) = self.font_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended, CallbackKind::Font, callback_id, cpu, dos, memory, &mut active_call,
            ) {
                self.font_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
            self.font_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
        }
        let (allocation, locked) = self.font_callbacks.last().map(|frame|
            (frame.allocation, frame.allocation_locked)).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "font callback frame disappeared during teardown"))?;
        if let Some(allocation) = allocation {
            if locked {
                self.heap.unlock(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
                self.font_callbacks.last_mut().expect("frame checked").allocation_locked = false;
            }
            self.heap.free(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
            self.font_callbacks.last_mut().expect("frame checked").allocation = None;
        }
        let frame = self.font_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "font callback frame disappeared during teardown"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::Font, callback_id) {
            self.font_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }
}
