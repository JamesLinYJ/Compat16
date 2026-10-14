//! Guest execution frames for GDI object enumeration callbacks.
//!
//! Native GDI enumeration finishes before these frames are scheduled. The
//! copied records are serialized into guest-owned memory one at a time; the
//! normal instruction loop executes every guest callback and nested API call.

use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers};
use guest_core::memory::Memory;
use win16_abi::{Access, AllocationFlags, GlobalHandle, SegmentedPointer, Win16Error, Win16ReturnKind};
use win16_abi::gdi_abi::{LogBrush16, LogPen16, LOGBRUSH16_SIZE, LOGPEN16_SIZE};

use super::{CallbackKind, Win16State};
use x86_cpu::Cpu;
use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostGdiObject,
    Win16HostGdiObjectRecord,
};

// FAR return followed by two DWORDs in reverse Pascal argument order.
const CALLBACK_STACK_BYTES: u16 = 12;

struct ObjectRecord {
    bytes: [u8; LOGPEN16_SIZE],
    pattern: Option<(u16, Win16HostGdiObject)>,
}

pub(super) struct ObjectCallbackFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    callback: u32,
    parameter: i32,
    records: Vec<ObjectRecord>,
    record_bytes: usize,
    next_index: usize,
    last_result: u16,
    allocation: Option<GlobalHandle>,
    allocation_locked: bool,
    data: SegmentedPointer,
    active_call: Option<Win16FarCallbackFrame>,
}

impl Win16State {
    pub(super) fn object_code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(self.object_callbacks.len().saturating_mul(3));
        for frame in &self.object_callbacks {
            references.push(frame.callback);
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }

    pub(super) fn begin_enum_objects(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        dc: u16,
        object_type: i16,
        callback: u32,
        parameter: i32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let record_bytes = match object_type {
            1 => LOGPEN16_SIZE,
            2 => LOGBRUSH16_SIZE,
            _ => return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word),
        };
        let Some(native_dc) = self.guest_gdi.dc(dc) else {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        let native_records = host.win16_enum_objects(native_dc, object_type)?;
        let mut records = Vec::new();
        records.try_reserve(native_records.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "retain Win16 GDI enumeration records", error,
        ))?;
        for record in native_records {
            let Some(bytes) = self.encode_object_record(record, object_type)? else {
                return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Word);
            };
            records.push(bytes);
        }
        if records.is_empty() {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        }
        let target = self.selectors.pointer_from_far(callback).map_err(crate::runtime_error)?;
        self.selectors.translate(target, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        if cpu.regs.sp() < CALLBACK_STACK_BYTES {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 GDI object callback has insufficient guest stack space"));
        }
        self.object_callbacks.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "retain Win16 GDI object callback frame", error,
        ))?;
        // Reserves both central binding stacks before acquiring guest memory.
        let callback_id = self.reserve_callback_frame_id()?;
        let allocation = match self.heap.alloc(memory, OwnerId(1),
            record_bytes as u32, AllocationFlags::fixed().with_zero_init()) {
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
        self.object_callbacks.push(ObjectCallbackFrame {
            callback_id, saved: cpu.regs.clone(), return_to, callback, parameter, records, record_bytes,
            next_index: 0, last_result: 0, allocation: Some(allocation),
            allocation_locked: true, data, active_call: None,
        });
        self.push_callback_kind(CallbackKind::GdiObject, callback_id)?;
        if !self.schedule_object_callback(cpu, dos, memory)? {
            self.complete_object_enumeration(cpu)?;
        }
        Ok(None)
    }

    fn encode_object_record(
        &mut self, record: Win16HostGdiObjectRecord, object_type: i16,
    ) -> Result<Option<ObjectRecord>, RuntimeError> {
        let mut bytes = [0; LOGPEN16_SIZE];
        let mut pattern_identity = None;
        match (object_type, record) {
            (1, Win16HostGdiObjectRecord::Pen(pen)) => {
                bytes = LogPen16 { style: pen.style, width_x: pen.width_x,
                    width_y: pen.width_y, color: pen.color }.encode();
            }
            (2, Win16HostGdiObjectRecord::Brush { brush, pattern }) => {
                let hatch = match (brush.style, pattern) {
                    (3 | 5, Some(pattern)) => {
                        let handle = self.guest_gdi.existing_object(pattern)
                            .or_else(|| self.guest_gdi.allocate_object(pattern));
                        let Some(handle) = handle else { return Ok(None); };
                        pattern_identity = Some((handle, pattern));
                        handle as i16
                    }
                    (0 | 1 | 2 | 4, None) => brush.hatch as u16 as i16,
                    _ => return Err(RuntimeError::new(Kind::HostFailure,
                        "enumerated brush has inconsistent pattern identity")),
                };
                bytes[..LOGBRUSH16_SIZE].copy_from_slice(&LogBrush16 {
                    style: brush.style, color: brush.color, hatch,
                }.encode());
            }
            _ => return Err(RuntimeError::new(Kind::HostFailure,
                "native GDI enumeration returned a different object type")),
        }
        Ok(Some(ObjectRecord { bytes, pattern: pattern_identity }))
    }

    fn schedule_object_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let frame = self.object_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 GDI object callback frame is missing"))?;
        let record = frame.records.get(frame.next_index).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 GDI object callback record is missing"))?;
        if let Some((handle, expected)) = record.pattern {
            // A previous guest callback can delete an owned pattern bitmap
            // and eventually reuse its WORD handle. Never expose that new
            // object through an older enumeration snapshot, or resurrect a
            // retired host token under another guest alias.
            if self.guest_gdi.object(handle) != Some(expected) {
                self.object_callbacks.last_mut().expect("frame checked").last_result = 0;
                return Ok(false);
            }
        }
        self.selectors.write(memory, frame.data, &record.bytes[..frame.record_bytes])
            .map_err(crate::runtime_error)?;
        let callback = frame.callback;
        let parameter = frame.parameter as u32;
        let data_far = frame.data.far_value();
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
                    bytes: frame.record_bytes as u32,
                },
                Win16FarCallbackArgument::Dword(parameter),
            ],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )?;
        let frame = self.object_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 GDI object callback frame disappeared"))?;
        frame.next_index += 1;
        frame.active_call = Some(active_call);
        // The WOW16 GOBJENUMPROC entry starts with DS = ES = SS. A procedure
        // instance thunk may then load its instance DS. The checked owner
        // retains the original caller segments and already pins SS.
        cpu.regs.ds = cpu.regs.ss;
        cpu.regs.es = cpu.regs.ss;
        Ok(true)
    }

    pub(crate) fn finish_object_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::GdiObject)?;
        if self.object_callbacks.last().is_none_or(|frame| frame.callback_id != callback_id) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GDI object callback identity changed before guest return"));
        }
        let mut active_call = self.object_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take()).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 callback gate has no active call"))?;
        let callback_result = match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active_call) {
            Ok(value) => value,
            Err(error) => {
                self.object_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
        };
        let continue_enumeration = {
            let frame = self.object_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 GDI object callback frame disappeared"))?;
            frame.last_result = callback_result as u16;
            frame.last_result != 0 && frame.next_index < frame.records.len()
        };
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.object_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
            return Err(error);
        }
        self.object_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
        if continue_enumeration {
            let completed_call = self.object_callbacks.last_mut().expect("frame checked").active_call.take();
            if self.schedule_object_callback(cpu, dos, memory)? {
                return Ok(());
            }
            self.object_callbacks.last_mut().expect("frame checked").active_call = completed_call;
        }
        self.complete_object_enumeration(cpu)
    }

    fn complete_object_enumeration(&mut self, cpu: &mut Cpu) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::GdiObject)?;
        let (allocation, allocation_locked, saved, return_to, last_result) = {
            let frame = self.object_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 GDI object callback frame disappeared"))?;
            if frame.callback_id != callback_id {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 GDI object completion has a different callback identity"));
            }
            (frame.allocation, frame.allocation_locked, frame.saved.clone(),
                frame.return_to, frame.last_result)
        };
        if let Some(allocation) = allocation {
            if allocation_locked {
                self.heap.unlock(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
                self.object_callbacks.last_mut().expect("frame checked").allocation_locked = false;
            }
            self.heap.free(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
            self.object_callbacks.last_mut().expect("frame checked").allocation = None;
        }

        cpu.regs = saved;
        self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
            return_to.2, u32::from(last_result), Win16ReturnKind::Word)?;
        let frame = self.object_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 GDI object callback frame disappeared"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::GdiObject, callback_id) {
            self.object_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_object_callback_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::GdiObject)?;
        let frame = self.object_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "top GDI object callback has no family frame"))?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "top GDI object callback identity differs from its family frame"));
        }
        if let Some(mut active_call) = self.object_callbacks.last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended, CallbackKind::GdiObject, callback_id, cpu, dos, memory, &mut active_call,
            ) {
                self.object_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
            self.object_callbacks.last_mut().expect("frame checked").active_call = Some(active_call);
        }
        let (allocation, locked) = self.object_callbacks.last().map(|frame|
            (frame.allocation, frame.allocation_locked)).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "GDI object callback frame disappeared during teardown"))?;
        if let Some(allocation) = allocation {
            if locked {
                self.heap.unlock(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
                self.object_callbacks.last_mut().expect("frame checked").allocation_locked = false;
            }
            self.heap.free(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
            self.object_callbacks.last_mut().expect("frame checked").allocation = None;
        }
        let frame = self.object_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "GDI object callback frame disappeared during teardown"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::GdiObject, callback_id) {
            self.object_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }
}

