//! Guest execution frames for GDI font enumeration callbacks.
//!
//! Native GDI enumeration finishes before these frames are scheduled. The
//! copied records are serialized into guest-owned memory one at a time; the
//! normal instruction loop executes every guest callback and nested API call.

use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers};
use guest_core::memory::Memory;
use win16_abi::{
    Access, AllocationFlags, GlobalHandle, SegmentedPointer, Win16Error, Win16GdiInternalArg,
    Win16GdiInternalRequest, Win16ReturnKind,
};
use win16_abi::gdi_abi::{LogFont16, LOGFONT16_SIZE, TextMetric16, TEXTMETRIC16_SIZE};

use super::{CallbackKind, Win16State};
use x86_cpu::Cpu;
use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostFontRecord};

const LOGFONT16_BYTES: usize = 50;
const NEWTEXTMETRIC16_BYTES: usize = 41;
const ENUMLOGFONT16_BYTES: usize = 146;
/// `ENUMLOGFONT` plus the 32-byte `elfScript` field of `ENUMLOGFONTEX`.
const ENUMLOGFONTEX16_BYTES: usize = 178;
/// `NEWTEXTMETRIC` plus the 24-byte `FONTSIGNATURE`.
const NEWTEXTMETRICEX16_BYTES: usize = 65;
const FONT_RECORD_BYTES: usize = ENUMLOGFONTEX16_BYTES + NEWTEXTMETRICEX16_BYTES;

#[derive(Clone, Copy)]
pub(super) enum FontEnumerationMode { Fonts, Families, FamiliesEx }

impl FontEnumerationMode {
    fn font_bytes(self) -> usize {
        match self {
            Self::Fonts => LOGFONT16_BYTES,
            Self::Families => ENUMLOGFONT16_BYTES,
            Self::FamiliesEx => ENUMLOGFONTEX16_BYTES,
        }
    }

    fn metric_bytes(self) -> usize {
        match self {
            Self::Fonts | Self::Families => NEWTEXTMETRIC16_BYTES,
            Self::FamiliesEx => NEWTEXTMETRICEX16_BYTES,
        }
    }
}
const CALLBACK_STACK_BYTES: u16 = 18; // FAR return, two FAR pointers, WORD, DWORD.

pub(super) struct FontCallbackFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    callback: u32,
    parameter: i32,
    records: Vec<Win16HostFontRecord>,
    mode: FontEnumerationMode,
    next_index: usize,
    last_result: u16,
    allocation: Option<GlobalHandle>,
    allocation_locked: bool,
    data: SegmentedPointer,
    active_call: Option<Win16FarCallbackFrame>,
}

fn fit_i16<const N: usize>(values: [i32; N]) -> Option<[i16; N]> {
    let mut narrowed = [0_i16; N];
    for (slot, value) in narrowed.iter_mut().zip(values) {
        *slot = i16::try_from(value).ok()?;
    }
    Some(narrowed)
}

/// Windows 3.1 `LOGFONT` and `TEXTMETRIC` store these fields as signed 16-bit
/// ints. `NEWTEXTMETRIC` stores `ntmSizeEM`, `ntmCellHeight`, and `ntmAvgWidth`
/// as 16-bit unsigned ints. A value outside that range is omitted, not clamped.
fn encode_font(record: &Win16HostFontRecord, mode: FontEnumerationMode)
    -> Option<[u8; FONT_RECORD_BYTES]>
{
    let mut bytes = [0_u8; FONT_RECORD_BYTES];
    let dimensions = fit_i16(record.logfont_dimensions)?;
    for (index, value) in dimensions.iter().enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[10..18].copy_from_slice(&record.logfont_styles);
    bytes[18..50].copy_from_slice(&record.face_name);
    if matches!(mode, FontEnumerationMode::Families | FontEnumerationMode::FamiliesEx) {
        bytes[50..114].copy_from_slice(&record.full_name);
        bytes[114..146].copy_from_slice(&record.style);
    }
    if matches!(mode, FontEnumerationMode::FamiliesEx) {
        bytes[146..178].copy_from_slice(&record.script_name);
    }
    let metric = mode.font_bytes();
    let encoded = TextMetric16 {
        dimensions: fit_i16(record.textmetric_dimensions)?,
        styles: record.textmetric_styles,
        extra: fit_i16(record.textmetric_extra)?,
    }.encode();
    bytes[metric..metric + TEXTMETRIC16_SIZE].copy_from_slice(&encoded);
    if let Some([flags, em, cell, average]) = record.newtextmetric_extra {
        bytes[metric + 31..metric + 35].copy_from_slice(&flags.to_le_bytes());
        for (index, value) in [em, cell, average].into_iter().enumerate() {
            let narrowed = u16::try_from(value).ok()?;
            let at = metric + 35 + index * 2;
            bytes[at..at + 2].copy_from_slice(&narrowed.to_le_bytes());
        }
    }
    if let FontEnumerationMode::FamiliesEx = mode {
        if let Some(signature) = record.font_signature {
            let at = metric + NEWTEXTMETRIC16_BYTES;
            for (index, word) in signature.iter().enumerate() {
                let offset = at + index * 4;
                bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
    }
    Some(bytes)
}

fn slot(kind: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        format!("EnumFontFamiliesEx is missing a {kind} argument"))
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
        mode: FontEnumerationMode,
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
        let records = match mode {
            FontEnumerationMode::Fonts => host.win16_enum_fonts(native_dc, face_name)?,
            FontEnumerationMode::Families => host.win16_enum_font_families(native_dc, face_name)?,
            FontEnumerationMode::FamiliesEx => return Err(RuntimeError::new(
                Kind::InternalInvariant, "EnumFontFamiliesEx is not a face-name enumeration")),
        };
        self.open_font_enumeration(cpu, dos, memory, mode, callback, parameter, return_to, records)
    }

    pub(super) fn begin_enum_font_families_ex(
        &mut self, cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        host: &mut impl RuntimeHost, request: Win16GdiInternalRequest,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let args = &request.arguments;
        let dc = match args.first() {
            Some(Win16GdiInternalArg::Word(value)) => *value,
            _ => return Err(slot("hdc")),
        };
        let logfont = match args.get(1) {
            Some(Win16GdiInternalArg::Far(value)) => *value,
            _ => return Err(slot("LOGFONT")),
        };
        let callback = match args.get(2) {
            Some(Win16GdiInternalArg::Far(value)) => *value,
            _ => return Err(slot("callback")),
        };
        let parameter = match args.get(3) {
            Some(Win16GdiInternalArg::Dword(value)) => *value as i32,
            _ => return Err(slot("lParam")),
        };
        let flags = match args.get(4) {
            Some(Win16GdiInternalArg::Dword(value)) => *value,
            _ => return Err(slot("dwFlags")),
        };
        let Some(native_dc) = self.guest_gdi.dc(dc) else {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        // EnumFontFamiliesEx requires the LOGFONT. A null pointer fails and
        // does not enumerate.
        if logfont == 0 {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        }
        let pointer = self.selectors.pointer_from_far(logfont).map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, LOGFONT16_SIZE)?;
        let font = LogFont16::decode(&bytes).map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 LOGFONT decode rejected a full record"))?;
        // lfFaceName is a fixed NUL-terminated field. An unterminated 32-byte
        // array is not passed through as a C string.
        let Some(end) = font.face_name.iter().position(|byte| *byte == 0) else {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        let records = host.win16_enum_font_families_ex(
            native_dc, &font.face_name[..end], font.styles[3], font.styles[7], flags,
        )?;
        self.open_font_enumeration(
            cpu, dos, memory, FontEnumerationMode::FamiliesEx, callback, parameter, return_to,
            records,
        )
    }

    fn open_font_enumeration(
        &mut self, cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        mode: FontEnumerationMode, callback: u32, parameter: i32, return_to: (u16, u16, u32),
        records: Option<Vec<Win16HostFontRecord>>,
    ) -> Result<Option<u8>, RuntimeError> {
        // None is a native DC that could not be leased. That is a failed call.
        let Some(mut records) = records else {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        // Omit a font whose signed or unsigned 16-bit fields do not fit.
        // The callback buffer is not written for that font.
        records.retain(|record| encode_font(record, mode).is_some());
        if records.is_empty() {
            // Windows 3.1 DDK EnumDFonts returns 1 when no font matches.
            // EnumFontFamilies does the same when the callback is not called.
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 1, Win16ReturnKind::Word);
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
            (mode.font_bytes() + mode.metric_bytes()) as u32, AllocationFlags::fixed().with_zero_init()) {
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
            callback_id, saved: cpu.regs.clone(), return_to, callback, parameter, records, mode,
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
        let bytes = encode_font(record, frame.mode).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 font record was kept after a 16-bit field did not fit"))?;
        let stored = frame.mode.font_bytes() + frame.mode.metric_bytes();
        self.selectors.write(memory, frame.data, &bytes[..stored]).map_err(crate::runtime_error)?;
        let metric = self.selectors.add_bytes(frame.data, frame.mode.font_bytes() as u32)
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
                    bytes: frame.mode.font_bytes() as u32,
                },
                Win16FarCallbackArgument::GuestPointer {
                    far: metric_far,
                    access: Access::Read,
                    bytes: frame.mode.metric_bytes() as u32,
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

#[cfg(test)]
#[path = "win16_font_callback_tests.rs"]
mod tests;
