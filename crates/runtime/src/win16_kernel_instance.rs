//! Guest-memory KERNEL instance and NE segment information queries.

use guest_core::Selector;
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer};
use zerocopy::byteorder::little_endian::U16;
use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{Win16State, module_registry::ModuleState};
use crate::{DiagnosticKind as Kind, RuntimeError};

const NE_SEGMENT_DATA: u16 = 0x0001;
const SEGINFO16_SIZE: usize = 16;

/// Windows 3.1 SEGINFO is eight little-endian 16-bit fields. `zerocopy`
/// keeps its packed guest layout explicit without borrowing guest memory.
#[derive(Clone, Copy, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SegInfo16 {
    off_segment: U16,
    cb_segment: U16,
    flags: U16,
    cb_alloc: U16,
    handle: U16,
    align_shift: U16,
    reserved: [U16; 2],
}

#[derive(Clone, Copy)]
struct NeSegmentInfo {
    handle: u16,
    off_segment: u16,
    cb_segment: u16,
    flags: u16,
    cb_alloc: u16,
    align_shift: u16,
}

impl Win16State {
    /// Copy the same data-segment offset from a previous module instance into
    /// the caller's DS. Invalid handles, signed lengths, and guest ranges use
    /// the documented zero result and leave the destination untouched.
    pub(super) fn kernel_get_instance_data(
        &self,
        previous_instance: u16,
        buffer_offset: u16,
        byte_count: u16,
        current_ds: u16,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let count = i16::from_le_bytes(byte_count.to_le_bytes());
        if previous_instance == 0 || count <= 0 {
            return Ok(0);
        }
        let length = usize::from(count as u16);
        let end = u32::from(buffer_offset) + u32::from(count as u16);
        if end > 0x1_0000 {
            return Ok(0);
        }

        let Some(module_handle) = self.module_handle_for_instance(previous_instance) else {
            return Ok(0);
        };
        let Some(record) = self.modules.records.get(&module_handle) else {
            return Ok(0);
        };
        let Some(definition) = record.definition.as_ref() else {
            return Ok(0);
        };
        let data_segment_number = definition.header.automatic_data_segment;
        if data_segment_number == 0 {
            return Ok(0);
        }
        let Some(loaded) = record.loaded.as_ref() else {
            return Ok(0);
        };
        let Some(data_selector) = loaded.segment_selector(data_segment_number) else {
            return Ok(0);
        };
        let Some(segment) = definition
            .segments
            .iter()
            .find(|segment| segment.number == data_segment_number)
        else {
            return Ok(0);
        };
        let Some(&data_handle) = self.loaded_segment_handles.get(&data_selector.0) else {
            return Ok(0);
        };
        if previous_instance != record.instance
            && previous_instance != data_selector.0
            && previous_instance != data_handle
        {
            return Ok(0);
        }
        if segment.flags & NE_SEGMENT_DATA == 0 {
            return Ok(0);
        }

        let Ok(source_selector) = self.selectors.reference(data_selector) else {
            return Ok(0);
        };
        let Ok(destination_selector) = self.selectors.reference(Selector(current_ds)) else {
            return Ok(0);
        };
        let source = SegmentedPointer::new(source_selector, buffer_offset);
        let destination = SegmentedPointer::new(destination_selector, buffer_offset);
        if self
            .selectors
            .translate(source, Access::Read, length, memory)
            .is_err()
            || self
                .selectors
                .translate(destination, Access::Write, length, memory)
                .is_err()
        {
            return Ok(0);
        }

        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() {
            return Ok(0);
        }
        bytes.resize(length, 0);
        if self.selectors.read(memory, source, &mut bytes).is_err() {
            return Ok(0);
        }
        if self.selectors.write(memory, destination, &bytes).is_err() {
            return Ok(0);
        }
        Ok(count as u16)
    }

    /// Return the guest HGLOBAL of the loaded code segment containing a
    /// direct FARPROC or runtime-owned MakeProcInstance thunk. This runtime
    /// eagerly loads NE segments and has no code-segment eviction queue.
    pub(super) fn kernel_get_code_handle(&self, procedure: u32, memory: &Memory) -> u32 {
        let procedure = self.proc_instance_target(procedure).unwrap_or(procedure);
        let Ok(pointer) = self.selectors.pointer_from_far(procedure) else {
            return 0;
        };
        if self
            .selectors
            .translate(pointer, Access::Execute, 1, memory)
            .is_err()
        {
            return 0;
        }
        self.ne_segment_by_selector(pointer.selector().raw().0, true)
            .map_or(0, |segment| u32::from(segment.handle))
    }

    /// Fill the documented 16-byte SEGINFO for a loaded guest NE segment.
    /// The input may be a FARPROC/MakeProcInstance thunk or the documented
    /// module-handle:segment-number packed pair. The catalog marks this API
    /// void, so the dispatcher preserves caller return registers.
    pub(super) fn kernel_get_code_info(
        &self,
        procedure_or_module_segment: u32,
        output: u32,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some(segment) = self.ne_segment_for_code_info(procedure_or_module_segment, memory)
        else {
            return Ok(0);
        };
        let Ok(output) = self.selectors.pointer_from_far(output) else {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "KERNEL GetCodeInfo output is not a valid guest far pointer",
            ));
        };
        if self
            .selectors
            .translate(output, Access::Write, SEGINFO16_SIZE, memory)
            .is_err()
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "KERNEL GetCodeInfo output does not contain a writable SEGINFO",
            ));
        }

        let wire = SegInfo16 {
            off_segment: U16::new(segment.off_segment),
            cb_segment: U16::new(segment.cb_segment),
            flags: U16::new(segment.flags),
            cb_alloc: U16::new(segment.cb_alloc),
            handle: U16::new(segment.handle),
            align_shift: U16::new(segment.align_shift),
            reserved: [U16::new(0); 2],
        };
        self.selectors
            .write(memory, output, wire.as_bytes())
            .map_err(crate::runtime_error)?;
        Ok(0)
    }

    fn ne_segment_for_code_info(
        &self,
        procedure_or_module_segment: u32,
        memory: &Memory,
    ) -> Option<NeSegmentInfo> {
        let module_handle = (procedure_or_module_segment >> 16) as u16;
        let segment_number = procedure_or_module_segment as u16;
        if let Some(record) = self.modules.records.get(&module_handle) {
            if record.handle == module_handle
                && record.external_application.is_none()
                && !matches!(record.state, ModuleState::Unloading | ModuleState::Retired)
            {
                return self.ne_segment_by_number(record.handle, segment_number);
            }
        }

        let procedure = self
            .proc_instance_target(procedure_or_module_segment)
            .unwrap_or(procedure_or_module_segment);
        let pointer = self.selectors.pointer_from_far(procedure).ok()?;
        self.selectors
            .translate(pointer, Access::Execute, 1, memory)
            .ok()?;
        self.ne_segment_by_selector(pointer.selector().raw().0, true)
    }

    fn ne_segment_by_number(&self, module: u16, number: u16) -> Option<NeSegmentInfo> {
        if number == 0 {
            return None;
        }
        let record = self.modules.records.get(&module)?;
        let loaded = record.loaded.as_ref()?;
        let loaded_segment = loaded
            .segments
            .iter()
            .find(|segment| segment.number == number)?;
        self.ne_segment_info(record, loaded_segment.selector.0, number)
    }

    fn ne_segment_by_selector(&self, selector: u16, require_code: bool) -> Option<NeSegmentInfo> {
        for record in self.modules.records.values() {
            if record.external_application.is_some()
                || matches!(record.state, ModuleState::Unloading | ModuleState::Retired)
            {
                continue;
            }
            let Some(loaded) = record.loaded.as_ref() else {
                continue;
            };
            let Some(segment) = loaded
                .segments
                .iter()
                .find(|segment| segment.selector.0 == selector)
            else {
                continue;
            };
            let Some(definition) = record.definition.as_ref() else {
                continue;
            };
            let Some(source) = definition
                .segments
                .iter()
                .find(|source| source.number == segment.number)
            else {
                continue;
            };
            if require_code && source.flags & NE_SEGMENT_DATA != 0 {
                return None;
            }
            return self.ne_segment_info(record, selector, segment.number);
        }
        None
    }

    fn ne_segment_info(
        &self,
        record: &super::module_registry::ModuleRecord,
        selector: u16,
        number: u16,
    ) -> Option<NeSegmentInfo> {
        let definition = record.definition.as_ref()?;
        let segment = definition
            .segments
            .iter()
            .find(|segment| segment.number == number)?;
        let alignment_shift = definition.header.alignment_shift;
        if alignment_shift > 15 {
            return None;
        }
        let off_segment = match segment.file_offset {
            Some(offset) => {
                let offset = u32::try_from(offset).ok()?;
                u16::try_from(offset >> u32::from(alignment_shift)).ok()?
            }
            None => 0,
        };
        let cb_segment = size_word(segment.file_size)?;
        let allocation = record
            .allocations
            .iter()
            .find(|allocation| allocation.selector.raw().0 == selector)?;
        let cb_alloc = size_word(self.heap.reserved_capacity(allocation.handle).ok()?)?;
        let handle = *self.loaded_segment_handles.get(&selector)?;
        Some(NeSegmentInfo {
            handle,
            off_segment,
            cb_segment,
            flags: segment.flags,
            cb_alloc,
            align_shift: alignment_shift,
        })
    }
}

/// Windows encodes a 64 KiB segment size as zero in SEGINFO.
fn size_word(size: u32) -> Option<u16> {
    if size == 0x1_0000 {
        Some(0)
    } else {
        u16::try_from(size).ok()
    }
}
