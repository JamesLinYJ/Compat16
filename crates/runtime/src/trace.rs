//! Opt-in bounded instruction history for failure diagnosis.
//! Reads only the process-owned guest bus; it cannot access host physical RAM.

use std::collections::VecDeque;
use std::fmt::Write;
use std::ops::Range;
use crate::{DiagnosticKind, RuntimeError};
use guest_core::{
    AtomicMemoryRange, GuestMemory, MemoryError, PhysAddr, Registers, memory::Memory, real_address,
};
use win16_abi::SelectorTable;

const CAPACITY: usize = 64;

struct Entry {
    instruction_count: u64,
    registers: Registers,
    bytes: [u8; 15],
    readable: usize,
    a20_enabled: bool,
}

pub(crate) struct InstructionTrace { entries: VecDeque<Entry> }

impl InstructionTrace {
    pub(crate) fn new() -> Result<Self, RuntimeError> {
        let mut entries = VecDeque::new();
        entries.try_reserve_exact(CAPACITY)
            .map_err(|error| RuntimeError::with_source(DiagnosticKind::ResourceExhausted, "allocate bounded instruction trace", error))?;
        Ok(Self { entries })
    }

    pub(crate) fn record(&mut self, count: u64, registers: &Registers, memory: &mut Memory) {
        let mut entry = Entry {
            instruction_count: count, registers: registers.clone(), bytes: [0; 15],
            readable: 0, a20_enabled: memory.a20_enabled(),
        };
        let bus = memory.bus();
        for offset in 0..15u16 {
            let address = real_address(registers.cs, registers.ip().wrapping_add(offset));
            let Ok(byte) = bus.read_u8(address) else { break; };
            entry.bytes[usize::from(offset)] = byte;
            entry.readable += 1;
        }
        if self.entries.len() == CAPACITY { self.entries.pop_front(); }
        self.entries.push_back(entry);
    }

    pub(crate) fn record_win16(
        &mut self,
        count: u64,
        registers: &Registers,
        memory: &Memory,
        selectors: &SelectorTable,
    ) {
        let mut entry = Entry {
            instruction_count: count, registers: registers.clone(), bytes: [0; 15],
            readable: 0, a20_enabled: memory.a20_enabled(),
        };
        for offset in 0..15_u16 {
            let Some(ip) = registers.ip().checked_add(offset) else { break; };
            let Ok(pointer) = selectors.pointer_from_raw(guest_core::Selector(registers.cs), ip)
                else { break; };
            let Ok(()) = selectors.read(memory, pointer,
                &mut entry.bytes[usize::from(offset)..usize::from(offset) + 1])
                else { break; };
            entry.readable += 1;
        }
        if self.entries.len() == CAPACITY { self.entries.pop_front(); }
        self.entries.push_back(entry);
    }

    pub(crate) fn format(&self) -> String {
        let mut text = String::new();
        for entry in &self.entries {
            let r = &entry.registers;
            let _ = write!(text, "#{} {:04X}:{:08X} SS:SP={:04X}:{:08X} DS={:04X} ES={:04X} AX={:08X} BX={:08X} CX={:08X} DX={:08X} SI={:08X} DI={:08X} BP={:08X} FLAGS={:08X} A20={} bytes=",
                entry.instruction_count, r.cs, r.eip, r.ss, r.esp, r.ds, r.es, r.eax, r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp, r.eflags, u8::from(entry.a20_enabled));
            for byte in &entry.bytes[..entry.readable] { let _ = write!(text, "{byte:02X}"); }
            if entry.readable < entry.bytes.len() { text.push_str(" <unreadable>"); }
            text.push('\n');
        }
        text
    }
}

const WATCH_RECENT_CHANGES: usize = 256;
pub(crate) const MAX_GUEST_MEMORY_WATCH_BYTES: u32 = 4096;

/// The runtime boundary at which a guest-memory write was requested.
#[derive(Clone, Copy)]
pub(crate) enum GuestWriteBoundary {
    CpuStep,
    InterruptEntry,
    DosInterrupt,
    DosCharacterService,
    BiosDeviceService,
    XmsService,
    MouseCallback,
    DeviceClock,
    DosSystemTables,
}

impl GuestWriteBoundary {
    fn name(self) -> &'static str {
        match self {
            Self::CpuStep => "cpu-step",
            Self::InterruptEntry => "interrupt-entry",
            Self::DosInterrupt => "dos-interrupt-service",
            Self::DosCharacterService => "dos-character-service",
            Self::BiosDeviceService => "bios-device-service",
            Self::XmsService => "xms-service",
            Self::MouseCallback => "mouse-callback-entry",
            Self::DeviceClock => "device-clock",
            Self::DosSystemTables => "dos-system-tables",
        }
    }
}

enum MemoryWriteData {
    WriteInput(Vec<u8>),
    AtomicTransform { input: Vec<u8>, output: Vec<u8> },
}

impl MemoryWriteData {
    fn try_clone(&self) -> Option<Self> {
        match self {
            Self::WriteInput(input) => Some(Self::WriteInput(try_copy_bytes(input)?)),
            Self::AtomicTransform { input, output } => Some(Self::AtomicTransform {
                input: try_copy_bytes(input)?,
                output: try_copy_bytes(output)?,
            }),
        }
    }
}

struct MemoryChange {
    instruction_count: u64,
    boundary: GuestWriteBoundary,
    cs: u16,
    eip: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    esp: u32,
    ebp: u32,
    eflags: u32,
    ds: u16,
    es: u16,
    ss: u16,
    code: [u8; 15],
    code_readable: usize,
    write_ranges: Vec<AtomicMemoryRange>,
    write_data: MemoryWriteData,
}

impl MemoryChange {
    fn try_clone(&self) -> Option<Self> {
        let mut write_ranges = Vec::new();
        write_ranges
            .try_reserve_exact(self.write_ranges.len())
            .ok()?;
        write_ranges.extend_from_slice(&self.write_ranges);
        Some(Self {
            instruction_count: self.instruction_count,
            boundary: self.boundary,
            cs: self.cs,
            eip: self.eip,
            eax: self.eax,
            ebx: self.ebx,
            ecx: self.ecx,
            edx: self.edx,
            esi: self.esi,
            edi: self.edi,
            esp: self.esp,
            ebp: self.ebp,
            eflags: self.eflags,
            ds: self.ds,
            es: self.es,
            ss: self.ss,
            code: self.code,
            code_readable: self.code_readable,
            write_ranges,
            write_data: self.write_data.try_clone()?,
        })
    }
}

fn try_copy_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).ok()?;
    copy.extend_from_slice(bytes);
    Some(copy)
}

/// Opt-in diagnostic history for one bounded physical guest-memory range.
/// The first write records and a separate recent ring are retained independently of
/// the rolling instruction trace.
pub(crate) struct GuestMemoryWriteWatch {
    address: u32,
    length: usize,
    first: Option<MemoryChange>,
    recent: VecDeque<MemoryChange>,
    records: u64,
    incomplete: u64,
    need_cpu_history: bool,
    cpu_history: Option<String>,
}

impl GuestMemoryWriteWatch {
    pub(crate) fn new(address: u32, length: u32) -> Result<Self, RuntimeError> {
        if length == 0 || length > MAX_GUEST_MEMORY_WATCH_BYTES {
            return Err(RuntimeError::new(
                DiagnosticKind::InvalidInput,
                format!("guest memory watch length must be between 1 and {MAX_GUEST_MEMORY_WATCH_BYTES} bytes"),
            ));
        }
        address.checked_add(length).ok_or_else(|| RuntimeError::new(
            DiagnosticKind::InvalidInput,
            "guest memory watch range overflows the physical address space",
        ))?;

        let mut recent = VecDeque::new();
        recent.try_reserve_exact(WATCH_RECENT_CHANGES).map_err(|error| {
            RuntimeError::with_source(DiagnosticKind::ResourceExhausted, "allocate recent guest memory watch history", error)
        })?;
        Ok(Self {
            address,
            length: length as usize,
            first: None,
            recent,
            records: 0,
            incomplete: 0,
            need_cpu_history: false,
            cpu_history: None,
        })
    }

    pub(crate) fn take_cpu_history_request(&mut self) -> bool {
        std::mem::take(&mut self.need_cpu_history)
    }

    pub(crate) fn set_cpu_history(&mut self, history: String) {
        if self.cpu_history.is_none() { self.cpu_history = Some(history); }
    }

    fn overlaps(&self, address: PhysAddr, length: usize) -> bool {
        if length == 0 { return false; }
        let write_start = u64::from(address.0);
        let write_end = write_start.saturating_add(length as u64);
        let watch_start = u64::from(self.address);
        let watch_end = watch_start + self.length as u64;
        write_start < watch_end && watch_start < write_end
    }

    fn record_write_input(
        &mut self,
        context: WriteContext,
        write_ranges: &[AtomicMemoryRange],
        input: Vec<u8>,
    ) {
        self.record_write_data(context, write_ranges, MemoryWriteData::WriteInput(input));
    }

    fn record_atomic_transform(
        &mut self,
        context: WriteContext,
        write_ranges: &[AtomicMemoryRange],
        input: Vec<u8>,
        output: Vec<u8>,
    ) {
        self.record_write_data(
            context,
            write_ranges,
            MemoryWriteData::AtomicTransform { input, output },
        );
    }

    fn record_write_data(
        &mut self,
        context: WriteContext,
        write_ranges: &[AtomicMemoryRange],
        write_data: MemoryWriteData,
    ) {
        let mut write_ranges_copy = Vec::new();
        if write_ranges_copy
            .try_reserve_exact(write_ranges.len())
            .is_err()
        {
            self.incomplete = self.incomplete.saturating_add(1);
            return;
        }
        write_ranges_copy.extend_from_slice(write_ranges);
        let change = MemoryChange {
            instruction_count: context.instruction_count,
            boundary: context.boundary,
            cs: context.cs,
            eip: context.eip,
            eax: context.eax,
            ebx: context.ebx,
            ecx: context.ecx,
            edx: context.edx,
            esi: context.esi,
            edi: context.edi,
            esp: context.esp,
            ebp: context.ebp,
            eflags: context.eflags,
            ds: context.ds,
            es: context.es,
            ss: context.ss,
            code: context.code,
            code_readable: context.code_readable,
            write_ranges: write_ranges_copy,
            write_data,
        };
        if self.first.is_none() {
            if let Some(first) = change.try_clone() {
                self.first = Some(first);
            } else {
                self.incomplete = self.incomplete.saturating_add(1);
            }
        }
        if self.recent.len() == WATCH_RECENT_CHANGES { self.recent.pop_front(); }
        self.recent.push_back(change);
        self.records = self.records.saturating_add(1);
        if matches!(context.boundary, GuestWriteBoundary::CpuStep) && self.cpu_history.is_none() {
            self.need_cpu_history = true;
        }
    }

    pub(crate) fn format(&self) -> String {
        use std::fmt::Write;
        let mut output = String::new();
        let end = u64::from(self.address) + self.length as u64;
        let _ = writeln!(output,
            "guest memory watch: 0x{:08X}..0x{:08X} ({} bytes); records={}, incomplete={}",
            self.address, end, self.length, self.records, self.incomplete);
        if self.records == 0 && self.incomplete == 0 { output.push_str("  no overlapping writes recorded\n"); }
        if self.records == 0 && self.incomplete != 0 {
            output.push_str("  no complete write records; some overlapping writes could not be observed\n");
        }
        if let Some(history) = &self.cpu_history {
            output.push_str("instruction history captured at the first CPU write (oldest first):\n");
            output.push_str(history);
        }
        if let Some(change) = &self.first { format_memory_change(&mut output, "first", change); }
        let (first, second) = self.recent.as_slices();
        for change in first { format_memory_change(&mut output, "recent", change); }
        for change in second { format_memory_change(&mut output, "recent", change); }
        output
    }
}

#[derive(Clone, Copy)]
struct WriteContext {
    instruction_count: u64,
    boundary: GuestWriteBoundary,
    cs: u16,
    eip: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    esp: u32,
    ebp: u32,
    eflags: u32,
    ds: u16,
    es: u16,
    ss: u16,
    code: [u8; 15],
    code_readable: usize,
}

/// A transparent memory adapter used only at runtime execution/service
/// boundaries. Observation failures never change the guest operation result.
pub(crate) struct GuestMemoryWriteObserver<'a, M> {
    inner: M,
    watch: Option<&'a mut GuestMemoryWriteWatch>,
    context: WriteContext,
}

impl<'a, M: GuestMemory> GuestMemoryWriteObserver<'a, M> {
    pub(crate) fn new(inner: M, watch: Option<&'a mut GuestMemoryWriteWatch>, instruction_count: u64,
        registers: &Registers, boundary: GuestWriteBoundary) -> Self {
        Self {
            inner,
            watch,
            context: WriteContext {
                instruction_count,
                boundary,
                cs: registers.cs,
                eip: registers.eip,
                eax: registers.eax,
                ebx: registers.ebx,
                ecx: registers.ecx,
                edx: registers.edx,
                esi: registers.esi,
                edi: registers.edi,
                esp: registers.esp,
                ebp: registers.ebp,
                eflags: registers.eflags,
                ds: registers.ds,
                es: registers.es,
                ss: registers.ss,
                code: [0; 15],
                code_readable: 0,
            },
        }
    }
}

impl<M: GuestMemory> GuestMemory for GuestMemoryWriteObserver<'_, M> {
    fn len(&self) -> u32 { self.inner.len() }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.inner.validate_read(address, length)
    }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.inner.validate_write(address, length)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.inner.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let Some(watch) = self.watch.as_deref() else {
            return self.inner.write(address, bytes);
        };
        let write_range = AtomicMemoryRange {
            offset: address.0,
            length: bytes.len(),
        };
        if !watch.overlaps(address, bytes.len()) {
            return self.inner.write(address, bytes);
        }
        // GuestMemory has no side-effect-free inspection contract. Record the
        // accepted write input instead of rereading device or storage state.
        let context = self.context;
        let mut watched_ranges = Vec::new();
        let mut watched_slices = Vec::new();
        let mut input = Vec::new();
        let mut capture_length = 0usize;
        let mut capture_ready = watch_write_slices(
            std::slice::from_ref(&write_range),
            watch,
            bytes.len(),
            &mut watched_ranges,
            &mut watched_slices,
        )
        .map(|length| {
            capture_length = length;
            true
        })
        .unwrap_or(false);
        if capture_ready && input.try_reserve_exact(capture_length).is_err() {
            capture_ready = false;
        }
        if capture_ready {
            for range in &watched_slices {
                input.extend_from_slice(&bytes[range.clone()]);
            }
        }

        let result = self.inner.write(address, bytes);
        if result.is_ok() {
            if let Some(watch) = self.watch.as_deref_mut() {
                if capture_ready {
                    watch.record_write_input(context, &watched_ranges, input);
                } else {
                    watch.incomplete = watch.incomplete.saturating_add(1);
                }
            }
        }
        result
    }

    fn atomic_update(
        &mut self,
        ranges: &[AtomicMemoryRange],
        value: &mut [u8],
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        let Some(watch) = self.watch.as_deref() else {
            return self.inner.atomic_update(ranges, value, update);
        };
        let overlaps = ranges.iter().any(|range| {
            watch.overlaps(PhysAddr(range.offset), range.length)
        });
        if !overlaps {
            return self.inner.atomic_update(ranges, value, update);
        }

        // The atomic callback supplies the exact bytes seen by and produced
        // by the transform. Do not read watch-neighborhood or instruction
        // bytes through guest memory: mapped reads may change device state or
        // latch a fatal backing-storage error.
        let context = self.context;

        let mut watched_ranges = Vec::new();
        let mut watched_slices = Vec::new();
        let mut capture_length = 0;
        let mut capture_ready = watch_write_slices(
            ranges,
            watch,
            value.len(),
            &mut watched_ranges,
            &mut watched_slices,
        )
        .map(|length| {
            capture_length = length;
            true
        })
        .unwrap_or(false);
        let mut atomic_input = Vec::new();
        let mut atomic_output = Vec::new();
        if capture_ready
            && (atomic_input.try_reserve_exact(capture_length).is_err()
                || atomic_output.try_reserve_exact(capture_length).is_err())
        {
            capture_ready = false;
        }

        // Keep the CPU's single provider transaction intact. Pre-reserved
        // copies capture the actual watched bytes seen by and produced by the
        // transform; no allocation or second transform runs inside the
        // provider callback. These are exact transaction bytes, not a read of
        // the wider watch range.
        let value_length = value.len();
        let mut callback_seen = false;
        let mut capture_failed = false;
        let mut observed_update = |bytes: &mut [u8]| {
            let first_call = !callback_seen;
            callback_seen = true;
            if first_call && capture_ready {
                if bytes.len() != value_length {
                    capture_failed = true;
                } else {
                    for range in &watched_slices {
                        atomic_input.extend_from_slice(&bytes[range.clone()]);
                    }
                }
            }
            update(bytes);
            if first_call && capture_ready && !capture_failed {
                for range in &watched_slices {
                    atomic_output.extend_from_slice(&bytes[range.clone()]);
                }
            }
        };
        let result = self
            .inner
            .atomic_update(ranges, value, &mut observed_update);
        drop(observed_update);
        if let Some(watch) = self.watch.as_deref_mut() {
            if result.is_ok() && callback_seen && capture_ready && !capture_failed {
                watch.record_atomic_transform(context, &watched_ranges, atomic_input, atomic_output);
            } else if callback_seen || result.is_ok() {
                watch.incomplete = watch.incomplete.saturating_add(1);
            }
        }
        result
    }
}

fn watch_write_slices(
    ranges: &[AtomicMemoryRange],
    watch: &GuestMemoryWriteWatch,
    value_length: usize,
    watched_ranges: &mut Vec<AtomicMemoryRange>,
    watched_slices: &mut Vec<Range<usize>>,
) -> Option<usize> {
    watched_ranges.try_reserve_exact(ranges.len()).ok()?;
    watched_slices.try_reserve_exact(ranges.len()).ok()?;

    let watch_start = u64::from(watch.address);
    let watch_end = watch_start.checked_add(watch.length as u64)?;
    let mut value_offset = 0usize;
    let mut watched_length = 0usize;
    for range in ranges {
        let range_start = u64::from(range.offset);
        let range_length = u64::try_from(range.length).ok()?;
        let range_end = range_start.checked_add(range_length)?;
        let value_end = value_offset.checked_add(range.length)?;
        if value_end > value_length {
            return None;
        }
        let overlap_start = range_start.max(watch_start);
        let overlap_end = range_end.min(watch_end);
        if overlap_start < overlap_end {
            let start = value_offset
                .checked_add(usize::try_from(overlap_start - range_start).ok()?)?;
            let end = start.checked_add(usize::try_from(overlap_end - overlap_start).ok()?)?;
            watched_ranges.push(AtomicMemoryRange {
                offset: u32::try_from(overlap_start).ok()?,
                length: end - start,
            });
            watched_slices.push(start..end);
            watched_length = watched_length.checked_add(end - start)?;
        }
        value_offset = value_end;
    }
    if value_offset != value_length || watched_ranges.is_empty() {
        return None;
    }
    Some(watched_length)
}

fn format_memory_change(output: &mut String, retention: &str, change: &MemoryChange) {
    use std::fmt::Write;
    let _ = write!(output,
        "  {retention} #{:010} {} CS:IP={:04X}:{:08X} EAX={:08X} EBX={:08X} ECX={:08X} EDX={:08X} ESI={:08X} EDI={:08X} EBP={:08X} DS={:04X} ES={:04X} SS:ESP={:04X}:{:08X} EFLAGS={:08X} code=",
        change.instruction_count, change.boundary.name(), change.cs, change.eip,
        change.eax, change.ebx, change.ecx, change.edx, change.esi, change.edi,
        change.ebp, change.ds, change.es, change.ss, change.esp, change.eflags);
    if change.code_readable == 0 {
        output.push_str("<unreadable>");
    } else {
        for byte in &change.code[..change.code_readable] { let _ = write!(output, "{byte:02X}"); }
    }
    output.push_str(" write-ranges=");
    for (index, range) in change.write_ranges.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        let _ = write!(output, "0x{:08X}+0x{:X}", range.offset, range.length);
    }
    match &change.write_data {
        MemoryWriteData::WriteInput(input) => {
            output.push_str(" write-input=");
            write_hex(output, input);
        }
        MemoryWriteData::AtomicTransform { input, output: after } => {
            output.push_str(" atomic-input=");
            write_hex(output, input);
            output.push_str(" atomic-output=");
            write_hex(output, after);
        }
    }
    output.push('\n');
}

fn write_hex(output: &mut String, bytes: &[u8]) {
    use std::fmt::Write;
    for byte in bytes { let _ = write!(output, "{byte:02X}"); }
}

#[cfg(test)]
#[path = "trace_tests.rs"]
mod tests;
