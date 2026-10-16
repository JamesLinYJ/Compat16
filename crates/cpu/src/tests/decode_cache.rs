//! Differential cache checks, not an independent instruction-semantics oracle:
//! both fixtures deliberately share the checked decoder and executor.

use super::*;
use crate::execution_boundary::{ExecutionBoundaryReport, ExecutionProgress as Progress};
use crate::SegmentResolver;
use guest_core::io::{PortError, PortIo, PortWidth};
use std::{cell::RefCell, rc::Rc};

#[derive(Debug, PartialEq)]
enum Access {
    Execute(u32, bool),
    ValidateRead(u32, usize),
    Read(u32, usize),
    ValidateWrite(u32, usize),
    Write(u32, Vec<u8>),
    Input(u16, PortWidth),
}
type Trace = Rc<RefCell<Vec<Access>>>;

struct Memory { ram: Ram, trace: Trace }
impl GuestMemory for Memory {
    fn len(&self) -> u32 { self.ram.len() }
    fn validate_read(&self, address: PhysAddr, len: usize) -> Result<(), MemoryError> {
        self.trace.borrow_mut().push(Access::ValidateRead(address.0, len));
        self.ram.validate_read(address, len)
    }
    fn validate_write(&self, address: PhysAddr, len: usize) -> Result<(), MemoryError> {
        self.trace.borrow_mut().push(Access::ValidateWrite(address.0, len));
        self.ram.validate_write(address, len)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.trace.borrow_mut().push(Access::Read(address.0, bytes.len()));
        self.ram.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.trace.borrow_mut().push(Access::Write(address.0, bytes.to_vec()));
        self.ram.write(address, bytes)
    }
}

// Provider-level remapping/execute permission and code width, not a claim to
// model architectural paging, NX, or protected-segment descriptor behavior.
struct Segments { base: u32, bits: u32, denied: Option<u32>, trace: Trace }
impl SegmentResolver for Segments {
    fn code_bits(&self) -> u32 { self.bits }
    fn resolve(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        RealModeSegments.resolve(segment, offset, address32)
    }
    fn resolve_execute(&self, _segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        self.trace.borrow_mut().push(Access::Execute(offset, address32));
        if self.denied == Some(offset) {
            return Err(MemoryError::OutOfBounds { address: offset, length: 1 }.into());
        }
        Ok(PhysAddr(self.base + offset))
    }
}
struct Ports { trace: Trace, reads: usize, fail_after: Option<usize> }
impl PortIo for Ports {
    fn read(&mut self, port: u16, width: PortWidth) -> Result<u32, PortError> {
        self.trace.borrow_mut().push(Access::Input(port, width));
        if self.fail_after == Some(self.reads) {
            return Err(PortError::Unsupported { port, width, write: false });
        }
        self.reads += 1;
        Ok(0x5a)
    }
    fn write(&mut self, port: u16, width: PortWidth, _value: u32) -> Result<(), PortError> {
        Err(PortError::Unsupported { port, width, write: true })
    }
}
struct Fixture { cpu: Cpu, memory: Memory, segments: Segments, ports: Ports, trace: Trace }
impl Fixture {
    fn new(code: &[u8], bypass: bool) -> Self {
        let (mut cpu, ram) = cpu_with(code, 0x20000);
        cpu.decode_cache.bypass = bypass;
        let trace = Trace::default();
        Self {
            cpu, memory: Memory { ram, trace: trace.clone() },
            segments: Segments { base: 0, bits: 16, denied: None, trace: trace.clone() },
            ports: Ports { trace: trace.clone(), reads: 0, fail_after: None }, trace,
        }
    }
    fn step(&mut self) -> ExecutionBoundaryReport<StepOutcome> {
        self.trace.borrow_mut().clear();
        self.cpu.step_with_context_report(&mut self.memory, &mut self.ports, &self.segments)
    }
}
fn pair(code: &[u8]) -> [Fixture; 2] { [Fixture::new(code, false), Fixture::new(code, true)] }
fn equal(pair: &[Fixture; 2]) {
    let [cached, reference] = pair;
    assert!(cached.cpu.capture_context() == reference.cpu.capture_context());
    assert_eq!(cached.cpu.call_boundary_sequence, reference.cpu.call_boundary_sequence);
    assert_eq!(cached.cpu.control_transfer_sequence, reference.cpu.control_transfer_sequence);
    assert_eq!(cached.memory.ram.bytes, reference.memory.ram.bytes);
    assert_eq!(cached.ports.reads, reference.ports.reads);
    assert_eq!(*cached.trace.borrow(), *reference.trace.borrow());
    assert!(reference.cpu.decode_cache.is_empty());
}
fn step(pair: &mut [Fixture; 2]) -> ExecutionBoundaryReport<StepOutcome> {
    let [cached, reference] = pair;
    let a = cached.step();
    let b = reference.step();
    assert_eq!(a.progress, b.progress);
    assert_eq!(a.outcome, b.outcome);
    equal(pair);
    a
}
fn fetched(fixture: &Fixture) -> Vec<u32> {
    fixture.trace.borrow().iter().filter_map(|access| match access {
        Access::Read(address, 1) => Some(*address), _ => None,
    }).collect()
}

#[test]
fn warm_hits_and_self_modification_preserve_exact_fetches_and_execution() {
    let mut pair = pair(&[0xb8, 0x34, 0x12]);
    for code in [&[0xb8, 0x34, 0x12][..], &[0xb8, 0x34, 0x12], // Warm hit.
        &[0xb8, 0x34, 0x56], &[0xb9, 0x34, 0x56], // Immediate and opcode.
        &[0x90], &[0x66, 0xb8, 0x78, 0x56, 0x34, 0x12], // Shorter, longer/prefix.
    ] {
        for fixture in &mut pair {
            fixture.cpu.regs.eip = 0;
            fixture.memory.ram.put(0, code);
        }
        assert_eq!(step(&mut pair).outcome, Ok(StepOutcome::Continue));
        assert!(!pair[0].cpu.decode_cache.is_empty());
        assert_eq!(pair[0].cpu.regs.eip, code.len() as u32);
        assert_eq!(fetched(&pair[0]), (0..code.len() as u32).collect::<Vec<_>>());
    }
    assert_eq!(pair[0].cpu.regs.eax, 0x1234_5678);
    assert_eq!(pair[0].cpu.regs.cx(), 0x5634);
}

#[test]
fn warm_fetches_revalidate_permissions_remapping_and_new_required_bytes() {
    let mut pair = pair(&[0xb8, 0x34, 0x12]);
    step(&mut pair).outcome.unwrap();
    for denied in [Some(0), Some(2), None] {
        for fixture in &mut pair { fixture.cpu.regs.eip = 0; fixture.segments.denied = denied; }
        let result = step(&mut pair);
        assert_eq!(result.outcome.is_err(), denied.is_some());
        assert_eq!(fetched(&pair[0]), (0..denied.unwrap_or(3)).collect::<Vec<_>>());
    }
    for code in [&[0xb8, 0x34, 0x12][..], &[0xb8, 0x78, 0x56]] {
        for fixture in &mut pair {
            fixture.cpu.regs.eip = 0;
            fixture.segments.base = 0x400;
            fixture.memory.ram.put(0x400, code);
        }
        step(&mut pair).outcome.unwrap();
        assert_eq!(fetched(&pair[0]), vec![0x400, 0x401, 0x402]);
    }
    for fixture in &mut pair {
        fixture.cpu.regs.eip = 0;
        fixture.memory.ram.put(0x400, &[0x66, 0xb8, 1, 2, 3, 4]);
        fixture.segments.denied = Some(4);
    }
    let result = step(&mut pair);
    assert_eq!(result.progress, Progress::InstructionIncomplete);
    assert!(result.outcome.is_err());
    assert_eq!(fetched(&pair[0]), vec![0x400, 0x401, 0x402, 0x403]);
    assert_eq!(pair[0].cpu.regs.eip, 0);
}

#[test]
fn warm_entries_do_not_cross_code_width_contexts() {
    for code in [&[0xb8, 1, 2, 3, 4][..], &[0x66, 0xb8, 1, 2, 3, 4]] {
        let mut pair = pair(code);
        for bits in [16, 16, 32, 32, 16] {
            for fixture in &mut pair { fixture.cpu.regs.eip = 0; fixture.segments.bits = bits; }
            step(&mut pair).outcome.unwrap();
            let length = if (bits == 32) == (code[0] != 0x66) { 5 } else { 3 }
                + usize::from(code[0] == 0x66);
            assert_eq!(pair[0].cpu.regs.eip, length as u32);
            assert_eq!(fetched(&pair[0]), (0..length as u32).collect::<Vec<_>>());
        }
    }
}

#[test]
fn repeated_io_matches_partial_final_and_faulted_committed_effects() {
    for fail_after in [None, Some(4097)] {
        let mut pair = pair(&[0xf3, 0x6c]); // REP INSB, warm on partial continuation.
        for fixture in &mut pair {
            fixture.cpu.regs.es = 0x200;
            fixture.cpu.regs.set_cx(4099);
            fixture.ports.fail_after = fail_after;
        }
        assert_eq!(step(&mut pair).progress, Progress::RepeatPartial);
        assert!(!pair[0].cpu.decode_cache.is_empty());
        let result = step(&mut pair);
        if fail_after.is_some() {
            assert_eq!(result.progress, Progress::InstructionIncomplete);
            assert!(matches!(result.outcome, Err(CpuError::Io(_))));
            assert_eq!((pair[0].cpu.regs.eip, pair[0].cpu.regs.cx()), (0, 2));
            assert_eq!(&pair[0].memory.ram.bytes[0x3000..0x3003], &[0x5a, 0, 0]);
        } else {
            assert_eq!(result.progress, Progress::InstructionBodyCompleted);
            assert_eq!(result.outcome, Ok(StepOutcome::Continue));
            assert_eq!(pair[0].cpu.regs.cx(), 0);
        }
    }
}

fn observe(pair: &mut [Fixture; 2], progress: Progress) -> [crate::CpuDeferredEvent; 2] {
    let events = pair.each_mut().map(|fixture| {
        fixture.trace.borrow_mut().clear();
        let boundary = fixture.cpu.step_with_context_observing_events_report(
            &mut fixture.memory, &mut fixture.ports, &RealModeSegments,
        );
        assert_eq!(boundary.progress, progress);
        match boundary.outcome.unwrap() {
            CpuObservedStepOutcome::EventDeferred(event) => event,
            other => panic!("expected deferred event, got {other:?}"),
        }
    });
    assert_eq!(events[0].observation(), events[1].observation());
    equal(pair); // Compare the deferred boundary before delivery can change it.
    events
}

#[test]
fn warmed_software_events_preserve_observations_and_local_authority() {
    let mut pair = pair(&[0xcd, 0x21]);
    // An IRET handler permits normal execution back to the same cached INT.
    for fixture in &mut pair {
        fixture.memory.ram.put(0x21 * 4, &[0, 4, 0, 0]);
        fixture.memory.ram.put(0x400, &[0xcf]);
    }
    for _ in 0..2 {
        for fixture in &mut pair { fixture.cpu.regs.eip = 0; }
        let events = observe(&mut pair, Progress::InstructionBodyCompleted);
        assert_eq!(events[0].observation().source, CpuEventSource::SoftwareInterrupt);
        for (fixture, event) in pair.iter_mut().zip(events) {
            assert!(fixture.cpu.capture_deferred_event_observer_continuation(&event).is_ok());
            fixture.cpu.resume_deferred_event(event, &mut fixture.memory, &RealModeSegments).unwrap();
        }
        equal(&pair);
        assert!(!pair[0].cpu.decode_cache.is_empty());
        step(&mut pair).outcome.unwrap(); // IRET consumes each CPU's own frame.
        assert_eq!(pair[0].cpu.regs.eip, 2);
    }
}

#[test]
fn warmed_decode_still_rejects_unsupported_model_features() {
    let mut pair = pair(&[0x0f, 0xa2]); // CPUID is unavailable on I486.
    for (index, fixture) in pair.iter_mut().enumerate() {
        fixture.cpu = Cpu::new_with_model(fixture.cpu.regs.clone(), CpuModel::I486);
        fixture.cpu.decode_cache.bypass = index == 1;
        fixture.memory.ram.put(6 * 4, &[0, 4, 0, 0]);
        fixture.memory.ram.put(0x400, &[0xcf]);
    }
    for _ in 0..2 {
        let events = observe(&mut pair, Progress::InstructionIncomplete);
        let event = events[0].observation();
        assert_eq!((event.vector, event.source, event.saved_ip), (6, CpuEventSource::Fault, 0));
        assert!(!pair[0].cpu.decode_cache.is_empty());
        for (fixture, event) in pair.iter_mut().zip(events) {
            fixture.cpu.resume_deferred_event(event, &mut fixture.memory, &RealModeSegments).unwrap();
        }
        equal(&pair);
        step(&mut pair).outcome.unwrap();
        assert_eq!(pair[0].cpu.regs.eip, 0);
    }
}
