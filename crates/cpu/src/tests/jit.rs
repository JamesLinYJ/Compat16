//! Native execution versus the existing interpreter, including checked access
//! and retirement. This comparison is not an independent x86 semantics oracle.

use super::*;
use crate::ExecutionEngine;
use crate::SegmentResolver;
use crate::execution_boundary::{ExecutionBoundaryReport, ExecutionProgress};
use std::cell::RefCell;

const DATA: u32 = 0x200;

#[derive(Debug, PartialEq)]
enum Access {
    ValidateRead(u32, usize),
    ValidateWrite(u32, usize),
    Read(u32, usize),
    Write(u32, Vec<u8>),
}

struct Memory {
    ram: Ram,
    trace: RefCell<Vec<Access>>,
    reject_data_read: bool,
}
impl GuestMemory for Memory {
    fn len(&self) -> u32 {
        self.ram.len()
    }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.trace
            .borrow_mut()
            .push(Access::ValidateRead(address.0, length));
        if self.reject_data_read && address.0 == DATA {
            return Err(MemoryError::OutOfBounds {
                address: DATA,
                length,
            });
        }
        self.ram.validate_read(address, length)
    }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.trace
            .borrow_mut()
            .push(Access::ValidateWrite(address.0, length));
        self.ram.validate_write(address, length)
    }
    fn read(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        self.trace
            .borrow_mut()
            .push(Access::Read(address.0, output.len()));
        self.ram.read(address, output)
    }
    fn write(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        self.trace
            .borrow_mut()
            .push(Access::Write(address.0, input.to_vec()));
        self.ram.write(address, input)
    }
}

// Provider-level code width, execute permission and remapping. Architectural
// paging/descriptor checks remain separate coverage.
struct Segments {
    base: u32,
    bits: u32,
    deny_execute: bool,
}
impl SegmentResolver for Segments {
    fn code_bits(&self) -> u32 {
        self.bits
    }
    fn resolve(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        RealModeSegments.resolve(segment, offset, address32)
    }
    fn resolve_execute(
        &self,
        _segment: u16,
        offset: u32,
        _address32: bool,
    ) -> Result<PhysAddr, CpuError> {
        if self.deny_execute {
            return Err(MemoryError::OutOfBounds {
                address: offset,
                length: 1,
            }
            .into());
        }
        Ok(PhysAddr(self.base + offset))
    }
}
struct Fixture {
    cpu: Cpu,
    memory: Memory,
    segments: Segments,
}
impl Fixture {
    fn new(engine: ExecutionEngine) -> Self {
        let (mut cpu, ram) = cpu_with(&[], 0x20000);
        cpu.set_execution_engine(engine);
        Self {
            cpu,
            memory: Memory {
                ram,
                trace: RefCell::default(),
                reject_data_read: false,
            },
            segments: Segments {
                base: 0,
                bits: 16,
                deny_execute: false,
            },
        }
    }
    fn step(&mut self) -> ExecutionBoundaryReport<StepOutcome> {
        self.memory.trace.borrow_mut().clear();
        self.cpu
            .step_with_context_report(&mut self.memory, &mut NoPorts, &self.segments)
    }
}
fn pair() -> [Fixture; 2] {
    [
        Fixture::new(ExecutionEngine::NativeJit),
        Fixture::new(ExecutionEngine::Interpreter),
    ]
}
fn equal(pair: &[Fixture; 2]) {
    let [native, interpreter] = pair;
    assert_eq!(native.cpu.regs, interpreter.cpu.regs);
    assert!(native.cpu.capture_context() == interpreter.cpu.capture_context());
    assert_eq!(
        native.cpu.call_boundary_sequence,
        interpreter.cpu.call_boundary_sequence
    );
    assert_eq!(
        native.cpu.control_transfer_sequence,
        interpreter.cpu.control_transfer_sequence
    );
    assert_eq!(native.memory.ram.bytes, interpreter.memory.ram.bytes);
    // Includes instruction fetches and data callbacks, so cold fallback and
    // warm execution must both preserve the exact read/write sequence.
    assert_eq!(
        *native.memory.trace.borrow(),
        *interpreter.memory.trace.borrow()
    );
    assert_eq!(native.cpu.jit_statistics().failures, 0);
    assert_eq!(interpreter.cpu.jit_statistics().executed, 0);
}
fn step(pair: &mut [Fixture; 2]) -> ExecutionBoundaryReport<StepOutcome> {
    let [native, interpreter] = pair;
    let a = native.step();
    let b = interpreter.step();
    assert_eq!(a.outcome, b.outcome);
    assert_eq!(a.progress, b.progress);
    equal(pair);
    a
}
fn flags(index: usize) -> u32 {
    let mut result = 2 | crate::DF | crate::IF;
    for (bit, mask) in [
        crate::CF,
        crate::PF,
        crate::AF,
        crate::ZF,
        crate::SF,
        crate::OF,
    ]
    .into_iter()
    .enumerate()
    {
        if index & (1 << bit) != 0 {
            result |= mask;
        }
    }
    result
}
fn input(pair: &mut [Fixture; 2], left: u32, right: u32, flags: u32) {
    for fixture in pair {
        fixture.cpu.regs = Registers {
            eax: left,
            ebx: right,
            ecx: 0x1357_2468,
            edx: 0xfedc_ba98,
            esi: 0x300,
            edi: 0x400,
            ebp: 0x500,
            esp: 0x600,
            eflags: flags,
            ..Registers::default()
        };
        fixture.memory.ram.put(DATA as usize, &left.to_le_bytes());
    }
}
fn code(pair: &mut [Fixture; 2], bytes: &[u8]) {
    for fixture in pair {
        fixture
            .memory
            .ram
            .put(fixture.segments.base as usize, bytes);
    }
}
fn exercise(pair: &mut [Fixture; 2], bytes: &[u8]) {
    code(pair, bytes);
    for _ in 0..40 {
        input(pair, 0x1234_5678, 1, flags(0));
        assert_eq!(
            step(pair).outcome,
            Ok(StepOutcome::Continue),
            "{bytes:02x?}"
        );
    }
    let before = pair[0].cpu.jit_statistics().executed;
    let edges = [
        0,
        1,
        0xf,
        0x10,
        0x7f,
        0x80,
        0xff,
        0xff00,
        0x7fff,
        0x8000,
        0xffff,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
    ];
    for (i, &left) in edges.iter().enumerate() {
        for (j, &right) in edges.iter().enumerate() {
            for carry in 0..2 {
                input(pair, left, right, flags(((i + j) << 1) | carry));
                let boundary = step(pair);
                assert_eq!(boundary.outcome, Ok(StepOutcome::Continue), "{bytes:02x?}");
                assert_eq!(
                    boundary.progress,
                    ExecutionProgress::InstructionBodyCompleted
                );
                assert_eq!(pair[0].cpu.regs.eip, bytes.len() as u32);
            }
        }
    }
    assert!(
        pair[0].cpu.jit_statistics().executed > before,
        "no native execution: {bytes:02x?}"
    );
}

#[test]
fn arithmetic_register_slices_and_extension_edges_match_interpreter() {
    let mut pair = pair();
    for opcode in [
        0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x84, 0x88, 0x86,
    ] {
        exercise(&mut pair, &[opcode, 0xd8]);
        exercise(&mut pair, &[opcode + 1, 0xd8]);
        exercise(&mut pair, &[0x66, opcode + 1, 0xd8]);
    }
    for (opcode, modrm) in [(0xfe, 0xc0), (0xfe, 0xc8), (0xf6, 0xd0), (0xf6, 0xd8)] {
        exercise(&mut pair, &[opcode, modrm]);
        exercise(&mut pair, &[opcode + 1, modrm]);
        exercise(&mut pair, &[0x66, opcode + 1, modrm]);
    }
    for bytes in [
        &[0x00, 0xdc][..],
        &[0x88, 0xe0],
        &[0x86, 0xe0],
        &[0xb4, 0x7f],
        &[0x83, 0xc0, 0xff],
        &[0x66, 0x83, 0xc0, 0xff],
        &[0x0f, 0xb6, 0xc7],
        &[0x0f, 0xbe, 0xc7],
        &[0x66, 0x0f, 0xb6, 0xc3],
        &[0x66, 0x0f, 0xbe, 0xc3],
        &[0x66, 0x0f, 0xb7, 0xc3],
        &[0x66, 0x0f, 0xbf, 0xc3],
        &[0x66, 0x0f, 0xc8],
    ] {
        exercise(&mut pair, bytes);
    }
    eprintln!("register JIT: {:?}", pair[0].cpu.jit_statistics());
}

#[test]
fn all_conditions_match_for_each_status_flag_combination() {
    let mut pair = pair();
    for condition in 0..16 {
        for bytes in [
            vec![0x0f, 0x90 + condition, 0xc0],
            vec![0x0f, 0x40 + condition, 0xc3],
            vec![0x66, 0x0f, 0x40 + condition, 0xc3],
        ] {
            code(&mut pair, &bytes);
            let before = pair[0].cpu.jit_statistics().executed;
            for index in 0_usize..104 {
                input(
                    &mut pair,
                    0xaabb_ccdd,
                    0x1234_5678,
                    flags(index.saturating_sub(40)),
                );
                assert_eq!(step(&mut pair).outcome, Ok(StepOutcome::Continue));
            }
            assert!(pair[0].cpu.jit_statistics().executed >= before + 64);
        }
    }
    eprintln!("conditional JIT: {:?}", pair[0].cpu.jit_statistics());
}

#[test]
fn checked_memory_accesses_match_in_cold_and_native_paths() {
    let mut pair = pair();
    for opcode in [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x84, 0x88] {
        for bytes in [
            vec![opcode, 0x1e, 0x00, 0x02],
            vec![opcode + 1, 0x1e, 0x00, 0x02],
            vec![0x66, opcode + 1, 0x1e, 0x00, 0x02],
        ] {
            exercise(&mut pair, &bytes);
        }
        if opcode != 0x84 {
            exercise(&mut pair, &[opcode + 3, 0x1e, 0x00, 0x02]);
            exercise(&mut pair, &[0x66, opcode + 3, 0x1e, 0x00, 0x02]);
        }
    }
    for bytes in [
        &[0xff, 0x06, 0x00, 0x02][..],
        &[0xff, 0x0e, 0x00, 0x02],
        &[0xf7, 0x16, 0x00, 0x02],
        &[0xf7, 0x1e, 0x00, 0x02],
        &[0x0f, 0xb6, 0x1e, 0x00, 0x02],
        &[0x66, 0x0f, 0xbf, 0x1e, 0x00, 0x02],
        &[0x0f, 0x94, 0x06, 0x00, 0x02],
        &[0x0f, 0x44, 0x1e, 0x00, 0x02],
        &[0x83, 0x16, 0x00, 0x02, 0xff],
    ] {
        exercise(&mut pair, bytes);
    }
    eprintln!("memory JIT: {:?}", pair[0].cpu.jit_statistics());
}

#[test]
fn hot_memory_faults_preserve_registers_flags_and_access_order() {
    for bytes in [
        &[0x01, 0x1e, 0x00, 0x02][..],
        &[0x89, 0x1e, 0x00, 0x02],
        &[0x8b, 0x1e, 0x00, 0x02],
        &[0x0f, 0x44, 0x1e, 0x00, 0x02],
        &[0x0f, 0x94, 0x06, 0x00, 0x02],
    ] {
        let mut pair = pair();
        exercise(&mut pair, bytes);
        for read_fault in [true, false] {
            input(&mut pair, 0xffff_ffff, 0x1234_5678, flags(0));
            for fixture in &mut pair {
                fixture.memory.reject_data_read = read_fault;
                fixture.memory.ram.rejected_write = if read_fault { None } else { Some(DATA) };
            }
            let before = pair[0].cpu.regs.clone();
            let boundary = step(&mut pair);
            let write_only = bytes[0] == 0x89 || bytes[1] == 0x94;
            let read_only = bytes[0] == 0x8b || bytes[1] == 0x44;
            if read_fault && write_only || !read_fault && read_only {
                assert_eq!(boundary.outcome, Ok(StepOutcome::Continue));
            } else {
                assert!(matches!(boundary.outcome, Err(CpuError::Memory(_))));
                assert_eq!(boundary.progress, ExecutionProgress::InstructionIncomplete);
                assert_eq!(pair[0].cpu.regs, before);
            }
        }
    }
}

#[test]
fn rewritten_remapped_and_denied_code_cannot_reuse_stale_native_body() {
    let mut pair = pair();
    exercise(&mut pair, &[0xb8, 0x34, 0x12]);
    for bytes in [
        &[0xb8, 0x78, 0x56][..],
        &[0xb9, 0x78, 0x56],
        &[0x66, 0xb8, 1, 2, 3, 4],
    ] {
        exercise(&mut pair, bytes);
    }
    for fixture in &mut pair {
        fixture.segments.base = 0x400;
    }
    exercise(&mut pair, &[0xb8, 0xbc, 0x9a]);
    input(&mut pair, 0x1234_5678, 0, flags(0));
    for fixture in &mut pair {
        fixture.segments.deny_execute = true;
    }
    let before = pair[0].cpu.jit_statistics().executed;
    assert!(step(&mut pair).outcome.is_err());
    assert_eq!(pair[0].cpu.jit_statistics().executed, before);
    for fixture in &mut pair {
        fixture.segments.deny_execute = false;
        fixture.segments.base = 0;
    }
    code(&mut pair, &[0xb8, 0x78, 0x56, 0x34, 0x12]);
    for bits in [16, 32, 16] {
        for fixture in &mut pair {
            fixture.segments.bits = bits;
        }
        for _ in 0..40 {
            input(&mut pair, 0, 0, flags(0));
            assert_eq!(step(&mut pair).outcome, Ok(StepOutcome::Continue));
            assert_eq!(
                pair[0].cpu.regs.eax,
                if bits == 32 { 0x1234_5678 } else { 0x5678 }
            );
        }
    }
}

#[test]
fn interpreter_switch_and_guest_model_checks_still_apply() {
    let mut pair = pair();
    exercise(&mut pair, &[0x01, 0xd8]);
    pair[0]
        .cpu
        .set_execution_engine(ExecutionEngine::Interpreter);
    let before = pair[0].cpu.jit_statistics().executed;
    input(&mut pair, 1, 2, flags(0));
    step(&mut pair).outcome.unwrap();
    assert_eq!(pair[0].cpu.jit_statistics().executed, before);
    pair[0].cpu.set_execution_engine(ExecutionEngine::NativeJit);
    input(&mut pair, 1, 2, flags(0));
    step(&mut pair).outcome.unwrap();
    assert!(pair[0].cpu.jit_statistics().executed > before);
    for fixture in &mut pair {
        fixture.cpu = Cpu::new_with_model(fixture.cpu.regs.clone(), CpuModel::I486);
    }
    pair[0].cpu.set_execution_engine(ExecutionEngine::NativeJit);
    pair[1]
        .cpu
        .set_execution_engine(ExecutionEngine::Interpreter);
    code(&mut pair, &[0x0f, 0x44, 0xc3]);
    for _ in 0..40 {
        input(&mut pair, 1, 2, flags(0));
        assert!(matches!(
            step(&mut pair).outcome,
            Err(CpuError::InvalidOpcode { .. })
        ));
    }
    assert_eq!(pair[0].cpu.jit_statistics().compiled, 0);
}

#[test]
fn native_retirement_preserves_single_step_observation_and_resume_authority() {
    let mut pair = pair();
    exercise(&mut pair, &[0x01, 0xd8]);
    input(&mut pair, 0x7fff, 1, flags(0) | crate::TF | (1 << 16));
    let before = pair[0].cpu.jit_statistics().executed;
    let events = pair.each_mut().map(|fixture| {
        fixture.memory.trace.borrow_mut().clear();
        let boundary = fixture.cpu.step_with_context_observing_events_report(
            &mut fixture.memory,
            &mut NoPorts,
            &RealModeSegments,
        );
        assert_eq!(
            boundary.progress,
            ExecutionProgress::InstructionBodyCompleted
        );
        match boundary.outcome.unwrap() {
            CpuObservedStepOutcome::EventDeferred(event) => event,
            other => panic!("expected single-step event, got {other:?}"),
        }
    });
    assert_eq!(events[0].observation(), events[1].observation());
    equal(&pair);
    assert_eq!(pair[0].cpu.regs.eip, 2);
    assert_eq!(pair[0].cpu.regs.eflags & (1 << 16), 0);
    assert!(pair[0].cpu.jit_statistics().executed > before);
    for (fixture, event) in pair.iter_mut().zip(events) {
        assert!(
            fixture
                .cpu
                .capture_deferred_event_observer_continuation(&event)
                .is_ok()
        );
    }
}
