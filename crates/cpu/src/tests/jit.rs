//! JIT execution versus the existing interpreter, including checked access
//! and retirement. This comparison is not an independent x86 semantics oracle.

use super::*;
mod protected_memory;
mod linked;
mod floating;
mod float_blocks;
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
        Fixture::new(ExecutionEngine::Jit),
        Fixture::new(ExecutionEngine::Interpreter),
    ]
}
fn equal(pair: &[Fixture; 2]) {
    let [jit, interpreter] = pair;
    assert_eq!(jit.cpu.regs, interpreter.cpu.regs);
    assert!(jit.cpu.capture_context() == interpreter.cpu.capture_context());
    assert_eq!(
        jit.cpu.call_boundary_sequence,
        interpreter.cpu.call_boundary_sequence
    );
    assert_eq!(
        jit.cpu.control_transfer_sequence,
        interpreter.cpu.control_transfer_sequence
    );
    assert_eq!(jit.memory.ram.bytes, interpreter.memory.ram.bytes);
    // Includes instruction fetches and data callbacks, so cold fallback and
    // warm execution must both preserve the exact read/write sequence.
    assert_eq!(
        *jit.memory.trace.borrow(),
        *interpreter.memory.trace.borrow()
    );
    assert_eq!(jit.cpu.jit_statistics().failures, 0);
    assert_eq!(interpreter.cpu.jit_statistics().executed, 0);
}
fn step(pair: &mut [Fixture; 2]) -> ExecutionBoundaryReport<StepOutcome> {
    let [jit, interpreter] = pair;
    let a = jit.step();
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
        "no jit execution: {bytes:02x?}"
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
fn checked_memory_accesses_match_in_cold_and_jit_paths() {
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
fn rewritten_remapped_and_denied_code_cannot_reuse_stale_jit_body() {
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
    pair[0].cpu.set_execution_engine(ExecutionEngine::Jit);
    input(&mut pair, 1, 2, flags(0));
    step(&mut pair).outcome.unwrap();
    assert!(pair[0].cpu.jit_statistics().executed > before);
    for fixture in &mut pair {
        fixture.cpu = Cpu::new_with_model(fixture.cpu.regs.clone(), CpuModel::I486);
    }
    pair[0].cpu.set_execution_engine(ExecutionEngine::Jit);
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
fn jit_retirement_preserves_single_step_observation_and_resume_authority() {
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

// Six pure operations followed by an interpreter boundary. Every operation is
// compared at its own retirement, including the block's intermediate states.
const BLOCK: &[u8] = &[
    0x40, 0x11, 0xd8, 0x31, 0xc1, 0x66, 0x0f, 0xb6, 0xd4, 0x39, 0xc8, 0x0f, 0x9c, 0xc2, 0x90,
];
fn warm_block(pair: &mut [Fixture; 2]) {
    code(pair, BLOCK);
    for round in 0..40 {
        input(pair, 0x7fff + round, 3, flags(round as usize));
        for _ in 0..7 {
            step(pair).outcome.unwrap();
        }
    }
    let statistics = pair[0].cpu.jit_statistics();
    assert!(statistics.blocks_executed > 0);
    assert!(statistics.checkpoint_hits > 0);
}

#[test]
fn fused_blocks_match_each_retirement_and_invalidate_changed_tails() {
    let mut pair = pair();
    warm_block(&mut pair);
    for rewrite_code in [true, false] {
        code(&mut pair, BLOCK);
        input(&mut pair, 0x7fff, 3, flags(1));
        step(&mut pair).outcome.unwrap();
        let before = pair[0].cpu.jit_statistics();
        for fixture in &mut pair {
            if rewrite_code {
                fixture.memory.ram.put(1, &[0x29]);
            } else {
                fixture.cpu.regs.ebx ^= 0x1234;
            }
        }
        step(&mut pair).outcome.unwrap();
        assert!(pair[0].cpu.jit_statistics().block_invalidations > before.block_invalidations);
        assert_eq!(
            pair[0].cpu.jit_statistics().checkpoint_hits,
            before.checkpoint_hits
        );
        for _ in 0..5 {
            step(&mut pair).outcome.unwrap();
        }
    }
    eprintln!("blocks JIT: {:?}", pair[0].cpu.jit_statistics());
}

#[test]
fn predicted_tail_still_requires_execute_permission_and_observes_single_step() {
    let mut pair = pair();
    warm_block(&mut pair);
    input(&mut pair, 0x7fff, 3, flags(0));
    step(&mut pair).outcome.unwrap();
    let before = pair[0].cpu.regs.clone();
    let hits = pair[0].cpu.jit_statistics().checkpoint_hits;
    for fixture in &mut pair {
        fixture.segments.deny_execute = true;
    }
    assert!(step(&mut pair).outcome.is_err());
    assert_eq!(pair[0].cpu.regs, before);
    assert_eq!(pair[0].cpu.jit_statistics().checkpoint_hits, hits);
    for fixture in &mut pair {
        fixture.segments.deny_execute = false;
        fixture.cpu.regs.eflags |= crate::TF;
    }
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
            other => panic!("expected block single-step event, got {other:?}"),
        }
    });
    assert_eq!(events[0].observation(), events[1].observation());
    equal(&pair);
    assert_eq!(pair[0].cpu.regs.eip, 3);
    for (fixture, event) in pair.iter_mut().zip(events) {
        assert!(
            fixture
                .cpu
                .capture_deferred_event_observer_continuation(&event)
                .is_ok()
        );
    }
}

#[test]
fn long_blocks_split_and_memory_faults_remain_at_the_actual_instruction() {
    let mut pair = pair();
    let mut program = vec![0x40; 35];
    program.extend([0x01, 0x1e, 0x00, 0x02, 0x90]);
    code(&mut pair, &program);
    for round in 0..40 {
        input(&mut pair, round, 7, flags(0));
        for _ in 0..37 {
            step(&mut pair).outcome.unwrap();
        }
    }
    assert!(pair[0].cpu.jit_statistics().blocks_executed > 0);
    input(&mut pair, 0x7ff0, 7, flags(0));
    for fixture in &mut pair {
        fixture.memory.reject_data_read = true;
    }
    for _ in 0..35 {
        step(&mut pair).outcome.unwrap();
    }
    let before = pair[0].cpu.regs.clone();
    assert!(matches!(step(&mut pair).outcome, Err(CpuError::Memory(_))));
    assert_eq!(pair[0].cpu.regs, before);
}

#[test]
#[ignore = "explicit jit throughput measurement; no timing pass threshold"]
fn block_throughput_measurement() {
    use std::time::Instant;
    let operations = [
        0x01, 0xd8, 0x11, 0xc1, 0x31, 0xd3, 0x29, 0xca, 0x40, 0x49, 0x0f, 0x95, 0xc2, 0x66, 0x0f,
        0xb6, 0xdc,
    ];
    let mut program = operations.repeat(2);
    program.extend([0xeb, (-(program.len() as i16 + 2)) as u8]);
    let mut machines = [ExecutionEngine::Jit, ExecutionEngine::Interpreter].map(|engine| {
        let (mut cpu, mut ram) = cpu_with(&program, 0x20000);
        cpu.set_execution_engine(engine);
        cpu.regs.eax = 0x1234;
        cpu.regs.ebx = 0x5678;
        for _ in 0..(128 * 17) {
            cpu.step_with_context(&mut ram, &mut NoPorts, &RealModeSegments)
                .unwrap();
        }
        (cpu, ram)
    });
    let mut elapsed = [Vec::new(), Vec::new()];
    // Alternate order to reduce systematic bias from host load and clock
    // changes. Both owners execute the same warmup and instruction counts.
    for round in 0..5 {
        for index in if round % 2 == 0 { [0, 1] } else { [1, 0] } {
            let (cpu, ram) = &mut machines[index];
            let start = Instant::now();
            for _ in 0..(10_000 * 17) {
                std::hint::black_box(
                    cpu.step_with_context(ram, &mut NoPorts, &RealModeSegments)
                        .unwrap(),
                );
            }
            elapsed[index].push(start.elapsed().as_nanos());
        }
    }
    let measurements = elapsed.map(|mut samples| {
        samples.sort_unstable();
        samples[2]
    });
    assert_eq!(machines[0].0.regs, machines[1].0.regs);
    assert!(machines[0].0.jit_statistics().checkpoint_hits > 0);
    assert_eq!(machines[0].0.jit_statistics().failures, 0);
    eprintln!("throughput JIT: {:?}", machines[0].0.jit_statistics());
    eprintln!(
        "JIT_THROUGHPUT target={} steps_per_sample=170000 jit_median_ns={} interpreter_median_ns={} speedup={:.3}",
        std::env::consts::ARCH,
        measurements[0],
        measurements[1],
        measurements[1] as f64 / measurements[0] as f64
    );
}

const PURE_LOOP: &[u8] = &[0x40, 0x01, 0xc3, 0x11, 0xda, 0x31, 0xd6, 0x49, 0x75, 0xf6];
fn plain_loop(engine: ExecutionEngine) -> (Cpu, guest_core::memory::Memory) {
    let mut memory = guest_core::memory::Memory::with_size(0x100000).unwrap();
    memory.write(PhysAddr(0), PURE_LOOP).unwrap();
    let mut cpu = Cpu::new(Registers {
        eax: 0x1234_5678,
        ebx: 0x4321_abcd,
        ecx: 1000,
        eflags: 0x203,
        ..Registers::default()
    });
    cpu.reset_real_mode_segments_from_visible_registers()
        .unwrap();
    cpu.set_execution_engine(engine);
    if engine == ExecutionEngine::Jit {
        let original = cpu.regs.clone();
        let mut compiled = false;
        for _ in 0..64 {
            if cpu.try_run_integer_loop(&memory, 256).unwrap().is_some() {
                compiled = true;
                break;
            }
        }
        assert!(compiled, "{:?}", cpu.jit_statistics());
        cpu.regs = original;
    }
    (cpu, memory)
}

#[test]
fn jit_loop_budgets_and_exit_state_match_every_retired_instruction() {
    let (mut jit, ram) = plain_loop(ExecutionEngine::Jit);
    let (mut interpreter, mut reference) = plain_loop(ExecutionEngine::Interpreter);
    for count in [1, 2, 41, 1000] {
        for budget in (0..32).chain([255, 256, u32::MAX]) {
            let input = Registers {
                eax: 0xabcd_ffff,
                ecx: 0x1234_0000 | count,
                ebx: 0x7654_3210,
                eflags: 0x203,
                ..Registers::default()
            };
            jit.regs = input.clone();
            interpreter.regs = input;
            let before = jit.call_boundary_sequence;
            let retired = jit.try_run_integer_loop(&ram, budget).unwrap().unwrap_or(0);
            assert!(retired <= budget.min(256));
            assert_eq!(jit.call_boundary_sequence, before + u64::from(retired));
            for _ in 0..retired {
                interpreter.step(&mut reference).unwrap();
            }
            assert!(
                jit.capture_context() == interpreter.capture_context(),
                "count={count} budget={budget} retired={retired}"
            );
            assert_eq!(retired, (budget.min(256) / 6).min(count) * 6);
            assert_eq!(
                jit.regs.eip,
                if retired == count * 6 {
                    PURE_LOOP.len() as u32
                } else {
                    0
                }
            );
        }
    }
    assert!(jit.jit_statistics().loop_iterations > 0);
    assert_eq!(jit.jit_statistics().failures, 0);
}

#[test]
fn rewritten_jit_loops_and_unobservable_memory_providers_fall_back() {
    let (mut jit, mut ram) = plain_loop(ExecutionEngine::Jit);
    let (mut interpreter, mut reference) = plain_loop(ExecutionEngine::Interpreter);
    ram.write(PhysAddr(0), &[0x48]).unwrap(); // DEC AX replaces INC AX.
    reference.write(PhysAddr(0), &[0x48]).unwrap();
    let before = jit.capture_context();
    assert_eq!(jit.try_run_integer_loop(&ram, 256).unwrap(), None);
    assert!(jit.capture_context() == before);
    let mut remaining = 600;
    while remaining != 0 {
        let retired = match jit.try_run_integer_loop(&ram, remaining).unwrap() {
            Some(count) => count,
            None => {
                jit.step(&mut ram).unwrap();
                1
            }
        };
        for _ in 0..retired {
            interpreter.step(&mut reference).unwrap();
        }
        assert!(jit.capture_context() == interpreter.capture_context());
        remaining -= retired;
    }
    // A default provider may have read observers or custom validators. It has
    // not opted into plain snapshots, even if its bytes are ordinary RAM.
    let mut observed = Memory {
        ram: Ram::new(0x20000),
        trace: RefCell::new(Vec::new()),
        reject_data_read: false,
    };
    observed.ram.put(0, PURE_LOOP);
    jit.regs.eip = 0;
    let before = jit.capture_context();
    for _ in 0..20 {
        assert_eq!(jit.try_run_integer_loop(&observed, 256).unwrap(), None);
    }
    assert!(observed.trace.borrow().is_empty());
    assert!(jit.capture_context() == before);
}

#[test]
fn jit_loops_preserve_debug_event_shadow_and_continuation_boundaries() {
    let (mut cpu, ram) = plain_loop(ExecutionEngine::Jit);
    for guard in 0..12 {
        let saved = cpu.capture_context();
        match guard {
            0 => cpu.regs.eflags |= 1 << 8,
            1 => cpu.regs.eflags |= 1 << 16,
            2 => cpu.system.debug.control |= 1,
            3 => cpu.request_non_maskable_interrupt(),
            4 => cpu.maskable_interrupt_shadow = true,
            5 => cpu.debug_exception_shadow = true,
            6 => cpu.pending_task_debug_trap = true,
            7 => cpu.pending_x87_irq13 = true,
            8 => cpu.intermediate_rep_boundary = true,
            9 => cpu.system.segments[0].descriptor.limit = 7,
            10 => cpu.system.cr0 |= crate::system::CR0_PG,
            11 => cpu.halted = true,
            _ => unreachable!(),
        }
        let before = cpu.capture_context();
        assert_eq!(
            cpu.try_run_integer_loop(&ram, 256).unwrap(),
            None,
            "guard={guard}"
        );
        assert!(cpu.capture_context() == before);
        cpu.restore_context(&saved).unwrap();
    }
    cpu.call_boundary_sequence = u64::MAX - 5;
    assert_eq!(cpu.try_run_integer_loop(&ram, 256).unwrap(), None);
    assert_eq!(cpu.call_boundary_sequence, u64::MAX - 5);
    cpu.call_boundary_sequence = u64::MAX - 6;
    assert_eq!(cpu.try_run_integer_loop(&ram, 256).unwrap(), Some(6));
    assert_eq!(cpu.call_boundary_sequence, u64::MAX);
    assert_eq!(cpu.try_run_integer_loop(&ram, 256).unwrap(), None);
}

#[test]
fn jit_loop_lookahead_does_not_replace_precise_fetch_or_model_faults() {
    let (mut cpu, mut memory) = plain_loop(ExecutionEngine::Jit);
    let cmov = [0x0f, 0x45, 0xc3, 0x49, 0x75, 0xfa];
    memory.write(PhysAddr(0), &cmov).unwrap();
    let mut strict = Cpu::new_with_model(
        Registers {
            ecx: 100,
            eflags: 2,
            ..Registers::default()
        },
        crate::CpuModel::I486,
    );
    strict
        .reset_real_mode_segments_from_visible_registers()
        .unwrap();
    for _ in 0..32 {
        assert_eq!(strict.try_run_integer_loop(&memory, 256).unwrap(), None);
    }
    assert_eq!(strict.regs.eip, 0);
    let outcome = strict
        .step_with_context_observing_events(&mut memory, &mut NoPorts, &RealModeSegments)
        .unwrap();
    let CpuObservedStepOutcome::EventDeferred(event) = outcome else {
        panic!("expected model fault")
    };
    assert_eq!(event.observation().vector, 6);
    assert_eq!(event.observation().saved_ip, 0);
    cpu.regs.eip = 0xffff;
    memory.write(PhysAddr(0xffff), &[0x66]).unwrap();
    let before = cpu.capture_context();
    for _ in 0..20 {
        assert_eq!(cpu.try_run_integer_loop(&memory, 256).unwrap(), None);
    }
    assert!(cpu.capture_context() == before);
    let outcome = cpu
        .step_with_context_observing_events(&mut memory, &mut NoPorts, &RealModeSegments)
        .unwrap();
    let CpuObservedStepOutcome::EventDeferred(event) = outcome else {
        panic!("expected segment fetch fault")
    };
    assert_eq!(event.observation().vector, 13);
    assert_eq!(event.observation().saved_ip, 0xffff);
}

#[test]
#[ignore = "explicit budgeted jit-loop throughput measurement"]
fn jit_loop_throughput_measurement() {
    use std::time::Instant;
    let mut machines = [
        plain_loop(ExecutionEngine::Jit),
        plain_loop(ExecutionEngine::Interpreter),
    ];
    // Both engines execute the same finite instruction budget. A jump back to
    // the head is unconditional, preventing early termination from CX wrap.
    for (_, memory) in &mut machines {
        memory.write(PhysAddr(8), &[0xeb, 0xf6]).unwrap();
    }
    for (cpu, memory) in &mut machines {
        for _ in 0..1024 {
            if cpu.try_run_integer_loop(memory, 252).unwrap().is_none() {
                cpu.step(memory).unwrap();
            }
        }
        cpu.regs = Registers {
            eax: 0x1234,
            ebx: 0xabcd,
            ecx: 100,
            eflags: 0x203,
            ..Registers::default()
        };
    }
    let mut elapsed = [Vec::new(), Vec::new()];
    const STEPS: u32 = 1_000_002;
    for round in 0..5 {
        for index in if round % 2 == 0 { [0, 1] } else { [1, 0] } {
            let (cpu, memory) = &mut machines[index];
            let start = Instant::now();
            let mut remaining = STEPS;
            while remaining != 0 {
                let retired = match cpu.try_run_integer_loop(memory, remaining).unwrap() {
                    Some(count) => count,
                    None => {
                        std::hint::black_box(cpu.step(memory).unwrap());
                        1
                    }
                };
                remaining -= retired;
            }
            elapsed[index].push(start.elapsed().as_nanos());
        }
    }
    assert_eq!(machines[0].0.regs, machines[1].0.regs);
    assert!(machines[0].0.jit_statistics().loops_executed > 0);
    let measurements = elapsed.map(|mut samples| {
        samples.sort_unstable();
        samples[2]
    });
    eprintln!(
        "JIT_LOOP target={} steps_per_sample={} jit_median_ns={} interpreter_median_ns={} speedup={:.3}",
        std::env::consts::ARCH,
        STEPS,
        measurements[0],
        measurements[1],
        measurements[1] as f64 / measurements[0] as f64
    );
    eprintln!("jit loop JIT: {:?}", machines[0].0.jit_statistics());
}

#[test]
fn plain_code_snapshots_respect_a20_banks_and_bus_aliases() {
    let mut memory = guest_core::memory::Memory::with_size(0x400000).unwrap();
    memory.set_a20_enabled(false).unwrap();
    memory.write(PhysAddr(0x100), PURE_LOOP).unwrap();
    let mut actual = [0u8; 10];
    assert!(
        memory
            .bus()
            .read_plain_code(PhysAddr(0x100100), &mut actual)
            .unwrap()
    );
    assert_eq!(actual, PURE_LOOP);
    let mut crossing = [0xa5u8; 32];
    assert!(
        !memory
            .bus()
            .read_plain_code(PhysAddr(0xffff0), &mut crossing)
            .unwrap()
    );
    assert_eq!(crossing, [0xa5; 32]);
    // Equal endpoint decoding is insufficient when a large span crosses two
    // A20 transitions: the interior still contains a discontiguous bank.
    let mut two_banks = vec![0xa5u8; 0x200001];
    assert!(
        !memory
            .bus()
            .read_plain_code(PhysAddr(0), &mut two_banks)
            .unwrap()
    );
    assert!(two_banks.iter().all(|&byte| byte == 0xa5));
    memory.set_a20_enabled(true).unwrap();
    assert!(
        memory
            .bus()
            .read_plain_code(PhysAddr(0xffff0), &mut crossing)
            .unwrap()
    );
}
