//! Architectural segment caches and checked RAM windows, without host APIs.
use super::*;
use crate::{CpuArchitecturalContext, CpuSegmentCacheState};
use guest_core::memory::Memory as OwnedMemory;

const CODE: u32 = 0x10000;
const DATA_BASE: u32 = 0x50000;
fn program(bits: u32) -> &'static [u8] {
    if bits == 16 {
        &[0x8b, 0x04, 0x01, 0x04, 0x83, 0xc6, 2, 0x49, 0x75, 0xf6]
    } else {
        &[0x8b, 0x06, 0x01, 0x06, 0x83, 0xc6, 4, 0x49, 0x75, 0xf6]
    }
}
struct Protected {
    cpu: Cpu,
    memory: OwnedMemory,
    initial: Registers,
    data: [u8; 1024],
}
impl Protected {
    fn new(bits: u32, engine: ExecutionEngine, ip: u32) -> Self {
        let initial = Registers {
            eax: 0xabcd_1234,
            ecx: 40,
            esi: 0x300,
            eflags: 0x203,
            cs: 8,
            ss: 16,
            ds: 16,
            es: 16,
            fs: 16,
            gs: 16,
            esp: 0xfffe,
            eip: ip,
            ..Registers::default()
        };
        let mut cpu = Cpu::new(initial.clone());
        cpu.set_execution_engine(engine);
        let data_segment = CpuSegmentCacheState {
            selector: 16,
            base: DATA_BASE,
            limit: 0x3ffff,
            access: 0x93,
            flags: if bits == 32 { 0x40 } else { 0 },
            usable: true,
        };
        let mut segments = [data_segment; 6];
        segments[0] = CpuSegmentCacheState {
            selector: 8,
            base: CODE,
            access: 0x9b,
            ..data_segment
        };
        cpu.import_architectural_context(CpuArchitecturalContext {
            cr0: 0x11,
            cr2: 0,
            cr3: 0,
            cpl: 0,
            segments,
            tables: Default::default(),
            ldt: Default::default(),
            task: Default::default(),
        })
        .unwrap();
        let mut memory = OwnedMemory::with_size(0x100000).unwrap();
        // A 16-bit relative branch truncates its target. Use rel32 to
        // exercise a self loop above 64 KiB in a 16-bit protected CS.
        let high_ip_code = [
            0x8b, 0x04, 0x01, 0x04, 0x83, 0xc6, 2, 0x49, 0x66, 0x0f, 0x85, 0xf1, 0xff, 0xff, 0xff,
        ];
        memory
            .write(
                PhysAddr(CODE + ip),
                if bits == 16 && ip > 0xffff {
                    &high_ip_code
                } else {
                    program(bits)
                },
            )
            .unwrap();
        let data = std::array::from_fn(|i| (i.wrapping_mul(137) >> 2) as u8);
        memory.write(PhysAddr(DATA_BASE + 0x300), &data).unwrap();
        Self {
            cpu,
            memory,
            initial,
            data,
        }
    }
    fn reset(&mut self) {
        self.cpu.regs = self.initial.clone();
        self.memory
            .write(PhysAddr(DATA_BASE + 0x300), &self.data)
            .unwrap();
    }
    fn run(&mut self, budget: u32) -> Result<Option<u32>, CpuError> {
        self.cpu
            .try_run_jit_loop(&mut self.memory, &RealModeSegments, budget)
    }
    fn warm(&mut self) {
        let mut compiled = false;
        for _ in 0..64 {
            self.reset();
            if self.run(256).unwrap().is_some() {
                compiled = true;
                break;
            }
        }
        assert!(compiled, "{:?}", self.cpu.jit_statistics());
        self.reset();
    }
    fn step(&mut self) {
        assert_eq!(
            self.cpu
                .step_with_context(&mut self.memory, &mut NoPorts, &RealModeSegments)
                .unwrap(),
            StepOutcome::Continue
        );
    }
    fn equal(&self, reference: &Self) {
        assert!(
            self.cpu.capture_context() == reference.cpu.capture_context(),
            "{:?} != {:?}",
            self.cpu.regs,
            reference.cpu.regs
        );
        let mut actual = [0; 1024];
        let mut expected = [0; 1024];
        self.memory
            .read(PhysAddr(DATA_BASE + 0x300), &mut actual)
            .unwrap();
        reference
            .memory
            .read(PhysAddr(DATA_BASE + 0x300), &mut expected)
            .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn protected_16_32_memory_loops_match_each_budget_and_high_eip() {
    for (bits, ip) in [(16, 0), (16, 0x10000), (32, 0), (32, 0x10000)] {
        let mut jit = Protected::new(bits, ExecutionEngine::Jit, ip);
        let mut reference = Protected::new(bits, ExecutionEngine::Interpreter, ip);
        jit.warm();
        for count in [1, 3, 40] {
            for budget in (0..32).chain([255, 256, u32::MAX]) {
                jit.reset();
                reference.reset();
                jit.cpu.regs.ecx = count;
                reference.cpu.regs.ecx = count;
                let before = jit.cpu.call_boundary_sequence;
                let retired = jit.run(budget).unwrap().unwrap_or(0);
                assert!(retired <= budget.min(256));
                assert_eq!(jit.cpu.call_boundary_sequence, before + u64::from(retired));
                for _ in 0..retired {
                    reference.step();
                }
                jit.equal(&reference);
                assert_eq!(
                    retired,
                    if budget < 2 {
                        0
                    } else {
                        budget.min(256).min(count * 5)
                    }
                );
            }
        }
        assert_eq!(jit.cpu.jit_statistics().failures, 0);
        assert!(jit.cpu.jit_statistics().memory_loops_executed > 0);
    }
}

#[test]
fn protected_window_exit_commits_prefix_then_resumes_in_the_next_window() {
    let mut jit = Protected::new(16, ExecutionEngine::Jit, 0);
    let mut reference = Protected::new(16, ExecutionEngine::Interpreter, 0);
    jit.warm();
    for machine in [&mut jit, &mut reference] {
        machine.cpu.regs.esi = 0x3fe;
    }
    assert_eq!(jit.run(256).unwrap(), Some(5));
    for _ in 0..5 {
        reference.step();
    }
    jit.equal(&reference);
    assert_eq!(jit.cpu.regs.esi, 0x400);
    let retired = jit.run(256).unwrap().unwrap();
    for _ in 0..retired {
        reference.step();
    }
    jit.equal(&reference);
}

#[test]
fn high_byte_registers_and_scaled_dword_addresses_match_the_interpreter() {
    for (bits, code) in [
        (16, &[0x8a, 0x24, 0x00, 0x24, 0x46, 0x49, 0x75, 0xf8][..]),
        (
            32,
            &[
                0x8b, 0x44, 0x9e, 0xf8, 0x01, 0x44, 0x9e, 0xf8, 0x83, 0xc6, 4, 0x49, 0x75, 0xf2,
            ][..],
        ),
    ] {
        let mut jit = Protected::new(bits, ExecutionEngine::Jit, 0);
        let mut reference = Protected::new(bits, ExecutionEngine::Interpreter, 0);
        for machine in [&mut jit, &mut reference] {
            machine.memory.write(PhysAddr(CODE), code).unwrap();
            machine.initial.ebx = 2;
            machine.reset();
        }
        jit.warm();
        for budget in 2..=200 {
            jit.reset();
            reference.reset();
            let retired = jit.run(budget).unwrap().unwrap();
            for _ in 0..retired {
                reference.step();
            }
            jit.equal(&reference);
            assert_eq!(retired, budget);
        }
    }
}

fn fault(machine: &mut Protected) -> (u8, u32) {
    let result = machine
        .cpu
        .step_with_context_observing_events(&mut machine.memory, &mut NoPorts, &RealModeSegments)
        .unwrap();
    let CpuObservedStepOutcome::EventDeferred(event) = result else {
        panic!("expected precise CPU fault: {result:?}")
    };
    (event.observation().vector, event.observation().saved_ip)
}

#[test]
fn descriptor_permissions_and_limits_decline_without_early_guest_faults() {
    let mut jit = Protected::new(16, ExecutionEngine::Jit, 0);
    jit.warm();
    let ds = crate::registers::SegmentRegister::Ds;
    jit.cpu
        .system
        .segment_cache_mut(ds)
        .descriptor
        .descriptor_type = crate::system::DescriptorType::Data {
        writable: false,
        expand_down: false,
        accessed: true,
    };
    let before = jit.cpu.capture_context();
    assert_eq!(jit.run(256).unwrap(), None);
    assert!(jit.cpu.capture_context() == before);
    jit.step(); // MOV from read-only data still succeeds.
    assert_eq!(fault(&mut jit), (13, 2)); // ADD [SI],AX is the actual fault.

    let mut limited = Protected::new(32, ExecutionEngine::Jit, 0);
    limited.warm();
    limited.cpu.system.segment_cache_mut(ds).descriptor.limit = 0x301;
    let before = limited.cpu.capture_context();
    assert_eq!(limited.run(256).unwrap(), None);
    assert!(limited.cpu.capture_context() == before);
    assert_eq!(fault(&mut limited), (13, 0)); // Full dword crosses the limit.
}

#[test]
fn alignment_paging_and_code_aliases_keep_the_checked_path() {
    let mut jit = Protected::new(32, ExecutionEngine::Jit, 0);
    jit.warm();
    jit.cpu.system.cr0 |= crate::system::CR0_PG;
    let before = jit.cpu.capture_context();
    assert_eq!(jit.run(256).unwrap(), None);
    assert!(jit.cpu.capture_context() == before);
    jit.cpu.system.cr0 &= !crate::system::CR0_PG;
    jit.cpu.system.cr0 |= crate::system::CR0_AM;
    jit.cpu.system.cpl = 3;
    for segment in &mut jit.cpu.system.segments {
        segment.selector |= 3;
        segment.descriptor.dpl = 3;
    }
    jit.cpu.regs.cs |= 3;
    jit.cpu.regs.ss |= 3;
    jit.cpu.regs.ds |= 3;
    jit.cpu.regs.es |= 3;
    jit.cpu.regs.fs |= 3;
    jit.cpu.regs.gs |= 3;
    jit.cpu.regs.eflags |= 1 << 18;
    jit.cpu.regs.esi = 0x301;
    assert_eq!(jit.run(256).unwrap(), None);
    assert_eq!(fault(&mut jit), (17, 0));

    let mut alias = Protected::new(16, ExecutionEngine::Jit, 0);
    alias.warm();
    alias
        .cpu
        .system
        .segment_cache_mut(crate::registers::SegmentRegister::Ds)
        .descriptor
        .base = CODE;
    alias.cpu.regs.esi = 0;
    let before = alias.cpu.capture_context();
    assert_eq!(alias.run(256).unwrap(), None);
    assert!(alias.cpu.capture_context() == before);
}

#[test]
fn uncertified_provider_does_not_gain_speculative_reads_or_writes() {
    let mut jit = Protected::new(16, ExecutionEngine::Jit, 0);
    jit.warm();
    let mut memory = Memory {
        ram: Ram::new(0x100000),
        trace: RefCell::default(),
        reject_data_read: false,
    };
    memory.ram.put(CODE as usize, program(16));
    let before = jit.cpu.capture_context();
    for _ in 0..32 {
        assert_eq!(
            jit.cpu
                .try_run_jit_loop(&mut memory, &RealModeSegments, 256)
                .unwrap(),
            None
        );
    }
    assert!(memory.trace.borrow().is_empty());
    assert!(jit.cpu.capture_context() == before);
}

#[test]
fn a20_alias_to_the_current_code_never_enters_the_memory_loop() {
    let mut jit = Protected::new(16, ExecutionEngine::Jit, 0);
    jit.warm();
    jit.cpu
        .system
        .segment_cache_mut(crate::registers::SegmentRegister::Ds)
        .descriptor
        .base = CODE + 0x100000;
    jit.cpu.regs.esi = 0;
    jit.memory.set_a20_enabled(false).unwrap();
    let before = jit.cpu.capture_context();
    assert_eq!(
        jit.cpu
            .try_run_jit_loop(&mut jit.memory.bus(), &RealModeSegments, 256)
            .unwrap(),
        None
    );
    assert!(jit.cpu.capture_context() == before);
}

#[test]
fn failed_ram_publication_is_terminal_and_does_not_publish_cpu_state() {
    use std::rc::Rc;
    struct FailingStorage {
        bytes: Vec<u8>,
        written: Rc<RefCell<usize>>,
    }
    impl guest_core::memory::MemoryStorage for FailingStorage {
        fn len(&self) -> u32 {
            self.bytes.len() as u32
        }
        fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
            output.copy_from_slice(&self.bytes[offset as usize..offset as usize + output.len()]);
            Ok(())
        }
        fn read_plain_code(&self, offset: u32, output: &mut [u8]) -> Result<bool, MemoryError> {
            self.read(offset, output)?;
            Ok(true)
        }
        fn read_plain_data(
            &self,
            offset: u32,
            output: &mut [u8],
            _: bool,
        ) -> Result<bool, MemoryError> {
            self.read_plain_code(offset, output)
        }
        fn write(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
            self.bytes[offset as usize] = input[0];
            *self.written.borrow_mut() += 1;
            Err(MemoryError::StorageAccess {
                address: offset,
                length: input.len(),
                transferred: 1,
                write: true,
                os_error: None,
            })
        }
    }
    let mut jit = Protected::new(16, ExecutionEngine::Jit, 0);
    jit.warm();
    let written = Rc::new(RefCell::new(0));
    let mut bytes = vec![0; 0x100000];
    bytes[CODE as usize..CODE as usize + program(16).len()].copy_from_slice(program(16));
    bytes[(DATA_BASE + 0x300) as usize] = 3;
    let mut memory = OwnedMemory::with_storage(Box::new(FailingStorage {
        bytes,
        written: written.clone(),
    }))
    .unwrap();
    let before = jit.cpu.capture_context();
    let error = jit
        .cpu
        .try_run_jit_loop(&mut memory, &RealModeSegments, 256)
        .unwrap_err();
    assert!(matches!(
        error,
        CpuError::Memory(MemoryError::StorageAccess {
            transferred: 1,
            write: true,
            ..
        })
    ));
    assert!(jit.cpu.capture_context() == before);
    assert_eq!(*written.borrow(), 1);
    assert!(
        jit.cpu
            .try_run_jit_loop(&mut memory, &RealModeSegments, 256)
            .is_err()
    );
    assert_eq!(
        *written.borrow(),
        1,
        "a partial write must never be replayed"
    );
}

#[test]
#[ignore = "explicit protected-memory throughput comparison"]
fn protected_memory_throughput_measurement() {
    use std::time::Instant;
    let mut machines = [
        Protected::new(32, ExecutionEngine::Jit, 0),
        Protected::new(32, ExecutionEngine::Interpreter, 0),
    ];
    machines[0].warm();
    let mut samples = [Vec::new(), Vec::new()];
    for sample in 0..4 {
        for index in 0..2 {
            let machine = &mut machines[index];
            let started = Instant::now();
            for _ in 0..50 {
                machine.reset();
                let mut left = 200;
                while left > 0 {
                    let retired = machine.run(left).unwrap().unwrap_or_else(|| {
                        machine.step();
                        1
                    });
                    left -= retired;
                }
            }
            if sample > 0 {
                samples[index].push(started.elapsed().as_nanos());
            }
        }
        machines[0].equal(&machines[1]);
    }
    for values in &mut samples {
        values.sort_unstable();
    }
    assert!(machines[0].cpu.jit_statistics().memory_loops_executed > 0);
    assert_eq!(machines[0].cpu.jit_statistics().failures, 0);
    eprintln!(
        "JIT_PROTECTED_MEMORY target={} instructions=10000 jit_median_ns={} interpreter_median_ns={} speedup={:.3}",
        std::env::consts::ARCH,
        samples[0][1],
        samples[1][1],
        samples[1][1] as f64 / samples[0][1] as f64
    );
}
