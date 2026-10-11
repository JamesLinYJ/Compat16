use super::{
    Cpu, CpuError, CpuEventSource, CpuModel, CpuObservedStepOutcome, RealModeSegments,
    StepOutcome, CF, OF, SF,
};
use guest_core::io::NoPorts;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

mod modes32;
mod float_vectors;
mod x87_execution;
mod transcendental_vectors;
mod interrupt_shadow;
mod execution_boundary;

struct Ram {
    bytes: Vec<u8>,
    rejected_write: Option<u32>,
}

impl Ram {
    fn new(length: usize) -> Self {
        Self { bytes: vec![0; length], rejected_write: None }
    }

    fn put(&mut self, address: usize, bytes: &[u8]) {
        self.bytes[address..address + bytes.len()].copy_from_slice(bytes);
    }

    fn reject_write_at(&mut self, address: u32) {
        self.rejected_write = Some(address);
    }
}

impl GuestMemory for Ram {
    fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate_read(address, length)?;
        let length = u32::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        let end = address.0.checked_add(length).ok_or(MemoryError::AddressOverflow)?;
        if let Some(rejected) = self.rejected_write {
            if address.0 <= rejected && rejected < end {
                return Err(MemoryError::ReadOnly { address: rejected, length: 1 });
            }
        }
        Ok(())
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = address.0 as usize;
        let Some(end) = start.checked_add(bytes.len()) else {
            return Err(MemoryError::AddressOverflow);
        };
        let Some(source) = self.bytes.get(start..end) else {
            return Err(MemoryError::OutOfBounds { address: address.0, length: bytes.len() });
        };
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, bytes.len())?;
        let start = address.0 as usize;
        let Some(end) = start.checked_add(bytes.len()) else {
            return Err(MemoryError::AddressOverflow);
        };
        let Some(target) = self.bytes.get_mut(start..end) else {
            return Err(MemoryError::OutOfBounds { address: address.0, length: bytes.len() });
        };
        target.copy_from_slice(bytes);
        Ok(())
    }
}

fn cpu_with(code: &[u8], ram_size: usize) -> (Cpu, Ram) {
    let mut ram = Ram::new(ram_size);
    ram.put(0, code);
    let mut regs = Registers::default();
    regs.eflags = 2;
    regs.ss = 0x100;
    regs.set_sp(0xfffe);
    (Cpu::new(regs), ram)
}

#[test]
fn arithmetic_updates_width_specific_flags_and_halts() {
    let (mut cpu, mut ram) = cpu_with(&[0xb8, 0xff, 0x7f, 0x05, 0x01, 0x00, 0xf4], 0x10000);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(cpu.regs.ax(), 0x8000);
    assert_eq!(cpu.regs.eflags & (SF | OF), SF | OF);
    assert_eq!(cpu.regs.eflags & CF, 0);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
}

#[test]
fn loop_and_near_call_preserve_wrapping_stack_state() {
    let code = [0xb9, 0x03, 0x00, 0x49, 0x75, 0xfd, 0xe8, 0x02, 0x00, 0xf4, 0x90, 0xc3];
    let (mut cpu, mut ram) = cpu_with(&code, 0x20000);
    for _ in 0..9 {
        assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    }
    assert_eq!(cpu.regs.cx(), 0);
    assert_eq!(cpu.regs.ip(), 9);
    assert_eq!(cpu.regs.sp(), 0xfffe);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
}

#[test]
fn instruction_pointer_wraps_after_fetch_at_end_of_sixteen_bit_segment() {
    let mut ram = Ram::new(0x22000);
    let code_address = usize::from(0x1000_u16) * 16 + 0xfffe;
    ram.put(code_address, &[0xeb, 0xfe]);
    let mut regs = Registers::default();
    regs.cs = 0x1000;
    regs.set_ip(0xfffe);
    let mut cpu = Cpu::new(regs);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(cpu.regs.ip(), 0xfffe);
}

#[test]
fn real_mode_word_data_crossing_segment_limit_faults_without_wrapping() {
    // Intel SDM Vol. 3B, "Segment Wraparound": unlike the 8086, the
    // Intel486 faults when a word crosses a real-address segment limit.
    // mov ax,[ffff]; mov [ffff],ax
    for opcode in [0xa1, 0xa3] {
        let (mut cpu, mut ram) = cpu_with(&[opcode, 0xff, 0xff], 0x22000);
        cpu.regs.ds = 0x100;
        cpu.regs.set_ax(0xabcd);
        ram.put(0x10fff, &[0x34]);
        ram.put(0x1000, &[0x12]);
        let before = cpu.regs.clone();
        let event = observe_event(&mut cpu, &mut ram);
        assert_eq!(event.vector, 13);
        assert_eq!(event.source, CpuEventSource::Fault);
        assert_eq!(event.error_code, Some(0));
        assert_eq!(event.saved_ip, 0);
        assert_eq!(cpu.regs, before);
        assert_eq!(ram.bytes[0x10fff], 0x34);
        assert_eq!(ram.bytes[0x1000], 0x12);
    }
}

fn observe_event(cpu: &mut Cpu, ram: &mut Ram) -> super::CpuEventObservation {
    match cpu.step_with_context_observing_events(ram, &mut NoPorts, &RealModeSegments).unwrap() {
        CpuObservedStepOutcome::EventDeferred(event) => event.observation(),
        other => panic!("expected a processor event, got {other:?}"),
    }
}

#[test]
fn rep_movsb_updates_indices_and_count() {
    let (mut cpu, mut ram) = cpu_with(&[0xf3, 0xa4], 0x3000);
    cpu.regs.ds = 0x100;
    cpu.regs.es = 0x200;
    cpu.regs.set_si(0x20);
    cpu.regs.set_di(0x30);
    cpu.regs.set_cx(3);
    ram.put(0x1020, &[4, 5, 6]);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(&ram.bytes[0x2030..0x2033], &[4, 5, 6]);
    assert_eq!(cpu.regs.cx(), 0);
    assert_eq!(cpu.regs.si(), 0x23);
    assert_eq!(cpu.regs.di(), 0x33);
}

#[test]
fn failed_guest_data_read_is_reported_without_committing_ip() {
    let (mut cpu, mut ram) = cpu_with(&[0xa1, 0x00, 0x00], 0x1000);
    cpu.regs.ds = 0x200;
    let error = cpu.step(&mut ram).unwrap_err();
    assert!(matches!(error, CpuError::Memory(MemoryError::OutOfBounds { .. })));
    assert_eq!(cpu.regs.ip(), 0);
}

#[test]
fn software_interrupt_saves_ip_after_instruction_and_iret_returns() {
    let (mut cpu, mut ram) = cpu_with(&[0xcd, 0x21, 0xf4], 0x20000);
    ram.put(0x21 * 4, &[0x00, 0x02, 0x00, 0x00]);
    ram.put(0x200, &[0xcf]); // iret
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!((cpu.regs.cs, cpu.regs.ip(), cpu.regs.sp()), (0, 0x200, 0xfff8));
    assert_eq!(&ram.bytes[0x10ff8..0x10ffe], &[2, 0, 0, 0, 2, 0]);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!((cpu.regs.cs, cpu.regs.ip(), cpu.regs.sp()), (0, 2, 0xfffe));
    assert_eq!(cpu.regs.eflags, 2);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
}

#[test]
fn fifteen_prefix_bytes_enforce_the_instruction_length_limit() {
    let (mut cpu, mut ram) = cpu_with(&[0x66; 16], 0x1000);
    // Keep the decoder's precise diagnostic as well as the CPU's architectural
    // #GP delivery contract; the fault restarts at the beginning of the prefix run.
    let mut system = crate::system::CpuSystem::reset();
    let mut bus = crate::memory_access::CpuMemoryAccess::new(
        &mut ram, &RealModeSegments, &mut system,
        crate::memory_access::AccessSite { opcode: 0, ip: 0, eflags: 2 },
    );
    assert!(matches!(
        crate::x86_decode::decode(&mut bus, 0, 0),
        Err(CpuError::InstructionTooLong { ip: 15 })
    ));
    let event = observe_event(&mut cpu, &mut ram);
    assert_eq!(event.vector, 13);
    assert_eq!(event.source, CpuEventSource::Fault);
    assert_eq!(event.error_code, Some(0));
    assert_eq!(event.saved_ip, 0);
    assert_eq!(cpu.regs.ip(), 0);
}

#[test]
fn cpuid_is_an_invalid_opcode_on_the_i486_profile() {
    let (cpu, mut ram) = cpu_with(&[0x0f, 0xa2], 0x1000);
    let mut cpu = Cpu::new_with_model(cpu.regs, CpuModel::I486);
    let before = cpu.regs.clone();
    let event = observe_event(&mut cpu, &mut ram);
    assert_eq!(event.vector, 6);
    assert_eq!(event.source, CpuEventSource::Fault);
    assert_eq!(event.error_code, None);
    assert_eq!(event.saved_ip, 0);
    assert_eq!(cpu.regs, before);
}

#[test]
fn operand_size_override_executes_386_register_and_stack_forms() {
    let code = [
        0x66, 0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax,12345678h
        0x66, 0x50, // push eax
        0x66, 0x5b, // pop ebx
        0x66, 0x9c, // pushfd
        0x66, 0x9d, // popfd
        0x66, 0x60, // pushad
        0x66, 0x61, // popad
        0xf4,
    ];
    let (mut cpu, mut ram) = cpu_with(&code, 0x20000);
    for _ in 0..7 {
        assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    }
    assert_eq!(cpu.regs.eax, 0x1234_5678);
    assert_eq!(cpu.regs.ebx, 0x1234_5678);
    assert_eq!(cpu.regs.sp(), 0xfffe);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
}

#[test]
fn real_mode_interrupt_pushes_frame_loads_ivt_and_wakes_halted_cpu() {
    let (mut cpu, mut ram) = cpu_with(&[0xf4], 0x30000);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
    cpu.regs.cs = 0x1111;
    cpu.regs.set_ip(0x2222);
    cpu.regs.set_sp(0xfffe);
    cpu.regs.eflags = 0x0b02;
    ram.put(0x21 * 4, &[0x34, 0x12, 0x00, 0x20]);

    cpu.enter_real_mode_interrupt(0x21, &mut ram).unwrap();

    assert_eq!((cpu.regs.cs, cpu.regs.ip()), (0x2000, 0x1234));
    assert_eq!(cpu.regs.sp(), 0xfff8);
    assert_eq!(cpu.regs.eflags, 0x0802);
    assert_eq!(ram.bytes[0x10ff8..0x10ff8 + 6], [0x22, 0x22, 0x11, 0x11, 0x02, 0x0b]);

    ram.put(0x20000 + 0x1234, &[0xf4]);
    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Halt);
    assert_eq!(cpu.regs.ip(), 0x1235);
}

#[test]
fn real_mode_interrupt_stack_pointer_wraps_between_aligned_words() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x70000);
    cpu.regs.ss = 0x1000;
    cpu.regs.set_sp(0);
    cpu.regs.cs = 0x1234;
    cpu.regs.set_ip(0x4567);
    cpu.regs.eflags = 0x0302;
    // Direct interrupt entry consumes CPU-owned hidden caches; unlike step(),
    // it does not initialize them from fixture edits to the visible registers.
    cpu.reset_real_mode_segments_from_visible_registers().unwrap();
    let before = cpu.regs.clone();
    ram.put(0x80 * 4, &[0xbc, 0x9a, 0x78, 0x56]);
    ram.put(0x56780 + 0x9abc, &[0xcf]); // iret

    cpu.enter_real_mode_interrupt(0x80, &mut ram).unwrap();

    assert_eq!((cpu.regs.cs, cpu.regs.ip()), (0x5678, 0x9abc));
    assert_eq!(cpu.regs.sp(), 0xfffa);
    assert_eq!(&ram.bytes[0x1fffa..0x20000], &[0x67, 0x45, 0x34, 0x12, 0x02, 0x03]);
    assert_eq!(cpu.regs.eflags, 2);

    assert_eq!(cpu.step(&mut ram).unwrap(), StepOutcome::Continue);
    assert_eq!(cpu.regs, before);
}

#[test]
fn real_mode_interrupt_word_crossing_stack_limit_faults_without_writes() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x70000);
    cpu.regs.ss = 0x1000;
    cpu.regs.set_sp(1);
    cpu.regs.set_ip(0x4567);
    cpu.regs.cs = 0x1234;
    cpu.reset_real_mode_segments_from_visible_registers().unwrap();
    ram.put(0x80 * 4, &[0xbc, 0x9a, 0x78, 0x56]);
    ram.put(0x1fffb, &[0xaa; 5]);
    ram.put(0x10000, &[0xbb]);
    let before = cpu.regs.clone();
    assert_eq!(
        cpu.enter_real_mode_interrupt(0x80, &mut ram).unwrap_err(),
        CpuError::StackSegmentFault { error_code: 0, ip: 0x4567 }
    );
    assert_eq!(cpu.regs, before);
    assert_eq!(&ram.bytes[0x1fffb..0x20000], &[0xaa; 5]);
    assert_eq!(ram.bytes[0x10000], 0xbb);
}

#[test]
fn rejected_interrupt_stack_write_leaves_registers_and_stack_unchanged() {
    let (mut cpu, mut ram) = cpu_with(&[], 0x70000);
    cpu.regs.set_sp(0x1002);
    cpu.regs.set_ip(0x4567);
    cpu.regs.cs = 0x1234;
    cpu.regs.eflags = 0x0302;
    ram.put(0x80 * 4, &[0xbc, 0x9a, 0x78, 0x56]);
    ram.put(0x1ffc, &[0xaa; 6]);
    ram.reject_write_at(0x2001);
    let original_registers = cpu.regs.clone();

    let error = cpu.enter_real_mode_interrupt(0x80, &mut ram).unwrap_err();

    assert!(matches!(error, CpuError::Memory(MemoryError::ReadOnly { .. })));
    assert_eq!(cpu.regs, original_registers);
    assert_eq!(&ram.bytes[0x1ffc..0x2002], &[0xaa; 6]);
}

#[test]
fn cpu_error_display_is_readable_and_keeps_nested_sources() {
    use guest_core::io::{PortError, PortWidth};

    let errors = [
        CpuError::Memory(MemoryError::OutOfBounds {
            address: 0x1234,
            length: 4,
        }),
        CpuError::Io(PortError::Unsupported {
            port: 0x03c0,
            width: PortWidth::Word,
            write: true,
        }),
        CpuError::UnsupportedOpcode {
            opcode: 0x0f,
            ip: 0x1234,
        },
        CpuError::InvalidOpcode {
            opcode: 0xf1,
            ip: 0x1234,
        },
        CpuError::InvalidGroup {
            opcode: 0xf7,
            extension: 7,
            ip: 0x1234,
        },
        CpuError::InstructionTooLong { ip: 0x1234 },
        CpuError::InvalidCodeSize(64),
        CpuError::FloatException,
        CpuError::DivideError,
    ];

    for error in errors {
        let message = error.to_string();
        assert!(!message.contains('{'), "debug struct leaked into: {message}");
        assert!(!message.contains('}'), "debug struct leaked into: {message}");
    }

    let unsupported = CpuError::UnsupportedOpcode {
        opcode: 0x0f,
        ip: 0x1234,
    }
    .to_string();
    assert!(unsupported.contains("0x0F"));
    assert!(unsupported.contains("0x00001234"));
    assert!(unsupported.contains("not implemented"));

    let io_error = CpuError::Io(PortError::Unsupported {
        port: 0x03c0,
        width: PortWidth::Word,
        write: true,
    });
    let io_message = io_error.to_string();
    assert!(io_message.contains("word (16-bit) write"));
    assert!(io_message.contains("0x03C0"));
    assert!(std::error::Error::source(&io_error).is_some());
}
