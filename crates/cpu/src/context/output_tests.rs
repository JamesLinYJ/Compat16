use super::*;
use guest_core::{GuestMemory, PhysAddr};

#[test]
fn real_mode_data_outputs_reload_caches_before_the_next_memory_instruction() {
    let mut cpu = Cpu::new(Registers {
        cs: 0x1000,
        ds: 0x1000,
        ss: 0x2000,
        esi: 0x2300,
        ..Registers::default()
    });
    cpu.reset_real_mode_segments_from_visible_registers()
        .unwrap();
    let mut memory = guest_core::memory::Memory::new().unwrap();
    memory.write(PhysAddr(0x10000), &[0x8b, 0x04]).unwrap(); // MOV AX,[SI]
    memory
        .initialize_rom(PhysAddr(0xf2300), &[0x81, 0xfe])
        .unwrap();
    cpu.set_real_mode_data_segment_outputs(RealModeDataSegmentOutputs {
        ds: Some(0xf000),
        ..RealModeDataSegmentOutputs::default()
    })
    .unwrap();
    assert_eq!(
        cpu.step(&mut memory.bus()).unwrap(),
        super::super::StepOutcome::Continue
    );
    assert_eq!(cpu.regs.ax(), 0xfe81);
    assert_eq!(cpu.regs.ds, 0xf000);
}

#[test]
fn real_mode_data_outputs_reload_equal_selectors_and_preserve_other_unreal_caches() {
    let mut cpu = Cpu::new(Registers {
        ds: 0xf000,
        es: 0x1234,
        ss: 0x2000,
        ..Registers::default()
    });
    cpu.reset_real_mode_segments_from_visible_registers()
        .unwrap();
    cpu.system
        .segment_cache_mut(SegmentRegister::Ds)
        .descriptor
        .base = 0x456700;
    cpu.system
        .segment_cache_mut(SegmentRegister::Ds)
        .descriptor
        .limit = 0x1ffff;
    cpu.system
        .segment_cache_mut(SegmentRegister::Es)
        .descriptor
        .base = 0x234500;
    cpu.system
        .segment_cache_mut(SegmentRegister::Es)
        .descriptor
        .limit = 0x2ffff;
    let preserved = [
        SegmentRegister::Cs,
        SegmentRegister::Ss,
        SegmentRegister::Es,
        SegmentRegister::Fs,
        SegmentRegister::Gs,
    ]
    .map(|register| (register, *cpu.system.segment_cache(register)));
    cpu.set_real_mode_data_segment_outputs(RealModeDataSegmentOutputs {
        ds: Some(0xf000),
        ..RealModeDataSegmentOutputs::default()
    })
    .unwrap();
    let ds = cpu.system.segment_cache(SegmentRegister::Ds);
    assert_eq!(
        (ds.selector, ds.descriptor.base, ds.descriptor.limit),
        (0xf000, 0xf0000, 0xffff)
    );
    for (register, old) in preserved {
        assert_eq!(*cpu.system.segment_cache(register), old);
    }
}

#[test]
fn real_mode_data_outputs_reject_other_modes_before_any_mutation() {
    for state in 0..3 {
        let mut cpu = Cpu::new(Registers::default());
        if state != 0 {
            cpu.reset_real_mode_segments_from_visible_registers()
                .unwrap();
            if state == 1 {
                cpu.system.cr0 |= CR0_PE;
            } else {
                cpu.regs.eflags |= 1 << 17;
            }
        }
        let before = cpu.capture_context();
        assert!(
            cpu.set_real_mode_data_segment_outputs(RealModeDataSegmentOutputs {
                ds: Some(0x4321),
                es: Some(0x5432),
                fs: Some(0x6543),
                gs: Some(0x7654),
            })
            .is_err()
        );
        assert!(cpu.capture_context() == before);
    }
}
