use guest_core::Registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SegmentRegister {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

pub(crate) fn read_segment(regs: &Registers, segment: SegmentRegister) -> u16 {
    match segment {
        SegmentRegister::Es => regs.es,
        SegmentRegister::Cs => regs.cs,
        SegmentRegister::Ss => regs.ss,
        SegmentRegister::Ds => regs.ds,
        SegmentRegister::Fs => regs.fs,
        SegmentRegister::Gs => regs.gs,
    }
}

fn register32(regs: &Registers, index: u8) -> u32 {
    match index & 7 {
        0 => regs.eax,
        1 => regs.ecx,
        2 => regs.edx,
        3 => regs.ebx,
        4 => regs.esp,
        5 => regs.ebp,
        6 => regs.esi,
        _ => regs.edi,
    }
}

fn set_register32(regs: &mut Registers, index: u8, value: u32) {
    match index & 7 {
        0 => regs.eax = value,
        1 => regs.ecx = value,
        2 => regs.edx = value,
        3 => regs.ebx = value,
        4 => regs.esp = value,
        5 => regs.ebp = value,
        6 => regs.esi = value,
        _ => regs.edi = value,
    }
}

fn register16(regs: &Registers, index: u8) -> u16 {
    register32(regs, index) as u16
}

fn set_register16(regs: &mut Registers, index: u8, value: u16) {
    let old = register32(regs, index);
    set_register32(regs, index, (old & 0xffff_0000) | u32::from(value));
}

pub(crate) fn read_register(regs: &Registers, index: u8, width: u8) -> u32 {
    match width {
        1 if index < 4 => u32::from(register16(regs, index) as u8),
        1 => u32::from((register16(regs, index - 4) >> 8) as u8),
        2 => u32::from(register16(regs, index)),
        _ => register32(regs, index),
    }
}

pub(crate) fn write_register(regs: &mut Registers, index: u8, width: u8, value: u32) {
    match width {
        1 if index < 4 => {
            let word = register16(regs, index);
            set_register16(regs, index, (word & 0xff00) | value as u8 as u16);
        }
        1 => {
            let target = index - 4;
            let word = register16(regs, target);
            set_register16(regs, target, (word & 0x00ff) | ((value as u8 as u16) << 8));
        }
        2 => set_register16(regs, index, value as u16),
        _ => set_register32(regs, index, value),
    }
}

pub(crate) fn set_segment(regs: &mut Registers, segment: SegmentRegister, value: u16) {
    match segment {
        SegmentRegister::Es => regs.es = value,
        SegmentRegister::Ss => regs.ss = value,
        SegmentRegister::Ds => regs.ds = value,
        SegmentRegister::Fs => regs.fs = value,
        SegmentRegister::Gs => regs.gs = value,
        SegmentRegister::Cs => {}
    }
}
