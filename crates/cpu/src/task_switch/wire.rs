//! Fixed Intel task-state-segment byte layouts.

use guest_core::Registers;
use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

type Le16 = U16;
type Le32 = U32;

#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct Tss16Wire {
    pub(super) backlink: Le16,
    pub(super) sp0: Le16,
    pub(super) ss0: Le16,
    pub(super) sp1: Le16,
    pub(super) ss1: Le16,
    pub(super) sp2: Le16,
    pub(super) ss2: Le16,
    pub(super) ip: Le16,
    pub(super) flags: Le16,
    pub(super) ax: Le16,
    pub(super) cx: Le16,
    pub(super) dx: Le16,
    pub(super) bx: Le16,
    pub(super) sp: Le16,
    pub(super) bp: Le16,
    pub(super) si: Le16,
    pub(super) di: Le16,
    pub(super) es: Le16,
    pub(super) cs: Le16,
    pub(super) ss: Le16,
    pub(super) ds: Le16,
    pub(super) ldt: Le16,
}

#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct Tss32Wire {
    pub(super) backlink: Le16,
    pub(super) backlink_reserved: Le16,
    pub(super) esp0: Le32,
    pub(super) ss0: Le16,
    pub(super) ss0_reserved: Le16,
    pub(super) esp1: Le32,
    pub(super) ss1: Le16,
    pub(super) ss1_reserved: Le16,
    pub(super) esp2: Le32,
    pub(super) ss2: Le16,
    pub(super) ss2_reserved: Le16,
    pub(super) cr3: Le32,
    pub(super) eip: Le32,
    pub(super) eflags: Le32,
    pub(super) eax: Le32,
    pub(super) ecx: Le32,
    pub(super) edx: Le32,
    pub(super) ebx: Le32,
    pub(super) esp: Le32,
    pub(super) ebp: Le32,
    pub(super) esi: Le32,
    pub(super) edi: Le32,
    pub(super) es: Le16,
    pub(super) es_reserved: Le16,
    pub(super) cs: Le16,
    pub(super) cs_reserved: Le16,
    pub(super) ss: Le16,
    pub(super) ss_reserved: Le16,
    pub(super) ds: Le16,
    pub(super) ds_reserved: Le16,
    pub(super) fs: Le16,
    pub(super) fs_reserved: Le16,
    pub(super) gs: Le16,
    pub(super) gs_reserved: Le16,
    pub(super) ldt: Le16,
    pub(super) ldt_reserved: Le16,
    pub(super) debug_trap: Le16,
    pub(super) io_map_base: Le16,
}

const _: () = assert!(core::mem::size_of::<Tss16Wire>() == 44);
const _: () = assert!(core::mem::size_of::<Tss32Wire>() == 104);
const _: () = assert!(core::mem::offset_of!(Tss16Wire, ip) == 14);
const _: () = assert!(core::mem::offset_of!(Tss32Wire, cr3) == 28);
const _: () = assert!(core::mem::offset_of!(Tss32Wire, eip) == 32);
const _: () = assert!(core::mem::offset_of!(Tss32Wire, debug_trap) == 100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TaskWidth {
    Bits16,
    Bits32,
}

impl TaskWidth {
    pub(super) const fn word_bytes(self) -> u8 {
        match self {
            Self::Bits16 => 2,
            Self::Bits32 => 4,
        }
    }

    pub(super) const fn minimum_tss_limit(self) -> u32 {
        match self {
            Self::Bits16 => 0x2b,
            Self::Bits32 => 0x67,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum TssImage {
    Bits16(Tss16Wire),
    Bits32(Tss32Wire),
}

#[derive(Clone, Debug)]
pub(super) struct TaskRegisters {
    pub(super) registers: Registers,
    pub(super) cr3: Option<u32>,
    pub(super) ldt: u16,
    pub(super) debug_trap: bool,
}

impl TssImage {
    pub(super) fn read(system_type: u8, bytes: &[u8]) -> Option<Self> {
        match system_type {
            1 | 3 => Tss16Wire::read_from_bytes(bytes).ok().map(Self::Bits16),
            9 | 0x0b => Tss32Wire::read_from_bytes(bytes).ok().map(Self::Bits32),
            _ => None,
        }
    }

    pub(super) fn set_backlink(&mut self, selector: u16) {
        match self {
            Self::Bits16(tss) => tss.backlink.set(selector),
            Self::Bits32(tss) => tss.backlink.set(selector),
        }
    }

    pub(super) fn load_registers(self, prior: &Registers) -> TaskRegisters {
        match self {
            Self::Bits16(tss) => {
                // A 16-bit TSS has no high halves for these registers or
                // EIP/EFLAGS. Intel SDM Vol. 3A §8.6 says the upper GPR halves
                // are modified but not maintained; their value is unspecified.
                // This emulator uses zero extension for the represented words
                // as a deterministic policy, rather than claiming a hardware
                // value, and clears VM because a 16-bit TSS cannot enter VM86.
                let mut registers = prior.clone();
                registers.eax = u32::from(tss.ax.get());
                registers.ecx = u32::from(tss.cx.get());
                registers.edx = u32::from(tss.dx.get());
                registers.ebx = u32::from(tss.bx.get());
                registers.esp = u32::from(tss.sp.get());
                registers.ebp = u32::from(tss.bp.get());
                registers.esi = u32::from(tss.si.get());
                registers.edi = u32::from(tss.di.get());
                registers.eip = u32::from(tss.ip.get());
                registers.eflags = u32::from(tss.flags.get()) | 2;
                registers.es = tss.es.get();
                registers.cs = tss.cs.get();
                registers.ss = tss.ss.get();
                registers.ds = tss.ds.get();
                // The 286-format image has no FS/GS fields. Their existing
                // visible selectors and hidden caches are not task state in
                // this format and are therefore left unchanged.
                TaskRegisters {
                    registers,
                    cr3: None,
                    ldt: tss.ldt.get(),
                    debug_trap: false,
                }
            }
            Self::Bits32(tss) => {
                let mut registers = prior.clone();
                registers.eax = tss.eax.get();
                registers.ecx = tss.ecx.get();
                registers.edx = tss.edx.get();
                registers.ebx = tss.ebx.get();
                registers.esp = tss.esp.get();
                registers.ebp = tss.ebp.get();
                registers.esi = tss.esi.get();
                registers.edi = tss.edi.get();
                registers.eip = tss.eip.get();
                registers.eflags = tss.eflags.get() | 2;
                registers.es = tss.es.get();
                registers.cs = tss.cs.get();
                registers.ss = tss.ss.get();
                registers.ds = tss.ds.get();
                registers.fs = tss.fs.get();
                registers.gs = tss.gs.get();
                TaskRegisters {
                    registers,
                    cr3: Some(tss.cr3.get()),
                    ldt: tss.ldt.get(),
                    debug_trap: tss.debug_trap.get() & 1 != 0,
                }
            }
        }
    }

    // Intel SDM Vol. 3A §8.2.1 (253668-082US, printed p. 8-5) classifies
    // the LDT selector and CR3 as static TSS fields. Preserve their original
    // bytes while updating the dynamic register image below.
    pub(super) fn save_registers(
        &mut self,
        registers: &Registers,
        saved_eip: u32,
        saved_eflags: u32,
    ) {
        match self {
            Self::Bits16(tss) => {
                tss.ip.set(saved_eip as u16);
                tss.flags.set(saved_eflags as u16);
                tss.ax.set(registers.ax());
                tss.cx.set(registers.cx());
                tss.dx.set(registers.dx());
                tss.bx.set(registers.bx());
                tss.sp.set(registers.sp());
                tss.bp.set(registers.bp());
                tss.si.set(registers.si());
                tss.di.set(registers.di());
                tss.es.set(registers.es);
                tss.cs.set(registers.cs);
                tss.ss.set(registers.ss);
                tss.ds.set(registers.ds);
            }
            Self::Bits32(tss) => {
                tss.eip.set(saved_eip);
                tss.eflags.set(saved_eflags);
                tss.eax.set(registers.eax);
                tss.ecx.set(registers.ecx);
                tss.edx.set(registers.edx);
                tss.ebx.set(registers.ebx);
                tss.esp.set(registers.esp);
                tss.ebp.set(registers.ebp);
                tss.esi.set(registers.esi);
                tss.edi.set(registers.edi);
                tss.es.set(registers.es);
                tss.cs.set(registers.cs);
                tss.ss.set(registers.ss);
                tss.ds.set(registers.ds);
                tss.fs.set(registers.fs);
                tss.gs.set(registers.gs);
            }
        }
    }

    /// Only architectural dynamic fields are written when suspending a task.
    /// In a 32-bit TSS, each selector occupies a four-byte slot whose upper
    /// half is reserved; split the spans so those reserved bytes stay untouched
    /// without reading them or the old dynamic state first.
    pub(super) fn dynamic_fields(&self) -> [Option<(u32, &[u8])>; 6] {
        match self {
            Self::Bits16(tss) => {
                let bytes = tss.as_bytes();
                [Some((14, &bytes[14..42])), None, None, None, None, None]
            }
            Self::Bits32(tss) => {
                let bytes = tss.as_bytes();
                [
                    Some((32, &bytes[32..74])),
                    Some((76, &bytes[76..78])),
                    Some((80, &bytes[80..82])),
                    Some((84, &bytes[84..86])),
                    Some((88, &bytes[88..90])),
                    Some((92, &bytes[92..94])),
                ]
            }
        }
    }

    pub(super) fn backlink_bytes(&self) -> &[u8] {
        match self {
            Self::Bits16(tss) => &tss.as_bytes()[..2],
            Self::Bits32(tss) => &tss.as_bytes()[..2],
        }
    }
}
