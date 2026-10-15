//! Conservative payload access relative to the entry TOP. Every possible
//! write participates in prefix exits, including slots overwritten later.
use crate::FloatInstruction as I;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct Access {
    pub read: u8,
    pub written: u8,
    pub rotation: u8,
}
impl Access {
    pub fn for_instructions(instructions: &[I]) -> Self {
        let mut access = Self {
            read: 0,
            written: 0,
            rotation: 0,
        };
        let mut top = 0usize;
        for instruction in instructions {
            match *instruction {
                I::Binary {
                    destination,
                    source,
                    pop,
                    ..
                } => {
                    let dst = (top + usize::from(destination)) & 7;
                    let src = (top + usize::from(source)) & 7;
                    access.read |= (1 << dst) | (1 << src);
                    access.written |= 1 << dst;
                    if pop {
                        top = (top + 1) & 7;
                    }
                }
                I::BinaryMemory { .. } | I::Negate | I::Absolute => {
                    access.read |= 1 << top;
                    access.written |= 1 << top;
                }
                I::LoadRegister(source) => {
                    access.read |= 1 << ((top + usize::from(source)) & 7);
                    top = (top + 7) & 7;
                    access.written |= 1 << top;
                }
                I::Load80 { .. } | I::LoadMemory { .. } | I::One | I::Zero => {
                    top = (top + 7) & 7;
                    access.written |= 1 << top;
                }
                I::StoreRegister { destination, pop } => {
                    access.read |= 1 << top;
                    access.written |= 1 << ((top + usize::from(destination)) & 7);
                    if pop {
                        top = (top + 1) & 7;
                    }
                }
                I::Store80 { pop, .. } => {
                    access.read |= 1 << top;
                    if pop {
                        top = (top + 1) & 7;
                    }
                }
                I::Exchange(other) => {
                    let pair = (1 << top) | (1 << ((top + usize::from(other)) & 7));
                    access.read |= pair;
                    access.written |= pair;
                }
            }
        }
        access.rotation = top as u8;
        access
    }
}
