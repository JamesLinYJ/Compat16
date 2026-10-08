//! Normalization for i486 system instructions.
//!
//! iced-x86 types stay inside this decoder adapter; execution receives only
//! the crate's CPU-owned instruction and operand descriptions.

use guest_core::Registers;
use x86_decoder::{Instruction, Mnemonic, Register};

use crate::{memory_access::LogicalSpan, registers::SegmentRegister};

use super::{
    DecodedInstruction, Gpr, Operand, SystemRegister, SystemRegisterKind, normalize_operand,
    normalize_register,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NormalizedSystemInstruction {
    pub operation: SystemOperation,
    pub opcode: u8,
    pub ip: u32,
    pub operand32: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemOperation {
    Invd,
    Wbinvd,
    Invlpg(SystemOperand),
    MoveRegister {
        register: SystemRegister,
        direction: SystemRegisterDirection,
        operand: SystemOperand,
    },
    Clts,
    Lmsw(SystemOperand),
    Smsw(SystemOperand),
    StoreTable {
        table: SystemTableKind,
        operand: SystemOperand,
    },
    LoadTable {
        table: SystemTableKind,
        operand: SystemOperand,
    },
    StoreSystemSelector {
        register: SystemSegmentRegister,
        operand: SystemOperand,
    },
    LoadSystemSelector {
        register: SystemSegmentRegister,
        operand: SystemOperand,
    },
    QuerySelector {
        query: SelectorQuery,
        destination: Gpr,
        source: SystemOperand,
    },
    VerifySelector {
        writable: bool,
        source: SystemOperand,
    },
    AdjustRpl {
        destination: SystemOperand,
        source: Gpr,
    },
    Bound {
        index: Gpr,
        bounds: SystemOperand,
    },
    UnsupportedTestRegister,
    InvalidEncoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemTableKind {
    Global,
    Interrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemSegmentRegister {
    LocalDescriptorTable,
    Task,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SelectorQuery {
    AccessRights,
    Limit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemRegisterDirection {
    ToSystemRegister,
    FromSystemRegister,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemOperand {
    Gpr(Gpr),
    Memory(SystemMemoryAddress),
    Invalid,
    UnsupportedAddressing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SystemMemoryAddress {
    base: Option<Gpr>,
    index: Option<Gpr>,
    scale: u32,
    displacement: u32,
    segment: SegmentRegister,
    address32: bool,
}

impl SystemMemoryAddress {
    pub(crate) const fn segment_register(self) -> SegmentRegister {
        self.segment
    }

    pub(crate) const fn address32(self) -> bool {
        self.address32
    }

    pub(crate) fn logical_span(self, registers: &Registers, len: usize) -> LogicalSpan {
        let (selector, offset) = self.effective_address(registers);
        LogicalSpan {
            register: self.segment,
            selector,
            offset,
            len,
            address32: self.address32,
        }
    }

    /// Address a following internal reference within one multi-field operand.
    /// Its effective address was already truncated by address-size; continuation
    /// bytes advance without applying that truncation a second time.
    pub(crate) fn logical_subspan(
        self,
        registers: &Registers,
        byte_offset: u32,
        len: usize,
    ) -> Option<LogicalSpan> {
        let (selector, offset) = self.effective_address(registers);
        Some(LogicalSpan {
            register: self.segment,
            selector,
            offset: offset.checked_add(byte_offset)?,
            len,
            address32: true,
        })
    }

    fn from_memory(memory: super::MemoryOperand) -> Option<Self> {
        Some(Self {
            base: system_address_register(memory.base)?,
            index: system_address_register(memory.index)?,
            scale: memory.scale,
            displacement: memory.displacement as u32,
            segment: memory.segment,
            address32: memory.address32,
        })
    }

    /// This computes only the segmented effective address for INVLPG; it does
    /// not access memory, inspect page tables, or require a cached translation.
    pub(crate) fn effective_address(self, registers: &Registers) -> (u16, u32) {
        let base = self.base.map_or(0, |register| {
            crate::registers::read_register(registers, register.index, register.width)
        });
        let index = self.index.map_or(0, |register| {
            crate::registers::read_register(registers, register.index, register.width)
                .wrapping_mul(self.scale)
        });
        let offset = base.wrapping_add(index).wrapping_add(self.displacement);
        let offset = if self.address32 {
            offset
        } else {
            u32::from(offset as u16)
        };
        (
            crate::registers::read_segment(registers, self.segment),
            offset,
        )
    }
}

fn system_address_register(register: Register) -> Option<Option<Gpr>> {
    if register == Register::None {
        return Some(None);
    }
    match normalize_register(register) {
        Operand::Gpr(register) if matches!(register.width, 2 | 4) => Some(Some(register)),
        _ => None,
    }
}

/// Normalize i486 system instructions without exposing iced's instruction,
/// register, or operand types to the execution core.
pub(crate) fn normalize_system_instruction(
    decoded: DecodedInstruction,
) -> Option<NormalizedSystemInstruction> {
    let instruction = decoded.instruction;
    let locked = instruction.has_lock_prefix();
    let operation = match instruction.mnemonic() {
        Mnemonic::Invd => SystemOperation::Invd,
        Mnemonic::Wbinvd => SystemOperation::Wbinvd,
        Mnemonic::Invlpg => {
            let operand = if instruction.op_count() == 1 {
                match normalize_operand(instruction, 0) {
                    Operand::Memory(memory) => SystemMemoryAddress::from_memory(memory)
                        .map(SystemOperand::Memory)
                        .unwrap_or(SystemOperand::UnsupportedAddressing),
                    _ => SystemOperand::Invalid,
                }
            } else {
                SystemOperand::Invalid
            };
            SystemOperation::Invlpg(operand)
        }
        Mnemonic::Mov => {
            let operands = if instruction.op_count() == 2 {
                Some((
                    normalize_operand(instruction, 0),
                    normalize_operand(instruction, 1),
                ))
            } else {
                None
            };
            match operands {
                Some((Operand::SystemRegister(register), Operand::Gpr(_)))
                | Some((Operand::Gpr(_), Operand::SystemRegister(register)))
                    if register.kind == SystemRegisterKind::Test
                        && matches!(register.index, 3..=7) =>
                {
                    SystemOperation::UnsupportedTestRegister
                }
                Some((Operand::SystemRegister(register), Operand::Gpr(gpr))) => {
                    SystemOperation::MoveRegister {
                        register,
                        direction: SystemRegisterDirection::ToSystemRegister,
                        operand: SystemOperand::Gpr(gpr),
                    }
                }
                Some((Operand::Gpr(gpr), Operand::SystemRegister(register))) => {
                    SystemOperation::MoveRegister {
                        register,
                        direction: SystemRegisterDirection::FromSystemRegister,
                        operand: SystemOperand::Gpr(gpr),
                    }
                }
                Some((Operand::SystemRegister(_), _)) | Some((_, Operand::SystemRegister(_))) => {
                    SystemOperation::InvalidEncoding
                }
                _ => return None,
            }
        }
        Mnemonic::Clts => SystemOperation::Clts,
        Mnemonic::Lmsw => {
            let operand = if instruction.op_count() == 1 {
                normalize_system_operand(normalize_operand(instruction, 0))
            } else {
                SystemOperand::Invalid
            };
            SystemOperation::Lmsw(operand)
        }
        Mnemonic::Smsw => {
            let operand = if instruction.op_count() == 1 {
                normalize_system_operand(normalize_operand(instruction, 0))
            } else {
                SystemOperand::Invalid
            };
            SystemOperation::Smsw(operand)
        }
        Mnemonic::Sgdt | Mnemonic::Sidt => {
            let table = if instruction.mnemonic() == Mnemonic::Sgdt {
                SystemTableKind::Global
            } else {
                SystemTableKind::Interrupt
            };
            SystemOperation::StoreTable {
                table,
                operand: instruction_system_operand(instruction),
            }
        }
        Mnemonic::Lgdt | Mnemonic::Lidt => {
            let table = if instruction.mnemonic() == Mnemonic::Lgdt {
                SystemTableKind::Global
            } else {
                SystemTableKind::Interrupt
            };
            SystemOperation::LoadTable {
                table,
                operand: instruction_system_operand(instruction),
            }
        }
        Mnemonic::Sldt | Mnemonic::Str => {
            let register = if instruction.mnemonic() == Mnemonic::Sldt {
                SystemSegmentRegister::LocalDescriptorTable
            } else {
                SystemSegmentRegister::Task
            };
            SystemOperation::StoreSystemSelector {
                register,
                operand: instruction_system_operand(instruction),
            }
        }
        Mnemonic::Lldt | Mnemonic::Ltr => {
            let register = if instruction.mnemonic() == Mnemonic::Lldt {
                SystemSegmentRegister::LocalDescriptorTable
            } else {
                SystemSegmentRegister::Task
            };
            SystemOperation::LoadSystemSelector {
                register,
                operand: instruction_system_operand(instruction),
            }
        }
        Mnemonic::Lar | Mnemonic::Lsl => {
            if instruction.op_count() != 2 {
                SystemOperation::InvalidEncoding
            } else {
                let destination = match normalize_operand(instruction, 0) {
                    Operand::Gpr(gpr) if matches!(gpr.width, 2 | 4) => Some(gpr),
                    _ => None,
                };
                let source = normalize_system_operand(normalize_operand(instruction, 1));
                match destination {
                    Some(destination) => SystemOperation::QuerySelector {
                        query: if instruction.mnemonic() == Mnemonic::Lar {
                            SelectorQuery::AccessRights
                        } else {
                            SelectorQuery::Limit
                        },
                        destination,
                        source,
                    },
                    None => SystemOperation::InvalidEncoding,
                }
            }
        }
        Mnemonic::Verr | Mnemonic::Verw => SystemOperation::VerifySelector {
            writable: instruction.mnemonic() == Mnemonic::Verw,
            source: instruction_system_operand(instruction),
        },
        Mnemonic::Arpl => {
            if instruction.op_count() != 2 {
                SystemOperation::InvalidEncoding
            } else {
                let destination = normalize_system_operand(normalize_operand(instruction, 0));
                let source = match normalize_operand(instruction, 1) {
                    Operand::Gpr(gpr) if gpr.width == 2 => Some(gpr),
                    _ => None,
                };
                match source {
                    Some(source) => SystemOperation::AdjustRpl {
                        destination,
                        source,
                    },
                    None => SystemOperation::InvalidEncoding,
                }
            }
        }
        Mnemonic::Bound => {
            if instruction.op_count() != 2 {
                SystemOperation::InvalidEncoding
            } else {
                let index = match normalize_operand(instruction, 0) {
                    Operand::Gpr(gpr) if matches!(gpr.width, 2 | 4) => Some(gpr),
                    _ => None,
                };
                let bounds = normalize_system_operand(normalize_operand(instruction, 1));
                match index {
                    Some(index) => SystemOperation::Bound { index, bounds },
                    None => SystemOperation::InvalidEncoding,
                }
            }
        }
        _ => return None,
    };
    Some(NormalizedSystemInstruction {
        operation: if locked {
            SystemOperation::InvalidEncoding
        } else {
            operation
        },
        opcode: decoded.opcode,
        ip: decoded.start_ip,
        operand32: decoded.operand32,
    })
}

fn instruction_system_operand(instruction: Instruction) -> SystemOperand {
    if instruction.op_count() != 1 {
        SystemOperand::Invalid
    } else {
        normalize_system_operand(normalize_operand(instruction, 0))
    }
}

fn normalize_system_operand(operand: Operand) -> SystemOperand {
    match operand {
        Operand::Gpr(gpr) => SystemOperand::Gpr(gpr),
        Operand::Memory(memory) => SystemMemoryAddress::from_memory(memory)
            .map(SystemOperand::Memory)
            .unwrap_or(SystemOperand::UnsupportedAddressing),
        _ => SystemOperand::Invalid,
    }
}
