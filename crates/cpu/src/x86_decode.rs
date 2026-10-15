//! x86 instruction decoding and operand normalization for the real-mode
//! executor. The implementation uses the upstream iced-x86 decoder package
//! behind the local `x86_decoder` dependency name.
//!
//! Instruction bytes are fetched one at a time through the checked CPU bus. This is
//! deliberate: decoding must not read past the end of guest memory merely to
//! fill iced-x86's input buffer. Only the start of a new instruction wraps to
//! the code size; continuation bytes retain the segment-limit boundary.
use guest_core::Registers;
use x86_decoder::{
    Code, CpuidFeature, Decoder, DecoderError, DecoderOptions, Instruction, Mnemonic, OpKind,
    Register,
};

use crate::memory_access::{AccessKind, CpuBus, LogicalSpan};
use crate::model::CpuFeatureSet;
use crate::{ControlTransfer, CpuError, CpuExecutionMode, registers::SegmentRegister};

const MAX_INSTRUCTION_LENGTH: usize = 15;

mod cache;
pub(crate) use cache::DecodeCache;

mod system;
pub(super) use system::{
    NormalizedSystemInstruction, SelectorQuery, SystemMemoryAddress, SystemOperand,
    SystemOperation, SystemRegisterDirection, SystemSegmentRegister, SystemTableKind,
    normalize_system_instruction,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DecodedInstruction {
    pub instruction: Instruction,
    pub opcode: u8,
    /// Default 32-bit operand size after applying the legacy 66h override.
    pub operand32: bool,
    /// Architectural FOP: escape opcode low three bits followed by ModRM.
    /// Prefixes and WAIT are not part of this eleven-bit value.
    pub x87_opcode: Option<u16>,
    pub start_ip: u32,
    pub next_ip: u32,
}

impl DecodedInstruction {
    pub fn is_x87(&self) -> bool {
        self.x87_opcode.is_some() || self.instruction.mnemonic() == Mnemonic::Wait
    }

    pub fn is_wait(&self) -> bool {
        self.instruction.mnemonic() == Mnemonic::Wait
    }

    /// Normalize iced-x86 feature metadata into this CPU's private feature
    /// set. Third-party decoder feature types stay inside this adapter.
    pub(crate) fn required_cpu_features(&self) -> CpuFeatureSet {
        let mut required = CpuFeatureSet::EMPTY;
        for feature in self.instruction.cpuid_features() {
            // The profile is family-level and does not expose Intel486
            // stepping selection; retain the routed baseline CMPXCHG path.
            let normalized = match feature {
                CpuidFeature::INTEL8086
                | CpuidFeature::INTEL186
                | CpuidFeature::INTEL286
                | CpuidFeature::INTEL386
                | CpuidFeature::INTEL486
                | CpuidFeature::INTEL486_A_ONLY => CpuFeatureSet::EMPTY,
                CpuidFeature::FPU | CpuidFeature::FPU287 | CpuidFeature::FPU387 => {
                    CpuFeatureSet::FPU
                }
                CpuidFeature::CPUID => CpuFeatureSet::CPUID,
                CpuidFeature::CX8 => CpuFeatureSet::CX8,
                CpuidFeature::CMOV => CpuFeatureSet::CMOV,
                CpuidFeature::MOV_TR => CpuFeatureSet::TEST_REGISTERS,
                CpuidFeature::SSE3 => CpuFeatureSet::SSE3,
                // PAUSE is encoded as F3 90 and remains a REP NOP on the
                // baseline profile, even when the dedicated hint is absent.
                CpuidFeature::PAUSE => CpuFeatureSet::EMPTY,
                _ => CpuFeatureSet::UNMODELED,
            };
            required = required.union(normalized);
        }
        required
    }

    pub(super) fn restores_repeat_flags_on_fault(&self) -> bool {
        (self.instruction.has_repe_prefix() || self.instruction.has_repne_prefix())
            && matches!(
                self.instruction.mnemonic(),
                Mnemonic::Cmpsb
                    | Mnemonic::Cmpsw
                    | Mnemonic::Cmpsd
                    | Mnemonic::Scasb
                    | Mnemonic::Scasw
                    | Mnemonic::Scasd
            )
    }

    /// Describe a control-transfer candidate. The CPU publishes it only after
    /// the corresponding instruction executor returns success.
    pub(super) fn control_transfer_candidate(
        &self,
        return_selector: u16,
        stack_selector: u16,
    ) -> Option<ControlTransfer> {
        match self.instruction.mnemonic() {
            Mnemonic::Call if is_far_call(self.instruction) => Some(ControlTransfer::FarCall {
                return_selector,
                return_offset: self.next_ip,
                stack_selector,
            }),
            Mnemonic::Retf => Some(ControlTransfer::FarReturn),
            Mnemonic::Iret | Mnemonic::Iretd => Some(ControlTransfer::InterruptReturn),
            _ => None,
        }
    }

    /// Whether this retired instruction must block maskable interrupt
    /// recognition at the following boundary.
    pub(super) fn creates_interrupt_shadow(
        &self,
        if_was_set: bool,
        shadow_was_active: bool,
    ) -> bool {
        // Intel guarantees that only the first instruction in a sequence of
        // interrupt-delaying instructions delays delivery. The shadow active
        // before this instruction is consumed by its retirement.
        if shadow_was_active {
            return false;
        }

        match self.instruction.mnemonic() {
            // Intel guarantees the STI delay when IF changes from zero to
            // one. A following STI with IF already set consumes the first
            // delay and does not extend it.
            Mnemonic::Sti => !if_was_set,
            Mnemonic::Mov | Mnemonic::Pop => self.instruction.op0_register() == Register::SS,
            _ => false,
        }
    }

    /// Whether this retired instruction inhibits debug exceptions at the
    /// following boundary after loading SS. The inhibition belongs to the
    /// instruction boundary, independently of the maskable-interrupt shadow.
    pub(super) fn creates_debug_exception_shadow(&self) -> bool {
        matches!(self.instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Pop)
            && self.instruction.op0_register() == Register::SS
    }
}

/// Far calls have either a direct far-branch operand or one of the supported
/// memory far-pointer forms. A near CALL through a memory operand remains a
/// near call even though its mnemonic is also `CALL`.
fn is_far_call(instruction: Instruction) -> bool {
    if instruction.op_count() != 1 {
        return false;
    }
    match instruction.op_kind(0) {
        OpKind::FarBranch16 | OpKind::FarBranch32 => true,
        OpKind::Memory => matches!(instruction.code(), Code::Call_m1616 | Code::Call_m1632),
        _ => false,
    }
}

/// Decode exactly the bytes iced-x86 asks for, never speculatively fetching
/// the remainder of the architectural 15-byte instruction window.
#[cfg(test)]
pub(super) fn decode(
    bus: &mut impl CpuBus,
    cs: u16,
    start_ip: u32,
) -> Result<DecodedInstruction, CpuError> {
    decode_inner(bus, cs, start_ip, None)
}

pub(super) fn decode_cached(
    bus: &mut impl CpuBus,
    cs: u16,
    start_ip: u32,
    cache: &mut DecodeCache,
) -> Result<DecodedInstruction, CpuError> {
    #[cfg(test)]
    if cache.bypass {
        return decode(bus, cs, start_ip);
    }
    decode_inner(bus, cs, start_ip, Some(cache))
}

/// Decode only a provider-certified plain code snapshot. It grants no fetch
/// permission and never replaces the ordinary byte-ordered fault path.
#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) fn decode_plain(bytes: &[u8], start_ip: u32, bits: u32, protected_eip32: bool) -> Option<DecodedInstruction> {
    let mut decoder = Decoder::with_ip(bits, bytes, u64::from(start_ip), DecoderOptions::MOV_TR);
    let instruction = decoder.decode();
    if decoder.last_error() != DecoderError::None || instruction.is_invalid() { return None; }
    let bytes = &bytes[..instruction.len()];
    Some(DecodedInstruction { instruction, opcode: bytes[0], operand32: (bits==16)==has_operand_size_override(bytes), x87_opcode: x87_opcode(bytes), start_ip, next_ip: start_ip.wrapping_add(instruction.len() as u32) & if bits==16 && !protected_eip32 {0xffff} else {u32::MAX} })
}

fn decode_inner(
    bus: &mut impl CpuBus,
    cs: u16,
    start_ip: u32,
    mut cache: Option<&mut DecodeCache>,
) -> Result<DecodedInstruction, CpuError> {
    let bits = bus.code_bits();
    if !matches!(bits, 16 | 32) {
        return Err(CpuError::InvalidCodeSize(bits));
    }
    let protected_eip32 = bus.architectural_mode_active()
        && bus.execution_mode() == Some(CpuExecutionMode::Protected);
    let ip_mask = if bits == 16 && !protected_eip32 {
        0xffff
    } else {
        u32::MAX
    };
    let mut bytes = [0_u8; MAX_INSTRUCTION_LENGTH];
    let candidate = cache.as_ref().and_then(|cache| {
        cache.lookup(cs, start_ip, bits, protected_eip32)
    });
    let mut candidate_matches = true;
    for length in 1..=MAX_INSTRUCTION_LENGTH {
        let fetch_ip =
            start_ip
                .checked_add((length - 1) as u32)
                .ok_or(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: start_ip,
                })?;
        crate::memory_values::read_bytes(
            bus,
            LogicalSpan {
                register: SegmentRegister::Cs,
                selector: cs,
                offset: fetch_ip,
                len: 1,
                address32: bits == 32 || protected_eip32,
            },
            AccessKind::Fetch,
            crate::memory_access::DataAlignment::Unaligned,
            &mut bytes[length - 1..length],
        )?;

        if let Some(candidate) = candidate {
            candidate_matches &= bytes[length - 1] == candidate.bytes[length - 1];
            if candidate_matches {
                if length == candidate.decoded.instruction.len() {
                    return Ok(candidate.decoded);
                }
                // This unchanged prefix belonged to a complete instruction.
                // Read its next byte through the same bus before reusing it.
                continue;
            }
        }

        let mut decoder = Decoder::with_ip(
            bits,
            &bytes[..length],
            u64::from(start_ip),
            DecoderOptions::MOV_TR,
        );
        let instruction = decoder.decode();
        match decoder.last_error() {
            DecoderError::None if !instruction.is_invalid() => {
                let instruction_length = instruction.len() as u32;
                let decoded = DecodedInstruction {
                    instruction,
                    opcode: bytes[0],
                    operand32: if bits == 16 {
                        has_operand_size_override(&bytes[..length])
                    } else {
                        !has_operand_size_override(&bytes[..length])
                    },
                    x87_opcode: x87_opcode(&bytes[..length]),
                    start_ip,
                    next_ip: start_ip.wrapping_add(instruction_length) & ip_mask,
                };
                if let Some(cache) = cache.as_mut() {
                    cache.insert(cs, bits, protected_eip32, bytes, decoded);
                }
                return Ok(decoded);
            }
            DecoderError::NoMoreBytes if length < MAX_INSTRUCTION_LENGTH => {}
            DecoderError::NoMoreBytes => {
                return Err(CpuError::InstructionTooLong {
                    ip: start_ip.wrapping_add(MAX_INSTRUCTION_LENGTH as u32) & ip_mask,
                });
            }
            DecoderError::InvalidInstruction
                if bytes[..length]
                    .iter()
                    .all(|byte| is_instruction_prefix(*byte))
                    && length < MAX_INSTRUCTION_LENGTH =>
            {
                // iced-x86 marks a prefix-only buffer invalid because it does
                // not yet contain an instruction. Keep fetching only while
                // every fetched byte is itself a legal legacy prefix.
            }
            DecoderError::InvalidInstruction
                if bytes[..length]
                    .iter()
                    .all(|byte| is_instruction_prefix(*byte)) =>
            {
                return Err(CpuError::InstructionTooLong {
                    ip: start_ip.wrapping_add(MAX_INSTRUCTION_LENGTH as u32) & ip_mask,
                });
            }
            DecoderError::InvalidInstruction => {
                return Err(CpuError::InvalidOpcode {
                    opcode: bytes[0],
                    ip: start_ip,
                });
            }
            DecoderError::None => {
                return Err(CpuError::InvalidOpcode {
                    opcode: bytes[0],
                    ip: start_ip,
                });
            }
            // `DecoderError` is non-exhaustive upstream. Future decoder
            // failures are reported as guest instruction errors, never
            // treated as successful decoding.
            _ => {
                return Err(CpuError::InvalidOpcode {
                    opcode: bytes[0],
                    ip: start_ip,
                });
            }
        }
    }

    Err(CpuError::InstructionTooLong {
        ip: start_ip.wrapping_add(MAX_INSTRUCTION_LENGTH as u32) & ip_mask,
    })
}

fn has_operand_size_override(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .take_while(|byte| is_instruction_prefix(**byte))
        .any(|byte| *byte == 0x66)
}

fn is_instruction_prefix(byte: u8) -> bool {
    matches!(
        byte,
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
    )
}

fn x87_opcode(bytes: &[u8]) -> Option<u16> {
    let index = bytes
        .iter()
        .position(|byte| !is_instruction_prefix(*byte))?;
    let escape = bytes[index];
    if !(0xd8..=0xdf).contains(&escape) {
        return None;
    }
    let modrm = *bytes.get(index + 1)?;
    Some((u16::from(escape & 7) << 8) | u16::from(modrm))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Gpr {
    /// x86 register encoding order: AX/CX/DX/BX/SP/BP/SI/DI.
    pub index: u8,
    /// Width in bytes: 1, 2, or 4.
    pub width: u8,
    pub high8: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MemoryOperand {
    pub base: Register,
    pub index: Register,
    pub scale: u32,
    pub displacement: u64,
    pub segment: SegmentRegister,
    pub address32: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operand {
    Gpr(Gpr),
    SystemRegister(SystemRegister),
    /// Logical x87 stack register, independent of decoder register enums.
    FloatRegister(u8),
    Segment(SegmentRegister),
    Memory(MemoryOperand),
    Immediate(u64),
    NearBranch {
        target: u64,
        width: u8,
    },
    FarBranch {
        offset: u32,
        segment: u16,
        width: u8,
    },
    SecondImmediate(u8),
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SystemRegister {
    pub kind: SystemRegisterKind,
    pub index: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SystemRegisterKind {
    Control,
    Debug,
    Test,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NormalizedInstruction {
    pub decoded: DecodedInstruction,
    pub mnemonic: Mnemonic,
    pub operands: [Operand; 5],
    pub operand_count: u8,
    pub memory_width: usize,
    pub repeated: Option<bool>,
}

impl NormalizedInstruction {
    pub fn new(decoded: DecodedInstruction) -> Self {
        let instruction = decoded.instruction;
        let mut operands = [Operand::Other; 5];
        for index in 0..instruction.op_count() {
            operands[index as usize] = normalize_operand(instruction, index);
        }

        let repeated = if instruction.has_repne_prefix() {
            Some(false)
        } else if instruction.has_repe_prefix() {
            Some(true)
        } else {
            None
        };

        Self {
            decoded,
            mnemonic: instruction.mnemonic(),
            operands,
            operand_count: instruction.op_count() as u8,
            memory_width: instruction.memory_size().size(),
            repeated,
        }
    }

    pub fn operand(&self, index: usize) -> Operand {
        self.operands.get(index).copied().unwrap_or(Operand::Other)
    }

    pub fn float_register(&self, index: usize) -> Option<u8> {
        match self.operand(index) {
            Operand::FloatRegister(index) => Some(index),
            _ => None,
        }
    }

    /// Get the explicit data width in bytes where iced-x86's operands provide
    /// one. Instructions without data operands use the decoded memory width or
    /// their operand-size prefix as a fallback.
    pub fn data_width(&self) -> u8 {
        for operand in self.operands.iter().take(usize::from(self.operand_count)) {
            match operand {
                Operand::Gpr(gpr) => return gpr.width,
                Operand::NearBranch { width, .. } | Operand::FarBranch { width, .. } => {
                    return *width;
                }
                Operand::Memory(_) => {
                    let size = self.memory_width;
                    if matches!(size, 1 | 2 | 4) {
                        return size as u8;
                    }
                }
                Operand::Immediate(_) => {}
                _ => {}
            }
        }

        for index in 0..self.decoded.instruction.op_count() {
            match self.decoded.instruction.op_kind(index) {
                OpKind::Immediate8to16 | OpKind::Immediate16 => return 2,
                OpKind::Immediate8to32 | OpKind::Immediate32 => return 4,
                _ => {}
            }
        }

        2
    }
}

fn normalize_operand(instruction: Instruction, operand: u32) -> Operand {
    let kind = instruction.op_kind(operand);
    match kind {
        OpKind::Register => normalize_register(instruction.op_register(operand)),
        OpKind::NearBranch16 => Operand::NearBranch {
            target: u64::from(instruction.near_branch16()),
            width: 2,
        },
        OpKind::NearBranch32 => Operand::NearBranch {
            target: u64::from(instruction.near_branch32()),
            width: 4,
        },
        OpKind::NearBranch64 => Operand::NearBranch {
            target: instruction.near_branch64(),
            width: 8,
        },
        OpKind::FarBranch16 => Operand::FarBranch {
            offset: u32::from(instruction.far_branch16()),
            segment: instruction.far_branch_selector(),
            width: 2,
        },
        OpKind::FarBranch32 => Operand::FarBranch {
            offset: instruction.far_branch32(),
            segment: instruction.far_branch_selector(),
            width: 4,
        },
        OpKind::Immediate8 => Operand::Immediate(u64::from(instruction.immediate8())),
        OpKind::Immediate8_2nd => Operand::SecondImmediate(instruction.immediate8_2nd()),
        OpKind::Immediate16 => Operand::Immediate(u64::from(instruction.immediate16())),
        OpKind::Immediate32 => Operand::Immediate(u64::from(instruction.immediate32())),
        OpKind::Immediate64 => Operand::Immediate(instruction.immediate64()),
        OpKind::Immediate8to16 => {
            Operand::Immediate(u64::from(instruction.immediate8to16() as u16))
        }
        OpKind::Immediate8to32 => {
            Operand::Immediate(u64::from(instruction.immediate8to32() as u32))
        }
        OpKind::Immediate8to64 => Operand::Immediate(instruction.immediate8to64() as u64),
        OpKind::Immediate32to64 => Operand::Immediate(instruction.immediate32to64() as u64),
        OpKind::Memory => normalize_memory(
            instruction,
            instruction.memory_base(),
            instruction.memory_index(),
            false,
        ),
        OpKind::MemorySegSI => normalize_memory(instruction, Register::SI, Register::None, false),
        OpKind::MemorySegESI => normalize_memory(instruction, Register::ESI, Register::None, false),
        OpKind::MemorySegRSI => normalize_memory(instruction, Register::RSI, Register::None, false),
        OpKind::MemorySegDI => normalize_memory(instruction, Register::DI, Register::None, false),
        OpKind::MemorySegEDI => normalize_memory(instruction, Register::EDI, Register::None, false),
        OpKind::MemorySegRDI => normalize_memory(instruction, Register::RDI, Register::None, false),
        OpKind::MemoryESDI => normalize_memory(instruction, Register::DI, Register::None, true),
        OpKind::MemoryESEDI => normalize_memory(instruction, Register::EDI, Register::None, true),
        OpKind::MemoryESRDI => normalize_memory(instruction, Register::RDI, Register::None, true),
    }
}

fn normalize_memory(
    instruction: Instruction,
    base: Register,
    index: Register,
    fixed_es: bool,
) -> Operand {
    let address32 = if register_width(base) == Some(4) || register_width(index) == Some(4) {
        true
    } else if register_width(base) == Some(2) || register_width(index) == Some(2) {
        false
    } else {
        instruction.memory_displ_size() == 4
    };
    let segment = if fixed_es {
        SegmentRegister::Es
    } else {
        segment_register(instruction.memory_segment()).unwrap_or(SegmentRegister::Ds)
    };
    Operand::Memory(MemoryOperand {
        base,
        index,
        scale: instruction.memory_index_scale(),
        displacement: instruction.memory_displacement64(),
        segment,
        address32,
    })
}

fn normalize_register(register: Register) -> Operand {
    if let Some(segment) = segment_register(register) {
        return Operand::Segment(segment);
    }
    if let Some(system_register) = system_register(register) {
        return Operand::SystemRegister(system_register);
    }
    match register {
        Register::ST0 => Operand::FloatRegister(0),
        Register::ST1 => Operand::FloatRegister(1),
        Register::ST2 => Operand::FloatRegister(2),
        Register::ST3 => Operand::FloatRegister(3),
        Register::ST4 => Operand::FloatRegister(4),
        Register::ST5 => Operand::FloatRegister(5),
        Register::ST6 => Operand::FloatRegister(6),
        Register::ST7 => Operand::FloatRegister(7),
        Register::AL => Operand::Gpr(Gpr {
            index: 0,
            width: 1,
            high8: false,
        }),
        Register::CL => Operand::Gpr(Gpr {
            index: 1,
            width: 1,
            high8: false,
        }),
        Register::DL => Operand::Gpr(Gpr {
            index: 2,
            width: 1,
            high8: false,
        }),
        Register::BL => Operand::Gpr(Gpr {
            index: 3,
            width: 1,
            high8: false,
        }),
        Register::AH => Operand::Gpr(Gpr {
            index: 0,
            width: 1,
            high8: true,
        }),
        Register::CH => Operand::Gpr(Gpr {
            index: 1,
            width: 1,
            high8: true,
        }),
        Register::DH => Operand::Gpr(Gpr {
            index: 2,
            width: 1,
            high8: true,
        }),
        Register::BH => Operand::Gpr(Gpr {
            index: 3,
            width: 1,
            high8: true,
        }),
        Register::AX => gpr(0, 2),
        Register::CX => gpr(1, 2),
        Register::DX => gpr(2, 2),
        Register::BX => gpr(3, 2),
        Register::SP => gpr(4, 2),
        Register::BP => gpr(5, 2),
        Register::SI => gpr(6, 2),
        Register::DI => gpr(7, 2),
        Register::EAX => gpr(0, 4),
        Register::ECX => gpr(1, 4),
        Register::EDX => gpr(2, 4),
        Register::EBX => gpr(3, 4),
        Register::ESP => gpr(4, 4),
        Register::EBP => gpr(5, 4),
        Register::ESI => gpr(6, 4),
        Register::EDI => gpr(7, 4),
        _ => Operand::Other,
    }
}

fn system_register(register: Register) -> Option<SystemRegister> {
    use Register as R;
    use SystemRegisterKind as K;

    let (kind, index) = match register {
        R::CR0 => (K::Control, 0),
        R::CR1 => (K::Control, 1),
        R::CR2 => (K::Control, 2),
        R::CR3 => (K::Control, 3),
        R::CR4 => (K::Control, 4),
        R::CR5 => (K::Control, 5),
        R::CR6 => (K::Control, 6),
        R::CR7 => (K::Control, 7),
        R::CR8 => (K::Control, 8),
        R::CR9 => (K::Control, 9),
        R::CR10 => (K::Control, 10),
        R::CR11 => (K::Control, 11),
        R::CR12 => (K::Control, 12),
        R::CR13 => (K::Control, 13),
        R::CR14 => (K::Control, 14),
        R::CR15 => (K::Control, 15),
        R::DR0 => (K::Debug, 0),
        R::DR1 => (K::Debug, 1),
        R::DR2 => (K::Debug, 2),
        R::DR3 => (K::Debug, 3),
        R::DR4 => (K::Debug, 4),
        R::DR5 => (K::Debug, 5),
        R::DR6 => (K::Debug, 6),
        R::DR7 => (K::Debug, 7),
        R::DR8 => (K::Debug, 8),
        R::DR9 => (K::Debug, 9),
        R::DR10 => (K::Debug, 10),
        R::DR11 => (K::Debug, 11),
        R::DR12 => (K::Debug, 12),
        R::DR13 => (K::Debug, 13),
        R::DR14 => (K::Debug, 14),
        R::DR15 => (K::Debug, 15),
        R::TR0 => (K::Test, 0),
        R::TR1 => (K::Test, 1),
        R::TR2 => (K::Test, 2),
        R::TR3 => (K::Test, 3),
        R::TR4 => (K::Test, 4),
        R::TR5 => (K::Test, 5),
        R::TR6 => (K::Test, 6),
        R::TR7 => (K::Test, 7),
        _ => return None,
    };
    Some(SystemRegister { kind, index })
}

fn gpr(index: u8, width: u8) -> Operand {
    Operand::Gpr(Gpr {
        index,
        width,
        high8: false,
    })
}

fn register_width(register: Register) -> Option<u8> {
    match register {
        Register::SI
        | Register::DI
        | Register::BX
        | Register::BP
        | Register::SP
        | Register::AX
        | Register::CX
        | Register::DX => Some(2),
        Register::ESI
        | Register::EDI
        | Register::EBX
        | Register::EBP
        | Register::ESP
        | Register::EAX
        | Register::ECX
        | Register::EDX => Some(4),
        _ => None,
    }
}

pub(super) fn register_value(registers: &Registers, register: Register) -> Option<u32> {
    Some(match register {
        Register::AX => registers.ax().into(),
        Register::CX => registers.cx().into(),
        Register::DX => registers.dx().into(),
        Register::BX => registers.bx().into(),
        Register::SP => registers.sp().into(),
        Register::BP => registers.bp().into(),
        Register::SI => registers.si().into(),
        Register::DI => registers.di().into(),
        Register::EAX => registers.eax,
        Register::ECX => registers.ecx,
        Register::EDX => registers.edx,
        Register::EBX => registers.ebx,
        Register::ESP => registers.esp,
        Register::EBP => registers.ebp,
        Register::ESI => registers.esi,
        Register::EDI => registers.edi,
        _ => return None,
    })
}

fn segment_register(register: Register) -> Option<SegmentRegister> {
    Some(match register {
        Register::ES => SegmentRegister::Es,
        Register::CS => SegmentRegister::Cs,
        Register::SS => SegmentRegister::Ss,
        Register::DS => SegmentRegister::Ds,
        Register::FS => SegmentRegister::Fs,
        Register::GS => SegmentRegister::Gs,
        _ => return None,
    })
}

pub(super) fn memory_offset(registers: &Registers, memory: MemoryOperand) -> Option<u32> {
    let base = if memory.base == Register::None {
        0
    } else {
        register_value(registers, memory.base)?
    };
    let index = if memory.index == Register::None {
        0
    } else {
        register_value(registers, memory.index)?.wrapping_mul(memory.scale)
    };
    let offset = base
        .wrapping_add(index)
        .wrapping_add(memory.displacement as u32);
    Some(if memory.address32 {
        offset
    } else {
        u32::from(offset as u16)
    })
}
