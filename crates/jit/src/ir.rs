//! Pointer-free integer IR. Register indexes and widths are constructor checked.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Register {
    pub(crate) index: u8,
    pub(crate) bytes: u8,
    pub(crate) high8: bool,
}
impl Register {
    pub fn new(index: u8, bytes: u8, high8: bool) -> Option<Self> {
        (index < 8 && matches!(bytes, 1 | 2 | 4) && (!high8 || bytes == 1 && index < 4)).then_some(
            Self {
                index,
                bytes,
                high8,
            },
        )
    }
    pub(crate) fn mask(self) -> u32 {
        match self.bytes {
            1 => 0xff,
            2 => 0xffff,
            _ => u32::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Operand {
    Register(Register),
    Immediate(u32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Condition {
    Overflow,
    NotOverflow,
    Below,
    AboveEqual,
    Equal,
    NotEqual,
    BelowEqual,
    Above,
    Sign,
    NotSign,
    Parity,
    NotParity,
    Less,
    GreaterEqual,
    LessEqual,
    Greater,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Operation {
    Move,
    Add,
    AddCarry,
    Subtract,
    SubtractBorrow,
    And,
    Or,
    Xor,
    Compare,
    Test,
    Increment,
    Decrement,
    Negate,
    Not,
    Exchange,
    ZeroExtend,
    SignExtend,
    ByteSwap,
    SetCondition(Condition),
    ConditionalMove(Condition),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Instruction {
    pub(crate) operation: Operation,
    pub(crate) destination: Register,
    pub(crate) source: Operand,
}
impl Instruction {
    pub fn new(operation: Operation, destination: Register, source: Operand) -> Option<Self> {
        if let Operand::Register(register) = source
            && if matches!(operation, Operation::ZeroExtend | Operation::SignExtend) {
                register.bytes > destination.bytes
            } else {
                register.bytes != destination.bytes
            }
        {
            return None;
        }
        if operation == Operation::Exchange && !matches!(source, Operand::Register(_)) {
            return None;
        }
        if operation == Operation::ByteSwap && destination.bytes != 4 {
            return None;
        }
        if matches!(operation, Operation::SetCondition(_)) && destination.bytes != 1 {
            return None;
        }
        Some(Self {
            operation,
            destination,
            source,
        })
    }
}

/// The only memory generated code can address: nine owned 32-bit words.
/// Ordering follows x86 register encoding, not the guest Registers Rust layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntegerState {
    pub registers: [u32; 8],
    pub flags: u32,
}

const _: () = {
    assert!(std::mem::size_of::<IntegerState>() == 36);
    assert!(std::mem::align_of::<IntegerState>() == 4);
};
