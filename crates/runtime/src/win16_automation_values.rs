//! Owned values crossing the Win16 Automation host boundary.
//!
//! Strings and arrays contain copied data, while COM references contain only
//! opaque IDs. No guest address or native pointer is stored here.

use compat_services::com::{ComObjectId, Guid};

/// A guest Automation value after its FAR references have been checked and
/// copied. Guest BSTR bytes and native UTF-16 BSTRs remain separate ABIs.
#[derive(Clone, Debug, PartialEq)]
pub enum Win16AutomationValue {
    Empty,
    Null,
    I1(i8),
    I2(i16),
    I4(i32),
    R4(f32),
    R8(f64),
    Currency(i64),
    Date(f64),
    Bstr(Vec<u8>),
    NullBstr,
    Dispatch { object: ComObjectId, iid: Guid },
    Error(i32),
    Bool(i16),
    Unknown { object: ComObjectId, iid: Guid },
    Ui1(u8),
    Ui2(u16),
    Ui4(u32),
    I8(i64),
    Ui8(u64),
    Int(i32),
    UInt(u32),
    Array(Win16SafeArrayValue),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Win16SafeArrayValue {
    pub element_vartype: u16,
    pub bounds: Vec<Win16SafeArrayBound>,
    pub elements: Vec<Win16AutomationValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SafeArrayBound {
    pub elements: u32,
    pub lower_bound: i32,
}
