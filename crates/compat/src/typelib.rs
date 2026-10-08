//! Portable identity and version values for Win16 TYPELIB exports.
//!
//! Type-library objects and native `ITypeLib` / `ITypeInfo` pointers remain in
//! the host COM object table. This module carries only guest-facing constants
//! and scalar values.

use crate::automation::{
    IID_ICREATETYPEINFO, IID_ICREATETYPELIB, IID_ITYPECOMP, IID_ITYPEINFO,
    IID_ITYPELIB,
};
use crate::com::Guid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TypeLibInterface {
    CreateTypeInfo,
    CreateTypeLib,
    TypeComp,
    TypeInfo,
    TypeLib,
}

impl TypeLibInterface {
    pub const fn iid(self) -> Guid {
        match self {
            Self::CreateTypeInfo => IID_ICREATETYPEINFO,
            Self::CreateTypeLib => IID_ICREATETYPELIB,
            Self::TypeComp => IID_ITYPECOMP,
            Self::TypeInfo => IID_ITYPEINFO,
            Self::TypeLib => IID_ITYPELIB,
        }
    }

    /// TYPELIB export ordinals 5 through 9 export these IID values.
    pub const fn variable_ordinal(self) -> u16 {
        match self {
            Self::CreateTypeInfo => 5,
            Self::CreateTypeLib => 6,
            Self::TypeComp => 7,
            Self::TypeInfo => 8,
            Self::TypeLib => 9,
        }
    }
}

pub const fn interface_for_variable_ordinal(ordinal: u16) -> Option<TypeLibInterface> {
    match ordinal {
        5 => Some(TypeLibInterface::CreateTypeInfo),
        6 => Some(TypeLibInterface::CreateTypeLib),
        7 => Some(TypeLibInterface::TypeComp),
        8 => Some(TypeLibInterface::TypeInfo),
        9 => Some(TypeLibInterface::TypeLib),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TypeLibSystemKind {
    Win16,
    Win32,
    Macintosh,
    Win64,
}

impl TryFrom<u16> for TypeLibSystemKind {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Win16),
            1 => Ok(Self::Win32),
            2 => Ok(Self::Macintosh),
            3 => Ok(Self::Win64),
            other => Err(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TypeLibVersion {
    pub major: u16,
    pub minor: u16,
}

impl TypeLibVersion {
    pub const fn packed(self) -> u32 {
        ((self.major as u32) << 16) | self.minor as u32
    }
}
