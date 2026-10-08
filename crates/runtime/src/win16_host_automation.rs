//! Owned host-boundary values for Win16 OLE Automation and TYPELIB.
//!
//! There are deliberately no guest FAR pointers in these DTOs. The runtime
//! resolves and copies guest strings, variants, bounds, and array elements
//! before sending a request; the host returns owned values for checked guest
//! writeback.

use crate::win16_automation_values::{Win16AutomationValue, Win16SafeArrayValue};
use compat_services::com::{ComObjectId, Guid, ReferenceDisposition};
use compat_services::typelib::{TypeLibSystemKind, TypeLibVersion};

#[derive(Clone, Debug, PartialEq)]
pub enum Win16OleAutOperation {
    VariantChangeType {
        source: Win16AutomationValue,
        target_vartype: u16,
        flags: u16,
        lcid: Option<u32>,
    },
    Convert {
        source_vartype: u16,
        source: Win16AutomationValue,
        target_vartype: u16,
        flags: u32,
        lcid: u32,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Win16TypeLibOperation {
    CreateTypeLib {
        system_kind: TypeLibSystemKind,
        path: Vec<u8>,
    },
    LoadTypeLib {
        path: Vec<u8>,
    },
    HashName {
        system_kind: TypeLibSystemKind,
        lcid: u32,
        name: Vec<u8>,
    },
    RegisterTypeLib {
        object: ComObjectId,
        full_path: Vec<u8>,
        help_directory: Vec<u8>,
    },
    LoadRegisteredTypeLib {
        iid: Guid,
        version: TypeLibVersion,
        lcid: u32,
    },
    QueryRegisteredTypeLibPath {
        iid: Guid,
        version: TypeLibVersion,
        lcid: u32,
    },
    OaBuildVersion,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Win16AutomationHostRequest {
    OleAut(Win16OleAutOperation),
    TypeLib(Win16TypeLibOperation),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Win16AutomationHostResult {
    Scalar(u32),
    HResult(u32),
    Variant {
        hresult: u32,
        value: Option<Win16AutomationValue>,
    },
    ComObject {
        hresult: u32,
        object: Option<ComObjectId>,
        iid: Guid,
        disposition: ReferenceDisposition,
    },
    TypeLibPath {
        hresult: u32,
        path: Option<Vec<u8>>,
    },
}
