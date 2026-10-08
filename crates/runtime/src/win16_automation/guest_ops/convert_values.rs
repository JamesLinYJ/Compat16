//! Win16 VARIANT value decoding and staging for conversion calls.

use compat_services::automation::{
    VT_ARRAY, VT_BOOL, VT_BSTR, VT_BYREF, VT_CY, VT_DATE, VT_DISPATCH, VT_EMPTY, VT_ERROR, VT_I1,
    VT_I2, VT_I4, VT_I8, VT_INT, VT_NULL, VT_R4, VT_R8, VT_TYPEMASK, VT_UI1, VT_UI2, VT_UI4,
    VT_UI8, VT_UINT, VT_UNKNOWN, VT_VARIANT, Variant16,
};
use guest_core::{OwnerId, memory::Memory};
use win16_abi::{GlobalHeap, SelectorTable};

use crate::win16_automation_values::Win16AutomationValue;
use crate::{DiagnosticKind as Kind, RuntimeError};

use super::super::super::read_guest_far_bytes;
use super::super::{AutomationFailure, E_POINTER, Win16AutomationState, variant};

const DISP_E_BADVARTYPE: u32 = 0x8002_0008;
const MAX_VARIANT_NESTING: usize = 32;

pub(super) fn read_owned_variant(
    state: &Win16AutomationState,
    selectors: &SelectorTable,
    memory: &Memory,
    value: Variant16,
    depth: usize,
) -> Result<Win16AutomationValue, AutomationFailure> {
    if depth >= MAX_VARIANT_NESTING {
        return Err(AutomationFailure::from(RuntimeError::new(
            Kind::CompatibilityGap,
            "VariantChangeType source exceeds the supported VARIANT indirection depth",
        )));
    }
    variant::validate_vartype_bits(value.vt)?;
    let base = value.vt & VT_TYPEMASK;
    if value.vt & VT_ARRAY != 0 {
        return Err(AutomationFailure::from(RuntimeError::new(
            Kind::CompatibilityGap,
            "VariantChangeType SAFEARRAY input needs an owned native SAFEARRAY bridge",
        )));
    }
    let byref = value.vt & VT_BYREF != 0;
    if !variant::supported_vartype(base) {
        return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
    }
    if base == VT_VARIANT {
        if !byref {
            return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
        }
        let far = value.guest_far();
        if far == 0 {
            return Err(AutomationFailure::HResult(E_POINTER));
        }
        let nested =
            variant::read_variant(selectors, memory, far).map_err(AutomationFailure::from)?;
        return read_owned_variant(state, selectors, memory, nested, depth + 1);
    }
    if matches!(base, VT_DISPATCH | VT_UNKNOWN) {
        return Err(AutomationFailure::from(RuntimeError::new(
            Kind::CompatibilityGap,
            "guest COM proxy cannot be used as a native VARIANT interface pointer",
        )));
    }
    if base == VT_BSTR {
        let far = if byref {
            read_far_u32(selectors, memory, value.guest_far()).map_err(AutomationFailure::from)?
        } else {
            value.guest_far()
        };
        return match state
            .read_bstr(selectors, memory, far)
            .map_err(AutomationFailure::from)?
        {
            Some(bytes) => Ok(Win16AutomationValue::Bstr(bytes)),
            None => Ok(Win16AutomationValue::NullBstr),
        };
    }
    let width = vartype_width(base).ok_or_else(|| AutomationFailure::HResult(DISP_E_BADVARTYPE))?;
    let mut raw = [0_u8; 8];
    if byref {
        let bytes = read_far_bytes(selectors, memory, value.guest_far(), width)
            .map_err(AutomationFailure::from)?;
        raw[..width].copy_from_slice(&bytes);
    } else {
        raw[..width].copy_from_slice(&value.payload[..width]);
    }
    let raw = &raw[..width];
    let owned = match base {
        VT_EMPTY => Win16AutomationValue::Empty,
        VT_NULL => Win16AutomationValue::Null,
        VT_I1 => Win16AutomationValue::I1(raw[0] as i8),
        VT_UI1 => Win16AutomationValue::Ui1(raw[0]),
        VT_I2 => Win16AutomationValue::I2(i16::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_UI2 => Win16AutomationValue::Ui2(u16::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_I4 => Win16AutomationValue::I4(i32::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_INT => Win16AutomationValue::Int(i32::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_UI4 => Win16AutomationValue::Ui4(u32::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_UINT => Win16AutomationValue::UInt(u32::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_I8 => Win16AutomationValue::I8(i64::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_UI8 => Win16AutomationValue::Ui8(u64::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_R4 => Win16AutomationValue::R4(f32::from_bits(u32::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        ))),
        VT_R8 => Win16AutomationValue::R8(f64::from_bits(u64::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        ))),
        VT_CY => Win16AutomationValue::Currency(i64::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_DATE => Win16AutomationValue::Date(f64::from_bits(u64::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        ))),
        VT_ERROR => Win16AutomationValue::Error(i32::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        VT_BOOL => Win16AutomationValue::Bool(i16::from_le_bytes(
            raw.try_into().map_err(|_| invalid_variant_payload())?,
        )),
        _ => return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE)),
    };
    Ok(owned)
}

pub(super) fn stage_variant(
    state: &mut Win16AutomationState,
    value: &Win16AutomationValue,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
) -> Result<(Variant16, Option<u32>), RuntimeError> {
    let mut value = match value {
        Win16AutomationValue::Bstr(bytes) => {
            let far = state.allocate_bstr(heap, selectors, memory, owner, bytes)?;
            let mut variant = Variant16 {
                vt: VT_BSTR,
                reserved: [0; 3],
                payload: [0; 8],
            };
            variant.payload[..4].copy_from_slice(&far.to_le_bytes());
            return Ok((variant, Some(far)));
        }
        Win16AutomationValue::NullBstr => Variant16 {
            vt: VT_BSTR,
            reserved: [0; 3],
            payload: [0; 8],
        },
        Win16AutomationValue::Empty => Variant16::EMPTY,
        Win16AutomationValue::Null => Variant16 {
            vt: VT_NULL,
            reserved: [0; 3],
            payload: [0; 8],
        },
        Win16AutomationValue::I1(value) => scalar_variant(VT_I1, &[*value as u8]),
        Win16AutomationValue::Ui1(value) => scalar_variant(VT_UI1, &[*value]),
        Win16AutomationValue::I2(value) => scalar_variant(VT_I2, &value.to_le_bytes()),
        Win16AutomationValue::Ui2(value) => scalar_variant(VT_UI2, &value.to_le_bytes()),
        Win16AutomationValue::I4(value) => scalar_variant(VT_I4, &value.to_le_bytes()),
        Win16AutomationValue::Int(value) => scalar_variant(VT_INT, &value.to_le_bytes()),
        Win16AutomationValue::Ui4(value) => scalar_variant(VT_UI4, &value.to_le_bytes()),
        Win16AutomationValue::UInt(value) => scalar_variant(VT_UINT, &value.to_le_bytes()),
        Win16AutomationValue::I8(value) => scalar_variant(VT_I8, &value.to_le_bytes()),
        Win16AutomationValue::Ui8(value) => scalar_variant(VT_UI8, &value.to_le_bytes()),
        Win16AutomationValue::R4(value) => scalar_variant(VT_R4, &value.to_bits().to_le_bytes()),
        Win16AutomationValue::R8(value) => scalar_variant(VT_R8, &value.to_bits().to_le_bytes()),
        Win16AutomationValue::Currency(value) => scalar_variant(VT_CY, &value.to_le_bytes()),
        Win16AutomationValue::Date(value) => {
            scalar_variant(VT_DATE, &value.to_bits().to_le_bytes())
        }
        Win16AutomationValue::Error(value) => scalar_variant(VT_ERROR, &value.to_le_bytes()),
        Win16AutomationValue::Bool(value) => scalar_variant(VT_BOOL, &value.to_le_bytes()),
        Win16AutomationValue::Dispatch { .. } | Win16AutomationValue::Unknown { .. } => {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "native VariantChangeType returned an interface value without a COM lease",
            ));
        }
        Win16AutomationValue::Array(_) => {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "native VariantChangeType returned an array without a SAFEARRAY bridge",
            ));
        }
    };
    value.reserved = [0; 3];
    Ok((value, None))
}

fn scalar_variant(vt: u16, bytes: &[u8]) -> Variant16 {
    let mut value = Variant16 {
        vt,
        reserved: [0; 3],
        payload: [0; 8],
    };
    value.payload[..bytes.len()].copy_from_slice(bytes);
    value
}

pub(super) fn value_vartype(value: &Win16AutomationValue) -> Option<u16> {
    Some(match value {
        Win16AutomationValue::Empty => VT_EMPTY,
        Win16AutomationValue::Null => VT_NULL,
        Win16AutomationValue::I1(_) => VT_I1,
        Win16AutomationValue::I2(_) => VT_I2,
        Win16AutomationValue::I4(_) => VT_I4,
        Win16AutomationValue::R4(_) => VT_R4,
        Win16AutomationValue::R8(_) => VT_R8,
        Win16AutomationValue::Currency(_) => VT_CY,
        Win16AutomationValue::Date(_) => VT_DATE,
        Win16AutomationValue::Bstr(_) | Win16AutomationValue::NullBstr => VT_BSTR,
        Win16AutomationValue::Error(_) => VT_ERROR,
        Win16AutomationValue::Bool(_) => VT_BOOL,
        Win16AutomationValue::Ui1(_) => VT_UI1,
        Win16AutomationValue::Ui2(_) => VT_UI2,
        Win16AutomationValue::Ui4(_) => VT_UI4,
        Win16AutomationValue::I8(_) => VT_I8,
        Win16AutomationValue::Ui8(_) => VT_UI8,
        Win16AutomationValue::Int(_) => VT_INT,
        Win16AutomationValue::UInt(_) => VT_UINT,
        Win16AutomationValue::Dispatch { .. } => VT_DISPATCH,
        Win16AutomationValue::Unknown { .. } => VT_UNKNOWN,
        Win16AutomationValue::Array(array) => VT_ARRAY | array.element_vartype,
    })
}

fn vartype_width(vartype: u16) -> Option<usize> {
    Some(match vartype {
        VT_EMPTY | VT_NULL => 0,
        VT_I1 | VT_UI1 => 1,
        VT_I2 | VT_UI2 | VT_BOOL => 2,
        VT_I4 | VT_UI4 | VT_INT | VT_UINT | VT_R4 | VT_ERROR => 4,
        VT_I8 | VT_UI8 | VT_R8 | VT_CY | VT_DATE => 8,
        _ => return None,
    })
}

fn read_far_bytes(
    selectors: &SelectorTable,
    memory: &Memory,
    far: u32,
    length: usize,
) -> Result<Vec<u8>, RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 VARIANT by-reference value is null",
        ));
    }
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    read_guest_far_bytes(selectors, memory, pointer, length)
}

fn read_far_u32(selectors: &SelectorTable, memory: &Memory, far: u32) -> Result<u32, RuntimeError> {
    let bytes = read_far_bytes(selectors, memory, far, 4)?;
    Ok(u32::from_le_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_variant_payload())?,
    ))
}

fn invalid_variant_payload() -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        "Win16 VARIANT payload width changed during decoding",
    )
}
