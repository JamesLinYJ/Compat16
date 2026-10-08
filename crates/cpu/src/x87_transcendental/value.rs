use rustc_apfloat::ieee::Quad;

use crate::x87_math::{self, Classification};
use crate::x87_state::Ext80;

pub(crate) const IE: u16 = 1 << 0;
pub(crate) const ZE: u16 = 1 << 2;
pub(crate) const OE: u16 = 1 << 3;
pub(crate) const UE: u16 = 1 << 4;
pub(crate) const PE: u16 = 1 << 5;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Number {
    Finite(Quad),
    Infinity { negative: bool },
    NaN { raw: Ext80 },
    Unsupported,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Decoded {
    pub number: Number,
    pub flags: u16,
}

pub(crate) fn decode(raw: Ext80) -> Decoded {
    let negative = raw.sign_exponent & 0x8000 != 0;
    match x87_math::classify(raw) {
        Classification::Unsupported => Decoded { number: Number::Unsupported, flags: IE },
        Classification::SignalingNaN => Decoded {
            number: Number::NaN { raw },
            flags: IE,
        },
        Classification::QuietNaN => Decoded {
            number: Number::NaN { raw },
            flags: 0,
        },
        Classification::Infinity => Decoded { number: Number::Infinity { negative }, flags: 0 },
        Classification::Zero | Classification::Finite => {
            match x87_math::to_quad(raw) {
                Ok((value, flags)) => Decoded { number: Number::Finite(value), flags },
                Err(flags) => Decoded { number: Number::Unsupported, flags: flags | IE },
            }
        }
    }
}

pub(crate) fn sign(raw: Ext80) -> bool {
    raw.sign_exponent & 0x8000 != 0
}

pub(crate) fn raw_zero(negative: bool) -> Ext80 {
    Ext80 { significand: 0, sign_exponent: if negative { 0x8000 } else { 0 } }
}

pub(crate) fn raw_infinity(negative: bool) -> Ext80 {
    Ext80 {
        significand: 1 << 63,
        sign_exponent: 0x7fff | if negative { 0x8000 } else { 0 },
    }
}

pub(crate) fn raw_nan(negative: bool, payload: u64) -> Ext80 {
    Ext80 {
        significand: (payload | (1 << 63) | (1 << 62)).max(0xc000_0000_0000_0000),
        sign_exponent: 0x7fff | if negative { 0x8000 } else { 0 },
    }
}

/// Preserve the first NaN's sign and payload while quieting it. Unsupported
/// encodings take precedence and produce the x87 masked-invalid indefinite.
pub(crate) fn propagated_nan(values: &[Decoded]) -> Option<Ext80> {
    if values.iter().any(|value| matches!(value.number, Number::Unsupported)) {
        return Some(crate::x87::indefinite());
    }
    values.iter().find_map(|value| match value.number {
        Number::NaN { raw } => Some(raw_nan(sign(raw), raw.significand)),
        _ => None,
    })
}
