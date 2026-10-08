//! ABI parameter layouts for KERNEL locale helpers.

use super::*;

pub(super) const IS_DBCS_LEAD_BYTE: &[Win16Parameter] = &[Win16Parameter {
    name: "value",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];
