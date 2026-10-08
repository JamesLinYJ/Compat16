//! ToolHelp memory-information parameter layouts.

use super::*;

pub(super) const SYSTEM_HEAP_INFO: &[Win16Parameter] = &[Win16Parameter {
    name: "output",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_OUTPUT_BUFFER,
}];

pub(super) const MEMMAN_INFO: &[Win16Parameter] = &[Win16Parameter {
    name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER,
}];
