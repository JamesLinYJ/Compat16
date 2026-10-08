//! Win16 ToolHelp stack-trace parameter layouts.

use super::*;

pub(super) const STACK_TRACE_FIRST: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const STACK_TRACE_CSIP_FIRST: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "stack_segment", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "code_segment", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "instruction_pointer", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "base_pointer", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const STACK_TRACE_NEXT: &[Win16Parameter] = &[Win16Parameter {
    name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER,
}];
