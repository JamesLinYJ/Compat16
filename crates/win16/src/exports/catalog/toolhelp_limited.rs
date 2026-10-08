//! ToolHelp parameter layouts for APIs with unavailable scheduler/flat-heap state.

use super::*;

pub(super) const TASK_SET_CSIP: &[Win16Parameter] = &[
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "code_segment", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "instruction_pointer", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TASK_SWITCH: &[Win16Parameter] = &[
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "new_cs_ip", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
