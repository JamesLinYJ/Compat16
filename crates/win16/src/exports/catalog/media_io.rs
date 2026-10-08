//! MMSYSTEM MMIO ABI parameter layouts from the Windows SDK 3.1 MMSYSTEM.H.

use super::*;

pub(super) const OPEN: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const CLOSE: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TRANSFER: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const SEEK: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "offset", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "origin", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const FLUSH: &[Win16Parameter] = CLOSE;

pub(super) const STRING_TO_FOURCC: &[Win16Parameter] = &[
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const DESCEND: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "chunk", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "parent", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CHUNK: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "chunk", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const RENAME: &[Win16Parameter] = &[
    Win16Parameter { name: "old_path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "new_path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
