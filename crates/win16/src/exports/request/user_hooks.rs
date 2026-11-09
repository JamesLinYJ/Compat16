//! Typed Win16 USER hook arguments.
//!
//! FAR values remain their original guest 16:16 bits. HHOOK arguments are
//! opaque DWORD tokens. The DefHookProc slot is a guest far pointer to the
//! next filter procedure. This decoder never creates host handles or pointers.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserHooksRequest {
    /// USER.121 returns the installed opaque guest HHOOK, or zero on failure.
    /// The procedure remains a guest FAR address until runtime checks it.
    SetWindowsHook { hook_type: i16, procedure: u32 },

    /// USER.123 calls the task's WH_MSGFILTER chain with this mutable guest
    /// MSG16 FAR address and the signed Win16 filter code.
    CallMsgFilter { message: u32, code: i16 },

    /// USER.234 removes a matching procedure from the task-local hook chain.
    UnhookWindowsHook { hook_type: i16, procedure: u32 },

    /// USER.235 forwards the signed code, WORD wParam, and DWORD lParam to the
    /// far procedure stored at this caller-owned slot. The slot is a guest far
    /// pointer. The procedure address it holds is not a host pointer.
    DefHookProc {
        code: i16,
        w_param: u16,
        l_param: u32,
        hook_slot: u32,
    },

    /// USER.291 extension variant. The module and task fields remain guest
    /// handles; runtime validates their ownership and scope.
    SetWindowsHookEx {
        hook_type: i16,
        procedure: u32,
        instance: u16,
        task: u16,
    },

    /// USER.292's HHOOK is kept as an opaque raw guest DWORD token.
    UnhookWindowsHookEx { hook: u32 },

    /// USER.293 receives the guest HHOOK, signed nCode, WORD WPARAM, and
    /// uninterpreted DWORD LPARAM without converting any pointer-bearing bits.
    CallNextHookEx {
        hook: u32,
        code: i16,
        w_param: u16,
        l_param: u32,
    },
}
