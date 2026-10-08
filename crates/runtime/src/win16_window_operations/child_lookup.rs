//! USER hit testing for direct child windows.

use super::*;

impl Win16State {
    /// Handle USER.191 and USER.399 while keeping HWND identities opaque.
    pub(super) fn begin_user_child_lookup(
        &mut self,
        request: win16_abi::Win16UserChildLookupRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use win16_abi::Win16UserChildLookupRequest as Request;

        let (parent, packed_point, flags) = match request {
            Request::ChildWindowFromPoint { parent, point } => (parent, point, None),
            Request::ChildWindowFromPointEx { parent, point, flags } => {
                (parent, point, Some(flags))
            }
        };
        let point = Win16HostPoint {
            x: i32::from(packed_point as u16 as i16),
            y: i32::from((packed_point >> 16) as u16 as i16),
        };
        let parent = self.native_window(parent);
        let call = match flags {
            Some(flags) => Win16WindowCall::ChildWindowFromPointEx {
                parent,
                point,
                flags,
            },
            None => Win16WindowCall::ChildWindowFromPoint { parent, point },
        };
        self.submit_value_call(
            registers,
            memory,
            host,
            call,
            return_to,
            return_kind,
        )
    }
}
