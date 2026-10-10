//! USER hit testing for direct children and descendant relationship queries.

use super::*;

impl Win16State {
    /// Handle USER.48, USER.191 and USER.399 with opaque HWND identities.
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

        let call = match request {
            Request::IsChild { parent, child } => Win16WindowCall::IsChild {
                parent: self.native_window(parent),
                child: self.native_window(child),
            },
            Request::ChildWindowFromPoint { parent, point } => {
                Win16WindowCall::ChildWindowFromPoint {
                    parent: self.native_window(parent),
                    point: unpack_point(point),
                }
            }
            Request::ChildWindowFromPointEx { parent, point, flags } => {
                Win16WindowCall::ChildWindowFromPointEx {
                    parent: self.native_window(parent),
                    point: unpack_point(point),
                    flags,
                }
            }
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

fn unpack_point(packed: u32) -> Win16HostPoint {
    // Coordinates are signed POINT16 fields in the parent's client space.
    // Do not translate to screen coordinates or interpret these bits as FAR.
    Win16HostPoint {
        x: i32::from(packed as u16 as i16),
        y: i32::from((packed >> 16) as u16 as i16),
    }
}
