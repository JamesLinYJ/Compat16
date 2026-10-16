//! Owned request values for Win16 USER child-window and descendant queries.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16UserChildLookupRequest {
    /// USER.48 checks the complete parent chain, excluding owner links.
    IsChild { parent: u16, child: u16 },
    /// USER.191 receives the Win16 POINT16 value packed into a LONG.
    ChildWindowFromPoint { parent: u16, point: u32 },
    /// USER.399 adds the SDK CWP_* filter flags to the same packed POINT16.
    ChildWindowFromPointEx { parent: u16, point: u32, flags: u16 },
}
