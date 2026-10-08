//! Geometry width conversion at the Win16 message boundary.

use win16_abi::{Point16, window_geometry::MinMaxInfo16};
use crate::{Win16HostMinMaxInfo, Win16HostPoint};

pub(super) const WM_GETMINMAXINFO: u16 = 0x0024;

pub(super) fn guest_minmax_info(data: Win16HostMinMaxInfo) -> MinMaxInfo16 {
    // Win16 coordinates contain signed 16-bit values. Keep their low-word
    // representation when narrowing native LONG fields to the guest ABI.
    let point = |value: Win16HostPoint| Point16 { x: value.x as i16, y: value.y as i16 };
    MinMaxInfo16 {
        pt_reserved: point(data.reserved), pt_max_size: point(data.max_size),
        pt_max_position: point(data.max_position),
        pt_min_track_size: point(data.min_track_size),
        pt_max_track_size: point(data.max_track_size),
    }
}

pub(super) fn host_minmax_info(data: MinMaxInfo16) -> Win16HostMinMaxInfo {
    let point = |value: Point16| Win16HostPoint { x: i32::from(value.x), y: i32::from(value.y) };
    Win16HostMinMaxInfo {
        reserved: point(data.pt_reserved), max_size: point(data.pt_max_size),
        max_position: point(data.pt_max_position),
        min_track_size: point(data.pt_min_track_size),
        max_track_size: point(data.pt_max_track_size),
    }
}
