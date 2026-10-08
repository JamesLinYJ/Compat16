//! Owned geometry conversion around native USER message calls.

use runtime::{Win16HostMinMaxInfo, Win16HostPoint};
use windows_sys::Win32::{Foundation::POINT, UI::WindowsAndMessaging::MINMAXINFO};

pub(super) fn copy_minmax(data: &MINMAXINFO) -> Win16HostMinMaxInfo {
    let point = |value: POINT| Win16HostPoint { x: value.x, y: value.y };
    Win16HostMinMaxInfo {
        reserved: point(data.ptReserved), max_size: point(data.ptMaxSize),
        max_position: point(data.ptMaxPosition),
        min_track_size: point(data.ptMinTrackSize),
        max_track_size: point(data.ptMaxTrackSize),
    }
}

pub(super) fn native_minmax(data: Win16HostMinMaxInfo) -> MINMAXINFO {
    let point = |value: Win16HostPoint| POINT { x: value.x, y: value.y };
    MINMAXINFO {
        ptReserved: point(data.reserved), ptMaxSize: point(data.max_size),
        ptMaxPosition: point(data.max_position),
        ptMinTrackSize: point(data.min_track_size),
        ptMaxTrackSize: point(data.max_track_size),
    }
}
