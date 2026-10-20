use super::{offset_host_rect, offset_point};
use runtime::Win16HostRect;

#[test]
fn placement_unset_positions_survive_a_change_of_monitor_work_area() {
    // GetWindowPlacement returns (-1,-1) before USER has a min/max position.
    // Saving on a monitor with a left/top taskbar and restoring on another
    // monitor must keep the default position instead of manufacturing one.
    for source_delta in [(48, 0), (0, 40), (48, 40)] {
        let guest = offset_point(-1, -1, source_delta).unwrap();
        assert_eq!((guest.x, guest.y), (-1, -1));
        for destination_delta in [(0, 0), (-64, 0), (0, -56)] {
            let native = offset_point(guest.x, guest.y, destination_delta).unwrap();
            assert_eq!((native.x, native.y), (-1, -1));
        }
    }
}

#[test]
fn placement_real_negative_coordinates_still_receive_the_work_area_offset() {
    let point = offset_point(-1, 7, (48, 40)).unwrap();
    assert_eq!((point.x, point.y), (47, 47));
    let point = offset_point(-9, -1, (48, 40)).unwrap();
    assert_eq!((point.x, point.y), (39, 39));
    // A normal rectangle is geometry even if its top-left is (-1,-1).
    let rect = offset_host_rect(
        Win16HostRect {
            left: -1,
            top: -1,
            right: 100,
            bottom: 80,
        },
        (48, 40),
    )
    .unwrap();
    assert_eq!(
        (rect.left, rect.top, rect.right, rect.bottom),
        (47, 39, 148, 120)
    );
}

#[test]
fn placement_unrepresentable_coordinates_still_fail() {
    assert!(offset_point(i32::MAX, 0, (1, 0)).is_none());
    assert!(offset_point(0, i32::MIN, (0, -1)).is_none());
    assert!(
        offset_host_rect(
            Win16HostRect {
                left: 0,
                top: 0,
                right: i32::MAX,
                bottom: 1
            },
            (1, 0),
        )
        .is_none()
    );
}
