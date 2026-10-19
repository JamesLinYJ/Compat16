use super::*;

fn info(reserved: (i32, i32)) -> Win16HostMinMaxInfo {
    Win16HostMinMaxInfo {
        reserved: Win16HostPoint {
            x: reserved.0,
            y: reserved.1,
        },
        max_size: Win16HostPoint { x: 1920, y: 1080 },
        max_position: Win16HostPoint { x: -8, y: -8 },
        min_track_size: Win16HostPoint { x: 136, y: 39 },
        max_track_size: Win16HostPoint { x: 1940, y: 1100 },
    }
}

#[test]
fn native_default_minimized_seed_uses_legacy_metrics_without_changing_other_bounds() {
    let native = info((314, 50));
    let projected = project_seed(
        native,
        native.reserved,
        Some(Win16HostPoint { x: 36, y: 36 }),
    );
    assert_eq!(projected.reserved.x, 36);
    assert_eq!(projected.reserved.y, 36);
    assert_eq!(projected.max_size.x, native.max_size.x);
    assert_eq!(projected.max_size.y, native.max_size.y);
    assert_eq!(projected.max_position.x, native.max_position.x);
    assert_eq!(projected.max_position.y, native.max_position.y);
    assert_eq!(projected.min_track_size.x, native.min_track_size.x);
    assert_eq!(projected.min_track_size.y, native.min_track_size.y);
    assert_eq!(projected.max_track_size.x, native.max_track_size.x);
    assert_eq!(projected.max_track_size.y, native.max_track_size.y);
}

#[test]
fn explicit_reserved_point_and_unavailable_metrics_are_preserved() {
    let custom = info((80, 45));
    let modern = Win16HostPoint { x: 314, y: 50 };
    let projected = project_seed(custom, modern, Some(Win16HostPoint { x: 36, y: 36 }));
    assert_eq!((projected.reserved.x, projected.reserved.y), (80, 45));
    let unchanged = project_seed(info((314, 50)), modern, None);
    assert_eq!((unchanged.reserved.x, unchanged.reserved.y), (314, 50));
}

#[test]
fn minimized_clamp_keeps_requested_sizes_and_respects_guest_maximum() {
    assert_eq!(clamp(154, 36, 1920), 154);
    assert_eq!(clamp(240, 36, 1080), 240);
    assert_eq!(clamp(154, 36, 100), 100);
    assert_eq!(clamp(20, 36, 1920), 36);
    assert_eq!(clamp(i32::MAX, 36, 1920), 1920);
    assert_eq!(clamp(-1, 36, 1920), 36);
    assert_eq!(
        clamp(80, 36, 20),
        36,
        "legacy minimum takes precedence over an invalid maximum"
    );
}

#[test]
fn callback_constraints_cannot_cross_operations_windows_or_nested_frames() {
    let parent = SizingKey {
        operation: 17,
        window: Win16HostWindow(2),
        hwnd: 0x100,
        cookie: 83,
        callback_depth: 3,
    };
    let observed = SizingKey {
        callback_depth: 4,
        ..parent
    };
    assert!(parent.accepts(observed));
    for other in [
        SizingKey {
            operation: 18,
            ..observed
        },
        SizingKey {
            window: Win16HostWindow(3),
            ..observed
        },
        SizingKey {
            hwnd: 0x200,
            ..observed
        },
        SizingKey {
            cookie: 84,
            ..observed
        },
        SizingKey {
            callback_depth: 3,
            ..observed
        },
        SizingKey {
            callback_depth: 5,
            ..observed
        },
    ] {
        assert!(!parent.accepts(other));
    }
}

#[test]
fn creation_projection_only_changes_explicit_untouched_native_defaults() {
    use super::creation::restore_axis;
    assert_eq!(restore_axis(154, 314, 314, 36, 1936), 154);
    assert_eq!(restore_axis(240, 240, 50, 36, 1096), 240);
    assert_eq!(restore_axis(154, 314, 314, 36, 100), 100);
    assert_eq!(restore_axis(154, 300, 314, 36, 1936), 300);
    assert_eq!(restore_axis(0, 314, 314, 36, 1936), 314);
    assert_eq!(restore_axis(i16::MIN as i32, 314, 314, 36, 1936), 314);
}
