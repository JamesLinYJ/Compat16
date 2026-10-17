//! Native argument contracts without changing desktop colors or mouse settings.
use super::set_sys_colors_with;

#[test]
fn system_colors_adapter_preserves_width_order_and_native_false_result() {
    for result in [0, -1] {
        let indices = [-1, 7];
        let colors = [0x00ab_cdef, 0xff01_0203];
        let mut calls = 0;
        let observed = set_sys_colors_with(&indices, &colors, |count, index_ptr, color_ptr| {
            calls += 1;
            assert_eq!(count, 2);
            // SAFETY: the helper retains both checked slices for this call.
            unsafe {
                assert_eq!(
                    std::slice::from_raw_parts(index_ptr, count as usize),
                    indices
                );
                assert_eq!(
                    std::slice::from_raw_parts(color_ptr, count as usize),
                    colors
                );
            }
            result
        })
        .unwrap();
        assert_eq!(observed, result != 0);
        assert_eq!(calls, 1);
    }
}
#[test]
fn system_colors_adapter_empty_arrays_have_zero_count_and_live_pointers() {
    let mut calls = 0;
    assert!(
        !set_sys_colors_with(&[], &[], |count, indices, colors| {
            calls += 1;
            assert_eq!(count, 0);
            assert!(!indices.is_null());
            assert!(!colors.is_null());
            0
        })
        .unwrap()
    );
    assert_eq!(calls, 1);
}
#[test]
fn system_colors_adapter_rejects_mismatch_before_native_effects() {
    let mut calls = 0;
    let error = set_sys_colors_with(&[1], &[], |_, _, _| {
        calls += 1;
        1
    })
    .unwrap_err();
    assert_eq!(error.kind(), runtime::DiagnosticKind::InternalInvariant);
    assert_eq!(calls, 0);
}
