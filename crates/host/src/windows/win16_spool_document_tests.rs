//! Inspect the real document adapter's arguments without invoking a printer.
use super::*;

#[test]
fn spool_document_keeps_unicode_title_and_raw_datatype_live_during_native_call() {
    let title: Vec<u16> = "Report \u{6587}\u{6863}\0".encode_utf16().collect();
    let printer = PRINTER_HANDLE::default();
    let mut calls = 0;
    let result = start_with(printer, Some(&title), |received, level, info| {
        calls += 1;
        assert_eq!(received.Value, printer.Value);
        assert_eq!(level, 1);
        assert_eq!(info.pDocName, title.as_ptr().cast_mut());
        assert!(info.pOutputFile.is_null());
        // SAFETY: the adapter keeps the complete static RAW string and the
        // borrowed title live for the duration of this injected call.
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(info.pDatatype, 4),
                &[82, 65, 87, 0]
            );
            assert_eq!(
                std::slice::from_raw_parts(info.pDocName, title.len()),
                title
            );
        }
        0xfedc_ba98
    });
    assert_eq!(calls, 1);
    assert_eq!(result, 0xfedc_ba98);
}

#[test]
fn spool_document_preserves_null_or_empty_title_and_native_zero_failure() {
    let empty = [0_u16];
    for title in [None, Some(empty.as_slice())] {
        let expected = title.map_or(ptr::null_mut(), |value| value.as_ptr().cast_mut());
        let mut calls = 0;
        let result = start_with(PRINTER_HANDLE::default(), title, |_, level, info| {
            calls += 1;
            assert_eq!(level, 1);
            assert_eq!(info.pDocName, expected);
            assert!(info.pOutputFile.is_null());
            assert!(!info.pDatatype.is_null());
            0
        });
        assert_eq!(calls, 1);
        assert_eq!(result, 0);
    }
}
