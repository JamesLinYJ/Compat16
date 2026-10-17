//! Noninteractive query conversion and native nonprinting-DC coverage.

use super::super::super::guest_text::GuestTextCodec;
use super::*;
use windows_sys::Win32::Graphics::Gdi::DT_RASDISPLAY;

fn mock_caps(
    query: Query,
    technology: u32,
    page: (i32, i32),
    value: (i32, i32),
) -> Option<(i32, i32)> {
    query_caps(query, |index| match index as u32 {
        TECHNOLOGY => technology as i32,
        PHYSICALWIDTH => page.0,
        PHYSICALHEIGHT => page.1,
        PHYSICALOFFSETX | SCALINGFACTORX => value.0,
        PHYSICALOFFSETY | SCALINGFACTORY => value.1,
        _ => panic!("unexpected caps index {index}"),
    })
}

#[test]
fn escape_caps_use_documented_indices_device_units_and_scaling_exponents() {
    for (query, expected, indices) in [
        (
            Query::PhysicalPageSize,
            (5100, 6600),
            vec![TECHNOLOGY, PHYSICALWIDTH, PHYSICALHEIGHT],
        ),
        (
            Query::PrintingOffset,
            (150, 300),
            vec![
                TECHNOLOGY,
                PHYSICALWIDTH,
                PHYSICALHEIGHT,
                PHYSICALOFFSETX,
                PHYSICALOFFSETY,
            ],
        ),
        (
            Query::ScalingFactor,
            (3, 0),
            vec![
                TECHNOLOGY,
                PHYSICALWIDTH,
                PHYSICALHEIGHT,
                SCALINGFACTORX,
                SCALINGFACTORY,
            ],
        ),
    ] {
        let mut calls = Vec::new();
        let actual = query_caps(query, |index| {
            calls.push(index as u32);
            match index as u32 {
                TECHNOLOGY => DT_RASPRINTER as i32,
                PHYSICALWIDTH => 5100,
                PHYSICALHEIGHT => 6600,
                PHYSICALOFFSETX => 150,
                PHYSICALOFFSETY => 300,
                SCALINGFACTORX => 3,
                SCALINGFACTORY => 0,
                _ => panic!("unexpected cap"),
            }
        });
        assert_eq!(actual, Some(expected));
        assert_eq!(calls, indices);
    }
}

#[test]
fn escape_caps_support_requires_print_device_page_and_representable_output() {
    for query in [
        Query::PhysicalPageSize,
        Query::PrintingOffset,
        Query::ScalingFactor,
    ] {
        for technology in [DT_RASPRINTER, DT_PLOTTER] {
            assert!(mock_caps(query, technology, (5100, 6600), (0, 0)).is_some());
        }
        assert_eq!(mock_caps(query, DT_RASDISPLAY, (5100, 6600), (1, 1)), None);
        for page in [(0, 6600), (5100, 0), (-1, 6600), (5100, -1)] {
            assert_eq!(mock_caps(query, DT_RASPRINTER, page, (0, 0)), None);
        }
    }
    assert_eq!(
        mock_caps(
            Query::PhysicalPageSize,
            DT_RASPRINTER,
            (32767, 32767),
            (0, 0)
        ),
        Some((32767, 32767))
    );
    assert_eq!(
        mock_caps(
            Query::PhysicalPageSize,
            DT_RASPRINTER,
            (32768, 32767),
            (0, 0)
        ),
        None
    );
    for query in [Query::PrintingOffset, Query::ScalingFactor] {
        assert_eq!(
            mock_caps(query, DT_RASPRINTER, (5100, 6600), (-32768, 32767)),
            Some((-32768, 32767))
        );
        for value in [(32768, 1), (1, -32769), (i32::MIN, 1), (1, i32::MAX)] {
            assert_eq!(mock_caps(query, DT_RASPRINTER, (5100, 6600), value), None);
        }
    }
    for query in [
        Query::QuerySupport,
        Query::StartDocument,
        Query::NewFrame,
        Query::EndDocument,
        Query::AbortDocument,
    ] {
        assert_eq!(
            query_caps(query, |_| panic!(
                "job and self queries are not POINT queries"
            )),
            None
        );
    }
}

#[test]
fn escape_job_support_follows_printer_or_plotter_technology() {
    assert!(printer_technology(DT_RASPRINTER as i32));
    assert!(printer_technology(DT_PLOTTER as i32));
    assert!(!printer_technology(DT_RASDISPLAY as i32));
    assert!(!printer_technology(0));
    assert!(!printer_technology(-1));
}

fn assert_unsupported(dcs: &Win16Dcs, dc: Win16HostDc, query: Query) {
    assert!(matches!(
        query_support(dcs, dc, query).unwrap(),
        Value::Bool(false)
    ));
    assert!(matches!(
        query_point(dcs, dc, query).unwrap(),
        Value::Point { success: false, .. }
    ));
}

#[test]
fn escape_native_memory_dc_is_not_a_printer_and_self_query_matches_native() {
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let dc = dcs.create_compatible(None).unwrap().unwrap();
    for query in [
        Query::PhysicalPageSize,
        Query::PrintingOffset,
        Query::ScalingFactor,
        Query::StartDocument,
        Query::NewFrame,
        Query::EndDocument,
        Query::AbortDocument,
    ] {
        assert_unsupported(&dcs, dc, query);
    }
    let expected = {
        let lease = dcs.lease_dc(dc).unwrap().unwrap();
        let query = QUERYESCSUPPORT as i32;
        // SAFETY: Test-owned leased DC and one owned native INT, no output.
        unsafe {
            Escape(
                lease.native(),
                QUERYESCSUPPORT as i32,
                size_of::<i32>() as i32,
                (&query as *const i32).cast(),
                std::ptr::null_mut(),
            ) > 0
        }
    };
    assert!(
        matches!(query_support(&dcs, dc, Query::QuerySupport).unwrap(), Value::Bool(value) if value == expected)
    );
    assert!(dcs.cleanup(dc));
    let replacement = dcs.create_compatible(None).unwrap().unwrap();
    assert_ne!(replacement, dc);
    for query in [
        Query::QuerySupport,
        Query::PhysicalPageSize,
        Query::PrintingOffset,
        Query::ScalingFactor,
        Query::StartDocument,
        Query::NewFrame,
        Query::EndDocument,
        Query::AbortDocument,
    ] {
        assert_unsupported(&dcs, dc, query);
        assert_unsupported(&dcs, Win16HostDc(u64::MAX), query);
    }
    assert!(dcs.cleanup(replacement));
}
