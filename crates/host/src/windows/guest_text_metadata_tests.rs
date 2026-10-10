//! Diagnostic comparisons of native code-page metadata and current probes.
//! Both APIs must succeed; neither call is a fallback for the other.

use super::GuestTextCodec;
use runtime::Win16AnsiNextProbe as Probe;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::Globalization::{CPINFO, CPINFOEXW, GetCPInfo, GetCPInfoExW};

#[derive(Debug)]
struct MetadataObservation {
    extended_result: i32,
    extended_error: u32,
    extended_maximum: u32,
    basic_result: i32,
    basic_error: u32,
    basic_maximum: u32,
}

fn observe_metadata(page: u32) -> MetadataObservation {
    let mut extended = CPINFOEXW::default();
    // SAFETY: Both output structures are initialized and owned by this call.
    // Capture each error immediately, before another API or any formatting.
    let (extended_result, extended_error) = unsafe {
        SetLastError(0);
        let result = GetCPInfoExW(page, 0, &mut extended);
        let error = GetLastError();
        (result, error)
    };
    let mut basic = CPINFO::default();
    let (basic_result, basic_error) = unsafe {
        SetLastError(0);
        let result = GetCPInfo(page, &mut basic);
        let error = GetLastError();
        (result, error)
    };
    MetadataObservation {
        extended_result,
        extended_error,
        extended_maximum: extended.MaxCharSize,
        basic_result,
        basic_error,
        basic_maximum: basic.MaxCharSize,
    }
}

fn check_metadata(worker: usize, iterations: usize) -> Vec<String> {
    let mut failures = Vec::new();
    for iteration in 0..iterations {
        for (page, maximum) in [(932, 2), (936, 2), (1252, 1)] {
            let observation = observe_metadata(page);
            let probes = GuestTextCodec::new(page).and_then(|codec| {
                if maximum == 2 {
                    Ok((codec.next_character_probe(&[0x81])?,
                        codec.next_character_probe(&[0x81, 0x40])?))
                } else {
                    Ok((codec.next_character_probe(b"A")?, codec.next_character_probe(b"A")?))
                }
            });
            let expected = if maximum == 2 { (Probe::NeedMore, Probe::Complete(2)) }
                else { (Probe::Complete(1), Probe::Complete(1)) };
            let valid = observation.extended_result != 0 && observation.basic_result != 0
                && observation.extended_maximum == maximum && observation.basic_maximum == maximum
                && probes.as_ref().is_ok_and(|actual| *actual == expected);
            if !valid {
                // Error codes are meaningful on failed calls; successful
                // calls may leave LastError unchanged. Preserve both readings.
                failures.push(format!(
                    "worker {worker}, iteration {iteration}, page {page}: \
                     ExW result={}, error={}, maximum={}; basic result={}, error={}, maximum={}; probes={probes:?}",
                    observation.extended_result, observation.extended_error, observation.extended_maximum,
                    observation.basic_result, observation.basic_error, observation.basic_maximum,
                ));
            }
        }
    }
    failures
}

#[test]
fn code_page_metadata_serial_probes() {
    let failures = check_metadata(0, 32);
    assert!(failures.is_empty(), "native serial metadata/probe failures:\n{}", failures.join("\n"));
    eprintln!("native serial metadata/probe checks passed: 32 iterations x 3 code pages");
}

#[test]
fn code_page_metadata_concurrent_probes() {
    const WORKERS: usize = 4;
    let barrier = std::sync::Barrier::new(WORKERS);
    let failures = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for worker in 0..WORKERS {
            let barrier = &barrier;
            threads.push(scope.spawn(move || {
                barrier.wait();
                check_metadata(worker, 32)
            }));
        }
        threads.into_iter().flat_map(|thread| thread.join().expect("native metadata worker panicked"))
            .collect::<Vec<_>>()
    });
    assert!(failures.is_empty(), "native concurrent metadata/probe failures:\n{}", failures.join("\n"));
    eprintln!("native concurrent metadata/probe checks passed: 4 workers x 32 iterations x 3 code pages");
}
