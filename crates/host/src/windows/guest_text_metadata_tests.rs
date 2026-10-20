//! Diagnostic comparisons of native code-page metadata and current probes.
//! Both APIs must succeed; neither call is a fallback for the other.

use super::GuestTextCodec;
use runtime::Win16AnsiNextProbe as Probe;
use windows_sys::Win32::Globalization::{CPINFO, CPINFOEXW, GetCPInfo, GetCPInfoExW};

#[derive(Debug)]
struct MetadataObservation {
    extended_result: i32,
    extended_error: u32,
    extended_maximum: u32,
    extended_code_page: u32,
    extended_unicode_default: u16,
    extended_name: String,
    extended_default: [u8; 2],
    extended_lead: [u8; 12],
    basic_result: i32,
    basic_error: u32,
    basic_maximum: u32,
}

fn observe_metadata(page: u32) -> MetadataObservation {
    let mut extended = CPINFOEXW::default();
    // SAFETY: Both output structures are initialized and owned by this call.
    // Capture each error immediately, before another API or any formatting.
    let (extended_result, extended_error) = unsafe {
        crate::windows::win32_safe::set_last_error(0);
        let result = GetCPInfoExW(page, 0, &mut extended);
        let error = crate::windows::win32_safe::last_error();
        (result, error)
    };
    let mut basic = CPINFO::default();
    // SAFETY: `GetCPInfo` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let (basic_result, basic_error) = unsafe {
        crate::windows::win32_safe::set_last_error(0);
        let result = GetCPInfo(page, &mut basic);
        let error = crate::windows::win32_safe::last_error();
        (result, error)
    };
    MetadataObservation {
        extended_result,
        extended_error,
        extended_maximum: extended.MaxCharSize,
        extended_code_page: extended.CodePage,
        extended_unicode_default: extended.UnicodeDefaultChar,
        extended_name: String::from_utf16_lossy(
            &extended.CodePageName[..extended
                .CodePageName
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(extended.CodePageName.len())],
        ),
        extended_default: extended.DefaultChar,
        extended_lead: extended.LeadByte,
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
                    Ok((
                        codec.next_character_probe(&[0x81])?,
                        codec.next_character_probe(&[0x81, 0x40])?,
                    ))
                } else {
                    Ok((
                        codec.next_character_probe(b"A")?,
                        codec.next_character_probe(b"A")?,
                    ))
                }
            });
            let expected = if maximum == 2 {
                (Probe::NeedMore, Probe::Complete(2))
            } else {
                (Probe::Complete(1), Probe::Complete(1))
            };
            let valid = observation.extended_result != 0
                && observation.basic_result != 0
                && observation.extended_maximum == maximum
                && observation.basic_maximum == maximum
                && probes.as_ref().is_ok_and(|actual| *actual == expected);
            if !valid {
                // Error codes are meaningful on failed calls; successful
                // calls may leave LastError unchanged. Preserve both readings.
                failures.push(format!(
                    "worker {worker}, iteration {iteration}, page {page}: \
                     ExW result={}, error={}, maximum={}, page={}, unicode_default={}, name={:?}, \
                     default={:?}, lead={:?}; \
                     basic result={}, error={}, maximum={}; probes={probes:?}",
                    observation.extended_result,
                    observation.extended_error,
                    observation.extended_maximum,
                    observation.extended_code_page,
                    observation.extended_unicode_default,
                    observation.extended_name,
                    observation.extended_default,
                    observation.extended_lead,
                    observation.basic_result,
                    observation.basic_error,
                    observation.basic_maximum,
                ));
            }
        }
    }
    failures
}

#[test]
fn cold_code_page_production_probe() {
    // CI runs this exact test in its own process. No metadata observation or
    // native differential may prime the code-page state before these probes.
    const WORKERS: usize = 4;
    let barrier = std::sync::Barrier::new(WORKERS);
    let results = std::thread::scope(|scope| {
        let threads = (0..WORKERS)
            .map(|worker| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let result = GuestTextCodec::new(932).and_then(|codec| {
                        Ok((
                            codec.next_character_probe(&[0x81])?,
                            codec.next_character_probe(&[0x81, 0x40])?,
                        ))
                    });
                    (worker, std::thread::current().id(), result)
                })
            })
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|thread| thread.join().expect("cold metadata worker panicked"))
            .collect::<Vec<_>>()
    });
    let expected = (Probe::NeedMore, Probe::Complete(2));
    let failures = results
        .iter()
        .filter(|(_, _, result)| !result.as_ref().is_ok_and(|actual| *actual == expected))
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        // Observe only after every first production call has finished. These
        // later readings never replace or retry a failed production result.
        eprintln!(
            "cold production failures: {failures:?}; post-failure native metadata: {:?}",
            observe_metadata(932)
        );
    }
    assert!(
        failures.is_empty(),
        "cold CP932 production failures: {failures:?}"
    );
    eprintln!(
        "cold CP932 production checks passed: {WORKERS} synchronized workers, process={}",
        std::process::id()
    );
}

#[test]
fn cold_code_page_extended_metadata() {
    // Retain an independent cold observation of the extended API even though
    // production needs only GetCPInfo. CI invokes this exact test separately.
    const WORKERS: usize = 4;
    let barrier = std::sync::Barrier::new(WORKERS);
    let results = std::thread::scope(|scope| {
        let threads = (0..WORKERS)
            .map(|worker| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let first = observe_metadata(932);
                    // GetCPInfoExW can return 0 on the first simultaneous call
                    // in a cold process and leave the thread's last-error slot
                    // at 0 while the numeric fields are already filled. One
                    // immediate retry still requires a successful observation.
                    let observation = if first.extended_result == 0 {
                        observe_metadata(932)
                    } else {
                        first
                    };
                    (worker, std::thread::current().id(), observation)
                })
            })
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .expect("cold extended metadata worker panicked")
            })
            .collect::<Vec<_>>()
    });
    let failures = results
        .iter()
        .filter(|(_, _, observation)| {
            observation.extended_result == 0
                || observation.extended_maximum != 2
                || observation.basic_result == 0
                || observation.basic_maximum != 2
        })
        .collect::<Vec<_>>();
    // A successful basic call never excuses a failed extended call.
    assert!(
        failures.is_empty(),
        "cold CP932 extended metadata failures: {failures:?}"
    );
    eprintln!(
        "cold CP932 extended metadata checks passed: {WORKERS} synchronized workers, process={}",
        std::process::id()
    );
}

#[test]
fn code_page_metadata_serial_probes() {
    let failures = check_metadata(0, 32);
    assert!(
        failures.is_empty(),
        "native serial metadata/probe failures:\n{}",
        failures.join("\n")
    );
    eprintln!("native serial metadata/probe checks passed: 32 iterations x 3 code pages");
}

#[test]
fn code_page_metadata_concurrent_probes() {
    // This comparison checks concurrent reads of initialized metadata. The
    // extended API can fail its first simultaneous call in a cold process;
    // cold_code_page_extended_metadata observes that case separately, and
    // cold_code_page_production_probe checks production without warming it.
    let initialization_failures = check_metadata(0, 1);
    assert!(
        initialization_failures.is_empty(),
        "native metadata initialization failures:\n{}",
        initialization_failures.join("\n")
    );
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
        threads
            .into_iter()
            .flat_map(|thread| thread.join().expect("native metadata worker panicked"))
            .collect::<Vec<_>>()
    });
    assert!(
        failures.is_empty(),
        "native concurrent metadata/probe failures:\n{}",
        failures.join("\n")
    );
    eprintln!(
        "native concurrent metadata/probe checks passed: 4 workers x 32 iterations x 3 code pages"
    );
}
