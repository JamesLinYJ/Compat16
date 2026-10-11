//! Full DOS SFT refresh CPU cost with a deterministic host, not native
//! filesystem latency or application speed. Run explicitly in release mode.

use std::hint::black_box;
use std::time::{Duration, Instant};

use super::{DosKernel, TestHost, TestMemory, install_default_jft, install_file_status};
use super::super::{Handle, MAX_JFT_LEN, SFT_ENTRY_COUNT, SFT_ENTRY_LEN, SFT_HEADER_LEN,
    SFT_OFFSET, read_jft_pointer, refresh_entry};
use crate::{DosAction, DosHost};
use guest_core::{GuestMemory, Registers, real_address};

const PSP: u16 = 0x1000;
const SAMPLES: usize = 9;

#[derive(Clone, Copy, Debug)]
struct Case {
    handles: u16,
    records: u16,
    late_unique: bool,
    standards: bool,
}

const fn files(handles: u16, records: u16, late_unique: bool) -> Case {
    Case { handles, records, late_unique, standards: false }
}

const CASES: [Case; 25] = [
    Case { handles: 3, records: 3, late_unique: false, standards: true },
    files(20, 3, false), files(20, 3, true),
    files(20, 4, false), files(20, 4, true),
    files(20, 5, false), files(20, 5, true),
    files(20, 8, false), files(20, 8, true),
    files(20, 16, false), files(20, 16, true),
    files(256, 3, true), files(256, 32, false),
    files(256, 4, false), files(256, 4, true),
    files(256, 5, false), files(256, 5, true),
    files(256, 8, false), files(256, 8, true),
    files(256, 16, false), files(256, 16, true),
    files(4096, 255, true),
    files(MAX_JFT_LEN, 3, false), files(MAX_JFT_LEN, 3, true),
    files(MAX_JFT_LEN, 255, true),
];

struct Fixture {
    dos: DosKernel,
    memory: TestMemory,
    host: TestHost,
}

impl Fixture {
    fn new(case: Case) -> Self {
        let mut fixture = Self {
            dos: DosKernel::new(PSP),
            memory: TestMemory::with_size(0xa_0000),
            host: TestHost::default(),
        };
        install_default_jft(&mut fixture.memory, PSP);
        fixture.dos.initialize_system_tables(&mut fixture.memory).unwrap();
        if case.handles > 20 {
            // Release the program tail through the real MCB resize path, then
            // obtain owned external JFT storage through AH=67h. Setup only.
            fixture.interrupt(0x4a00, 0x100);
            fixture.interrupt(0x6700, case.handles);
        }
        if !case.standards {
            fixture.dos.file_table.clear();
            fixture.dos.handles.clear();
            for guest in 0..case.handles {
                let unique = if case.late_unique {
                    guest == 0 || guest > case.handles - case.records
                } else {
                    guest < case.records
                };
                if unique {
                    let token = fixture.host.file_create(format!("F{guest:05}").as_bytes(), 0).unwrap();
                    install_file_status(&mut fixture.host, token);
                    assert!(fixture.dos.file_table.register_open(guest, 0).is_some());
                    fixture.dos.handles.insert(guest, Handle::File(token));
                } else {
                    let source = if case.late_unique { 0 } else { guest % case.records };
                    assert!(fixture.dos.file_table.duplicate_handle(source, guest));
                    let Handle::File(token) = fixture.dos.handles[&source] else { unreachable!() };
                    let alias = fixture.host.file_duplicate(token).unwrap();
                    fixture.dos.handles.insert(guest, Handle::File(alias));
                }
            }
        }
        assert_eq!(fixture.dos.handles.len(), usize::from(case.handles));
        assert_eq!(fixture.dos.file_table.entries_snapshot().len(), usize::from(case.records));
        assert_eq!(fixture.dos.jft_capacity, case.handles.max(20));
        fixture.dos.validate_jft(&fixture.memory).unwrap();
        fixture
    }

    fn interrupt(&mut self, ax: u16, bx: u16) {
        let mut regs = Registers::default();
        regs.set_ax(ax);
        regs.set_bx(bx);
        regs.es = PSP;
        assert_eq!(self.dos.interrupt(0x21, &mut regs, &mut self.memory, &mut self.host).unwrap(), DosAction::Continue);
        assert!(!regs.carry(), "fixture setup AX={:04x}", regs.ax());
    }

    fn old_refresh(&mut self) {
        self.dos.refresh_sft_with(&mut self.memory, &mut self.host, |dos, records, host, segment| {
            // Original search/query interleaving, without the candidate's
            // threshold, iterator wrapper, or precomputed representative array.
            for (index, entry) in records {
                let current = dos.handles.iter().find_map(|(&guest, &handle)| {
                    (dos.file_table.index_for_handle(guest) == Some(*index)).then_some(handle)
                });
                refresh_entry(entry, current, host, segment)?;
            }
            Ok(())
        }).unwrap();
    }

    fn candidate_refresh(&mut self) {
        self.dos.refresh_sft(&mut self.memory, &mut self.host).unwrap();
    }

    fn guest_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        let mut sft = vec![0; SFT_HEADER_LEN + SFT_ENTRY_COUNT * SFT_ENTRY_LEN];
        assert_eq!(sft.len(), 15_051);
        let segment = self.dos.system_tables.as_ref().unwrap().segment;
        self.memory.read(real_address(segment, SFT_OFFSET), &mut sft).unwrap();
        let (count, offset, segment) = read_jft_pointer(PSP, &self.memory).unwrap();
        let mut jft = vec![0; usize::from(count)];
        self.memory.read(real_address(segment, offset), &mut jft).unwrap();
        (sft, jft)
    }
}

fn checked_pair(case: Case) -> (Fixture, Fixture) {
    // Construction is independent: the SFT Rc pools, host objects, and guest
    // storage must not be shared across the old and candidate executions.
    let mut old = Fixture::new(case);
    let mut candidate = Fixture::new(case);
    assert!(!std::rc::Rc::ptr_eq(&old.dos.file_table.pool, &candidate.dos.file_table.pool));
    old.host.prepare_sft_queries(usize::from(case.records), 1);
    candidate.host.prepare_sft_queries(usize::from(case.records), 1);
    old.old_refresh();
    candidate.candidate_refresh();
    assert_eq!(old.guest_bytes(), candidate.guest_bytes(), "{case:?}");
    assert_eq!(old.dos.file_table.entries_snapshot(), candidate.dos.file_table.entries_snapshot(), "{case:?}");
    let queries = old.host.sft_queries();
    assert_eq!(queries, candidate.host.sft_queries(), "{case:?}");
    assert_eq!(queries.len(), usize::from(case.records) * if case.standards { 1 } else { 2 });
    assert_eq!(old.host.sft_status_calls(), candidate.host.sft_status_calls(), "{case:?}");
    assert_eq!(old.host.sft_status_calls().len(), if case.standards { 0 } else { usize::from(case.records) });
    (old, candidate)
}

// Generic dispatch at the batch boundary; no per-record black_box or indirect
// call. Log clearing/reservation, fixture setup, and oracle checks are untimed.
fn elapsed(fixture: &mut Fixture, case: Case, rounds: usize, refresh: impl Fn(&mut Fixture)) -> Duration {
    fixture.host.prepare_sft_queries(usize::from(case.records), rounds);
    let start = Instant::now();
    for _ in 0..rounds {
        refresh(black_box(&mut *fixture));
        black_box(&fixture.memory);
    }
    start.elapsed()
}

fn median(mut samples: [f64; SAMPLES]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

fn spread(samples: [f64; SAMPLES]) -> (f64, f64, f64) {
    let mean = samples.iter().sum::<f64>() / SAMPLES as f64;
    let sd = (samples.iter().map(|sample| (sample - mean).powi(2)).sum::<f64>() / (SAMPLES - 1) as f64).sqrt();
    (samples.into_iter().fold(f64::INFINITY, f64::min), samples.into_iter().fold(f64::NEG_INFINITY, f64::max), sd)
}

#[test]
fn full_refresh_matches_old_baseline_matrix() {
    for case in CASES {
        let _ = checked_pair(case);
    }
}

#[test]
#[ignore = "full-refresh deterministic-host CPU benchmark; run explicitly with --release --nocapture"]
fn full_refresh_paired_benchmark() {
    println!("Complete SFT refresh, deterministic TestHost/TestMemory. Includes validation, snapshot, host queries, pool updates, 15051-byte SFT and full JFT writes. No native filesystem or application-speed claim; no timing assertions.");
    for case in CASES {
        let (mut old, mut candidate) = checked_pair(case);
        let old_warm = elapsed(&mut old, case, 1, Fixture::old_refresh);
        let new_warm = elapsed(&mut candidate, case, 1, Fixture::candidate_refresh);
        let warm_ns = old_warm.max(new_warm).as_nanos().max(1);
        let max_rounds = if case.handles == MAX_JFT_LEN { 1 } else { 10_000 };
        let rounds = (Duration::from_millis(20).as_nanos() / warm_ns).clamp(1, max_rounds) as usize;
        let mut old_ns = [0.0; SAMPLES];
        let mut new_ns = [0.0; SAMPLES];
        for sample in 0..SAMPLES {
            let (before, after) = if sample % 2 == 0 {
                (elapsed(&mut old, case, rounds, Fixture::old_refresh),
                 elapsed(&mut candidate, case, rounds, Fixture::candidate_refresh))
            } else {
                let after = elapsed(&mut candidate, case, rounds, Fixture::candidate_refresh);
                (elapsed(&mut old, case, rounds, Fixture::old_refresh), after)
            };
            old_ns[sample] = before.as_secs_f64() * 1e9 / rounds as f64;
            new_ns[sample] = after.as_secs_f64() * 1e9 / rounds as f64;
        }
        let differences = std::array::from_fn(|i| new_ns[i] - old_ns[i]);
        println!("H={} S={} capacity={} layout={} rounds={} paired_samples={SAMPLES}", case.handles, case.records, case.handles.max(20), if case.standards { "default-standard" } else if case.late_unique { "low-alias-prefix" } else { "early-unique" }, rounds);
        println!("ns/refresh old={old_ns:?} candidate={new_ns:?} paired_candidate_minus_old={differences:?}");
        println!("median_ns old={:.1} candidate={:.1} paired_delta={:.1}; min/max/sample_sd_ns old={:?} candidate={:?} paired_delta={:?}", median(old_ns), median(new_ns), median(differences), spread(old_ns), spread(new_ns), spread(differences));
    }
}
