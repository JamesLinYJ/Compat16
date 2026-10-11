//! Isolated representative-selection benchmark, not a full SFT refresh or an
//! application-speed benchmark. Run the ignored test with `--release --nocapture`.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use super::super::{FileTable, Handle, MAX_JFT_LEN, SFT_ENTRY_COUNT, SftEntry};
use crate::DosHostFile;

struct Fixture {
    table: FileTable,
    handles: BTreeMap<u16, Handle>,
    records: Vec<(u8, SftEntry)>,
}

impl Fixture {
    fn new(handle_count: u16, sft_count: u16, late_unique: bool) -> Self {
        assert!(sft_count > 0 && sft_count <= SFT_ENTRY_COUNT as u16);
        assert!(sft_count <= handle_count && handle_count <= MAX_JFT_LEN);
        let mut table = FileTable::new();
        table.clear();
        let mut handles = BTreeMap::new();
        for guest in 0..handle_count {
            // The adverse layout puts almost all low-numbered aliases before
            // the other unique SFT objects. The early layout permits the old
            // search to stop quickly, even with many trailing aliases.
            let unique = if late_unique {
                guest == 0 || guest > handle_count - sft_count
            } else {
                guest < sft_count
            };
            if unique {
                assert!(table.register_open(guest, 0).is_some());
                handles.insert(guest, Handle::File(DosHostFile(u64::from(guest))));
            } else {
                let source = if late_unique { 0 } else { guest % sft_count };
                assert!(table.duplicate_handle(source, guest));
                handles.insert(guest, handles[&source]);
            }
        }
        let records = table.entries_snapshot();
        Self { table, handles, records }
    }

    fn old_representative(&self, index: u8) -> Option<Handle> {
        // The production search before this optimization, including early exit
        // and its BTreeMap lookup for every candidate DOS handle.
        self.handles.iter().find_map(|(&guest, &handle)| {
            (self.table.index_for_handle(guest) == Some(index)).then_some(handle)
        })
    }

    fn check_equivalence(&self) {
        let mut old = [None; SFT_ENTRY_COUNT];
        for &(index, _) in &self.records {
            old[usize::from(index)] = self.old_representative(index);
        }
        let new = self.table.representatives(
            &self.records, self.handles.iter().map(|(&guest, &handle)| (guest, handle)),
        );
        assert_eq!(old, new);
    }
}

fn old_selection(fixture: &Fixture) {
    for &(index, _) in &fixture.records {
        let _ = black_box(fixture.old_representative(index));
    }
}

fn indexed_selection(fixture: &Fixture) {
    // Array and live-target mask initialization belong inside the timing,
    // including in small cases; both paths use the existing records snapshot.
    let representatives = fixture.table.representatives(
        &fixture.records,
        fixture.handles.iter().map(|(&guest, &handle)| (guest, handle)),
    );
    for &(index, _) in &fixture.records {
        let _ = black_box(representatives[usize::from(index)]);
    }
}

fn elapsed(fixture: &Fixture, rounds: usize, selection: fn(&Fixture)) -> Duration {
    let start = Instant::now();
    for _ in 0..rounds {
        selection(black_box(fixture));
    }
    start.elapsed()
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
#[ignore = "selection-only microbenchmark; run explicitly with --release --nocapture"]
fn representative_selection_microbenchmark() {
    const SAMPLES: usize = 5;
    const TARGET_SAMPLE: Duration = Duration::from_millis(3);
    println!("Selection only; old/indexed ratio > 1 favors the index. No timing assertions.");
    for (handle_count, sft_counts) in [
        (20, &[3][..]),
        (256, &[3, 32, 255][..]),
        (4096, &[3, 32, 255][..]),
        (MAX_JFT_LEN, &[3, 32, 255][..]),
    ] {
        for &sft_count in sft_counts {
            for late_unique in [false, true] {
                // All allocation, registration, aliasing, record snapshots and
                // correctness checks are outside the timed selection loops.
                let fixture = Fixture::new(handle_count, sft_count, late_unique);
                assert_eq!(fixture.handles.len(), usize::from(handle_count));
                assert_eq!(fixture.records.len(), usize::from(sft_count));
                fixture.check_equivalence();

                // Warm both paths, then use the slower path to bound rounds.
                // Adverse large cases have at most four rounds/sample. Early
                // exits can use more rounds for useful sub-microsecond samples.
                let old_warm = elapsed(&fixture, 1, old_selection);
                let new_warm = elapsed(&fixture, 1, indexed_selection);
                let warm_nanos = old_warm.max(new_warm).as_nanos().max(1);
                let max_rounds = if handle_count == MAX_JFT_LEN && late_unique { 4 } else { 10_000 };
                let rounds = (TARGET_SAMPLE.as_nanos() / warm_nanos)
                    .clamp(1, max_rounds) as usize;
                let mut old_samples = [Duration::ZERO; SAMPLES];
                let mut new_samples = [Duration::ZERO; SAMPLES];
                for sample in 0..SAMPLES {
                    // Alternate order to reduce systematic thermal/order bias.
                    if sample % 2 == 0 {
                        old_samples[sample] = elapsed(&fixture, rounds, old_selection);
                        new_samples[sample] = elapsed(&fixture, rounds, indexed_selection);
                    } else {
                        new_samples[sample] = elapsed(&fixture, rounds, indexed_selection);
                        old_samples[sample] = elapsed(&fixture, rounds, old_selection);
                    }
                }
                let old_ns = median(&mut old_samples).as_secs_f64() * 1e9 / rounds as f64;
                let new_ns = median(&mut new_samples).as_secs_f64() * 1e9 / rounds as f64;
                println!(
                    "H={} S={} layout={} rounds={} samples={} median_ns/selection old={:.1} indexed={:.1} old/indexed={:.3}",
                    fixture.handles.len(), fixture.records.len(),
                    if late_unique { "low-alias-prefix" } else { "early-unique" },
                    rounds, SAMPLES, old_ns, new_ns, old_ns / new_ns,
                );
            }
        }
    }
}
