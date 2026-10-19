//! USER.52 read-only native oracle and deterministic BOOL normalization.
use super::{AnyPopup, any_popup, any_popup_with};

#[test]
fn any_popup_adapter_reads_once_and_normalizes_every_nonzero_native_bool() {
    for native in [0, 1, -1, i32::MIN, i32::MAX, 0x10000] {
        let mut calls = 0;
        let actual = any_popup_with(|| {
            calls += 1;
            native
        });
        assert_eq!(actual, native != 0);
        assert_eq!(calls, 1);
    }
}

#[test]
#[ignore = "requires Windows USER; read-only desktop-wide AnyPopup query"]
fn any_popup_matches_read_only_native_oracle() {
    // Desktop state can change independently of this process. Do not assume
    // no popups exist, create windows, or alter focus, visibility, or input.
    for _ in 0..8 {
        // SAFETY: `AnyPopup` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let before = unsafe { AnyPopup() } != 0;
        let actual = any_popup();
        // SAFETY: `AnyPopup` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let after = unsafe { AnyPopup() } != 0;
        if before == after && actual == before {
            if actual {
                eprintln!("AnyPopup: native positive result observed and matched");
            } else {
                eprintln!(
                    "AnyPopup: native negative result matched; positive desktop case remains unverified"
                );
            }
            // Matching samples establish only the observed value. Even equal
            // brackets cannot exclude an external ABA visibility change.
            return;
        }
    }
    panic!(
        "AnyPopup native oracle inconclusive: no matching stable samples; possible adapter mismatch or concurrent desktop changes; rerun on a quiescent desktop"
    );
}
