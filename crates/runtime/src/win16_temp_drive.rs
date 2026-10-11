//! Read-only Win16 temporary-drive selection, independent of native storage.

const TF_FORCEDRIVE: u8 = 0x80;

/// Select a drive letter using task-owned current-drive state and the same
/// fixed-media classification as GetDriveType. Neither callback changes the
/// current drive, opens a file, or consults a native temporary directory.
///
/// Windows 3.1 SDK KRNL286.EXE, ordinal 92 (3:05b4): an unforced request
/// always searches A: through Z:, even if its suggested drive is fixed. The
/// suggestion/current drive is only a fallback. The low-byte bit operations
/// intentionally also preserve historical behavior for nonletter inputs.
pub(super) fn select<E>(
    requested: u8,
    current_drive: impl FnOnce() -> Result<u8, E>,
    mut is_fixed: impl FnMut(u8) -> Result<bool, E>,
) -> Result<u8, E> {
    let requested_letter = requested & !TF_FORCEDRIVE;
    let fallback = if requested_letter == 0 {
        b'A' + current_drive()?
    } else {
        requested_letter
    } & 0x5f;

    if requested & TF_FORCEDRIVE == 0 {
        for drive in 0..26 {
            if is_fixed(drive)? {
                return Ok(b'A' + drive);
            }
        }
    }
    Ok(fallback)
}

#[cfg(test)]
mod tests {
    use super::select;

    #[test]
    fn temp_drive_forced_letters_skip_current_state_and_all_probes() {
        for input in [b'A', b'Z', b'a', b'z', b'1', b'`', 0x7f] {
            assert_eq!(select::<()>(input | 0x80,
                || panic!("forced letter read current drive"),
                |_| panic!("forced letter probed a drive")), Ok(input & 0x5f));
        }
    }

    #[test]
    fn temp_drive_forced_zero_uses_current_drive_without_probing() {
        for current in 0..26 {
            assert_eq!(select::<()>(0x80, || Ok(current),
                |_| panic!("forced current drive probed media")), Ok(b'A' + current));
        }
    }

    #[test]
    fn temp_drive_first_fixed_wins_over_requested_or_current_drive() {
        for request in [0, b'F', b'f'] {
            let mut queried = Vec::new();
            assert_eq!(select::<()>(request, || Ok(5), |drive| {
                queried.push(drive);
                Ok([1, 3, 5].contains(&drive))
            }), Ok(b'B'));
            assert_eq!(queried, [0, 1]);
        }
    }

    #[test]
    fn temp_drive_includes_both_ends_of_drive_search() {
        for fixed in [0, 25] {
            let mut queried = Vec::new();
            assert_eq!(select::<()>(b'C', || panic!("unneeded current drive"), |drive| {
                queried.push(drive);
                Ok(drive == fixed)
            }), Ok(b'A' + fixed));
            assert_eq!(queried, (0..=fixed).collect::<Vec<_>>());
        }
    }

    #[test]
    fn temp_drive_no_fixed_media_falls_back_after_exactly_26_probes() {
        for (input, expected) in [(0, b'H'), (b'b', b'B'), (b'`', b'@')] {
            let mut queried = Vec::new();
            assert_eq!(select::<()>(input, || Ok(7), |drive| {
                queried.push(drive);
                Ok(false)
            }), Ok(expected));
            assert_eq!(queried, (0..26).collect::<Vec<_>>());
        }
    }

    #[test]
    fn temp_drive_current_state_and_probe_errors_are_not_invented_success() {
        assert_eq!(select(0, || Err("current"), |_| panic!("unexpected probe")), Err("current"));
        let mut queried = Vec::new();
        assert_eq!(select(b'C', || panic!("unneeded current drive"), |drive| {
            queried.push(drive);
            if drive == 2 { Err("probe") } else { Ok(false) }
        }), Err("probe"));
        assert_eq!(queried, [0, 1, 2]);
    }
}
