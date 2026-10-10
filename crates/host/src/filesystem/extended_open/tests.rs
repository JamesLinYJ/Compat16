use super::*;

fn run_attempts(
    disposition: DosFileDisposition,
    access: DosFileAccess,
    results: Vec<Result<(), DosErrorCode>>,
) -> (Result<DosFileOpenOutcome, DosErrorCode>, Vec<OpenAttempt>) {
    let mut calls = Vec::new();
    let mut results = results.into_iter();
    let result = nontruncating_open(disposition, access, |operation| {
        calls.push(operation);
        results.next().expect("unexpected native operation").map_err(invalid)
    });
    assert!(results.next().is_none(), "expected native operation was skipped");
    (result.map(|(_, outcome)| outcome).map_err(|error| error.code), calls)
}

#[test]
fn actual_successful_operation_determines_extended_open_outcome() {
    use DosFileDisposition::{CreateNew, OpenExisting, OpenOrCreate};
    use DosFileOpenOutcome::{Created, Opened};
    use OpenAttempt::{CreateNew as Create, Existing};
    for (disposition, results, outcome, calls) in [
        (OpenExisting, vec![Ok(())], Opened, vec![Existing]),
        (CreateNew, vec![Ok(())], Created, vec![Create]),
        (OpenOrCreate, vec![Ok(())], Opened, vec![Existing]),
        (OpenOrCreate, vec![Err(DosErrorCode::FileNotFound), Ok(())], Created, vec![Existing, Create]),
        (
            OpenOrCreate,
            vec![Err(DosErrorCode::FileNotFound), Err(DosErrorCode::FileExists), Ok(())],
            Opened,
            vec![Existing, Create, Existing],
        ),
    ] {
        assert_eq!(
            run_attempts(disposition, DosFileAccess::ReadWrite, results),
            (Ok(outcome), calls),
        );
    }
}

#[test]
fn nontruncating_open_retries_only_missing_then_existing_races() {
    for error in [
        DosErrorCode::PathNotFound,
        DosErrorCode::AccessDenied,
        DosErrorCode::SharingViolation,
        DosErrorCode::LockViolation,
        DosErrorCode::DiskFull,
        DosErrorCode::InvalidData,
        DosErrorCode::GeneralFailure,
    ] {
        assert_eq!(
            run_attempts(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite, vec![Err(error)]),
            (Err(error), vec![OpenAttempt::Existing]),
        );
        assert_eq!(
            run_attempts(
                DosFileDisposition::OpenOrCreate,
                DosFileAccess::ReadWrite,
                vec![Err(DosErrorCode::FileNotFound), Err(error)],
            ),
            (Err(error), vec![OpenAttempt::Existing, OpenAttempt::CreateNew]),
        );
    }
    for error in [DosErrorCode::FileNotFound, DosErrorCode::SharingViolation, DosErrorCode::AccessDenied] {
        assert_eq!(
            run_attempts(
                DosFileDisposition::OpenOrCreate,
                DosFileAccess::ReadWrite,
                vec![Err(DosErrorCode::FileNotFound), Err(DosErrorCode::FileExists), Err(error)],
            ),
            (Err(error), vec![OpenAttempt::Existing, OpenAttempt::CreateNew, OpenAttempt::Existing]),
        );
    }
}

#[test]
fn strict_dispositions_do_not_fall_back() {
    assert_eq!(
        run_attempts(
            DosFileDisposition::OpenExisting,
            DosFileAccess::ReadWrite,
            vec![Err(DosErrorCode::FileNotFound)],
        ),
        (Err(DosErrorCode::FileNotFound), vec![OpenAttempt::Existing]),
    );
    assert_eq!(
        run_attempts(
            DosFileDisposition::CreateNew,
            DosFileAccess::ReadWrite,
            vec![Err(DosErrorCode::FileExists)],
        ),
        (Err(DosErrorCode::FileExists), vec![OpenAttempt::CreateNew]),
    );
}

#[test]
fn read_only_creation_is_rejected_before_any_create_attempt() {
    assert_eq!(
        run_attempts(DosFileDisposition::CreateNew, DosFileAccess::ReadOnly, vec![]),
        (Err(DosErrorCode::InvalidFunction), vec![]),
    );
    assert_eq!(
        run_attempts(
            DosFileDisposition::OpenOrCreate,
            DosFileAccess::ReadOnly,
            vec![Err(DosErrorCode::FileNotFound)],
        ),
        (Err(DosErrorCode::InvalidFunction), vec![OpenAttempt::Existing]),
    );
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::OpenOrCreate] {
        assert_eq!(
            run_attempts(disposition, DosFileAccess::ReadOnly, vec![Ok(())]),
            (Ok(DosFileOpenOutcome::Opened), vec![OpenAttempt::Existing]),
        );
    }
}
