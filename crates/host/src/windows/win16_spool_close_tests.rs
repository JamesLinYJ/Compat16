//! Fault injection at each native close phase; no printer API is invoked.
use super::super::{NativeJob, NetworkJobIndexKind};
use super::*;
use guest_core::OwnerId;

const JOB: Win16HostSpoolJob = Win16HostSpoolJob::new(7);
const OTHER: Win16HostSpoolJob = Win16HostSpoolJob::new(8);
const ID: u32 = 0xabcd_1234;

struct Fixture {
    jobs: Win16SpoolJobs,
}
impl Fixture {
    fn new() -> Self {
        let mut jobs = Win16SpoolJobs::default();
        for (token, owner, id) in [(JOB, OwnerId(1), ID), (OTHER, OwnerId(2), ID + 1)] {
            let kind = NetworkJobIndexKind::OwnedDocument;
            jobs.jobs.insert(
                token,
                NativeJob {
                    printer: PRINTER_HANDLE::default(),
                    job_id: id,
                    printer_name: vec![81],
                    queue_name: vec![81],
                    document_open: true,
                    terminal_action: false,
                    network_owner: Some(owner),
                    network_index_kind: kind,
                },
            );
            jobs.network_job_index
                .insert((owner, vec![81], id, kind), token);
        }
        Self { jobs }
    }
    fn retained(&self, open: bool, cancelled: bool) {
        let job = &self.jobs.jobs[&JOB];
        assert_eq!((job.document_open, job.terminal_action), (open, cancelled));
        assert_eq!(job.network_owner, Some(OwnerId(1)));
        assert!(
            self.jobs
                .network_job_index
                .values()
                .any(|token| *token == JOB)
        );
        assert!(self.jobs.jobs.contains_key(&OTHER));
    }
    fn retired(&self) {
        assert!(!self.jobs.jobs.contains_key(&JOB));
        assert!(
            !self
                .jobs
                .network_job_index
                .values()
                .any(|token| *token == JOB)
        );
        assert!(self.jobs.jobs.contains_key(&OTHER));
        assert!(
            self.jobs
                .network_job_index
                .values()
                .any(|token| *token == OTHER)
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // These are inert fixture handles. Clear them before the production
        // destructor so every effect remains inside the injected closures.
        self.jobs.jobs.clear();
        self.jobs.orphaned_printers.clear();
    }
}
fn failed(value: ResultValue, error: u32) {
    assert!(
        matches!(value,ResultValue::Status {succeeded:false,native_error:Some(code)} if code==error)
    );
}
fn succeeded(value: ResultValue) {
    assert!(matches!(
        value,
        ResultValue::Status {
            succeeded: true,
            native_error: None
        }
    ));
}

#[test]
fn spool_close_end_failure_keeps_open_job_for_retry_or_abort() {
    let mut f = Fixture::new();
    failed(
        f.jobs
            .close_job_with(
                JOB,
                false,
                |action, printer, id| {
                    assert_eq!(action, Finish::EndDocument);
                    assert!(printer.Value.is_null());
                    assert_eq!(id, ID);
                    Err(112)
                },
                |_| panic!("must not close after failed EndDocPrinter"),
            )
            .unwrap(),
        112,
    );
    f.retained(true, false);
    succeeded(
        f.jobs
            .close_job_with(
                JOB,
                true,
                |action, _, id| {
                    assert_eq!(action, Finish::AbortOpenDocument);
                    assert_eq!(id, ID);
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap(),
    );
    f.retired();
}

#[test]
fn spool_close_native_close_failure_does_not_replay_successful_end() {
    let mut f = Fixture::new();
    let mut ended = 0;
    let mut closed = 0;
    failed(
        f.jobs
            .close_job_with(
                JOB,
                false,
                |action, _, _| {
                    assert_eq!(action, Finish::EndDocument);
                    ended += 1;
                    Ok(())
                },
                |_| {
                    closed += 1;
                    Err(5)
                },
            )
            .unwrap(),
        5,
    );
    f.retained(false, false);
    succeeded(
        f.jobs
            .close_job_with(
                JOB,
                false,
                |_, _, _| panic!("EndDocPrinter replay"),
                |_| {
                    closed += 1;
                    Ok(())
                },
            )
            .unwrap(),
    );
    assert_eq!((ended, closed), (1, 2));
    f.retired();
}

#[test]
fn spool_close_abort_failure_preserves_the_live_document() {
    let mut f = Fixture::new();
    failed(
        f.jobs
            .close_job_with(
                JOB,
                true,
                |action, _, _| {
                    assert_eq!(action, Finish::AbortOpenDocument);
                    Err(8)
                },
                |_| panic!("must not close after failed AbortPrinter"),
            )
            .unwrap(),
        8,
    );
    f.retained(true, false);
}

#[test]
fn spool_close_failed_handle_release_does_not_replay_successful_cancel() {
    let mut f = Fixture::new();
    let mut aborted = 0;
    failed(
        f.jobs
            .close_job_with(
                JOB,
                true,
                |action, _, _| {
                    assert_eq!(action, Finish::AbortOpenDocument);
                    aborted += 1;
                    Ok(())
                },
                |_| Err(5),
            )
            .unwrap(),
        5,
    );
    f.retained(false, true);
    succeeded(
        f.jobs
            .close_job_with(
                JOB,
                true,
                |_, _, _| panic!("AbortPrinter replay"),
                |_| Ok(()),
            )
            .unwrap(),
    );
    assert_eq!(aborted, 1);
    f.retired();
}

#[test]
fn spool_close_delete_after_completed_end_targets_only_the_queued_job_id() {
    let mut f = Fixture::new();
    failed(
        f.jobs
            .close_job_with(
                JOB,
                false,
                |action, _, _| {
                    assert_eq!(action, Finish::EndDocument);
                    Ok(())
                },
                |_| Err(5),
            )
            .unwrap(),
        5,
    );
    failed(
        f.jobs
            .close_job_with(
                JOB,
                true,
                |action, _, id| {
                    assert_eq!(action, Finish::CancelQueuedJob);
                    assert_eq!(id, ID);
                    Err(5)
                },
                |_| panic!("must not close after failed SetJob"),
            )
            .unwrap(),
        5,
    );
    f.retained(false, false);
    succeeded(
        f.jobs
            .close_job_with(
                JOB,
                true,
                |action, _, id| {
                    assert_eq!(action, Finish::CancelQueuedJob);
                    assert_eq!(id, ID);
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap(),
    );
    f.retired();
}

#[test]
fn spool_close_unknown_token_has_no_native_effect() {
    let mut f = Fixture::new();
    failed(
        f.jobs
            .close_job_with(
                Win16HostSpoolJob::new(99),
                false,
                |_, _, _| panic!("unknown job must not finish"),
                |_| panic!("unknown job must not close"),
            )
            .unwrap(),
        ERROR_INVALID_HANDLE,
    );
    f.retained(true, false);
}
