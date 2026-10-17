//! Native Windows spool jobs behind the owned Win16 HPJOB token boundary.

use std::collections::HashMap;
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostSpoolJob, Win16HostSpoolOperation as Operation,
    Win16HostSpoolResult as ResultValue, Win16HostTaskOwner,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_HANDLE, ERROR_NOT_SUPPORTED, GetLastError,
};
use windows_sys::Win32::Graphics::Printing::{
    AbortPrinter, ClosePrinter, EndPagePrinter,
    OpenPrinterW, PRINTER_HANDLE,
    StartDocPrinterW, StartPagePrinter, WritePrinter,
};

use super::guest_text::GuestTextCodec;

#[path = "win16_spool_printer_resolution.rs"]
mod printer_resolution;

pub(super) fn resolve_printer_name(
    target_z: &[u16],
) -> Result<Result<Vec<u16>, u32>, RuntimeError> {
    printer_resolution::resolve_printer_name(target_z)
}

pub(super) fn ordinal_equal_ignore_case(left: &[u16], right: &[u16]) -> bool {
    printer_resolution::ordinal_equal_ignore_case(left, right)
}

#[path = "win16_spool_network.rs"]
mod network;

#[path = "win16_spool_document.rs"]
mod document;

#[path = "win16_spool_close.rs"]
mod close;

#[derive(Default)]
pub(crate) struct Win16SpoolJobs {
    jobs: HashMap<Win16HostSpoolJob, NativeJob>,
    network_job_index: HashMap<NetworkJobIndexKey, Win16HostSpoolJob>,
    /// Printer handles whose first close failed, retained with the task
    /// identity that created them so ReleaseNetworkOwner can retry them.
    orphaned_printers: Vec<(Option<Win16HostTaskOwner>, PRINTER_HANDLE)>,
    next_token: u64,
}

type NetworkJobIndexKey = (Win16HostTaskOwner, Vec<u16>, u32, NetworkJobIndexKind);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NetworkJobIndexKind {
    /// A WNetOpenJob document whose lifecycle belongs to this task.
    OwnedDocument,
    /// A printer job borrowed from a WNetLockQueueData snapshot.
    SnapshotLease,
}

struct NativeJob {
    printer: PRINTER_HANDLE,
    job_id: u32,
    printer_name: Vec<u16>,
    queue_name: Vec<u8>,
    document_open: bool,
    /// A successful WNet abort/cancel must not be repeated if closing the
    /// owned printer handle fails and the runtime retries cleanup by token.
    terminal_action: bool,
    network_owner: Option<Win16HostTaskOwner>,
    network_index_kind: NetworkJobIndexKind,
}

struct StartedJob {
    token: Win16HostSpoolJob,
    queue_name: Vec<u8>,
}

impl Win16SpoolJobs {
    /// Release a borrowed snapshot token from the sibling queue adapter.
    /// This closes the duplicated printer handle without canceling a native job.
    pub(super) fn release_snapshot_network_job(
        &mut self,
        job: Win16HostSpoolJob,
    ) -> Result<ResultValue, RuntimeError> {
        self.release_network_job(job)
    }

    pub(crate) fn execute(
        &mut self,
        codec: GuestTextCodec,
        operation: Operation,
    ) -> Result<ResultValue, RuntimeError> {
        match operation {
            Operation::OpenJob {
                owner,
                output_target,
                document_name,
                legacy_argument: _,
            } => self.open_job(codec, owner, &output_target, &document_name),
            Operation::NetworkOpenJob {
                owner,
                queue,
                document_name,
                copies,
            } => self.open_network_job(codec, owner, &queue, document_name.as_deref(), copies),
            Operation::StartPage { job } => self.with_job(job, |native| {
                // SAFETY: the handle is retained by this owner and the API
                // only borrows it for the duration of the call.
                let succeeded = unsafe { StartPagePrinter(native.printer) != 0 };
                status_result(succeeded)
            }),
            Operation::EndPage { job } => self.with_job(job, |native| {
                // SAFETY: the handle is retained by this owner and the API
                // only borrows it for the duration of the call.
                let succeeded = unsafe { EndPagePrinter(native.printer) != 0 };
                status_result(succeeded)
            }),
            Operation::Write { job, bytes } => self.with_job(job, |native| {
                let byte_count = u32::try_from(bytes.len()).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InvalidInput,
                        "Win16 WriteSpool byte count exceeds the Windows spooler ABI",
                        error,
                    )
                })?;
                let mut written = 0u32;
                let empty = 0_u8;
                let data = (bytes.first().unwrap_or(&empty) as *const u8).cast();
                // SAFETY: bytes owns `byte_count` readable bytes for the
                // duration of this synchronous call; `written` is writable.
                let succeeded =
                    unsafe { WritePrinter(native.printer, data, byte_count, &mut written) != 0 };
                Ok(if succeeded {
                    ResultValue::Write {
                        bytes_written: written,
                        native_error: None,
                    }
                } else {
                    ResultValue::Write {
                        bytes_written: 0,
                        native_error: Some(last_error()),
                    }
                })
            }),
            Operation::CloseJob { job } => self.close_job(job, false),
            Operation::NetworkCloseJob { job } => self.close_network_job(job),
            Operation::NetworkAbortJob { job, queue } => self.abort_network_job(job, codec, &queue),
            Operation::NetworkJobControl {
                job,
                queue,
                control,
            } => self.control_network_job(job, codec, &queue, control),
            Operation::NetworkSetJobCopies { job, queue, copies } => {
                self.set_network_job_copies(job, codec, &queue, copies)
            }
            Operation::ReleaseNetworkJob { job } => self.release_network_job(job),
            Operation::ReleaseNetworkOwner { owner } => self.release_network_owner(owner),
            Operation::DeleteJob {
                job,
                legacy_argument: _,
            } => self.close_job(job, true),
            Operation::WriteDialog { .. } => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 WriteDialog needs a guest-visible UI continuation",
            )),
            Operation::DeleteSpoolPage { .. } => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Windows spooler cannot remove one page from an active Win16 spool job",
            )),
        }
    }

    fn release_network_owner(
        &mut self,
        owner: Win16HostTaskOwner,
    ) -> Result<ResultValue, RuntimeError> {
        // Snapshot exact task-owned tokens before native effects. The vector
        // is bounded by the registry size and allocated before any release.
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(self.jobs.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate task-owned WNet spool cleanup list",
                error,
            )
        })?;
        jobs.extend(self.jobs.iter().filter_map(|(token, native)|
            (native.network_owner == Some(owner)).then_some(*token)));
        jobs.sort_unstable();
        jobs.dedup();

        let mut succeeded = true;
        let mut first_native_error = None;
        for job in jobs {
            match self.release_network_job(job)? {
                ResultValue::Status { succeeded: true, .. } => {}
                ResultValue::Status { succeeded: false, native_error } => {
                    succeeded = false;
                    first_native_error = first_native_error.or(Some(
                        native_error.filter(|code| *code != 0).unwrap_or(ERROR_NOT_SUPPORTED),
                    ));
                }
                _ => return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "task-owned WNet cleanup returned a different spool result",
                )),
            }
        }
        let mut index = 0;
        while index < self.orphaned_printers.len() {
            if self.orphaned_printers[index].0 != Some(owner) {
                index += 1;
                continue;
            }
            let printer = self.orphaned_printers[index].1;
            // SAFETY: this owner-tagged orphan was retained after a prior
            // ClosePrinter failure and is retried against that exact handle.
            if unsafe { ClosePrinter(printer) } != 0 {
                self.orphaned_printers.swap_remove(index);
            } else {
                succeeded = false;
                first_native_error.get_or_insert_with(last_error);
                index += 1;
            }
        }
        Ok(ResultValue::Status {
            succeeded,
            native_error: (!succeeded).then_some(first_native_error.unwrap_or(ERROR_NOT_SUPPORTED)),
        })
    }

    fn open_job(
        &mut self,
        codec: GuestTextCodec,
        owner: Win16HostTaskOwner,
        output_target: &[u8],
        document_name: &[u8],
    ) -> Result<ResultValue, RuntimeError> {
        Ok(
            match self.start_job(
                codec,
                output_target,
                Some(document_name),
                Some(owner),
                false,
            )? {
                Ok(started) => ResultValue::OpenJob {
                    job: Some(started.token),
                    native_error: None,
                },
                Err(error) => ResultValue::OpenJob {
                    job: None,
                    native_error: Some(error),
                },
            },
        )
    }

    fn start_job(
        &mut self,
        codec: GuestTextCodec,
        output_target: &[u8],
        document_name: Option<&[u8]>,
        task_owner: Option<Win16HostTaskOwner>,
        index_network_job: bool,
    ) -> Result<Result<StartedJob, u32>, RuntimeError> {
        self.jobs.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 spool job identity",
                error,
            )
        })?;
        if index_network_job {
            self.network_job_index.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 network job identity",
                    error,
                )
            })?;
        }
        self.orphaned_printers.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 spool printer cleanup slot",
                error,
            )
        })?;

        let target = codec.to_wide_z(output_target)?;
        let document = document_name
            .map(|bytes| codec.to_wide_z(bytes))
            .transpose()?;
        let printer_name = match resolve_printer_name(&target)? {
            Ok(name) => name,
            Err(error) => return Ok(Err(error)),
        };
        let stable_printer_name = printer_name.strip_suffix(&[0]).unwrap_or(&printer_name);
        let native_printer_name =
            copy_wide_units(stable_printer_name, "copy native Win16 spool printer name")?;
        let indexed_printer_name =
            copy_wide_units(stable_printer_name, "copy Win16 spool printer index name")?;
        let returned_queue_name = codec.from_wide(stable_printer_name).map_or_else(
            |_| copy_bytes(output_target, "copy returned Win16 spool queue name"),
            |value| Ok(value.bytes),
        )?;
        let native_queue_name =
            copy_bytes(&returned_queue_name, "copy retained Win16 spool queue name")?;
        let started_queue_name = copy_bytes(&returned_queue_name, "copy WNetOpenJob queue name")?;
        let token = self.allocate_token()?;

        let mut printer = PRINTER_HANDLE::default();
        // SAFETY: `printer_name` is terminated and owned; `printer` is an
        // initialized writable SDK output record. A null defaults pointer
        // asks OpenPrinterW to use the caller's normal printer access defaults.
        if unsafe { OpenPrinterW(printer_name.as_ptr(), &mut printer, ptr::null()) } == 0 {
            return Ok(Err(last_error()));
        }

        let job_id = document::start_with(printer, document.as_deref(), |printer, level, info| {
            // SAFETY: the record and terminated strings remain live throughout
            // this synchronous call; the printer handle is owned by this job.
            unsafe { StartDocPrinterW(printer, level, info) }
        });
        if job_id == 0 {
            let error = last_error();
            if unsafe { ClosePrinter(printer) } == 0 {
                self.orphaned_printers.push((task_owner, printer));
            }
            return Ok(Err(error));
        }

        self.jobs.insert(
            token,
            NativeJob {
                printer,
                job_id,
                printer_name: native_printer_name,
                queue_name: native_queue_name,
                document_open: true,
                terminal_action: false,
                network_owner: task_owner,
                network_index_kind: NetworkJobIndexKind::OwnedDocument,
            },
        );
        if index_network_job && let Some(owner) = task_owner {
            self.network_job_index.insert(
                (owner, indexed_printer_name, job_id, NetworkJobIndexKind::OwnedDocument),
                token,
            );
        }
        Ok(Ok(StartedJob {
            token,
            queue_name: started_queue_name,
        }))
    }

    pub(crate) fn register_existing_job(
        &mut self,
        owner: Win16HostTaskOwner,
        printer_name: &[u16],
        job_id: u32,
    ) -> Result<(Win16HostSpoolJob, bool), RuntimeError> {
        let printer_name = printer_name.strip_suffix(&[0]).unwrap_or(printer_name);
        let existing = self.network_job_index.iter().find_map(|(key, token)| {
            (key.0 == owner
                && key.2 == job_id
                && ordinal_equal_ignore_case(&key.1, printer_name)
                && key.3 == NetworkJobIndexKind::SnapshotLease)
                .then_some(*token)
        });
        if let Some(token) = existing {
            if self.jobs.contains_key(&token) {
                return Ok((token, false));
            }
        }
        let key_name = copy_wide_units(printer_name, "copy network queue job index name")?;
        let native_printer_name =
            copy_wide_units(printer_name, "copy network queue job printer name")?;
        let mut terminated_name =
            copy_wide_units(printer_name, "terminate network queue printer name")?;
        terminated_name.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "terminate network queue printer name",
                error,
            )
        })?;
        terminated_name.push(0);
        let key = (owner, key_name, job_id, NetworkJobIndexKind::SnapshotLease);
        self.jobs.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate network queue job identity",
                error,
            )
        })?;
        self.network_job_index.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate network queue job index",
                error,
            )
        })?;
        self.orphaned_printers.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve network queue printer cleanup",
                error,
            )
        })?;
        let token = self.allocate_token()?;
        let mut printer = PRINTER_HANDLE::default();
        // SAFETY: the queue name is a terminated owned UTF-16 string and the
        // output printer handle is initialized storage owned by this call.
        if unsafe { OpenPrinterW(terminated_name.as_ptr(), &mut printer, ptr::null()) } == 0 {
            let error = last_error();
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!("open printer for queued job failed with Windows error {error}"),
            ));
        }
        self.jobs.insert(
            token,
            NativeJob {
                printer,
                job_id,
                printer_name: native_printer_name,
                queue_name: Vec::new(),
                document_open: false,
                terminal_action: false,
                network_owner: Some(owner),
                network_index_kind: NetworkJobIndexKind::SnapshotLease,
            },
        );
        self.network_job_index.insert(key, token);
        Ok((token, true))
    }

    fn with_job(
        &mut self,
        job: Win16HostSpoolJob,
        operation: impl FnOnce(&mut NativeJob) -> Result<ResultValue, RuntimeError>,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get_mut(&job) else {
            return Ok(ResultValue::Status {
                succeeded: false,
                native_error: Some(ERROR_INVALID_HANDLE),
            });
        };
        operation(native)
    }

    fn allocate_token(&mut self) -> Result<Win16HostSpoolJob, RuntimeError> {
        let first = if self.next_token == 0 {
            1
        } else {
            self.next_token
        };
        let mut candidate = first;
        loop {
            let token = Win16HostSpoolJob::new(candidate);
            if !self.jobs.contains_key(&token) {
                self.next_token = candidate.wrapping_add(1);
                if self.next_token == 0 {
                    self.next_token = 1;
                }
                return Ok(token);
            }
            candidate = candidate.wrapping_add(1);
            if candidate == 0 {
                candidate = 1;
            }
            if candidate == first {
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 spool job token space is exhausted",
                ));
            }
        }
    }
}

impl Drop for Win16SpoolJobs {
    fn drop(&mut self) {
        for (_, native) in self.jobs.drain() {
            // Shutdown owns these jobs. Abort the active document, then close
            // the native printer handle; no guest handle outlives this owner.
            unsafe {
                if native.document_open {
                    AbortPrinter(native.printer);
                }
                ClosePrinter(native.printer);
            }
        }
        for (_, printer) in self.orphaned_printers.drain(..) {
            unsafe { ClosePrinter(printer) };
        }
    }
}

fn status_success() -> ResultValue {
    ResultValue::Status {
        succeeded: true,
        native_error: None,
    }
}

fn status_error(error: u32) -> ResultValue {
    ResultValue::Status {
        succeeded: false,
        native_error: Some(error),
    }
}

fn status_result(succeeded: bool) -> Result<ResultValue, RuntimeError> {
    Ok(if succeeded {
        ResultValue::Status {
            succeeded: true,
            native_error: None,
        }
    } else {
        ResultValue::Status {
            succeeded: false,
            native_error: Some(last_error()),
        }
    })
}

fn last_error() -> u32 {
    // SAFETY: GetLastError reads the calling thread's Windows status value.
    unsafe { GetLastError() }
}

fn copy_wide_units(source: &[u16], context: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

fn copy_bytes(source: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

fn remove_network_job_index(
    index: &mut HashMap<NetworkJobIndexKey, Win16HostSpoolJob>,
    token: Win16HostSpoolJob,
    native: &NativeJob,
) {
    index.retain(|(owner, printer_name, job_id, kind), indexed_token| {
        !(*indexed_token == token
            && native.network_owner == Some(*owner)
            && *job_id == native.job_id
            && printer_name.as_slice() == native.printer_name.as_slice()
            && *kind == native.network_index_kind)
    });
}
