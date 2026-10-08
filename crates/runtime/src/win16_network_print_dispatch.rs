//! WNet printer request planning against task-local guest identities.
//!
//! This layer maps guest HFILE/job WORDs to opaque host spool tokens before a
//! host call is formed. Guest FAR values, HWNDs, and selectors never enter a
//! host operation.

use win16_abi::Win16UserNetworkRequest;
use win16_abi::network_print_abi::{
    WN_ALREADY_LOCKED, WN_BAD_FILE_HANDLE, WN_BAD_QUEUE, WN_JOB_NOT_FOUND,
};

use super::network_print_jobs::Win16NetworkPrintJobs;
use crate::win16_host_spool::{
    Win16HostNetworkQueueOperation, Win16HostNetworkQueueWatch, Win16HostSpoolOperation,
    Win16NetworkPrintJobControl,
};
use crate::{DiagnosticKind as Kind, RuntimeError, Win16HostTaskOwner};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Win16NetworkPrintRequestPlan {
    OpenJob {
        operation: Win16HostSpoolOperation,
        queue: Vec<u8>,
        hfile_output: u32,
    },
    CloseJob {
        hfile: u16,
        host_job: crate::win16_host_spool::Win16HostSpoolJob,
        queue_name: Vec<u8>,
        job_id_output: u32,
        queue_name_output: u32,
    },
    Spool(Win16HostSpoolOperation),
    WatchQueue {
        operation: Win16HostNetworkQueueOperation,
        guest_window: u16,
        local_device: Vec<u8>,
        n_queue: u16,
    },
    UnwatchQueue {
        local_device: Vec<u8>,
        watches: Vec<Win16HostNetworkQueueWatch>,
    },
    LockQueueData {
        operation: Win16HostNetworkQueueOperation,
        queue: Vec<u8>,
        output: u32,
    },
    UnlockQueueData {
        queue: Vec<u8>,
        global_handle: Option<u16>,
    },
    GuestStatus(u16),
    /// WFW and the local NTVDM source establish only the pointer types for
    /// WNetWriteJob. They do not establish the LPINT direction/length
    /// contract, so this call must remain a compatibility gap.
    UnverifiedWriteJob,
    NotPrintRequest,
}

pub(crate) fn is_print_request(request: &Win16UserNetworkRequest) -> bool {
    matches!(request,
        Win16UserNetworkRequest::OpenJob { .. }
            | Win16UserNetworkRequest::CloseJob { .. }
            | Win16UserNetworkRequest::AbortJob { .. }
            | Win16UserNetworkRequest::HoldJob { .. }
            | Win16UserNetworkRequest::ReleaseJob { .. }
            | Win16UserNetworkRequest::CancelJob { .. }
            | Win16UserNetworkRequest::SetJobCopies { .. }
            | Win16UserNetworkRequest::WatchQueue { .. }
            | Win16UserNetworkRequest::UnwatchQueue { .. }
            | Win16UserNetworkRequest::LockQueueData { .. }
            | Win16UserNetworkRequest::UnlockQueueData { .. }
            | Win16UserNetworkRequest::WriteJob { .. })
}

/// Prepare a host-owned operation using the current task's opaque job/watch
/// table. This function does not execute the operation or write guest memory;
/// the runtime dispatcher owns completion and ABI projection.
pub(crate) fn plan(
    owner: Win16HostTaskOwner,
    request: Win16UserNetworkRequest,
    jobs: &Win16NetworkPrintJobs,
) -> Result<Win16NetworkPrintRequestPlan, RuntimeError> {
    Ok(match request {
        Win16UserNetworkRequest::OpenJob {
            queue,
            job_name,
            copies,
            hfile_output,
        } => {
            let retained_queue = copy_bytes(&queue, "retain WNetOpenJob queue")?;
            Win16NetworkPrintRequestPlan::OpenJob {
                operation: Win16HostSpoolOperation::NetworkOpenJob {
                    owner,
                    queue,
                    document_name: job_name,
                    copies,
                },
                queue: retained_queue,
                hfile_output,
            }
        }
        Win16UserNetworkRequest::CloseJob {
            hfile,
            job_id_output,
            queue_name_output,
        } => {
            let Some(job) = jobs.open_job(hfile) else {
                return Ok(Win16NetworkPrintRequestPlan::GuestStatus(
                    WN_BAD_FILE_HANDLE,
                ));
            };
            let queue_name = copy_bytes(
                job.normalized_queue_name.as_deref().unwrap_or(&job.queue),
                "retain WNetCloseJob normalized queue name",
            )?;
            Win16NetworkPrintRequestPlan::CloseJob {
                hfile,
                host_job: job.host_job,
                queue_name,
                job_id_output,
                queue_name_output,
            }
        }
        Win16UserNetworkRequest::AbortJob { queue, hfile } => {
            // This WFW export takes the still-open task HFILE. It is distinct
            // from queue JOBSTRUCT IDs used by Hold/Release/Cancel.
            let Some(job) = jobs.open_job(hfile) else {
                return Ok(Win16NetworkPrintRequestPlan::GuestStatus(
                    WN_BAD_FILE_HANDLE,
                ));
            };
            Win16NetworkPrintRequestPlan::Spool(Win16HostSpoolOperation::NetworkAbortJob {
                job: job.host_job,
                queue,
            })
        }
        Win16UserNetworkRequest::HoldJob { queue, job_id } => {
            control(jobs, queue, job_id, Win16NetworkPrintJobControl::Hold)?
        }
        Win16UserNetworkRequest::ReleaseJob { queue, job_id } => {
            control(jobs, queue, job_id, Win16NetworkPrintJobControl::Release)?
        }
        Win16UserNetworkRequest::CancelJob { queue, job_id } => {
            control(jobs, queue, job_id, Win16NetworkPrintJobControl::Cancel)?
        }
        Win16UserNetworkRequest::SetJobCopies {
            queue,
            job_id,
            copies,
        } => {
            let Some(job) = jobs.host_job_for_id(job_id) else {
                return Ok(Win16NetworkPrintRequestPlan::GuestStatus(WN_JOB_NOT_FOUND));
            };
            Win16NetworkPrintRequestPlan::Spool(Win16HostSpoolOperation::NetworkSetJobCopies {
                job,
                queue,
                copies,
            })
        }
        Win16UserNetworkRequest::WatchQueue {
            owner: guest_window,
            local_device,
            user,
            n_queue,
        } => {
            if !jobs.matching_watches_for_queue(&local_device)?.is_empty() {
                return Ok(Win16NetworkPrintRequestPlan::GuestStatus(WN_ALREADY_LOCKED));
            }
            let retained_device = copy_bytes(&local_device, "retain WNetWatchQueue local device")?;
            Win16NetworkPrintRequestPlan::WatchQueue {
                operation: Win16HostNetworkQueueOperation::Watch {
                    owner,
                    local_device,
                    user,
                },
                guest_window,
                local_device: retained_device,
                n_queue,
            }
        }
        Win16UserNetworkRequest::UnwatchQueue { local_device } => {
            let watches = jobs.matching_watches_for_queue(&local_device)?;
            if watches.is_empty() {
                return Ok(Win16NetworkPrintRequestPlan::GuestStatus(WN_BAD_QUEUE));
            }
            Win16NetworkPrintRequestPlan::UnwatchQueue {
                local_device,
                watches,
            }
        }
        Win16UserNetworkRequest::LockQueueData {
            queue,
            user,
            output,
        } => {
            if jobs.queue_data_handle_for(&queue).is_some() {
                return Ok(Win16NetworkPrintRequestPlan::GuestStatus(WN_ALREADY_LOCKED));
            }
            let retained_queue = copy_bytes(&queue, "retain WNetLockQueueData queue")?;
            Win16NetworkPrintRequestPlan::LockQueueData {
                operation: Win16HostNetworkQueueOperation::Snapshot { owner, queue, user },
                queue: retained_queue,
                output,
            }
        }
        Win16UserNetworkRequest::UnlockQueueData { queue } => {
            let global_handle = jobs.queue_data_handle_for(&queue);
            Win16NetworkPrintRequestPlan::UnlockQueueData {
                queue,
                global_handle,
            }
        }
        Win16UserNetworkRequest::WriteJob { .. } => {
            Win16NetworkPrintRequestPlan::UnverifiedWriteJob
        }
        _ => Win16NetworkPrintRequestPlan::NotPrintRequest,
    })
}

fn control(
    jobs: &Win16NetworkPrintJobs,
    queue: Vec<u8>,
    job_id: u16,
    control: Win16NetworkPrintJobControl,
) -> Result<Win16NetworkPrintRequestPlan, RuntimeError> {
    let Some(job) = jobs.host_job_for_id(job_id) else {
        return Ok(Win16NetworkPrintRequestPlan::GuestStatus(WN_JOB_NOT_FOUND));
    };
    Ok(Win16NetworkPrintRequestPlan::Spool(
        Win16HostSpoolOperation::NetworkJobControl {
            job,
            queue,
            control,
        },
    ))
}

fn copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
