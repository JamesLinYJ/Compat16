//! Win16 WNet spool calls and task-owned guest job identities.
//!
//! HFILEs and job IDs remain WORD aliases owned by OwnerId; native spool jobs
//! use opaque host tokens.

use guest_core::{memory::Memory, OwnerId};
use win16_abi::Win16UserNetworkRequest;
pub(super) use win16_abi::network_print_abi::{
    WN_BAD_VALUE, WN_NET_ERROR, WN_NOT_SUPPORTED, WN_SUCCESS,
};
use win16_abi::network_print_abi::{WN_BAD_POINTER, WN_CANT_SET_COPIES};

use super::Win16State;
use super::network_print_completion as completion;
use super::network_print_dispatch::{self, Win16NetworkPrintRequestPlan as Plan};
use super::network_print_jobs::Win16NetworkPrintJobs;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostSpoolOperation, Win16HostSpoolResult, Win16NetworkPrintJobControl,
};

impl Win16State {
    /// Execute only the printing subset of USER/WFW network requests. The
    /// caller continues routing every other request through its existing path.
    pub(super) fn dispatch_network_print(
        &mut self,
        request: Win16UserNetworkRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u16>, RuntimeError> {
        if !network_print_dispatch::is_print_request(&request) {
            return Ok(None);
        }
        let owner = self.current_network_print_owner()?;
        self.sweep_retired_network_print_windows(host)?;
        let plan = {
            let jobs = self.network_print_jobs.entry(owner).or_default();
            network_print_dispatch::plan(owner, request, jobs)?
        };
        let status = match plan {
            Plan::NotPrintRequest => {
                self.drop_empty_network_print_owner(owner);
                return Ok(None);
            }
            Plan::GuestStatus(status) => status,
            Plan::OpenJob { operation, queue, hfile_output } => {
                self.open_network_print_job(owner, operation, queue, hfile_output, memory, host)?
            }
            Plan::CloseJob { hfile, host_job, queue_name, job_id_output, queue_name_output, .. } => {
                self.close_network_print_job(
                    owner, hfile, host_job, queue_name, job_id_output,
                    queue_name_output, memory, host,
                )?
            }
            Plan::Spool(operation) => self.execute_network_print_spool(owner, operation, host)?,
            Plan::WatchQueue { operation, guest_window, local_device, n_queue } => {
                self.watch_network_print_queue(
                    owner, operation, guest_window, local_device, n_queue, host,
                )?
            }
            Plan::UnwatchQueue { local_device: _, watches } => {
                self.unwatch_network_print_queues(owner, watches, host)?
            }
            Plan::LockQueueData { operation, queue, output } => {
                self.lock_network_print_queue(owner, operation, queue, output, memory, host)?
            }
            Plan::UnlockQueueData { queue, global_handle } => {
                self.unlock_network_print_queue(owner, &queue, global_handle, host)?
            }
            Plan::UnverifiedWriteJob => {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "WNetWriteJob remains unbridged because the WFW and NTVDM sources do not establish the LPINT direction or byte-count contract",
                ));
                WN_NOT_SUPPORTED
            }
        };
        Ok(Some(status))
    }

    /// Route one WNet-created HFILE through the same host spool job used by
    /// _lwrite and INT 21h/AH=40h. The caller copies guest bytes first.
    pub(super) fn write_network_print_hfile(
        &mut self,
        owner: OwnerId,
        hfile: u16,
        bytes: &[u8],
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u32>, RuntimeError> {
        let Some(job) = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.open_job(hfile)) else { return Ok(None); };
        if job.closed_queue_name.is_some() { return Ok(Some(u32::MAX)); }
        let token = job.host_job;
        let requested = u32::try_from(bytes.len()).map_err(|error| RuntimeError::with_source(
            Kind::InvalidInput, "Win16 WNet HFILE transfer exceeds the Windows spooler byte count", error,
        ))?;
        match host.win16_spool(Win16HostSpoolOperation::Write {
            job: token,
            bytes: copy_bytes(bytes, "copy Win16 network print transfer")?,
        })? {
            Win16HostSpoolResult::Write { bytes_written, native_error: None }
                if bytes_written <= requested => Ok(Some(bytes_written)),
            Win16HostSpoolResult::Write { native_error: Some(code), .. } => {
                report_native_failure(host, "WritePrinter for Win16 WNet HFILE", code);
                Ok(Some(u32::MAX))
            }
            Win16HostSpoolResult::Write { bytes_written, native_error: None } => {
                Err(RuntimeError::new(Kind::InternalInvariant, format!(
                    "WritePrinter returned {bytes_written} bytes for a {}-byte Win16 transfer",
                    requested,
                )))
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "WNet HFILE write received a different spool result")),
        }
    }

    pub(super) fn network_print_hfile_is_owned(&self, owner: OwnerId, hfile: u16) -> bool {
        self.network_print_jobs.get(&owner).is_some_and(|jobs| jobs.owns_hfile(hfile))
    }

    /// WNet spool HFILEs are write-only and do not have a seekable file cursor.
    pub(super) fn reject_network_print_hfile_io(&self, owner: OwnerId, hfile: u16) -> bool {
        self.network_print_hfile_is_owned(owner, hfile)
    }

    /// _lclose/INT 21h close releases an unclosed spool document. Keep the
    /// guest alias on any native failure so the same operation can be retried.
    pub(super) fn close_network_print_hfile(
        &mut self,
        owner: OwnerId,
        hfile: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u32>, RuntimeError> {
        let Some((token, document_closed)) = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.open_job(hfile))
            .map(|job| (job.host_job, job.closed_queue_name.is_some())) else {
                return Ok(None);
            };
        let has_guest_job_id = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.guest_job_id_for_host(token)).is_some();
        if document_closed && has_guest_job_id {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet HFILE owner disappeared during close"))?
                .retire_open_job(hfile);
            self.drop_empty_network_print_owner(owner);
            return Ok(Some(0));
        }
        let status = completion::spool_status(host.win16_spool(
            Win16HostSpoolOperation::ReleaseNetworkJob { job: token },
        )?)?;
        if status == WN_SUCCESS {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet HFILE owner disappeared during close"))?
                .retire_open_job(hfile);
            self.drop_empty_network_print_owner(owner);
            Ok(Some(0))
        } else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::HostFailure,
                format!("ReleaseNetworkJob for Win16 HFILE 0x{hfile:04X} returned WN status 0x{status:04X}"),
            ));
            Ok(Some(u32::from(super::INVALID_GUEST_HFILE)))
        }
    }

    fn current_network_print_owner(&self) -> Result<OwnerId, RuntimeError> {
        self.tasks.current().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WNet printing has no current Win16 task owner"))
    }

    pub(super) fn drop_empty_network_print_owner(&mut self, owner: OwnerId) {
        if self.network_print_jobs.get(&owner).is_some_and(Win16NetworkPrintJobs::is_empty) {
            self.network_print_jobs.remove(&owner);
        }
    }

    fn open_network_print_job(
        &mut self,
        owner: OwnerId,
        operation: Win16HostSpoolOperation,
        queue: Vec<u8>,
        hfile_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let output = match self.prepare_network_print_output(memory, hfile_output, 2) {
            Ok(output) => output,
            Err(error) if error.kind() == Kind::GuestFault => return Ok(WN_BAD_POINTER),
            Err(error) => return Err(error),
        };
        let hfile = self.next_free_file_number().ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 task HFILE space is exhausted"))?;
        let reserved = self.network_print_jobs.entry(owner).or_default().reserve_hfile(hfile)?;
        if !reserved { return Err(print_invariant("shared HFILE allocator returned an occupied WNet slot")); }
        let result = match host.win16_spool(operation) {
            Ok(result) => result,
            Err(error) => {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet open reservation owner disappeared"))?
                    .cancel_hfile_reservation(hfile);
                return Err(error);
            }
        };
        let completion = match completion::open_job(result) {
            Ok(completion) => completion,
            Err(error) => {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet open reservation owner disappeared"))?
                    .cancel_hfile_reservation(hfile);
                self.drop_empty_network_print_owner(owner);
                return Err(error);
            }
        };
        if let Some(diagnostic) = completion.copies_diagnostic.as_ref() {
            host.report_diagnostic(&Diagnostic::warning(
                diagnostic.kind,
                format!("WNetOpenJob copy negotiation: {}", diagnostic.message),
            ));
        }
        if completion.status != WN_SUCCESS && completion.status != WN_CANT_SET_COPIES {
            if let Some(job) = completion.job {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet open cleanup owner disappeared"))?
                    .retain_unexposed_host_job(job)?;
            }
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet open reservation owner disappeared"))?
                .cancel_hfile_reservation(hfile);
            return Ok(completion.status);
        }
        let Some(job) = completion.job else {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet open reservation owner disappeared"))?
                .cancel_hfile_reservation(hfile);
            return Err(print_invariant("successful WNetOpenJob omitted its native cleanup token"));
        };
        let Some(normalized_queue) = completion.queue_name else {
            let jobs = self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet open reservation owner disappeared"))?;
            jobs.retain_unexposed_host_job(job)?;
            jobs.cancel_hfile_reservation(hfile);
            return Err(print_invariant("successful WNetOpenJob omitted its normalized queue name"));
        };
        let insert = self.network_print_jobs.get_mut(&owner)
            .ok_or_else(|| print_invariant("WNet open reservation owner disappeared"))?
            .insert_open_job(hfile, job, queue, Some(normalized_queue));
        if let Err(primary) = insert {
            let jobs = self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet open cleanup owner disappeared"))?;
            let cleanup = jobs.retain_unexposed_host_job(job);
            jobs.cancel_hfile_reservation(hfile);
            return Err(match cleanup {
                Ok(()) => primary,
                Err(error) => primary.with_cleanup("retaining native WNet job for task cleanup", error),
            });
        }
        output.commit(memory, &hfile.to_le_bytes())?;
        Ok(completion.status)
    }

    #[allow(clippy::too_many_arguments)]
    fn close_network_print_job(
        &mut self,
        owner: OwnerId,
        hfile: u16,
        planned_job: crate::Win16HostSpoolJob,
        planned_queue: Vec<u8>,
        job_id_output: u32,
        queue_name_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let (job_id, host_job, expected_queue, already_closed) = self
            .network_print_jobs.get_mut(&owner)
            .ok_or_else(|| print_invariant("WNetCloseJob task table disappeared"))?
            .reserve_close_job(hfile)?;
        if host_job != planned_job || expected_queue.eq_ignore_ascii_case(&planned_queue) == false {
            return Err(print_invariant("WNetCloseJob plan changed its exact HFILE/job identity"));
        }
        let job_output = match self.prepare_network_print_output(memory, job_id_output, 2) {
            Ok(output) => output,
            Err(error) if error.kind() == Kind::GuestFault => {
                if already_closed.is_none() { self.network_print_jobs.get_mut(&owner)
                    .expect("reserved WNet close owner")
                    .cancel_close_reservation(hfile, job_id); }
                return Ok(WN_BAD_POINTER);
            }
            Err(error) => return Err(error),
        };
        let queue_for_preflight = already_closed.as_deref().unwrap_or(&expected_queue);
        let mut queue_bytes = nul_terminated(queue_for_preflight)?;
        let mut queue_output = match self.prepare_network_print_output(
            memory, queue_name_output, queue_bytes.len(),
        ) {
            Ok(output) => output,
            Err(error) if error.kind() == Kind::GuestFault => {
                if already_closed.is_none() { self.network_print_jobs.get_mut(&owner)
                    .expect("reserved WNet close owner")
                    .cancel_close_reservation(hfile, job_id); }
                return Ok(WN_BAD_POINTER);
            }
            Err(error) => return Err(error),
        };

        let close_name = if let Some(closed) = already_closed {
            closed
        } else {
            // Prepare the no-name fallback before EndDocPrinter. If the native
            // host result omits its normalized name, the completed close can
            // still be retained without a post-close allocation.
            let fallback_queue = copy_bytes(&expected_queue, "reserve completed WNet queue name")?;
            let result = match host.win16_spool(Win16HostSpoolOperation::NetworkCloseJob { job: host_job }) {
                Ok(result) => result,
                Err(error) => {
                    self.network_print_jobs.get_mut(&owner)
                        .ok_or_else(|| print_invariant("WNet close owner disappeared"))?
                        .cancel_close_reservation(hfile, job_id);
                    return Err(error);
                }
            };
            let Win16HostSpoolResult::NetworkCloseJob { succeeded, queue_name, native_error } = result else {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet close owner disappeared"))?
                    .cancel_close_reservation(hfile, job_id);
                return Err(print_invariant("WNetCloseJob received a different host result"));
            };
            if !succeeded {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet close owner disappeared"))?
                    .cancel_close_reservation(hfile, job_id);
                return Ok(native_error.map_or(WN_NET_ERROR, completion::map_native_error));
            }
            let actual = queue_name.unwrap_or(fallback_queue);
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet close owner disappeared"))?
                .retain_closed_job(hfile, job_id, actual)?;
            let retained = self.network_print_jobs.get(&owner)
                .and_then(|jobs| jobs.open_job(hfile))
                .and_then(|job| job.closed_queue_name.as_deref())
                .ok_or_else(|| print_invariant("WNetCloseJob failed to retain its completed queue name"))?;
            copy_bytes(retained, "copy completed WNet queue name for guest output")?
        };
        if !close_name.eq_ignore_ascii_case(&expected_queue) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native WNetCloseJob returned a different queue name; completed close remains task-owned"));
        }
        if queue_bytes.len() != close_name.len().saturating_add(1) {
            queue_bytes = nul_terminated(&close_name)?;
            queue_output = match self.prepare_network_print_output(memory, queue_name_output, queue_bytes.len()) {
                Ok(output) => output,
                Err(error) => return if error.kind() == Kind::GuestFault { Ok(WN_BAD_POINTER) } else { Err(error) },
            };
        } else {
            queue_bytes[..close_name.len()].copy_from_slice(&close_name);
        }
        queue_output.commit(memory, &queue_bytes)?;
        job_output.commit(memory, &job_id.to_le_bytes())?;
        self.network_print_jobs.get_mut(&owner)
            .ok_or_else(|| print_invariant("WNetCloseJob owner disappeared before ID commit"))?
            .complete_close_job(hfile, job_id)?;
        Ok(WN_SUCCESS)
    }

    fn execute_network_print_spool(
        &mut self,
        owner: OwnerId,
        operation: Win16HostSpoolOperation,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let set_copies = matches!(&operation,
            Win16HostSpoolOperation::NetworkSetJobCopies { .. });
        let retired_job = match &operation {
            Win16HostSpoolOperation::NetworkAbortJob { job, .. } => Some(*job),
            Win16HostSpoolOperation::NetworkJobControl {
                job, control: Win16NetworkPrintJobControl::Cancel, ..
            } => Some(*job),
            _ => None,
        };
        let result = host.win16_spool(operation)?;
        let status = if set_copies {
            completion::set_job_copies_status(result)?
        } else {
            completion::spool_status(result)?
        };
        if status == WN_SUCCESS {
            if let (Some(job), Some(jobs)) = (retired_job, self.network_print_jobs.get_mut(&owner)) {
                jobs.retire_owned_job(job);
            }
        }
        Ok(status)
    }

}


pub(super) fn print_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

pub(super) fn report_native_failure(host: &mut impl RuntimeHost, context: &str, code: u32) {
    host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure, format!(
        "{context} failed with native Windows error {code}; guest operation failed",
    )));
}

pub(super) fn remember_error(first: &mut Option<RuntimeError>, error: RuntimeError) {
    if first.is_none() { *first = Some(error); }
}

pub(super) fn copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

pub(super) fn nul_terminated(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "WNet queue name contains an embedded NUL"));
    }
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len().saturating_add(1)).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted,
            "allocate WNet queue output string", error)
    })?;
    result.extend_from_slice(bytes);
    result.push(0);
    Ok(result)
}
