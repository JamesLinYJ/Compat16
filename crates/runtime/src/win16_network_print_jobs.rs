//! Task-owned Win16 WNet printer identities and queue-data projection.
//!
//! Win16 HFILE/job IDs are guest WORD values. They map to opaque host spool
//! tokens here; no Windows handle, pointer, or DWORD job ID enters guest RAM.

use std::collections::{HashMap, HashSet, VecDeque};
use std::mem::{align_of, offset_of, size_of};

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::win16_host_spool::{
    Win16HostNetworkPrintQueueSnapshot, Win16HostNetworkQueueWatch, Win16HostSpoolJob,
};
use crate::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16WindowOperationStartedFailure};
use win16_abi::network_print_abi::SP_QUEUECHANGED;
use win16_abi::{GlobalHandle, SelectorRef};
use super::window_post::WindowPostAttempt;

const NULL_JOB_ID: u16 = 0;
const INVALID_HFILE: u16 = u16::MAX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16NetworkPrintOpenJob {
    pub(crate) host_job: Win16HostSpoolJob,
    pub(crate) queue: Vec<u8>,
    pub(crate) normalized_queue_name: Option<Vec<u8>>,
    /// A reserved WORD ID exists before EndDocPrinter, so a successful native
    /// close cannot be followed by an unrepresentable guest identity.
    pub(crate) reserved_job_id: Option<u16>,
    /// Retain a completed native close until both guest outputs are committed.
    pub(crate) closed_queue_name: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Win16NetworkPrintQueueEvent {
    /// Guest alias and opaque host identity captured together when the watch
    /// was installed. A reused WORD HWND must never redirect a stale event.
    pub(crate) guest_window: u16,
    pub(crate) window: Win16HostWindow,
    pub(crate) index: u16,
    pub(crate) message: u16,
    pub(crate) watch: Win16HostNetworkQueueWatch,
    pub(crate) notification_source_id: u64,
    pub(crate) sequence: u64,
    pub(crate) post_attempt: Option<WindowPostAttempt>,
    pub(crate) started_failure: Option<std::sync::Arc<Win16WindowOperationStartedFailure>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuestPrintJob {
    host_job: Win16HostSpoolJob,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuestQueueWatch {
    guest_window: u16,
    window: Win16HostWindow,
    index: u16,
    queue: Vec<u8>,
    notification_source_id: u64,
    next_sequence: u64,
    /// Native publication was stopped but the watch identity is retained until
    /// a pending USER source is exactly acknowledged.
    native_unwatched: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16NetworkPrintQueueDataLease {
    pub(crate) queue: Vec<u8>,
    pub(crate) global_handle: u16,
    pub(crate) global_identity: GlobalHandle,
    /// Present only while the one runtime-owned GlobalLock is outstanding.
    pub(crate) selector: Option<SelectorRef>,
    pub(crate) locked: bool,
}

#[derive(Default)]
pub(crate) struct Win16NetworkPrintJobs {
    open_jobs: HashMap<u16, Win16NetworkPrintOpenJob>,
    reserved_hfiles: HashSet<u16>,
    guest_jobs: HashMap<u16, GuestPrintJob>,
    job_ids_by_host: HashMap<Win16HostSpoolJob, u16>,
    reserved_guest_job_ids: HashMap<u16, Win16HostSpoolJob>,
    /// Host tokens retained after an open failed but native cleanup did not.
    /// They are task-owned and never exposed through a guest HFILE.
    unexposed_host_jobs: Vec<Win16HostSpoolJob>,
    /// Moved cleanup batches returned by a host snapshot whose projection
    /// failed after opening some native job handles.
    unexposed_host_job_batches: Vec<Vec<Win16HostSpoolJob>>,
    watches: HashMap<Win16HostNetworkQueueWatch, GuestQueueWatch>,
    retired_windows: Vec<(u16, Win16HostWindow)>,
    queue_events: VecDeque<Win16NetworkPrintQueueEvent>,
    queue_data_leases: Vec<Win16NetworkPrintQueueDataLease>,
    queue_data_reservations: usize,
    watch_reservations: usize,
    next_job_id: u16,
}

impl Win16NetworkPrintJobs {
    pub(crate) fn needs_scheduler_progress(&self) -> bool {
        !self.is_empty()
    }

    /// Retain a host token under a HFILE already reserved by the task's
    /// shared HFILE allocator. Network jobs must share that namespace with
    /// ordinary Win16 files rather than inventing a parallel handle range.
    pub(crate) fn insert_open_job(
        &mut self,
        guest_hfile: u16,
        host_job: Win16HostSpoolJob,
        queue: Vec<u8>,
        normalized_queue_name: Option<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
        if guest_hfile == NULL_JOB_ID || guest_hfile == INVALID_HFILE {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 network print HFILE is outside the valid guest range",
            ));
        }
        if self.open_jobs.contains_key(&guest_hfile) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 network print HFILE was already assigned",
            ));
        }
        let pending_open_jobs = self.reserved_hfiles.len().checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 network print HFILE reservation count overflow",
            )
        })?;
        self.unexposed_host_jobs.try_reserve(pending_open_jobs).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WNet open-job cleanup token",
                error,
            )
        })?;
        self.open_jobs
            .try_reserve(pending_open_jobs)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate Win16 network print HFILE mapping",
                    error,
                )
            })?;
        self.open_jobs.insert(
            guest_hfile,
            Win16NetworkPrintOpenJob {
                host_job,
                queue,
                normalized_queue_name,
                reserved_job_id: None,
                closed_queue_name: None,
            },
        );
        self.reserved_hfiles.remove(&guest_hfile);
        Ok(())
    }

    pub(crate) fn open_job(&self, guest_hfile: u16) -> Option<&Win16NetworkPrintOpenJob> {
        self.open_jobs.get(&guest_hfile)
    }

    pub(crate) fn owns_hfile(&self, guest_hfile: u16) -> bool {
        self.open_jobs.contains_key(&guest_hfile) || self.reserved_hfiles.contains(&guest_hfile)
    }

    pub(crate) fn retain_unexposed_host_job(
        &mut self,
        host_job: Win16HostSpoolJob,
    ) -> Result<(), RuntimeError> {
        if self.open_jobs.values().any(|record| record.host_job == host_job)
            || self.guest_jobs.values().any(|record| record.host_job == host_job)
            || self.unexposed_host_jobs.contains(&host_job)
        {
            return Ok(());
        }
        self.unexposed_host_jobs.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "retain unexposed WNet spool cleanup token", error))?;
        self.unexposed_host_jobs.push(host_job);
        Ok(())
    }

    /// Reserve one guest HFILE before StartDocPrinter can create a native job.
    /// The ordinary HFILE allocator consults this set so callbacks during a
    /// host operation cannot hand the same WORD to another open call.
    pub(crate) fn reserve_hfile(&mut self, guest_hfile: u16) -> Result<bool, RuntimeError> {
        if guest_hfile == NULL_JOB_ID
            || guest_hfile == INVALID_HFILE
            || self.open_jobs.contains_key(&guest_hfile)
            || self.reserved_hfiles.contains(&guest_hfile)
        {
            return Ok(false);
        }
        self.reserved_hfiles.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 network print HFILE",
                error,
            )
        })?;
        let pending_open_jobs = self.reserved_hfiles.len().checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 network print HFILE reservation count overflow",
            )
        })?;
        self.open_jobs
            .try_reserve(pending_open_jobs)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 network print open-job mapping",
                    error,
                )
            })?;
        self.unexposed_host_jobs.try_reserve(pending_open_jobs).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve unexposed WNet open-job cleanup tokens",
                error,
            )
        })?;
        self.reserved_hfiles.insert(guest_hfile);
        Ok(true)
    }

    pub(crate) fn cancel_hfile_reservation(&mut self, guest_hfile: u16) -> bool {
        self.reserved_hfiles.remove(&guest_hfile)
    }

    /// Reserve a WORD job ID and all map capacity before EndDocPrinter. The
    /// open HFILE remains task-owned until output writes complete.
    pub(crate) fn reserve_close_job(
        &mut self,
        guest_hfile: u16,
    ) -> Result<(u16, Win16HostSpoolJob, Vec<u8>, Option<Vec<u8>>), RuntimeError> {
        let (host_job, reserved_job_id, queue, closed_queue_name) = {
            let record = self.open_jobs.get(&guest_hfile).ok_or_else(|| {
                RuntimeError::new(Kind::InvalidInput, "invalid Win16 network print HFILE")
            })?;
            let queue = copy_win16_bytes(
                record.normalized_queue_name.as_deref().unwrap_or(&record.queue),
                "copy WNetCloseJob queue name",
            )?;
            let closed_queue_name = record.closed_queue_name.as_deref()
                .map(|value| copy_win16_bytes(value, "copy retained WNetCloseJob queue name"))
                .transpose()?;
            (record.host_job, record.reserved_job_id, queue, closed_queue_name)
        };
        let guest_job_id = if let Some(id) = reserved_job_id {
            id
        } else {
            let pending_ids = self.reserved_guest_job_ids.len().checked_add(1).ok_or_else(||
                RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 WNetCloseJob reservation count overflow"))?;
            self.guest_jobs.try_reserve(pending_ids).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve Win16 WNetCloseJob guest IDs", error))?;
            self.job_ids_by_host.try_reserve(pending_ids).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve Win16 WNetCloseJob reverse mappings", error))?;
            self.reserved_guest_job_ids.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve Win16 WNetCloseJob ID owner", error))?;
            let id = match self.job_ids_by_host.get(&host_job).copied() {
                Some(existing) => existing,
                None => self.allocate_job_id()?,
            };
            self.reserved_guest_job_ids.insert(id, host_job);
            self.open_jobs.get_mut(&guest_hfile).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "WNetCloseJob HFILE disappeared during ID reservation"))?
                .reserved_job_id = Some(id);
            id
        };
        Ok((guest_job_id, host_job, queue, closed_queue_name))
    }

    pub(crate) fn retain_closed_job(
        &mut self,
        guest_hfile: u16,
        guest_job_id: u16,
        queue_name: Vec<u8>,
    ) -> Result<(), RuntimeError> {
        let record = self.open_jobs.get_mut(&guest_hfile).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "completed WNetCloseJob lost its HFILE owner"))?;
        if record.reserved_job_id != Some(guest_job_id)
            || self.reserved_guest_job_ids.get(&guest_job_id) != Some(&record.host_job)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "completed WNetCloseJob changed its reserved guest ID"));
        }
        record.closed_queue_name = Some(queue_name);
        Ok(())
    }

    pub(crate) fn complete_close_job(
        &mut self,
        guest_hfile: u16,
        guest_job_id: u16,
    ) -> Result<(), RuntimeError> {
        let (host_job, reserved_job_id, is_closed) = {
            let record = self.open_jobs.get(&guest_hfile).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "WNetCloseJob HFILE disappeared before output commit"))?;
            (record.host_job, record.reserved_job_id, record.closed_queue_name.is_some())
        };
        if reserved_job_id != Some(guest_job_id) || !is_closed {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WNetCloseJob output commit changed its retained close identity"));
        }
        if self.reserved_guest_job_ids.get(&guest_job_id) == Some(&host_job) {
            self.reserved_guest_job_ids.remove(&guest_job_id);
            self.guest_jobs.insert(guest_job_id, GuestPrintJob { host_job });
            self.job_ids_by_host.insert(host_job, guest_job_id);
        } else if self.guest_jobs.get(&guest_job_id).is_none_or(|guest|
            guest.host_job != host_job)
            || self.job_ids_by_host.get(&host_job) != Some(&guest_job_id)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WNetCloseJob retry lost its committed guest job ID"));
        }
        // Keep the HFILE record so common _lclose/INT 21h close can release
        // its alias while the returned job ID continues to own the host token.
        Ok(())
    }

    pub(crate) fn cancel_close_reservation(&mut self, guest_hfile: u16, guest_job_id: u16) {
        if let Some(record) = self.open_jobs.get_mut(&guest_hfile)
            && record.reserved_job_id == Some(guest_job_id)
            && record.closed_queue_name.is_none()
        {
            self.reserved_guest_job_ids.remove(&guest_job_id);
            record.reserved_job_id = None;
        }
    }

    pub(crate) fn retire_open_job(&mut self, guest_hfile: u16) -> Option<Win16HostSpoolJob> {
        let record = self.open_jobs.remove(&guest_hfile)?;
        if let Some(id) = record.reserved_job_id {
            self.reserved_guest_job_ids.remove(&id);
        }
        Some(record.host_job)
    }

    pub(crate) fn host_job_for_id(&self, guest_job_id: u16) -> Option<Win16HostSpoolJob> {
        self.guest_jobs
            .get(&guest_job_id)
            .map(|record| record.host_job)
    }

    pub(crate) fn guest_job_id_for_host(&self, host_job: Win16HostSpoolJob) -> Option<u16> {
        self.job_ids_by_host.get(&host_job).copied()
    }

    pub(crate) fn retire_guest_job(&mut self, guest_job_id: u16) -> Option<Win16HostSpoolJob> {
        let record = self.guest_jobs.remove(&guest_job_id)?;
        self.job_ids_by_host.remove(&record.host_job);
        self.reserved_guest_job_ids.remove(&guest_job_id);
        Some(record.host_job)
    }

    pub(crate) fn guest_job_id_for(
        &mut self,
        host_job: Win16HostSpoolJob,
    ) -> Result<u16, RuntimeError> {
        if let Some(guest_job_id) = self.job_ids_by_host.get(&host_job) {
            return Ok(*guest_job_id);
        }
        self.guest_jobs.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 network print job ID",
                error,
            )
        })?;
        self.job_ids_by_host.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 network print reverse mapping",
                error,
            )
        })?;
        let guest_job_id = self.allocate_job_id()?;
        self.guest_jobs
            .insert(guest_job_id, GuestPrintJob { host_job });
        self.job_ids_by_host.insert(host_job, guest_job_id);
        Ok(guest_job_id)
    }

    pub(crate) fn insert_watch(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        notification_source_id: u64,
        guest_window: u16,
        window: Win16HostWindow,
        queue: Vec<u8>,
        index: u16,
    ) -> Result<(), RuntimeError> {
        if self.watches.contains_key(&watch) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 network printer watch token was already assigned",
            ));
        }
        self.watches.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 network printer watch",
                error,
            )
        })?;
        self.watches.insert(
            watch,
            GuestQueueWatch {
                guest_window,
                window,
                index,
                queue,
                notification_source_id,
                next_sequence: 1,
                native_unwatched: false,
            },
        );
        self.watch_reservations = self.watch_reservations.saturating_sub(1);
        Ok(())
    }

    /// Reserve runtime storage before asking the host to create a native
    /// printer notification. A started native watch must never become
    /// untracked because the guest-side map could not grow afterward.
    pub(crate) fn reserve_watch_slot(&mut self) -> Result<(), RuntimeError> {
        let additional = self.watch_reservations.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 printer-watch reservation count overflow",
            )
        })?;
        self.watches.try_reserve(additional).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 network printer watch mapping",
                error,
            )
        })?;
        self.watch_reservations = additional;
        Ok(())
    }

    pub(crate) fn cancel_watch_slot_reservation(&mut self) -> bool {
        if self.watch_reservations == 0 {
            return false;
        }
        self.watch_reservations -= 1;
        true
    }

    pub(crate) fn matching_watches_for_queue(
        &self,
        queue: &[u8],
    ) -> Result<Vec<Win16HostNetworkQueueWatch>, RuntimeError> {
        self.matching_watches(|record| !record.native_unwatched && queue_name_eq(&record.queue, queue))
    }

    pub(crate) fn matching_watches_for_window(
        &self,
        guest_window: u16,
        window: Win16HostWindow,
    ) -> Result<Vec<Win16HostNetworkQueueWatch>, RuntimeError> {
        self.matching_watches(|record| {
            !record.native_unwatched
                && record.guest_window == guest_window && record.window == window
        })
    }

    pub(crate) fn watches_for_cleanup(
        &self,
    ) -> Result<Vec<Win16HostNetworkQueueWatch>, RuntimeError> {
        self.matching_watches(|_| true)
    }

    pub(crate) fn watches_for_producer_quiescence(
        &self,
    ) -> Result<Vec<Win16HostNetworkQueueWatch>, RuntimeError> {
        self.matching_watches(|record| !record.native_unwatched)
    }

    pub(crate) fn watch_window(
        &self,
        watch: Win16HostNetworkQueueWatch,
    ) -> Option<(u16, Win16HostWindow)> {
        self.watches
            .get(&watch)
            .map(|record| (record.guest_window, record.window))
    }

    pub(crate) fn watch_exists(&self, watch: Win16HostNetworkQueueWatch) -> bool {
        self.watches.contains_key(&watch)
    }

    pub(crate) fn has_watches(&self) -> bool {
        self.watches.values().any(|record| !record.native_unwatched)
    }

    pub(crate) fn watch_native_unwatched(&self, watch: Win16HostNetworkQueueWatch) -> bool {
        self.watches.get(&watch).is_some_and(|record| record.native_unwatched)
    }

    pub(crate) fn mark_watch_native_unwatched(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
    ) -> bool {
        let Some(record) = self.watches.get_mut(&watch) else { return false; };
        record.native_unwatched = true;
        true
    }

    pub(crate) fn record_retired_window(
        &mut self,
        guest_window: u16,
        window: Win16HostWindow,
    ) -> Result<(), RuntimeError> {
        if !self.watches.values().any(|record| {
            !record.native_unwatched && record.guest_window == guest_window && record.window == window
        }) || self.retired_windows.contains(&(guest_window, window)) {
            return Ok(());
        }
        self.retired_windows.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "retain retired HWND for WNet watch cleanup", error,
        ))?;
        self.retired_windows.push((guest_window, window));
        Ok(())
    }

    pub(crate) fn retired_windows_for_cleanup(
        &self,
    ) -> Result<Vec<(u16, Win16HostWindow)>, RuntimeError> {
        let mut pending = Vec::new();
        pending.try_reserve_exact(self.retired_windows.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "copy pending WNet retired HWND cleanup identities", error,
        ))?;
        pending.extend_from_slice(&self.retired_windows);
        Ok(pending)
    }

    pub(crate) fn retire_window_cleanup_marker(
        &mut self,
        guest_window: u16,
        window: Win16HostWindow,
    ) -> bool {
        let Some(index) = self.retired_windows.iter()
            .position(|item| *item == (guest_window, window)) else { return false; };
        self.retired_windows.remove(index);
        true
    }

    /// Retire only the exact watch whose native Unwatch succeeded. Pending
    /// queue notifications for the same watch are removed with its owner.
    pub(crate) fn retire_watch(&mut self, watch: Win16HostNetworkQueueWatch) -> bool {
        if self.watches.remove(&watch).is_none() {
            return false;
        }
        // An entered failed POST is a source owner in the shared USER ledger.
        // Keep its exact failure identity after the native watch is released.
        self.queue_events.retain(|event| {
            event.watch != watch || event.started_failure.is_some()
        });
        true
    }

    fn matching_watches(
        &self,
        mut matches: impl FnMut(&GuestQueueWatch) -> bool,
    ) -> Result<Vec<Win16HostNetworkQueueWatch>, RuntimeError> {
        let count = self
            .watches
            .values()
            .filter(|record| matches(record))
            .count();
        let mut matching = Vec::new();
        matching.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 printer-watch cleanup list",
                error,
            )
        })?;
        for (watch, record) in &self.watches {
            if matches(record) {
                matching.push(*watch);
            }
        }
        Ok(matching)
    }

    /// Publish each native watch at most once until the caller acknowledges
    /// its queued event. The caller still validates HWND generation and posts
    /// the Win16 message through the normal USER queue path.
    pub(crate) fn publish_queue_changes(
        &mut self,
        changed: impl IntoIterator<Item = Win16HostNetworkQueueWatch>,
    ) -> Result<(), RuntimeError> {
        for watch in changed {
            let Some(record) = self.watches.get(&watch) else {
                continue;
            };
            if record.native_unwatched { continue; }
            if self.queue_events.iter().any(|event| event.watch == watch) {
                continue;
            }
            self.queue_events.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "queue Win16 network printer change event",
                    error,
                )
            })?;
            self.queue_events.push_back(Win16NetworkPrintQueueEvent {
                guest_window: record.guest_window,
                window: record.window,
                index: record.index,
                message: SP_QUEUECHANGED,
                watch,
                notification_source_id: record.notification_source_id,
                sequence: record.next_sequence,
                post_attempt: None,
                started_failure: None,
            });
        }
        Ok(())
    }

    pub(crate) fn peek_queue_event(&self) -> Option<Win16NetworkPrintQueueEvent> {
        self.queue_events.front().cloned()
    }

    pub(crate) fn queue_event_for_watch(
        &self,
        watch: Win16HostNetworkQueueWatch,
    ) -> Option<Win16NetworkPrintQueueEvent> {
        self.queue_events.iter().find(|event| event.watch == watch).cloned()
    }

    pub(crate) fn started_failure_for_terminal_source(
        &self,
        operation: crate::Win16HostWindowOperationId,
        kind: crate::Win16NativeWindowOperationKind,
        state: crate::Win16NativeWindowOperationState,
        worker_generation: u64,
    ) -> Result<Option<(Win16HostNetworkQueueWatch, u64, std::sync::Arc<Win16WindowOperationStartedFailure>)>, RuntimeError> {
        let mut matching = None;
        for event in &self.queue_events {
            let Some(failure) = event.started_failure.as_ref() else { continue; };
            if failure.operation.operation_id != operation || failure.operation.kind != kind
                || failure.state != state || failure.worker_generation != worker_generation
            { continue; }
            if matching.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "one USER terminal POST source is retained by multiple WNet queue events"));
            }
            matching = Some((event.watch, event.sequence, std::sync::Arc::clone(failure)));
        }
        Ok(matching)
    }

    pub(crate) fn acknowledge_started_failure(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
        failure: &std::sync::Arc<Win16WindowOperationStartedFailure>,
    ) -> Result<bool, RuntimeError> {
        let Some(index) = self.queue_events.iter().position(|event| {
            event.watch == watch && event.sequence == sequence
        }) else { return Ok(false); };
        if !self.queue_events[index].started_failure.as_ref()
            .is_some_and(|retained| std::sync::Arc::ptr_eq(retained, failure))
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WNet terminal ACK changed its exact retained POST failure"));
        }
        let next = sequence.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 printer queue notification sequence is exhausted"))?;
        self.queue_events.remove(index);
        if let Some(record) = self.watches.get_mut(&watch) { record.next_sequence = next; }
        Ok(true)
    }

    pub(crate) fn queue_event(
        &self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
    ) -> Option<Win16NetworkPrintQueueEvent> {
        self.queue_events.iter().find(|event| event.watch == watch && event.sequence == sequence).cloned()
    }

    pub(crate) fn queue_events_for_update(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
    ) -> Option<&mut Win16NetworkPrintQueueEvent> {
        self.queue_events.iter_mut().find(|event| event.watch == watch && event.sequence == sequence)
    }

    pub(crate) fn retain_queue_post_attempt(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
        attempt: WindowPostAttempt,
    ) -> bool {
        let Some(event) = self.queue_events.iter_mut()
            .find(|event| event.watch == watch && event.sequence == sequence) else { return false; };
        if event.post_attempt.is_some() || event.started_failure.is_some() { return false; }
        event.post_attempt = Some(attempt);
        true
    }

    pub(crate) fn retain_queue_post_failure(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
        failure: std::sync::Arc<Win16WindowOperationStartedFailure>,
    ) -> bool {
        let Some(event) = self.queue_events.iter_mut()
            .find(|event| event.watch == watch && event.sequence == sequence) else { return false; };
        if event.post_attempt.is_some() || event.started_failure.is_some() { return false; }
        event.started_failure = Some(failure);
        true
    }

    pub(crate) fn acknowledge_queue_event(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
    ) -> Result<bool, RuntimeError> {
        let Some(index) = self.queue_events.iter()
            .position(|event| event.watch == watch && event.sequence == sequence) else { return Ok(false); };
        let next = sequence.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 printer queue notification sequence is exhausted"))?;
        self.queue_events.remove(index);
        if let Some(record) = self.watches.get_mut(&watch) { record.next_sequence = next; }
        Ok(true)
    }

    pub(crate) fn discard_unposted_queue_event(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
    ) {
        self.queue_events.retain(|event| {
            event.watch != watch
                || event.post_attempt.is_some()
                || event.started_failure.is_some()
        });
    }

    /// A consumed FALSE PostMessage result did not deliver the event. Keep the
    /// same queue change and advance only its stable source sequence.
    pub(crate) fn retry_queue_event_after_rejection(
        &mut self,
        watch: Win16HostNetworkQueueWatch,
        sequence: u64,
    ) -> Result<bool, RuntimeError> {
        let Some(event) = self.queue_events.iter_mut()
            .find(|event| event.watch == watch && event.sequence == sequence) else { return Ok(false); };
        if event.post_attempt.as_ref().is_none_or(|attempt|
            !super::window_post::window_post_attempt_consumed(attempt)
                || super::window_post::window_post_attempt_result(attempt) != Some(false))
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WNet queue retry lacks its exact consumed FALSE post proof"));
        }
        let next = sequence.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 printer queue notification sequence is exhausted"))?;
        event.sequence = next;
        event.post_attempt = None;
        if let Some(record) = self.watches.get_mut(&watch) { record.next_sequence = next; }
        Ok(true)
    }

    pub(crate) fn reserve_queue_event_capacity(&mut self) -> Result<(), RuntimeError> {
        let needed = self.watches.len().saturating_sub(self.queue_events.len());
        self.queue_events.try_reserve(needed).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 printer notification ledger", error))
    }

    pub(crate) fn reserve_queue_data_lease(&mut self) -> Result<(), RuntimeError> {
        let additional = self.queue_data_reservations.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 queue-data lease reservation count overflow",
            )
        })?;
        self.queue_data_leases
            .try_reserve(additional)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 network queue-data lease",
                    error,
                )
            })?;
        self.unexposed_host_job_batches.try_reserve(additional).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve partial queue-snapshot cleanup batch",
                error,
            )
        })?;
        self.queue_data_reservations = additional;
        Ok(())
    }

    pub(crate) fn retain_unexposed_host_job_batch(
        &mut self,
        jobs: Vec<Win16HostSpoolJob>,
    ) -> Result<(), RuntimeError> {
        if jobs.is_empty() { return Ok(()); }
        if self.unexposed_host_job_batches.len() == self.unexposed_host_job_batches.capacity() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "partial queue snapshot cleanup was not pre-reserved",
            ));
        }
        self.unexposed_host_job_batches.push(jobs);
        Ok(())
    }

    pub(crate) fn cancel_queue_data_lease_reservation(&mut self) -> bool {
        if self.queue_data_reservations == 0 {
            return false;
        }
        self.queue_data_reservations -= 1;
        true
    }

    pub(crate) fn insert_queue_data_lease(
        &mut self,
        lease: Win16NetworkPrintQueueDataLease,
    ) -> Result<(), RuntimeError> {
        if self.queue_data_reservations == 0 {
            self.reserve_queue_data_lease()?;
        }
        self.queue_data_reservations -= 1;
        self.queue_data_leases.push(lease);
        Ok(())
    }

    pub(crate) fn queue_data_lease_for(&self, queue: &[u8]) -> Option<&Win16NetworkPrintQueueDataLease> {
        self.queue_data_leases.iter().find(|lease| queue_name_eq(&lease.queue, queue))
    }

    pub(crate) fn queue_data_lease_for_mut(&mut self, queue: &[u8]) -> Option<&mut Win16NetworkPrintQueueDataLease> {
        self.queue_data_leases.iter_mut().find(|lease| queue_name_eq(&lease.queue, queue))
    }

    pub(crate) fn queue_data_lease_for_handle_mut(
        &mut self,
        handle: u16,
    ) -> Option<&mut Win16NetworkPrintQueueDataLease> {
        self.queue_data_leases.iter_mut().find(|lease| lease.global_handle == handle)
    }

    pub(crate) fn queue_data_handle_for(&self, queue: &[u8]) -> Option<u16> {
        self.queue_data_leases
            .iter()
            .find(|lease| queue_name_eq(&lease.queue, queue))
            .map(|lease| lease.global_handle)
    }

    pub(crate) fn retire_queue_data_lease(&mut self, queue: &[u8], global_handle: u16) -> bool {
        let Some(index) = self.queue_data_leases.iter().position(|lease| {
            lease.global_handle == global_handle && queue_name_eq(&lease.queue, queue)
        }) else {
            return false;
        };
        self.queue_data_leases.remove(index);
        true
    }

    /// Retire the exact HGLOBAL lease allocated by the current WNet call.
    /// This path is used when GlobalLock fails before a caller can retain the
    /// queue key for a later retry.
    pub(crate) fn retire_queue_data_lease_by_handle(&mut self, global_handle: u16) -> bool {
        let Some(index) = self.queue_data_leases.iter()
            .position(|lease| lease.global_handle == global_handle) else { return false; };
        self.queue_data_leases.remove(index);
        true
    }

    pub(crate) fn queue_data_leases_for_cleanup(
        &self,
    ) -> Result<Vec<Win16NetworkPrintQueueDataLease>, RuntimeError> {
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(self.queue_data_leases.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate Win16 task queue-data cleanup list",
                    error,
                )
            })?;
        for lease in &self.queue_data_leases {
            let mut queue = Vec::new();
            queue
                .try_reserve_exact(lease.queue.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "copy Win16 task queue-data cleanup identity",
                        error,
                    )
                })?;
            queue.extend_from_slice(&lease.queue);
            leases.push(Win16NetworkPrintQueueDataLease {
                queue,
                global_handle: lease.global_handle,
                global_identity: lease.global_identity,
                selector: lease.selector,
                locked: lease.locked,
            });
        }
        Ok(leases)
    }

    pub(crate) fn retire_owned_job(&mut self, host_job: Win16HostSpoolJob) -> bool {
        let before = self.open_jobs.len() + self.guest_jobs.len() + self.unexposed_host_jobs.len()
            + self.unexposed_host_job_batches.iter().map(Vec::len).sum::<usize>();
        self.open_jobs.retain(|_, record| record.host_job != host_job);
        self.unexposed_host_jobs.retain(|record| *record != host_job);
        for batch in &mut self.unexposed_host_job_batches {
            batch.retain(|record| *record != host_job);
        }
        self.unexposed_host_job_batches.retain(|batch| !batch.is_empty());
        self.reserved_guest_job_ids.retain(|_, reserved| *reserved != host_job);
        if let Some(job_id) = self.job_ids_by_host.get(&host_job).copied() {
            let _ = self.retire_guest_job(job_id);
        }
        self.open_jobs.len() + self.guest_jobs.len() + self.unexposed_host_jobs.len()
            + self.unexposed_host_job_batches.iter().map(Vec::len).sum::<usize>() != before
    }

    /// The host's owner-scoped release operation succeeded for every native
    /// WNet lease. It is now safe to discard runtime aliases as a batch.
    pub(crate) fn retire_all_owned_jobs(&mut self) {
        self.open_jobs.clear();
        self.guest_jobs.clear();
        self.job_ids_by_host.clear();
        self.reserved_guest_job_ids.clear();
        self.unexposed_host_jobs.clear();
        self.unexposed_host_job_batches.clear();
    }

    /// Drop only in-flight reservations after the task has stopped executing.
    /// Native jobs, watches and HGLOBAL leases remain owned until their host
    /// release succeeds and their ordinary records are retired.
    pub(crate) fn retire_task_reservations(&mut self) {
        self.reserved_hfiles.clear();
        self.reserved_guest_job_ids.clear();
        for record in self.open_jobs.values_mut() {
            record.reserved_job_id = None;
        }
        self.queue_data_reservations = 0;
        self.watch_reservations = 0;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.open_jobs.is_empty()
            && self.reserved_hfiles.is_empty()
            && self.guest_jobs.is_empty()
            && self.reserved_guest_job_ids.is_empty()
            && self.unexposed_host_jobs.is_empty()
            && self.unexposed_host_job_batches.is_empty()
            && self.watches.is_empty()
            && self.retired_windows.is_empty()
            && self.queue_events.is_empty()
            && self.queue_data_leases.is_empty()
            && self.queue_data_reservations == 0
            && self.watch_reservations == 0
    }

    fn allocate_job_id(&mut self) -> Result<u16, RuntimeError> {
        let first = if self.next_job_id == NULL_JOB_ID || self.next_job_id == INVALID_HFILE {
            1
        } else {
            self.next_job_id
        };
        let mut candidate = first;
        loop {
            if !self.guest_jobs.contains_key(&candidate)
                && !self.reserved_guest_job_ids.contains_key(&candidate)
            {
                self.next_job_id = candidate.wrapping_add(1);
                if self.next_job_id == NULL_JOB_ID || self.next_job_id == INVALID_HFILE {
                    self.next_job_id = 1;
                }
                return Ok(candidate);
            }
            candidate = candidate.wrapping_add(1);
            if candidate == NULL_JOB_ID || candidate == INVALID_HFILE {
                candidate = 1;
            }
            if candidate == first {
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 network print job ID space is exhausted",
                ));
            }
        }
    }
}

fn queue_name_eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

/// Owned, task-local version of the 3.1 QUEUESTRUCT/JOBSTRUCT block. Its byte
/// representation uses the SDK's packed little-endian offsets; selector
/// allocation and guest output validation remain with the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16GuestNetworkPrintQueueData {
    pub(crate) name: Vec<u8>,
    pub(crate) comment: Option<Vec<u8>>,
    pub(crate) status: u16,
    pub(crate) printer_count: u16,
    pub(crate) jobs: Vec<Win16GuestNetworkPrintJobData>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16GuestNetworkPrintJobData {
    pub(crate) job_id: u16,
    pub(crate) username: Option<Vec<u8>>,
    pub(crate) parameters: Option<Vec<u8>>,
    pub(crate) position: u16,
    pub(crate) status: u16,
    pub(crate) submitted: u32,
    pub(crate) size: u32,
    pub(crate) copies: u16,
    pub(crate) comment: Option<Vec<u8>>,
}

impl Win16GuestNetworkPrintQueueData {
    pub(crate) fn from_host(
        state: &mut Win16NetworkPrintJobs,
        snapshot: Win16HostNetworkPrintQueueSnapshot,
    ) -> Result<Self, RuntimeError> {
        // The host has already opened native printer handles for these job
        // tokens. Retain every token before any guest-ID or buffer allocation
        // can fail; successful projection transfers them to the guest-job map.
        state.unexposed_host_jobs.try_reserve(snapshot.jobs.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve queue snapshot job cleanup identities",
                error,
            )
        })?;
        for job in &snapshot.jobs {
            let token = job.job;
            if !state.open_jobs.values().any(|record| record.host_job == token)
                && !state.guest_jobs.values().any(|record| record.host_job == token)
                && !state.unexposed_host_jobs.contains(&token)
            {
                state.unexposed_host_jobs.push(token);
            }
        }
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(snapshot.jobs.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate Win16 network queue job records",
                    error,
                )
            })?;
        for job in snapshot.jobs {
            jobs.push(Win16GuestNetworkPrintJobData {
                job_id: state.guest_job_id_for(job.job)?,
                username: job.username,
                parameters: job.parameters,
                position: job.position,
                status: job.status,
                submitted: job.submitted,
                size: job.size,
                copies: job.copies,
                comment: job.comment,
            });
        }
        let mapped_tokens = &state.job_ids_by_host;
        state.unexposed_host_jobs.retain(|token| !mapped_tokens.contains_key(token));
        Ok(Self {
            name: snapshot.name,
            comment: snapshot.comment,
            status: snapshot.status,
            printer_count: snapshot.printer_count,
            jobs,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, RuntimeError> {
        let job_count = u16::try_from(self.jobs.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 network queue has more jobs than QUEUESTRUCT can represent",
                error,
            )
        })?;
        let records_size = self
            .jobs
            .len()
            .checked_mul(size_of::<JobStruct16>())
            .and_then(|size| size.checked_add(size_of::<QueueStruct16>()))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 network queue structure size overflow",
                )
            })?;
        if records_size > usize::from(u16::MAX) {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 network queue records exceed the 16-bit selector offset range",
            ));
        }
        let mut output = Vec::new();
        output.try_reserve_exact(records_size).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 network queue data",
                error,
            )
        })?;
        output.resize(records_size, 0);

        let name = append_string(&mut output, &self.name)?;
        let comment = append_optional_string(&mut output, self.comment.as_deref())?;
        let header = QueueStruct16 {
            name: U16::new(name),
            comment: U16::new(comment),
            status: U16::new(self.status),
            job_count: U16::new(job_count),
            printer_count: U16::new(self.printer_count),
        };
        output[..size_of::<QueueStruct16>()].copy_from_slice(header.as_bytes());

        for (index, job) in self.jobs.iter().enumerate() {
            let user = append_optional_string(&mut output, job.username.as_deref())?;
            let parameters = append_optional_string(&mut output, job.parameters.as_deref())?;
            let comment = append_optional_string(&mut output, job.comment.as_deref())?;
            let wire = JobStruct16 {
                id: U16::new(job.job_id),
                username: U16::new(user),
                parameters: U16::new(parameters),
                position: U16::new(job.position),
                status: U16::new(job.status),
                submitted: U32::new(job.submitted),
                size: U32::new(job.size),
                copies: U16::new(job.copies),
                comment: U16::new(comment),
            };
            let start = size_of::<QueueStruct16>() + index * size_of::<JobStruct16>();
            output[start..start + size_of::<JobStruct16>()].copy_from_slice(wire.as_bytes());
        }
        Ok(output)
    }
}

fn append_optional_string(output: &mut Vec<u8>, value: Option<&[u8]>) -> Result<u16, RuntimeError> {
    match value {
        Some(value) => append_string(output, value),
        None => Ok(0),
    }
}

fn append_string(output: &mut Vec<u8>, value: &[u8]) -> Result<u16, RuntimeError> {
    if value.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 network queue string contains an embedded NUL",
        ));
    }
    let offset = u16::try_from(output.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "Win16 network queue string offset exceeds the SDK WORD field",
            error,
        )
    })?;
    let required = value.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 network queue string size overflow",
        )
    })?;
    if output
        .len()
        .checked_add(required)
        .is_none_or(|length| length > usize::from(u16::MAX) + 1)
    {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 network queue block exceeds the largest representable offset range",
        ));
    }
    output.try_reserve(required).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 network queue string",
            error,
        )
    })?;
    output.extend_from_slice(value);
    output.push(0);
    Ok(offset)
}

fn copy_win16_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, context, error,
    ))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct QueueStruct16 {
    name: U16,
    comment: U16,
    status: U16,
    job_count: U16,
    printer_count: U16,
}

#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct JobStruct16 {
    id: U16,
    username: U16,
    parameters: U16,
    position: U16,
    status: U16,
    submitted: U32,
    size: U32,
    copies: U16,
    comment: U16,
}

const _: () = {
    assert!(size_of::<QueueStruct16>() == 10);
    assert!(align_of::<QueueStruct16>() == 1);
    assert!(offset_of!(QueueStruct16, name) == 0);
    assert!(offset_of!(QueueStruct16, comment) == 2);
    assert!(offset_of!(QueueStruct16, status) == 4);
    assert!(offset_of!(QueueStruct16, job_count) == 6);
    assert!(offset_of!(QueueStruct16, printer_count) == 8);
    assert!(size_of::<JobStruct16>() == 22);
    assert!(align_of::<JobStruct16>() == 1);
    assert!(offset_of!(JobStruct16, id) == 0);
    assert!(offset_of!(JobStruct16, username) == 2);
    assert!(offset_of!(JobStruct16, parameters) == 4);
    assert!(offset_of!(JobStruct16, position) == 6);
    assert!(offset_of!(JobStruct16, status) == 8);
    assert!(offset_of!(JobStruct16, submitted) == 10);
    assert!(offset_of!(JobStruct16, size) == 14);
    assert!(offset_of!(JobStruct16, copies) == 18);
    assert!(offset_of!(JobStruct16, comment) == 20);
};
