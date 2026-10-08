//! Guest queue-data HGLOBAL projection and selector-generation leases.

use guest_core::{memory::Memory, OwnerId, Selector};
use win16_abi::global::{GMEM_MOVEABLE, GMEM_LOCKCOUNT_MASK, GMEM_ZEROINIT};
use win16_abi::SelectorRef;

use super::Win16State;
use super::network_print_api::print_invariant;
use win16_abi::network_print_abi::{
    WN_ALREADY_LOCKED, WN_BAD_POINTER, WN_BAD_QUEUE, WN_FUNCTION_BUSY, WN_NET_ERROR,
    WN_OUT_OF_MEMORY, WN_SUCCESS,
};
use super::network_print_cleanup;
use super::network_print_completion as completion;
use super::network_print_jobs::{
    Win16GuestNetworkPrintQueueData,
    Win16NetworkPrintQueueDataLease,
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostNetworkQueueOperation, Win16HostNetworkQueueResult,
};

impl Win16State {
    pub(super) fn lock_network_print_queue(
        &mut self,
        owner: OwnerId,
        operation: Win16HostNetworkQueueOperation,
        queue: Vec<u8>,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let output = match self.prepare_network_print_output(memory, output_far, 4) {
            Ok(output) => output,
            Err(error) if error.kind() == Kind::GuestFault => return Ok(WN_BAD_POINTER),
            Err(error) => return Err(error),
        };
        let jobs = self.network_print_jobs.entry(owner).or_default();
        if jobs.queue_data_handle_for(&queue).is_some() { return Ok(WN_ALREADY_LOCKED); }
        jobs.reserve_queue_data_lease()?;
        let result = match host.win16_network_print_queues(operation) {
            Ok(result) => result,
            Err(error) => {
                self.network_print_jobs.get_mut(&owner).expect("queue lease reservation").cancel_queue_data_lease_reservation();
                return Err(error);
            }
        };
        let snapshot = match result {
            Win16HostNetworkQueueResult::Snapshot {
                snapshot,
                native_error,
                cleanup_jobs,
                diagnostic,
            } => {
                if let Some(diagnostic) = diagnostic {
                    host.report_diagnostic(&Diagnostic::warning(
                        diagnostic.kind,
                        format!("WNetLockQueueData host cleanup: {}", diagnostic.message),
                    ));
                }
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("queue lease reservation owner disappeared"))?
                    .retain_unexposed_host_job_batch(cleanup_jobs)?;
                if let Some(snapshot) = snapshot {
                    snapshot
                } else {
                    self.network_print_jobs.get_mut(&owner)
                        .ok_or_else(|| print_invariant("queue lease reservation owner disappeared"))?
                        .cancel_queue_data_lease_reservation();
                    return Ok(native_error.map_or(WN_NET_ERROR, completion::map_native_error));
                }
            }
            other => {
                self.network_print_jobs.get_mut(&owner).expect("queue lease reservation").cancel_queue_data_lease_reservation();
                return Ok(completion::queue_status(other)?);
            }
        };
        let projection = (|| {
            let data = Win16GuestNetworkPrintQueueData::from_host(
                self.network_print_jobs.get_mut(&owner).ok_or_else(||
                    print_invariant("queue lease reservation owner disappeared"))?, snapshot,
            )?;
            let bytes = data.encode()?;
            let size = u32::try_from(bytes.len()).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "Win16 queue-data size exceeds GlobalAlloc ABI", error))?;
            Ok::<_, RuntimeError>((bytes, size))
        })();
        let (bytes, size) = match projection {
            Ok(value) => value,
            Err(error) => {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("queue lease reservation owner disappeared"))?
                    .cancel_queue_data_lease_reservation();
                return Err(error);
            }
        };
        let handle = match self.global_alloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size, memory, host) {
            Ok(handle) => handle,
            Err(error) => {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("queue lease reservation owner disappeared"))?
                    .cancel_queue_data_lease_reservation();
                return Err(error);
            }
        };
        if handle == 0 {
            self.network_print_jobs.get_mut(&owner).expect("queue lease reservation").cancel_queue_data_lease_reservation();
            return Ok(WN_OUT_OF_MEMORY);
        }
        let Some(identity) = self.global_handles.get(&handle).copied() else {
            let freed = self.global_free(handle)? == 0;
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet queue lease reservation owner disappeared"))?
                .cancel_queue_data_lease_reservation();
            return Err(RuntimeError::new(Kind::InternalInvariant, format!(
                "GlobalAlloc omitted the WNet queue HGLOBAL identity (cleanup freed={freed})",
            )));
        };
        self.network_print_jobs.get_mut(&owner).expect("queue lease reservation")
            .insert_queue_data_lease(Win16NetworkPrintQueueDataLease {
                queue,
                global_handle: handle,
                global_identity: identity,
                selector: None,
                locked: false,
            })?;
        let far = self.global_lock(handle, memory)?;
        if far == 0 {
            if self.global_free(handle)? == 0 {
                self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet queue lease owner disappeared after failed GlobalLock"))?
                    .retire_queue_data_lease_by_handle(handle);
                self.drop_empty_network_print_owner(owner);
            }
            return Ok(WN_OUT_OF_MEMORY);
        }
        self.mark_queue_data_global_locked(owner, handle)?;
        let selector = self.selectors.reference(Selector((far >> 16) as u16)
            ).map_err(crate::runtime_error)?;
        self.set_queue_data_lock(owner, handle, selector)?;
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.write_text_bytes(memory, pointer, &bytes)?;
        output.commit(memory, &far.to_le_bytes())?;
        Ok(WN_SUCCESS)
    }

    pub(super) fn unlock_network_print_queue(
        &mut self,
        owner: OwnerId,
        queue: &[u8],
        handle: Option<u16>,
        _host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(handle) = handle else { return Ok(WN_BAD_QUEUE); };
        let lease = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.queue_data_lease_for(queue)).cloned()
            .ok_or_else(|| print_invariant("WNetUnlockQueueData lost its exact lease"))?;
        self.validate_queue_data_lease(&lease)?;
        if lease.locked {
            let _ = self.global_unlock(handle)?;
            if let Some(current) = self.network_print_jobs.get_mut(&owner)
                .and_then(|jobs| jobs.queue_data_lease_for_mut(queue))
            {
                current.locked = false;
                current.selector = None;
            }
            if self.kernel_global_flags(handle) & u32::from(GMEM_LOCKCOUNT_MASK) != 0 {
                return Ok(WN_FUNCTION_BUSY);
            }
        }
        let freed = self.global_free(handle)? == 0;
        if freed {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet queue lease owner disappeared"))?
                .retire_queue_data_lease(queue, handle);
            self.drop_empty_network_print_owner(owner);
            Ok(WN_SUCCESS)
        } else {
            Ok(WN_FUNCTION_BUSY)
        }
    }

    fn mark_queue_data_global_locked(
        &mut self,
        owner: OwnerId,
        handle: u16,
    ) -> Result<(), RuntimeError> {
        let lease = self.network_print_jobs.get_mut(&owner)
            .and_then(|jobs| jobs.queue_data_lease_for_handle_mut(handle))
            .ok_or_else(|| print_invariant("WNet queue HGLOBAL lease disappeared after GlobalLock"))?;
        lease.locked = true;
        Ok(())
    }

    fn set_queue_data_lock(
        &mut self,
        owner: OwnerId,
        handle: u16,
        selector: SelectorRef,
    ) -> Result<(), RuntimeError> {
        let lease = self.network_print_jobs.get_mut(&owner)
            .and_then(|jobs| jobs.queue_data_lease_for_handle_mut(handle))
            .ok_or_else(|| print_invariant("WNet queue HGLOBAL lease disappeared after lock"))?;
        lease.selector = Some(selector);
        lease.locked = true;
        Ok(())
    }

    fn validate_queue_data_lease(
        &self,
        lease: &Win16NetworkPrintQueueDataLease,
    ) -> Result<(), RuntimeError> {
        if self.global_handles.get(&lease.global_handle).copied() != Some(lease.global_identity) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WNet queue HGLOBAL identity changed before unlock"));
        }
        if let Some(expected) = lease.selector {
            let actual = self.selectors.reference(expected.raw()).map_err(crate::runtime_error)?;
            if actual.generation() != expected.generation() {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "WNet queue-data selector generation changed before unlock"));
            }
        }
        Ok(())
    }

    pub(super) fn release_queue_data_lease(
        &mut self,
        owner: OwnerId,
        lease: &Win16NetworkPrintQueueDataLease,
    ) -> Result<(), RuntimeError> {
        self.validate_queue_data_lease(lease)?;
        if lease.locked {
            let _ = self.global_unlock(lease.global_handle)?;
            if let Some(current) = self.network_print_jobs.get_mut(&owner)
                .and_then(|jobs| jobs.queue_data_lease_for_mut(&lease.queue))
            {
                current.locked = false;
                current.selector = None;
            }
            if self.kernel_global_flags(lease.global_handle) & u32::from(GMEM_LOCKCOUNT_MASK) != 0 {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "WNet queue-data HGLOBAL remains locked during task cleanup"));
            }
        }
        if self.global_free(lease.global_handle)? != 0 {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "WNet queue-data HGLOBAL could not be freed during cleanup"));
        }
        let jobs = self.network_print_jobs.get_mut(&owner)
            .ok_or_else(|| print_invariant("WNet cleanup queue-data owner disappeared"))?;
        network_print_cleanup::retire_queue_data_after_global_release(
            jobs, &lease.queue, lease.global_handle,
        );
        Ok(())
    }

    pub(super) fn prepare_network_print_output(
        &self,
        memory: &Memory,
        far_pointer: u32,
        length: usize,
    ) -> Result<super::text_memory::PreparedTextWrite, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(far_pointer).map_err(crate::runtime_error)?;
        self.prepare_text_write(memory, pointer, length)
    }
}
