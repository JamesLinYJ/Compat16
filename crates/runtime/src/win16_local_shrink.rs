//! KERNEL.LocalShrink: heap compaction plus checked data-extent contraction.

use super::{Win16State, legacy_cpu_binding::AutomaticDataOwner, local_heap::commit_local_spans};
use crate::{DiagnosticKind as Kind, RuntimeError};
use guest_core::{Registers, memory::Memory};
use win16_abi::{
    Win16Error,
    local_heap::{LocalHeap, LocalHeapError},
};

impl Win16State {
    pub(super) fn kernel_local_shrink(
        &mut self,
        registers: &Registers,
        requested_heap: u16,
        minimum: u16,
        return_sp: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let selector = if requested_heap == 0 {
            registers.ds
        } else {
            self.toolhelp_global_handle_to_sel(requested_heap)
        };
        if selector == 0 {
            return Ok(0);
        }
        let (address, mut bytes) = self.local_segment(selector, true, memory)?;
        let old_size = bytes.len() as u32;
        let mut previous = Vec::new();
        if previous.try_reserve_exact(bytes.len()).is_err() {
            return Ok(0);
        }
        previous.extend_from_slice(&bytes);
        let floor = self.retained_data_floor(address, old_size, registers, return_sp);
        let (value, retained, owns_tail, spans) = {
            let mut heap = match LocalHeap::open(&mut bytes) {
                Ok(heap) => heap,
                Err(LocalHeapError::Uninitialized | LocalHeapError::OutOfMemory) => return Ok(0),
                Err(error) => return Err(heap_error(error)),
            };
            let floor = floor.saturating_sub(u32::from(heap.first_offset())) as u16;
            let value = match heap.shrink(minimum.max(floor)) {
                Ok(value) => value,
                Err(LocalHeapError::OutOfMemory) => return Ok(0),
                Err(error) => return Err(heap_error(error)),
            };
            (
                value,
                heap.retained_segment_bytes() as u32,
                heap.owns_segment_tail(),
                heap.take_write_spans(),
            )
        };
        // LocalShrink returns the resulting heap span even when the global
        // allocation cannot contract. The heap's admitted tail remains known
        // so a later LocalAlloc can reclaim it without consuming adjacent data.
        let plan = if owns_tail && retained < old_size {
            self.prepare_local_data_contraction(address, old_size, retained, memory)?
        } else {
            None
        };
        commit_local_spans(memory, address, &bytes, &spans)?;
        if let Some((owner, plan)) = plan {
            if let Err(error) =
                self.resize_data_owner(owner, old_size as usize, retained as usize, memory)
            {
                memory.write_physical(address, &previous).map_err(|rollback| RuntimeError::with_source(
                    Kind::InternalInvariant,
                    format!("LocalShrink extent commit failed ({error}) and guest bytes could not be restored"),
                    rollback))?;
                return Err(error);
            }
            if let AutomaticDataOwner::Main {
                module,
                selector,
                segment_flags,
                base,
                ..
            } = owner
            {
                self.commit_module_image_extent_change(
                    module,
                    selector,
                    base,
                    segment_flags,
                    old_size,
                    retained,
                );
            }
            self.commit_legacy_cpu_data_resize(plan);
            self.update_loaded_data_size(owner, retained);
        }
        Ok(u32::from(value))
    }

    fn prepare_local_data_contraction(
        &mut self,
        base: guest_core::PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &Memory,
    ) -> Result<
        Option<(
            AutomaticDataOwner,
            super::legacy_cpu_binding::LegacyCpuDataResizePlan,
        )>,
        RuntimeError,
    > {
        let Some(owner) = self.local_data_owner(base, old_size as usize)? else {
            return Ok(None);
        };
        // Saved CPU selector leases are covered by the extent plan below.
        // Page locks and other internal owners have no resize receipt; retain
        // their complete allocation extent. A loaded DLL owns one baseline pin.
        let allocation_pin = match owner {
            AutomaticDataOwner::Global { allocation, .. } => Some((allocation, 0)),
            AutomaticDataOwner::Library { allocation, .. } => Some((allocation, 1)),
            AutomaticDataOwner::Main { .. } => None,
        };
        if let Some((allocation, baseline)) = allocation_pin {
            if self
                .heap
                .page_lock_count(allocation)
                .map_err(crate::runtime_error)?
                != 0
                || self
                    .heap
                    .internal_pin_count(allocation)
                    .map_err(crate::runtime_error)?
                    != baseline
            {
                return Ok(None);
            }
        }
        let targets = match self
            .selectors
            .in_place_contraction_targets(base, old_size, new_size, memory)
        {
            Ok(targets)
                if targets
                    .iter()
                    .any(|(reference, _)| *reference == owner.selector()) =>
            {
                targets
            }
            Ok(_) | Err(Win16Error::SelectorBlockInterior | Win16Error::OutOfMemory) => {
                return Ok(None);
            }
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let plan = match self
            .prepare_legacy_cpu_data_resize(owner, old_size, new_size, &targets, memory)
        {
            Ok(plan) => plan,
            Err(super::legacy_cpu_binding::Win16LegacyCpuBindingError::Runtime(error))
                if error.kind() == Kind::ResourceExhausted =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "prepare LocalShrink saved CPU extent transitions",
                    error,
                ));
            }
        };
        if let AutomaticDataOwner::Main {
            module,
            selector,
            segment_flags,
            base,
            ..
        } = owner
        {
            self.preflight_module_image_extent_change(
                module,
                selector,
                base,
                segment_flags,
                old_size,
                new_size,
            )?;
        }
        Ok(Some((owner, plan)))
    }
}

fn heap_error(error: LocalHeapError) -> RuntimeError {
    RuntimeError::with_source(
        if matches!(error, LocalHeapError::CallbackRequired) {
            Kind::CompatibilityGap
        } else {
            Kind::GuestFault
        },
        "validate LocalShrink heap transaction",
        error,
    )
}
