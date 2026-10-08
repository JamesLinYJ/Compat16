//! Public segment-lock roots and retirement scheduling for loaded modules.

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn has_reapable_unreachable_modules(&self) -> Result<bool, RuntimeError> {
        let roots = self.module_segment_lock_roots()?;
        Ok(!self.modules.unreachable(&roots).is_empty())
    }

    /// Locked segment owners and their dependency graph remain resident after
    /// WEP, but do not keep the module publicly loadable. The matching
    /// UnlockSegment path clears the last lock and schedules another reap.
    pub(super) fn module_segment_lock_roots(&self) -> Result<Vec<u16>, RuntimeError> {
        let mut roots = Vec::new();
        roots.try_reserve_exact(self.modules.records.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 segment-lock retirement roots",
                error,
            )
        })?;
        for (&handle, record) in &self.modules.records {
            if record.resources_retirement_deferred
                && self.resources.has_live_teardown_retention(
                    handle, &self.global_handles, &self.heap,
                ).map_err(crate::runtime_error)?
            {
                // A still-locked resource owner keeps this module's dependency
                // closure alive. Once the real alias/page counts fall to zero,
                // the normal safe-point reaper can retry retirement.
                roots.push(handle);
            }
            for allocation in &record.allocations {
                let info = self.heap.info(allocation.handle).map_err(crate::runtime_error)?;
                let aliases = self.heap.selector_alias_count(allocation.handle)
                    .map_err(crate::runtime_error)?;
                if info.lock_count == 0 && info.page_lock_count == 0 && aliases == 0 {
                    continue;
                }
                let segment_locks = self.heap.segment_lock_count(allocation.handle)
                    .map_err(crate::runtime_error)?;
                if segment_locks > info.lock_count {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 module segment locks exceed its projected guest lock count"));
                }
                if segment_locks != 0 {
                    let selector = allocation.selector.raw().0;
                    let guest_unlockable = record.loaded.as_ref().is_some_and(|loaded|
                        loaded.segments.iter().any(|segment| segment.selector.0 == selector))
                        && self.loaded_segment_handles.contains_key(&selector);
                    if !guest_unlockable {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 segment lock has no loaded segment UnlockSegment identity"));
                    }
                }
                roots.push(handle);
                break;
            }
        }
        Ok(roots)
    }
}
