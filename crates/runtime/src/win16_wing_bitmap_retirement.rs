//! Exact WinG selector-view retirement after native DIB operations.

use guest_core::{PhysAddr, memory::Memory};
use win16_abi::{AccessRights, SelectorRef, Win16Error};

use super::{
    Win16State,
    wing_bitmap::{Phase, SelectorRetirement, Win16WingBitmap},
};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn preflight_wing_bitmap(
        &self,
        record: &Win16WingBitmap,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        if let Some(guest) = record.guest_handle {
            match self.guest_gdi.object(guest) {
                Some(object) if object == record.object => {}
                None if record.phase == Phase::NativeDeleted => {}
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "WinG bitmap guest handle no longer identifies its exact host object",
                    ));
                }
            }
        }
        if let (Some(allocation), Some(base)) = (record.allocation, record.base) {
            let block = self.heap.info(allocation).map_err(crate::runtime_error)?;
            if block.owner != record.owner || block.base != base || block.size != record.extent {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG bitmap GlobalHeap identity changed before retirement",
                ));
            }
        } else if record.allocation.is_some() != record.base.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG bitmap allocation record has only one exact heap identity",
            ));
        }
        if let Some(mapping) = &record.mapping {
            let base = record.base.ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG device mapping has no exact heap base",
                )
            })?;
            if !memory.device_mapping_matches(mapping, base, record.extent, &record.device) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG bitmap device mapping identity changed before retirement",
                ));
            }
        } else if record.phase == Phase::Live {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "live WinG bitmap has no exact device mapping",
            ));
        }
        if record.phase == Phase::Live
            && (record.allocation.is_none()
                || record.base.is_none()
                || record.mapping.is_none()
                || record.selector.is_none()
                || record.guest_handle.is_none())
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "live WinG bitmap is missing part of its guest allocation identity",
            ));
        }
        if let Some(selector) = record.selector {
            let descriptor = self
                .selectors
                .describe(selector)
                .map_err(crate::runtime_error)?;
            match record.phase {
                Phase::Provisioning | Phase::Live => {
                    let size = self
                        .selectors
                        .allocation_size(selector)
                        .map_err(crate::runtime_error)?;
                    if record.selector_retirement.is_some()
                        || !descriptor.present
                        || descriptor.base != record.base.unwrap_or(PhysAddr(0))
                        || descriptor.rights != AccessRights::read_write()
                        || size != record.extent
                    {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "live WinG bitmap selector no longer matches its exact allocation",
                        ));
                    }
                }
                Phase::Hidden | Phase::NativeDeleted => {
                    self.validate_suspended_wing_selectors(record, selector, descriptor.present)?
                }
            }
        } else if record.phase == Phase::Hidden {
            match record.selector_retirement.as_deref() {
                Some(SelectorRetirement::Retired { reservations }) if reservations.is_empty() => {}
                Some(SelectorRetirement::Suspended { .. }) => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "WinG bitmap has suspended selector views without its primary selector",
                    ));
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "WinG bitmap without a selector lacks an empty retirement receipt",
                    ));
                }
            }
        } else if record.phase == Phase::NativeDeleted {
            match record.selector_retirement.as_deref() {
                Some(SelectorRetirement::Retired { reservations }) => {
                    self.validate_retired_wing_selectors(reservations)?;
                }
                None => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "deleted WinG bitmap lost its selector retirement ledger",
                    ));
                }
                Some(SelectorRetirement::Suspended { .. }) => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "suspended WinG bitmap selector ledger lost its primary reference",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_suspended_wing_selectors(
        &self,
        record: &Win16WingBitmap,
        selector: SelectorRef,
        present: bool,
    ) -> Result<(), RuntimeError> {
        if present {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "retiring WinG bitmap still exposes a guest selector",
            ));
        }
        let Some(SelectorRetirement::Suspended {
            views,
            owned_blocks,
        }) = record.selector_retirement.as_deref()
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "hidden WinG bitmap has no complete selector-view ledger",
            ));
        };
        if !views.iter().any(|view| view.reference() == selector)
            || !owned_blocks.contains(&selector)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG selector ledger does not retain its exact primary block",
            ));
        }
        self.selectors
            .validate_suspended_allocation_views(views)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "WinG selector aliases changed after being hidden",
                    crate::runtime_error(error),
                )
            })
    }

    fn validate_retired_wing_selectors(
        &self,
        reservations: &[SelectorRef],
    ) -> Result<(), RuntimeError> {
        for &reference in reservations {
            let descriptor = self
                .selectors
                .describe(reference)
                .map_err(crate::runtime_error)?;
            let size = self
                .selectors
                .allocation_size(reference)
                .map_err(crate::runtime_error)?;
            if descriptor.present
                || descriptor.base != PhysAddr(0)
                || descriptor.limit != 0
                || descriptor.rights != AccessRights::new(false, false, false)
                || size != 0
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "retired WinG alias is not its exact inaccessible selector reservation",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn hide_wing_bitmap_selector(
        &mut self,
        index: usize,
        record: &Win16WingBitmap,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let (selector, base) = match (record.selector, record.base) {
            (None, _) => {
                self.wing_bitmaps.records[index].selector_retirement =
                    Some(std::rc::Rc::new(SelectorRetirement::Retired {
                        reservations: Vec::new(),
                    }));
                self.wing_bitmaps.records[index].phase = Phase::Hidden;
                return Ok(true);
            }
            (Some(_), None) => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG selector has no exact GlobalHeap base for alias retirement",
                ));
            }
            (Some(selector), Some(base)) => (selector, base),
        };
        if record.selector_retirement.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "live WinG bitmap already has a selector retirement ledger",
            ));
        }
        let mut owned_blocks = Vec::new();
        owned_blocks
            .try_reserve_exact(
                self.allocated_selector_aliases.len()
                    .saturating_add(1),
            )
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve WinG selector ownership ledger",
                    error,
                )
            })?;
        owned_blocks.push(selector);
        let allocation_end = u64::from(base.0) + u64::from(record.extent);
        for &alias in self.allocated_selector_aliases.values() {
            let descriptor = self
                .selectors
                .describe(alias)
                .map_err(crate::runtime_error)?;
            if !descriptor.present {
                continue;
            }
            let start = u64::from(descriptor.base.0);
            let end = start + u64::from(descriptor.limit) + 1;
            if start < allocation_end && u64::from(base.0) < end && !owned_blocks.contains(&alias) {
                owned_blocks.push(alias);
            }
        }
        let views = match self.selectors.suspend_allocation_views(base, record.extent) {
            Ok(views) => views,
            // An externally created selector block that straddles this DIB
            // cannot be retired without invalidating bytes outside the DIB.
            // Preserve every original view and return the documented FALSE
            // path instead of performing native deletion with stale aliases.
            Err(Win16Error::SelectorBlockInterior) => {
                if !self.wing_bitmaps.warned_partial_selector_view {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "WinG DeleteObject was declined because a guest selector view crosses the DIB allocation"));
                    self.wing_bitmaps.warned_partial_selector_view = true;
                }
                return Ok(false);
            }
            Err(error) => return Err(crate::runtime_error(error)),
        };
        if !views.iter().any(|view| view.reference() == selector) {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "WinG primary selector is absent from the complete allocation-view set",
            );
            return Err(match self.selectors.resume_allocation_views(&views) {
                Ok(()) => primary,
                Err(error) => combine(
                    primary,
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "restore selector views after a missing primary identity",
                        crate::runtime_error(error),
                    ),
                ),
            });
        }
        if owned_blocks
            .iter()
            .any(|owned| !views.iter().any(|view| view.reference() == *owned))
        {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "owned WinG alias is absent from the suspended view set",
            );
            return Err(match self.selectors.resume_allocation_views(&views) {
                Ok(()) => primary,
                Err(error) => combine(
                    primary,
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "restore selector views after alias ownership mismatch",
                        crate::runtime_error(error),
                    ),
                ),
            });
        }
        self.wing_bitmaps.records[index].selector_retirement =
            Some(std::rc::Rc::new(SelectorRetirement::Suspended {
                views,
                owned_blocks,
            }));
        self.wing_bitmaps.records[index].phase = Phase::Hidden;
        Ok(true)
    }

    pub(super) fn restore_wing_bitmap_selector(
        &mut self,
        index: usize,
        record: &Win16WingBitmap,
    ) -> Result<(), RuntimeError> {
        let Some(selector) = record.selector else {
            self.wing_bitmaps.records[index].phase = Phase::Provisioning;
            return Ok(());
        };
        let Some(SelectorRetirement::Suspended { views, .. }) = record.selector_retirement.as_deref()
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DeleteObject returned FALSE without suspended WinG selector identities",
            ));
        };
        self.selectors.resume_allocation_views(views).map_err(|error|
            RuntimeError::with_source(Kind::InternalInvariant,
                "DeleteObject returned FALSE but the exact WinG selector set could not be restored",
                crate::runtime_error(error)))?;
        self.wing_bitmaps.records[index].selector = Some(selector);
        self.wing_bitmaps.records[index].selector_retirement = None;
        self.wing_bitmaps.records[index].phase = Phase::Live;
        Ok(())
    }

    pub(super) fn retire_wing_bitmap_selector(
        &mut self,
        index: usize,
        record: &Win16WingBitmap,
    ) -> Result<(), RuntimeError> {
        let Some(_) = record.selector else {
            return match record.selector_retirement.as_deref() {
                Some(SelectorRetirement::Retired { reservations }) => {
                    self.validate_retired_wing_selectors(reservations)
                }
                None => Ok(()),
                Some(SelectorRetirement::Suspended { .. }) => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG selector is suspended but its primary identity is missing",
                )),
            };
        };
        let Some(SelectorRetirement::Suspended {
            views,
            owned_blocks,
        }) = record.selector_retirement.as_deref()
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native WinG deletion completed without a suspended alias ledger",
            ));
        };
        let mut reservations = Vec::new();
        reservations
            .try_reserve_exact(views.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve retired WinG selector identities",
                    error,
                )
            })?;
        let updates = self
            .selectors
            .retire_suspended_allocation_views(views, owned_blocks)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "retire exact WinG selector-view set after native deletion",
                    crate::runtime_error(error),
                )
            })?;
        reservations.extend(updates.iter().map(|(_, replacement)| *replacement));

        self.allocated_selector_aliases
            .retain(|_, reference| !owned_blocks.contains(reference));
        // AllocSelector identities remain API-owned when their guest backing
        // is retired. apply_selector_updates replaces each old generation with
        // its unbacked successor so FreeSelector can still release it.
        self.apply_selector_updates(&updates);
        self.wing_bitmaps.records[index].selector = None;
        self.wing_bitmaps.records[index].selector_retirement =
            Some(std::rc::Rc::new(SelectorRetirement::Retired { reservations }));
        Ok(())
    }
}

fn combine(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        "WinG bitmap operation and cleanup both failed",
        WingCleanupFailure { primary, cleanup },
    )
}

#[derive(Debug)]
struct WingCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for WingCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for WingCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
