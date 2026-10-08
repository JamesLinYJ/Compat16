//! Process-owned bitmap retention and pre-reserved transfer accounting.

use runtime::{DiagnosticKind as Kind, RuntimeError};
use std::sync::Arc;

use super::super::win16_common_controls_dc_retention::ToolbarDcReleaseOwner;
use super::ToolbarBitmapSidecar;

/// Keep outstanding owner commitments separate from allocator spare capacity.
pub(in crate::windows) struct ToolbarBitmapRetention {
    pub(super) sidecars: Vec<ToolbarBitmapSidecar>,
    pub(super) reserved_slots: usize,
    pub(super) emergency_sidecars: Option<Vec<ToolbarBitmapSidecar>>,
    pub(super) overflow_sidecars: Option<Vec<ToolbarBitmapSidecar>>,
    pub(super) dc_release_owners: Vec<ToolbarDcReleaseOwner>,
    pub(super) emergency_dc_release_owners: Option<Vec<ToolbarDcReleaseOwner>>,
    pub(super) overflow_dc_release_owners: Option<Vec<ToolbarDcReleaseOwner>>,
    pub(super) reserved_dc_release_slots: usize,
    pub(super) deferred_failure: Option<Arc<RuntimeError>>,
    pub(super) deferred_owner_failure: bool,
}

impl ToolbarBitmapRetention {
    pub(in crate::windows) fn new() -> Self {
        Self {
            sidecars: Vec::new(),
            reserved_slots: 0,
            emergency_sidecars: Some(Vec::new()),
            overflow_sidecars: None,
            dc_release_owners: Vec::new(),
            emergency_dc_release_owners: Some(Vec::new()),
            overflow_dc_release_owners: None,
            reserved_dc_release_slots: 0,
            deferred_failure: None,
            deferred_owner_failure: false,
        }
    }

    pub(in crate::windows) fn reserve_slots(&mut self, count: usize) -> Result<(), RuntimeError> {
        let reserved = self.reserved_slots.checked_add(count).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "toolbar bitmap outstanding reservation count overflow",
            )
        })?;
        self.sidecars.try_reserve(reserved).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve toolbar bitmap owner storage",
                error,
            )
        })?;
        self.emergency_sidecars
            .as_mut()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar emergency bitmap storage was retired while live",
                )
            })?
            .try_reserve(reserved)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve emergency toolbar bitmap owner storage",
                    error,
                )
            })?;
        self.reserved_slots = reserved;
        Ok(())
    }

    pub(in crate::windows) fn cancel_slots(&mut self, count: usize) -> Result<(), RuntimeError> {
        self.reserved_slots = self.reserved_slots.checked_sub(count).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap outstanding reservation underflow",
            )
        })?;
        Ok(())
    }

    pub(in crate::windows) fn push_reserved(
        &mut self,
        sidecar: ToolbarBitmapSidecar,
    ) -> Result<(), (RuntimeError, ToolbarBitmapSidecar)> {
        if self.reserved_slots == 0 || self.sidecars.len() == self.sidecars.capacity() {
            return Err((
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar bitmap owner has no pre-reserved retention slot",
                ),
                sidecar,
            ));
        }
        self.sidecars.push(sidecar);
        self.reserved_slots -= 1;
        Ok(())
    }

    pub(in crate::windows) fn append_reserved(
        &mut self,
        sidecars: &mut Vec<ToolbarBitmapSidecar>,
    ) -> Result<(), RuntimeError> {
        let count = sidecars.len();
        if self.reserved_slots < count
            || self.sidecars.capacity().saturating_sub(self.sidecars.len()) < sidecars.len()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "live toolbar bitmap sidecars exceed their retention reservations",
            ));
        }
        self.sidecars.append(sidecars);
        self.reserved_slots -= count;
        Ok(())
    }

    pub(in crate::windows) fn retain_emergency(
        &mut self,
        mut sidecars: Vec<ToolbarBitmapSidecar>,
    ) -> Result<(), (RuntimeError, Vec<ToolbarBitmapSidecar>)> {
        let count = sidecars.len();
        let Some(emergency) = self.emergency_sidecars.as_mut() else {
            return Err((
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar emergency owner storage was already retired",
                ),
                sidecars,
            ));
        };
        if emergency.capacity().saturating_sub(emergency.len()) < count {
            return Err((
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar emergency owner exceeded pre-reserved storage",
                ),
                sidecars,
            ));
        }
        emergency.append(&mut sidecars);
        self.reserved_slots = self.reserved_slots.saturating_sub(count);
        Ok(())
    }

    /// Move an already-owned vector without allocating when reserved storage is damaged.
    pub(in crate::windows) fn retain_overflow_sidecars(
        &mut self,
        sidecars: Vec<ToolbarBitmapSidecar>,
    ) -> Result<(), Vec<ToolbarBitmapSidecar>> {
        if self.overflow_sidecars.is_some() {
            return Err(sidecars);
        }
        self.overflow_sidecars = Some(sidecars);
        Ok(())
    }

    pub(in crate::windows) fn reserve_dc_release_slot(&mut self) -> Result<(), RuntimeError> {
        let reserved = self
            .reserved_dc_release_slots
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "toolbar HDC retention reservation count overflow",
                )
            })?;
        self.dc_release_owners
            .try_reserve(reserved)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve process-owned toolbar HDC record",
                    error,
                )
            })?;
        self.emergency_dc_release_owners
            .as_mut()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar HDC emergency storage was retired while live",
                )
            })?
            .try_reserve(reserved)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve emergency toolbar HDC record",
                    error,
                )
            })?;
        self.reserved_dc_release_slots = reserved;
        Ok(())
    }

    pub(in crate::windows) fn cancel_dc_release_slot(&mut self) -> Result<(), RuntimeError> {
        self.reserved_dc_release_slots =
            self.reserved_dc_release_slots
                .checked_sub(1)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "toolbar HDC retention reservation underflow",
                    )
                })?;
        Ok(())
    }

    pub(in crate::windows) fn append_dc_owners_reserved(
        &mut self,
        owners: &mut Vec<ToolbarDcReleaseOwner>,
    ) -> Result<(), RuntimeError> {
        let count = owners.len();
        if self.reserved_dc_release_slots < count
            || self
                .dc_release_owners
                .capacity()
                .saturating_sub(self.dc_release_owners.len())
                < count
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "worker HDC owners exceed their process retention reservations",
            ));
        }
        self.dc_release_owners.append(owners);
        self.reserved_dc_release_slots -= count;
        Ok(())
    }

    pub(in crate::windows) fn retain_emergency_dc_owners(
        &mut self,
        mut owners: Vec<ToolbarDcReleaseOwner>,
    ) -> Result<(), (RuntimeError, Vec<ToolbarDcReleaseOwner>)> {
        let count = owners.len();
        let Some(emergency) = self.emergency_dc_release_owners.as_mut() else {
            return Err((
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar HDC emergency storage was already retired",
                ),
                owners,
            ));
        };
        if emergency.capacity().saturating_sub(emergency.len()) < count {
            return Err((
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar emergency HDC owner exceeded pre-reserved storage",
                ),
                owners,
            ));
        }
        emergency.append(&mut owners);
        self.reserved_dc_release_slots = self.reserved_dc_release_slots.saturating_sub(count);
        Ok(())
    }

    /// Keep the creator-thread records themselves if both reserved vectors are inconsistent.
    pub(in crate::windows) fn retain_overflow_dc_owners(
        &mut self,
        owners: Vec<ToolbarDcReleaseOwner>,
    ) -> Result<(), Vec<ToolbarDcReleaseOwner>> {
        if self.overflow_dc_release_owners.is_some() {
            return Err(owners);
        }
        self.overflow_dc_release_owners = Some(owners);
        Ok(())
    }

    pub(in crate::windows) fn record_failure(
        &mut self,
        error: RuntimeError,
        owner_is_inside_error: bool,
    ) {
        self.deferred_owner_failure |= owner_is_inside_error;
        self.deferred_failure = Some(Arc::new(match self.deferred_failure.take() {
            Some(previous) => RuntimeError::with_source(
                previous.kind(),
                "multiple toolbar retention failures were recorded during worker teardown",
                RetentionFailure {
                    previous,
                    current: error,
                },
            ),
            None => error,
        }));
    }
}

#[derive(Debug)]
struct RetentionFailure {
    previous: Arc<RuntimeError>,
    current: RuntimeError,
}

impl std::fmt::Display for RetentionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; another retention failure: {}",
            self.previous, self.current
        )
    }
}

impl std::error::Error for RetentionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.previous.as_ref())
    }
}
