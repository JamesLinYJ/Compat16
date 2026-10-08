//! Caller identity allocation and DOS address-space teardown.

use dos_kernel::{
    DosCallerAddressSpaceFailureKind as FailureKind, DosCallerId, DosError, DosHost, DosKernel,
};
use guest_core::OwnerId;
use guest_core::memory::Memory;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::RuntimeError;

use super::super::Win16State;
use super::{CallerIdentity, Win16DosCallerAddresses, address_failure};

// DosCallerId crosses DOS retained-pointer records. OwnerId values can repeat
// across Win16State instances, so a process-wide allocator prevents foreign
// persistent records from matching a local owner without encoding table bits.
static NEXT_DOS_CALLER_ID: AtomicU64 = AtomicU64::new(1);

fn validate_owner(owner: OwnerId, operation: &'static str) -> Result<(), DosError> {
    if owner.0 == 0 {
        return Err(address_failure(
            FailureKind::InternalInvariant,
            operation,
            "Win16 task owner is zero, which is reserved for the real-mode caller",
        ));
    }
    Ok(())
}

fn allocate_caller_id() -> Result<DosCallerId, DosError> {
    let raw = NEXT_DOS_CALLER_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 {
                None
            } else {
                Some(next.checked_add(1).unwrap_or(0))
            }
        })
        .map_err(|_| {
            address_failure(
                FailureKind::ResourceExhausted,
                "allocate protected DOS caller identity",
                "process-wide protected DOS caller identity space is exhausted",
            )
        })?;
    DosCallerId::new(raw).ok_or_else(|| {
        address_failure(
            FailureKind::ResourceExhausted,
            "allocate protected DOS caller identity",
            "process-wide protected DOS caller identity allocator returned the reserved zero id",
        )
    })
}

impl Win16DosCallerAddresses {
    pub(super) fn caller_id(&mut self, owner: OwnerId) -> Result<DosCallerId, DosError> {
        validate_owner(owner, "resolve protected DOS caller identity")?;
        if let Some(identity) = self.callers.iter().find(|entry| entry.owner == owner) {
            return Ok(identity.caller);
        }
        self.callers.try_reserve(1).map_err(|error| {
            DosError::caller_address_space(
                FailureKind::ResourceExhausted,
                "retain protected DOS caller identity",
                error,
            )
        })?;
        let caller = allocate_caller_id()?;
        self.callers.push(CallerIdentity { owner, caller });
        Ok(caller)
    }

    pub(super) fn existing_caller_id(
        &self,
        owner: OwnerId,
    ) -> Result<Option<DosCallerId>, DosError> {
        validate_owner(owner, "release protected DOS caller identity")?;
        Ok(self
            .callers
            .iter()
            .find(|entry| entry.owner == owner)
            .map(|entry| entry.caller))
    }

    pub(super) fn retire_caller(
        &mut self,
        owner: OwnerId,
        caller: DosCallerId,
    ) -> Result<(), DosError> {
        let index = self
            .callers
            .iter()
            .position(|entry| entry.owner == owner && entry.caller == caller)
            .ok_or_else(|| {
                address_failure(
                    FailureKind::InternalInvariant,
                    "retire protected DOS caller identity",
                    "successfully released protected DOS caller was missing from its ledger",
                )
            })?;
        self.callers.remove(index);
        Ok(())
    }
}

impl Win16State {
    /// Release the actual caller ledger, stopping at the first failed cleanup.
    /// Successful rows are retired; the failed and remaining rows stay for retry.
    pub(in crate::win16_runtime) fn release_all_dos_caller_address_spaces(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl DosHost,
    ) -> Result<(), RuntimeError> {
        while let Some(owner) = self
            .dos_caller_addresses
            .callers
            .first()
            .map(|identity| identity.owner)
        {
            self.release_dos_caller_address_space(dos, memory, host, owner)?;
        }
        Ok(())
    }
}
