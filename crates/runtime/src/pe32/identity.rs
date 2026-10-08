//! Non-reused identities that separate guest values from runtime ownership.

use crate::{DiagnosticKind as Kind, RuntimeError};

use crate::pe32_call::Pe32CallConvention;

use super::types::{Pe32CallReason, Pe32CallableTarget};

/// Guest-visible 32-bit module value. It is an opaque runtime token, never an
/// HMODULE or host pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32ModuleToken(u32);

impl Pe32ModuleToken {
    pub(super) const fn new(raw: u32) -> Self {
        Self(raw)
    }
}

/// Opaque runtime procedure value. It is not an executable address or guest
/// `FARPROC`; runtime resolves it before entering guest code or a typed service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32ProcedureToken(u32);

impl Pe32ProcedureToken {
    pub(super) const fn new(raw: u32) -> Self {
        Self(raw)
    }
}

/// A registry key for a runtime service whose invocation is implemented by an
/// explicit typed adapter; it is not a Windows `FARPROC` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32TypedHostServiceId(u16);

impl Pe32TypedHostServiceId {
    pub(crate) const fn from_typed_catalog(value: u16) -> Self {
        Self(value)
    }
    pub(crate) const fn raw(self) -> u16 {
        self.0
    }
}

/// Internal generation accompanies the public token so leases and graph edges
/// cannot accidentally attach to a later module instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32ModuleIdentity {
    pub(super) token: Pe32ModuleToken,
    pub(super) generation: u64,
}

impl Pe32ModuleIdentity {
    pub(super) const fn new(token: Pe32ModuleToken, generation: u64) -> Self {
        Self { token, generation }
    }
    pub(crate) const fn token(self) -> Pe32ModuleToken {
        self.token
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32ProcedureIdentity {
    pub(super) token: Pe32ProcedureToken,
    pub(super) generation: u64,
}

impl Pe32ProcedureIdentity {
    pub(super) const fn new(token: Pe32ProcedureToken, generation: u64) -> Self {
        Self { token, generation }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32CallLeaseId(u64);

impl Pe32CallLeaseId {
    pub(super) const fn new(raw: u64) -> Self {
        Self(raw)
    }
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

/// Retired IDs are recognized from the monotonic sequence without retaining an
/// unbounded per-call tombstone table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32CallLeaseState {
    Prepared,
    Executing,
    Retired,
}

/// DllMain progress is separate from module visibility: once attach executes,
/// normal unload and a rejected attach both require an ordered detach callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Pe32EntryPointLifecycle {
    NotRequired,
    AttachPending,
    AttachPrepared,
    AttachExecuting,
    AttachAborted,
    DetachPending,
    DetachPrepared,
    DetachExecuting,
    Detached,
    AttachFaulted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pe32CallLease {
    pub(super) id: Pe32CallLeaseId,
    pub(super) module: Option<Pe32ModuleIdentity>,
    pub(super) procedure: Option<Pe32ProcedureIdentity>,
    pub(super) target: Pe32CallableTarget,
    pub(super) convention: Pe32CallConvention,
    pub(super) reason: Pe32CallReason,
    pub(super) arguments: Vec<u32>,
}

impl Pe32CallLease {
    pub(crate) const fn id(&self) -> Pe32CallLeaseId {
        self.id
    }
    pub(crate) const fn module(&self) -> Option<Pe32ModuleIdentity> {
        self.module
    }
    pub(crate) const fn target(&self) -> Pe32CallableTarget {
        self.target
    }
    pub(crate) const fn convention(&self) -> Pe32CallConvention {
        self.convention
    }
    pub(crate) const fn reason(&self) -> Pe32CallReason {
        self.reason
    }
    pub(crate) fn arguments(&self) -> &[u32] {
        &self.arguments
    }
}

#[derive(Debug)]
pub(super) struct MonotonicU32 {
    next: Option<u32>,
    description: &'static str,
}

impl MonotonicU32 {
    pub(super) const fn new(description: &'static str) -> Self {
        Self {
            next: Some(1),
            description,
        }
    }

    /// Guest tokens are deliberately never recycled: internal generations
    /// cannot distinguish a stale guest DWORD after a token itself is reused.
    pub(super) fn take(&mut self) -> Result<u32, RuntimeError> {
        let value = self.next.ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                format!("{0} guest identity space is exhausted", self.description),
            )
        })?;
        self.next = value.checked_add(1);
        Ok(value)
    }
}

#[derive(Debug)]
pub(super) struct MonotonicU64 {
    next: Option<u64>,
    description: &'static str,
}

impl MonotonicU64 {
    pub(super) const fn new(description: &'static str) -> Self {
        Self {
            next: Some(1),
            description,
        }
    }

    pub(super) fn take(&mut self) -> Result<u64, RuntimeError> {
        let value = self.next.ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                format!("{0} identity generation is exhausted", self.description),
            )
        })?;
        self.next = value.checked_add(1);
        Ok(value)
    }

    pub(super) fn was_issued(&self, raw: u64) -> bool {
        raw != 0 && self.next.map_or(true, |next| raw < next)
    }
}
