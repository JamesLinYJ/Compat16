//! Typed owner state for deferred DDE guest-block release.

use win16_abi::GlobalHandle;

/// Keep allocator generation and lock progress rooted until the shared memory
/// owner verifies aliases, pins, and the final release.
#[derive(Clone, Debug)]
pub(crate) struct Win16DdeRetiredGuestBlock {
    pub identity: GlobalHandle,
    pub locked: bool,
    pub phase: Win16DdeGuestBlockRetirementPhase,
    pub selector_aliases: u16,
    pub page_locks: u16,
    pub internal_pins: u16,
    pub failure: Option<std::sync::Arc<crate::RuntimeError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win16DdeGuestBlockRetirementPhase {
    Pending,
    Retained,
}

impl Win16DdeRetiredGuestBlock {
    pub(crate) fn pending(identity: GlobalHandle, locked: bool) -> Self {
        Self {
            identity,
            locked,
            phase: Win16DdeGuestBlockRetirementPhase::Pending,
            selector_aliases: 0,
            page_locks: 0,
            internal_pins: 0,
            failure: None,
        }
    }
}

