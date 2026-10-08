//! Exact callback registration identity and retirement proofs.

use win16_abi::{DescriptorInfo, SelectorRef};

use crate::{RuntimeError, Win16GuestCallbackToken};

use super::{Win16CallbackScheduler, Win16GuestCallbackRegistration};
use super::super::callback_entry::Win16GuestCallbackAbi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct CallbackRegistrationRetirementProof {
    callback_token: Win16GuestCallbackToken,
    registration: Win16GuestCallbackRegistration,
}

impl CallbackRegistrationRetirementProof {
    pub(in crate::win16_runtime) fn matches_token(&self, token: Win16GuestCallbackToken) -> bool {
        self.callback_token == token
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum CallbackUnregisterOutcome {
    Unregistered(CallbackRegistrationRetirementProof),
    AlreadyRetired(CallbackRegistrationRetirementProof),
    Retained,
}

impl Win16CallbackScheduler {
    pub(in crate::win16_runtime) fn register(
        &mut self,
        procedure: u32,
        procedure_selector: SelectorRef,
        procedure_descriptor: DescriptorInfo,
        abi: Win16GuestCallbackAbi,
    ) -> Result<Win16GuestCallbackToken, RuntimeError> {
        let token = Win16GuestCallbackToken(self.next_token);
        self.next_token = self.next_token.checked_add(1).ok_or_else(|| RuntimeError::new(
            crate::DiagnosticKind::ResourceExhausted,
            "Win16 guest callback registration identities exhausted",
        ))?;
        self.registrations.insert(token, Win16GuestCallbackRegistration {
            procedure,
            procedure_selector,
            procedure_descriptor,
            abi,
            retirement_requested: false,
        });
        Ok(token)
    }

    pub(super) fn unregister(
        &mut self,
        token: Win16GuestCallbackToken,
    ) -> Option<Win16GuestCallbackRegistration> {
        if self.has_callback_receipts(token) {
            if let Some(registration) = self.registrations.get_mut(&token) {
                registration.retirement_requested = true;
            }
            return None;
        }
        let removed = self.registrations.remove(&token);
        self.retain_terminal_proof_if_requested(token, removed);
        removed
    }

    pub(super) fn unregister_if_quiescent(
        &mut self,
        token: Win16GuestCallbackToken,
    ) -> CallbackUnregisterOutcome {
        if self.has_callback_receipts(token) {
            if let Some(registration) = self.registrations.get_mut(&token) {
                registration.retirement_requested = true;
                self.quiescent_unregister_waiters.insert(token);
            }
            return CallbackUnregisterOutcome::Retained;
        }
        if let Some(registration) = self.registrations.remove(&token) {
            self.quiescent_unregister_waiters.remove(&token);
            return CallbackUnregisterOutcome::Unregistered(
                CallbackRegistrationRetirementProof {
                    callback_token: token,
                    registration,
                },
            );
        }
        if let Some(registration) = self.retired_callback_proofs.remove(&token) {
            CallbackUnregisterOutcome::AlreadyRetired(
                CallbackRegistrationRetirementProof {
                    callback_token: token,
                    registration,
                },
            )
        } else {
            CallbackUnregisterOutcome::Retained
        }
    }

    fn retain_terminal_proof_if_requested(
        &mut self,
        token: Win16GuestCallbackToken,
        removed: Option<Win16GuestCallbackRegistration>,
    ) {
        if let Some(registration) = removed
            && self.quiescent_unregister_waiters.remove(&token)
        {
            self.retired_callback_proofs.insert(token, registration);
        }
    }

    fn has_callback_receipts(&self, token: Win16GuestCallbackToken) -> bool {
        self.active.iter().any(|frame| frame.callback_token == token)
            || self.pending_cleanup.iter().any(|pending| pending.callback_token == token)
            || self.pending_source_retirements.iter().any(|receipt| receipt.callback_token == token)
    }

    pub(super) fn retire_requested_registration(&mut self, token: Win16GuestCallbackToken) {
        if !self.has_callback_receipts(token)
            && self.registrations.get(&token)
                .is_some_and(|registration| registration.retirement_requested)
        {
            let removed = self.registrations.remove(&token);
            self.retain_terminal_proof_if_requested(token, removed);
        }
    }

    pub(super) fn resolve(
        &self,
        token: Win16GuestCallbackToken,
    ) -> Option<Win16GuestCallbackRegistration> {
        self.registrations.get(&token)
            .filter(|registration| !registration.retirement_requested).copied()
    }
}
