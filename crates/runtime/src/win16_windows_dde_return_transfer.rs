//! Exact DDE callback return events attached to the owning operation frame.

use super::{Win16State, WindowReturn};
use super::super::dde_callback::invariant;
use crate::{RuntimeError, Win16HostDdeOperation, Win16HostDdeCallbackFrame};

impl Win16State {
    pub(in crate::win16_runtime) fn reserve_dde_guest_return_transfer(
        &mut self,
        operation: Win16HostDdeOperation,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| {
            invariant("foreground DDE callback has no exact operation frame")
        })?;
        let Some(WindowReturn::Dde(continuation)) = &mut frame.result else {
            return Err(invariant(
                "foreground DDE callback owner is not a DDE operation continuation",
            ));
        };
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "foreground DDE callback changed its exact operation owner",
            ));
        }
        continuation.reserve_guest_return_transfer()
    }

    pub(in crate::win16_runtime) fn cache_dde_guest_return_transfer(
        &mut self,
        operation: Win16HostDdeOperation,
        callback_frame: Win16HostDdeCallbackFrame,
        transfer: x86_cpu::ControlTransfer,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| {
            invariant("DDE callback return lost its exact operation frame")
        })?;
        let Some(WindowReturn::Dde(continuation)) = &mut frame.result else {
            return Err(invariant(
                "DDE callback return owner changed before provenance was cached",
            ));
        };
        continuation.cache_guest_return_transfer(operation, callback_frame, transfer)
    }
}
