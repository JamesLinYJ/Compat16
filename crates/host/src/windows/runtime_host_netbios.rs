//! Native Windows implementation of the Win16 NetBIOS host boundary.

use super::super::WindowsHost;
use runtime::{
    RuntimeError, RuntimeNetbiosHost, Win16HostNetbiosCall, Win16HostNetbiosId,
    Win16HostNetbiosResult, Win16HostNetbiosSubmission,
    Win16HostNetbiosTeardownReason, Win16HostNetbiosTeardownReceipt,
};

impl RuntimeNetbiosHost for WindowsHost {
    fn win16_netbios_call(
        &mut self,
        call: Win16HostNetbiosCall,
    ) -> Result<Win16HostNetbiosResult, RuntimeError> {
        super::super::win16_netbios::execute(call)
    }

    fn win16_netbios_submit(
        &mut self,
        call: Win16HostNetbiosCall,
    ) -> Result<Win16HostNetbiosSubmission, RuntimeError> {
        self.win16_netbios.submit(call)
    }

    fn win16_netbios_completion(
        &mut self,
        id: Win16HostNetbiosId,
    ) -> Result<Option<Win16HostNetbiosResult>, RuntimeError> {
        self.win16_netbios.completion(id)
    }

    fn win16_netbios_cancel(
        &mut self,
        id: Win16HostNetbiosId,
    ) -> Result<Win16HostNetbiosResult, RuntimeError> {
        self.win16_netbios.cancel(id)
    }

    fn win16_netbios_ack(
        &mut self,
        id: Win16HostNetbiosId,
    ) -> Result<bool, RuntimeError> {
        self.win16_netbios.ack(id)
    }

    fn win16_netbios_teardown(
        &mut self,
        id: Win16HostNetbiosId,
        reason: Win16HostNetbiosTeardownReason,
    ) -> Result<Win16HostNetbiosTeardownReceipt, RuntimeError> {
        self.win16_netbios.teardown(id, reason)
    }

    fn win16_netbios_teardown_ack(
        &mut self,
        receipt: &Win16HostNetbiosTeardownReceipt,
    ) -> Result<bool, RuntimeError> {
        self.win16_netbios.teardown_ack(receipt)
    }

    fn win16_netbios_terminal_wake_unavailable(&self) -> Result<bool, RuntimeError> {
        self.win16_netbios.terminal_wake_unavailable()
    }
}
