//! WindowsHost implementation of the MCI-specific runtime host seam.

use super::*;

pub(super) type MciCall = runtime::Win16HostMciCall;
pub(super) type MciNotificationSource = runtime::Win16GuestNotificationSource;
pub(super) type MciResume = runtime::Win16HostMciResume;
pub(super) type MciStep = Result<runtime::Win16HostMciStep, runtime::RuntimeError>;
pub(super) type MciResumeStep = Result<runtime::Win16HostMciResumeReceipt, runtime::RuntimeError>;
pub(super) type MciNotificationResult =
    Result<Option<runtime::Win16HostMciNotification>, runtime::RuntimeError>;
pub(super) type MciQuiescenceResult =
    Result<runtime::Win16HostMciQuiescenceReceipt, runtime::RuntimeError>;
pub(super) type MciProducerQuiescenceResult =
    Result<runtime::Win16HostMciProducerQuiescenceReceipt, runtime::RuntimeError>;

impl runtime::RuntimeMciHost for WindowsHost {
    fn win16_mci_call(&mut self, call: MciCall) -> MciStep {
        self.win16_mci.execute(call)
    }

    fn win16_mci_reconcile_begin(
        &mut self,
        operation: runtime::Win16HostMciOperationId,
    ) -> Result<Option<runtime::Win16HostMciStep>, runtime::RuntimeError> {
        self.win16_mci.reconcile_begin(operation)
    }

    fn win16_mci_resume(&mut self, resume: MciResume) -> MciResumeStep {
        self.win16_mci.resume(resume)
    }

    fn win16_mci_peek_notification(&mut self) -> MciNotificationResult {
        self.win16_mci.peek_notification()
    }

    fn win16_mci_ack_notification(
        &mut self,
        source: MciNotificationSource,
    ) -> Result<(), runtime::RuntimeError> {
        self.win16_mci.acknowledge_notification(source)
    }

    fn win16_mci_quiesce_producers(
        &mut self,
        request: runtime::Win16HostMciProducerQuiescenceRequest,
    ) -> MciProducerQuiescenceResult {
        self.win16_mci.quiesce_producers(request)
    }

    fn win16_mci_quiesce_owned(
        &mut self,
        request: runtime::Win16HostMciQuiesceRequest,
    ) -> MciQuiescenceResult {
        self.win16_mci.quiesce_owned(request)
    }
}
