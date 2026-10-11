//! Owned channel/record fixtures for the DDE protocol; no native worker or UI.

use super::*;

impl Win16DdeHost {
    pub(in crate::windows) fn completed_operation_fixture(
        operation: Win16HostDdeOperation,
        result: Win16HostDdeResult,
    ) -> (Self, Win16HostDdeStep) {
        let (command_sender, _) = mpsc::channel();
        let (_, event_receiver) = mpsc::channel();
        let mut host = Self {
            command_sender,
            event_receiver,
            identity_source: Arc::new(AtomicU64::new(100)),
            owner: Win16HostDdeOwner(11),
            worker_generation: 12,
            control_window: 0,
            shutdown_receiver: None,
            shutdown_report: None,
            shutdown_requested: false,
            abort_request_id: None,
            // This fixture never creates a native worker. Avoid native
            // shutdown/wake calls from Drop, including during a test panic.
            abort_receipt: Some(Win16DdeAbortReceipt::not_started()),
            worker: None,
            pending_callbacks: BTreeMap::new(),
            pending_operations: BTreeSet::from([operation]),
            pending_operation_instances: BTreeMap::from([(
                operation,
                PendingDdeOperationRecord {
                    instance: None,
                    request_phase: Some(Win16DdeOperationRequestPhase::SubmittedPending),
                    failure: None,
                    completed_result: None,
                    source_retirement_failure: None,
                },
            )]),
            pending_transfer_guards: BTreeMap::new(),
            pending_events: BTreeMap::new(),
            unsolicited_callbacks: VecDeque::new(),
            pending_callback_completions: BTreeMap::new(),
            diagnostics: VecDeque::new(),
        };
        let step = host
            .operation_step(
                operation,
                WorkerEvent::Complete {
                    operation,
                    entered_worker: true,
                    result: Ok(result),
                },
            )
            .expect("record the native Complete event through the production owner");
        (host, step)
    }

    pub(in crate::windows) fn cache_abort_receipt_fixture(
        &mut self,
        receipt: Win16DdeAbortReceipt,
    ) {
        assert!(receipt.is_quiesced());
        assert_eq!(receipt.owner, Some(self.owner));
        assert_eq!(receipt.worker_generation, Some(self.worker_generation));
        self.abort_receipt = Some(receipt);
    }

    pub(in crate::windows) fn retain_transfer_guard_fixture(
        &mut self,
        operation: Win16HostDdeOperation,
    ) {
        assert!(self.pending_operation_instances.contains_key(&operation));
        self.pending_transfer_guards
            .insert(operation, (Win16HostDdeData(51), Win16HostDdeInstance(31)));
    }
}
