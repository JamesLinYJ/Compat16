//! Receipt validation and diagnostics for exact-source NetBIOS teardown.

use std::sync::Arc;
use std::{error::Error, fmt};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostNetbiosFailureTally, Win16HostNetbiosTeardownPhase,
    Win16HostNetbiosTeardownReceipt,
};

use super::PendingNcb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TeardownProgress {
    NotAccepted,
    Retained,
    Retired,
}

pub(super) fn teardown_handoff_started(receipt: &Win16HostNetbiosTeardownReceipt) -> bool {
    matches!(
        receipt.phase,
        Win16HostNetbiosTeardownPhase::TeardownRequested
            | Win16HostNetbiosTeardownPhase::NativeOwnerQuarantined
            | Win16HostNetbiosTeardownPhase::EventCloseFailed
            | Win16HostNetbiosTeardownPhase::WorkerJoinPending
            | Win16HostNetbiosTeardownPhase::WorkerJoinFailed
            | Win16HostNetbiosTeardownPhase::NativeOwnerRetired
    )
}

pub(super) fn teardown_receipt_did_not_regress(
    previous: &Win16HostNetbiosTeardownReceipt,
    current: &Win16HostNetbiosTeardownReceipt,
) -> bool {
    (!previous.native_terminal || current.native_terminal)
        && (!previous.event_closed || current.event_closed)
        && (!previous.worker_joined || current.worker_joined)
        && teardown_phase_rank(current.phase) >= teardown_phase_rank(previous.phase)
        && previous.completion_publication
            .did_not_regress_to(current.completion_publication)
        && previous.failure_diagnostics
            .did_not_regress_to(&current.failure_diagnostics)
        && (!previous.native_owner_retired() || previous.same_cached_receipt(current))
}

fn teardown_phase_rank(phase: Win16HostNetbiosTeardownPhase) -> u8 {
    match phase {
        Win16HostNetbiosTeardownPhase::NativePending => 0,
        Win16HostNetbiosTeardownPhase::TerminalUnpublished
        | Win16HostNetbiosTeardownPhase::CompletionDeliveredAwaitingGuestAck => 1,
        Win16HostNetbiosTeardownPhase::TeardownRequested => 2,
        Win16HostNetbiosTeardownPhase::NativeOwnerQuarantined => 3,
        Win16HostNetbiosTeardownPhase::NativeTerminal => 4,
        Win16HostNetbiosTeardownPhase::EventCloseFailed => 5,
        Win16HostNetbiosTeardownPhase::WorkerJoinPending => 6,
        Win16HostNetbiosTeardownPhase::WorkerJoinFailed => 7,
        Win16HostNetbiosTeardownPhase::NativeOwnerRetired => 8,
    }
}

pub(super) fn retained_teardown_error(pending: &PendingNcb) -> RuntimeError {
    let message = if pending.callback_id.is_some() {
        "NetBIOS callback frame still owns its exact source during teardown"
    } else if let Some(receipt) = pending.teardown.as_ref() {
        return teardown_cause_error(pending, RuntimeError::new(
            Kind::HostFailure,
            format!(
                "NetBIOS source {} remains retained in teardown phase {}",
                pending.host_id.0,
                teardown_phase_label(receipt.phase),
            ),
        ));
    } else {
        "host has not accepted teardown for the exact NetBIOS source"
    };
    teardown_cause_error(pending, RuntimeError::new(Kind::HostFailure, message))
}

fn teardown_cause_error(pending: &PendingNcb, retained: RuntimeError) -> RuntimeError {
    let original = pending.source_cause.as_ref().or_else(|| {
        pending.teardown.as_ref().and_then(|receipt| receipt.cause.as_ref())
    });
    let mut report = match original {
        Some(cause) => shared_netbios_error(
            Arc::clone(cause),
            "original typed NetBIOS source failure remains retained",
        ).with_cleanup("NetBIOS teardown has not retired the exact source", retained),
        None => retained,
    };
    if let Some(cleanup) = pending.teardown.as_ref()
        .and_then(|receipt| receipt.cleanup_error.as_ref())
    {
        report = report.with_cleanup(
            "NetBIOS teardown also reported a native cleanup failure",
            shared_netbios_error(
                Arc::clone(cleanup),
                "native NetBIOS teardown cleanup failure",
            ),
        );
    }
    if let Some(query_error) = pending.terminal_state_query_error.as_ref() {
        report = report.with_cleanup(
            "shared USER wake terminal state query also failed",
            shared_netbios_error(
                Arc::clone(query_error),
                "query shared USER wake terminal state",
            ),
        );
    }
    if let Some(receipt) = pending.teardown.as_ref() {
        for (phase, tally) in failure_slots(&receipt.failure_diagnostics) {
            if tally.count == 0 {
                continue;
            }
            let Some(cause) = tally.first.as_ref() else { continue };
            report = report.with_cleanup(
                "a retained NetBIOS teardown phase reported a typed failure",
                RuntimeError::with_source(
                    cause.kind(),
                    format!(
                        "NetBIOS teardown phase {phase} recorded {} {}",
                        tally.count,
                        failure_word(tally.count),
                    ),
                    CountedNetbiosPhaseError {
                        phase,
                        count: tally.count,
                        cause: Arc::clone(cause),
                    },
                ),
            );
        }
    }
    report
}

pub(super) fn report_retirement_failure_warnings(
    receipt: &Win16HostNetbiosTeardownReceipt,
    host: &mut impl RuntimeHost,
) {
    for (phase, tally) in failure_slots(&receipt.failure_diagnostics) {
        if tally.count == 0 {
            continue;
        }
        let Some(cause) = tally.first.as_ref() else { continue };
        host.report_diagnostic(&Diagnostic::warning(
            Kind::HostFailure,
            format!(
                "Native NetBIOS teardown recovered after {} {} in phase {phase}",
                tally.count,
                failure_word(tally.count),
            ),
        ).with_cause(CountedNetbiosPhaseError {
            phase,
            count: tally.count,
            cause: Arc::clone(cause),
        }));
    }
}

pub(super) fn report_retirement_failure_warnings_once(
    already_reported: &mut bool,
    receipt: &Win16HostNetbiosTeardownReceipt,
    host: &mut impl RuntimeHost,
) {
    if *already_reported {
        return;
    }
    report_retirement_failure_warnings(receipt, host);
    *already_reported = true;
}

fn failure_slots(
    diagnostics: &crate::Win16HostNetbiosFailureDiagnostics,
) -> [(&'static str, &Win16HostNetbiosFailureTally); 7] {
    [
        ("USER wake publication", &diagnostics.wake_publication),
        ("native event wait", &diagnostics.native_wait),
        ("completion projection", &diagnostics.completion_projection),
        ("worker consumer", &diagnostics.no_consumer),
        ("teardown handoff", &diagnostics.teardown_handoff),
        ("native event close", &diagnostics.native_event_close),
        ("worker join", &diagnostics.worker_join),
    ]
}

#[derive(Debug)]
struct CountedNetbiosPhaseError {
    phase: &'static str,
    count: u32,
    cause: Arc<RuntimeError>,
}

impl fmt::Display for CountedNetbiosPhaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} {}: {}",
            self.phase,
            self.count,
            failure_word(self.count),
            self.cause,
        )
    }
}

impl Error for CountedNetbiosPhaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

fn failure_word(count: u32) -> &'static str {
    if count == 1 { "failure" } else { "failures" }
}

fn teardown_phase_label(phase: Win16HostNetbiosTeardownPhase) -> &'static str {
    match phase {
        Win16HostNetbiosTeardownPhase::NativePending => "native pending",
        Win16HostNetbiosTeardownPhase::TerminalUnpublished => "terminal unpublished",
        Win16HostNetbiosTeardownPhase::CompletionDeliveredAwaitingGuestAck => {
            "completion awaiting guest ACK"
        }
        Win16HostNetbiosTeardownPhase::TeardownRequested => "teardown requested",
        Win16HostNetbiosTeardownPhase::NativeOwnerQuarantined => "native owner quarantined",
        Win16HostNetbiosTeardownPhase::NativeTerminal => "native terminal",
        Win16HostNetbiosTeardownPhase::WorkerJoinPending => "worker join pending",
        Win16HostNetbiosTeardownPhase::EventCloseFailed => "event close failed",
        Win16HostNetbiosTeardownPhase::WorkerJoinFailed => "worker join failed",
        Win16HostNetbiosTeardownPhase::NativeOwnerRetired => "native owner retired",
    }
}

pub(super) fn shared_netbios_error(
    error: Arc<RuntimeError>,
    context: &'static str,
) -> RuntimeError {
    RuntimeError::with_source(error.kind(), context, SharedNetbiosError(error))
}

#[derive(Debug)]
struct SharedNetbiosError(Arc<RuntimeError>);

impl std::fmt::Display for SharedNetbiosError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedNetbiosError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) fn remember_failure(failures: &mut Option<RuntimeError>, error: RuntimeError) {
    *failures = Some(match failures.take() {
        Some(primary) => primary.with_cleanup("additional NetBIOS task cleanup failure", error),
        None => error,
    });
}
