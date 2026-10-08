use super::*;
use std::collections::TryReserveError;
use std::{error::Error, fmt};
use runtime::DiagnosticKind as Kind;

pub(super) struct MciCallbackFailureCause {
    pub(super) native_device: u32,
    pub(super) id: Option<Win16HostMciNotificationId>,
    pub(super) status: usize,
    pub(super) cause: Arc<RuntimeError>,
}

impl fmt::Debug for MciCallbackFailureCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MciCallbackFailureCause")
            .field("native_device", &self.native_device)
            .field("notification_id", &self.id.map(|id| id.0))
            .field("raw_status", &self.status)
            .field("cause_kind", &self.cause.kind())
            .finish()
    }
}

impl fmt::Display for MciCallbackFailureCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id {
            Some(id) => write!(
                formatter,
                "native device {}, notification {}, raw status {}: {}",
                self.native_device, id.0, self.status, self.cause
            ),
            None => write!(
                formatter,
                "native device {}, unresolved notification route, raw status {}: {}",
                self.native_device, self.status, self.cause
            ),
        }
    }
}

impl Error for MciCallbackFailureCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

#[derive(Debug)]
struct MciNotificationFailureCause {
    callback_failures: Vec<MciCallbackFailureCause>,
    failures: VecDeque<Arc<RuntimeError>>,
    worker_wait_failure: Option<Arc<RuntimeError>>,
    worker_wait_wake_failure: Option<Arc<RuntimeError>>,
    entered_yield_failure: Option<Arc<RuntimeError>>,
    entered_yield_wake_failure: Option<Arc<RuntimeError>>,
    entered_yield_client_failure: Option<Arc<RuntimeError>>,
}

impl fmt::Display for MciNotificationFailureCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote_cause = false;
        for (index, failure) in self.callback_failures.iter().enumerate() {
            if wrote_cause {
                formatter.write_str("; ")?;
            }
            write!(formatter, "callback failure {}: {failure}", index + 1)?;
            wrote_cause = true;
        }
        for (index, failure) in self.failures.iter().enumerate() {
            if wrote_cause {
                formatter.write_str("; ")?;
            }
            write!(formatter, "wake failure {}: {failure}", index + 1)?;
            wrote_cause = true;
        }
        if let Some(failure) = &self.worker_wait_failure {
            if wrote_cause {
                formatter.write_str("; ")?;
            }
            write!(formatter, "native owner wait failure: {failure}")?;
            wrote_cause = true;
        }
        for (label, failure) in [
            ("native MCI wait wake failure", &self.worker_wait_wake_failure),
            ("entered native MCI YIELD failure", &self.entered_yield_failure),
            ("entered MCI wake failure", &self.entered_yield_wake_failure),
            ("entered MCI client delivery failure", &self.entered_yield_client_failure),
        ] {
            if let Some(failure) = failure {
                if wrote_cause {
                    formatter.write_str("; ")?;
                }
                write!(formatter, "{label}: {failure}")?;
                wrote_cause = true;
            }
        }
        Ok(())
    }
}

impl Error for MciNotificationFailureCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(failure) = self
            .callback_failures
            .iter()
            .find(|failure| failure.cause.kind() == Kind::InternalInvariant)
        {
            return Some(failure as &(dyn Error + 'static));
        }
        if let Some(failure) = self
            .failures
            .iter()
            .find(|failure| failure.kind() == Kind::InternalInvariant)
        {
            return Some(failure.as_ref() as &(dyn Error + 'static));
        }
        if let Some(failure) = self
            .worker_wait_failure
            .as_ref()
            .filter(|failure| failure.kind() == Kind::InternalInvariant)
        {
            return Some(failure.as_ref() as &(dyn Error + 'static));
        }
        for failure in [
            self.entered_yield_failure.as_ref(),
            self.worker_wait_wake_failure.as_ref(),
            self.entered_yield_wake_failure.as_ref(),
            self.entered_yield_client_failure.as_ref(),
        ] {
            if let Some(failure) = failure.filter(|value| value.kind() == Kind::InternalInvariant) {
                return Some(failure.as_ref() as &(dyn Error + 'static));
            }
        }
        self.callback_failures
            .first()
            .map(|failure| failure as &(dyn Error + 'static))
            .or_else(|| {
                self.failures
                    .front()
                    .map(|failure| failure.as_ref() as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.worker_wait_failure
                    .as_ref()
                    .map(|failure| failure.as_ref() as &(dyn Error + 'static))
            })
            .or_else(|| self.entered_yield_failure.as_ref().map(|v| v.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.worker_wait_wake_failure.as_ref().map(|v| v.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.entered_yield_wake_failure.as_ref().map(|v| v.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.entered_yield_client_failure.as_ref().map(|v| v.as_ref() as &(dyn Error + 'static)))
    }
}

#[derive(Debug)]
struct MciFailureSnapshotAllocationError {
    allocation: TryReserveError,
    callback_failures: usize,
    retained_failures: usize,
    retained_cause: Arc<RuntimeError>,
}

impl fmt::Display for MciFailureSnapshotAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "could not allocate the complete MCI failure snapshot ({}) while {} callback and {} worker/entry cause(s) remain retained; first typed cause: {}",
            self.allocation, self.callback_failures, self.retained_failures, self.retained_cause
        )
    }
}

impl Error for MciFailureSnapshotAllocationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.retained_cause.as_ref())
    }
}

impl MciNotificationLedger {
    pub(super) fn first_pending_failure(&self) -> Option<Arc<RuntimeError>> {
        self.failure_source()
    }

    fn failure_source(&self) -> Option<Arc<RuntimeError>> {
        self.failed_callbacks
            .iter()
            .find(|failure| failure.cause.kind() == Kind::InternalInvariant)
            .map(|failure| Arc::clone(&failure.cause))
            .or_else(|| {
                self.wake_failures
                    .iter()
                    .find(|failure| failure.kind() == Kind::InternalInvariant)
                    .cloned()
            })
            .or_else(|| {
                self.worker_wait_failure
                    .as_ref()
                    .filter(|failure| failure.kind() == Kind::InternalInvariant)
                    .cloned()
            })
            .or_else(|| {
                self.entered_yield_failure
                    .as_ref()
                    .filter(|failure| failure.kind() == Kind::InternalInvariant)
                    .cloned()
            })
            .or_else(|| {
                self.worker_wait_wake_failure
                    .as_ref()
                    .filter(|failure| failure.kind() == Kind::InternalInvariant)
                    .cloned()
            })
            .or_else(|| {
                self.failed_callbacks
                    .front()
                    .map(|failure| Arc::clone(&failure.cause))
            })
            .or_else(|| self.wake_failures.front().cloned())
            .or_else(|| self.worker_wait_failure.clone())
            .or_else(|| self.entered_yield_failure.clone())
            .or_else(|| self.worker_wait_wake_failure.clone())
            .or_else(|| self.entered_yield_wake_failure.clone())
            .or_else(|| self.entered_yield_client_failure.clone())
    }

    fn failure_snapshot(&self) -> Result<MciNotificationFailureCause, TryReserveError> {
        let mut callback_failures = Vec::new();
        callback_failures.try_reserve_exact(self.failed_callbacks.len())?;
        callback_failures.extend(self.failed_callbacks.iter().map(|failure| {
            MciCallbackFailureCause {
                native_device: failure.native_device,
                id: failure.id,
                status: failure.status,
                cause: Arc::clone(&failure.cause),
            }
        }));
        let mut failures = VecDeque::new();
        failures.try_reserve(self.wake_failures.len())?;
        failures.extend(self.wake_failures.iter().cloned());
        Ok(MciNotificationFailureCause {
            callback_failures,
            failures,
            worker_wait_failure: self.worker_wait_failure.clone(),
            worker_wait_wake_failure: self.worker_wait_wake_failure.clone(),
            entered_yield_failure: self.entered_yield_failure.clone(),
            entered_yield_wake_failure: self.entered_yield_wake_failure.clone(),
            entered_yield_client_failure: self.entered_yield_client_failure.clone(),
        })
    }

    fn failure_kind(&self) -> Option<Kind> {
        self.failed_callbacks
            .iter()
            .map(|failure| failure.cause.kind())
            .chain(self.wake_failures.iter().map(|failure| failure.kind()))
            .chain(self.worker_wait_failure.iter().map(|failure| failure.kind()))
            .chain(self.worker_wait_wake_failure.iter().map(|failure| failure.kind()))
            .chain(self.entered_yield_failure.iter().map(|failure| failure.kind()))
            .chain(self.entered_yield_wake_failure.iter().map(|failure| failure.kind()))
            .chain(self.entered_yield_client_failure.iter().map(|failure| failure.kind()))
            .reduce(super::combine_failure_kind)
    }

    pub(super) fn failure_error(
        &mut self,
        message: &'static str,
    ) -> Result<RuntimeError, RuntimeError> {
        let kind = self.failure_kind().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI failure snapshot requested without a retained typed cause",
            )
        })?;
        let retained_cause = self.failure_source().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI failure snapshot lost its retained typed source",
            )
        })?;
        let wake_failure_count = self
            .wake_failures
            .len()
            .saturating_add(usize::from(self.worker_wait_failure.is_some()))
            .saturating_add(usize::from(self.worker_wait_wake_failure.is_some()))
            .saturating_add(usize::from(self.entered_yield_failure.is_some()))
            .saturating_add(usize::from(self.entered_yield_wake_failure.is_some()))
            .saturating_add(usize::from(self.entered_yield_client_failure.is_some()));
        match self.failure_snapshot() {
            Ok(snapshot) => {
                self.wake_failures.clear();
                self.worker_wait_failure = None;
                self.worker_wait_wake_failure = None;
                self.worker_wait_wake_pending = false;
                self.entered_yield_failure = None;
                self.entered_yield_wake_failure = None;
                self.entered_yield_client_failure = None;
                self.entered_yield_wake_pending = false;
                Ok(RuntimeError::with_source(kind, message, snapshot))
            }
            Err(allocation) => Ok(RuntimeError::with_source(
                kind,
                message,
                MciFailureSnapshotAllocationError {
                    allocation,
                    callback_failures: self.failed_callbacks.len(),
                    retained_failures: wake_failure_count,
                    retained_cause,
                },
            )),
        }
    }
}
