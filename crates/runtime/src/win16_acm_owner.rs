//! Exact-generation owner records for retained ACM callback buffers.

use std::sync::Arc;
use win16_abi::GlobalHandle;

use crate::RuntimeError;

#[derive(Debug)]
pub(super) struct OrphanAcmAllocation {
    pub(super) identity: GlobalHandle,
    first_failure: Option<Arc<RuntimeError>>,
}

impl OrphanAcmAllocation {
    pub(super) fn new(identity: GlobalHandle) -> Self {
        Self { identity, first_failure: None }
    }

    pub(super) fn remember_failure(&mut self, error: RuntimeError) -> RuntimeError {
        if let Some(cause) = &self.first_failure {
            return RuntimeError::with_source(
                cause.kind().with_cleanup(error.kind()),
                "MSACM callback allocation retry retained its first typed cleanup cause",
                Arc::clone(cause),
            ).with_cleanup("retrying MSACM callback allocation retirement", error);
        }
        let cause = Arc::new(error);
        let report = RuntimeError::with_source(
            cause.kind(),
            "MSACM callback allocation retained its initial typed cleanup cause",
            Arc::clone(&cause),
        );
        self.first_failure = Some(cause);
        report
    }
}
