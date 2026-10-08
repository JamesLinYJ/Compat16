use crate::RuntimeError;

pub(super) fn combine_process_failure(
    operation: RuntimeError,
    cleanup: RuntimeError,
) -> RuntimeError {
    // Two stopped operations do not establish an invariant violation. The
    // shared typed pair preserves both causes and their actual classifications.
    operation.with_cleanup(
        "DOS child operation failed and its cleanup did not complete",
        cleanup,
    )
}
