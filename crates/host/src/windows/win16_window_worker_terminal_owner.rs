//! Shared terminal ownership between producer Abort requests and shutdown.

use runtime::{DiagnosticKind as Kind, RuntimeError};

use super::terminal_responses::preserve_abort_receipt_after_publication_failure;
use super::{
    WindowWorker, combine_worker_failures,
    shared_terminal_response_failure,
};
use super::shutdown::ShutdownResult;

impl WindowWorker {
    pub(in crate::windows::win16_windows) fn request_abort(
        &self,
    ) -> Result<ShutdownResult, RuntimeError> {
        let publication = self.modal_wake_dispatcher.request_abort_for_modal_failure();
        let Some(request_id) = self.canonical_abort_response.request_id() else {
            return match publication {
                Err(error) => Err(error),
                Ok(()) => self.canonical_abort_response.wait_for_response(),
            };
        };
        if let Err(publication_failure) = publication {
            return match self.canonical_abort_response.response_if_ready() {
                Ok(Some(Ok(receipt))) => Err(
                    preserve_abort_receipt_after_publication_failure(
                        publication_failure, request_id, receipt,
                    ),
                ),
                Ok(Some(Err(worker_failure))) => Err(combine_worker_failures(
                    publication_failure,
                    RuntimeError::with_source(
                        worker_failure.kind(),
                        "canonical Win16 USER Abort worker result",
                        worker_failure,
                    ),
                    "canonical Abort publication and worker failures combined",
                )),
                Ok(None) => Err(publication_failure),
                Err(receive_failure) => Err(combine_worker_failures(
                    publication_failure,
                    receive_failure,
                    "canonical Abort publication and response failures combined",
                )),
            };
        }
        let response = match self.canonical_abort_response.wait_for_response() {
            Ok(response) => response,
            Err(receive_failure) => return Err(receive_failure),
        };
        Ok(response)
    }

    pub(in crate::windows::win16_windows) fn canonical_abort_before_shutdown(
        &self,
    ) -> Result<Option<(ShutdownResult, Option<RuntimeError>)>, RuntimeError> {
        let Some((request_id, publication_failure)) = self
            .modal_wake_dispatcher
            .close_abort_submission_for_shutdown()?
        else {
            return Ok(None);
        };
        let response = match publication_failure.as_ref() {
            Some(publication_failure) => {
                match self.canonical_abort_response.response_if_ready() {
                    Ok(Some(response)) => response,
                    Ok(None) => return Err(shared_terminal_response_failure(
                        publication_failure,
                        "canonical Abort wake publication failed before its response arrived",
                    )),
                    Err(receive_failure) => return Err(combine_worker_failures(
                        shared_terminal_response_failure(
                            publication_failure,
                            "canonical Abort wake publication failed",
                        ),
                        receive_failure,
                        "canonical Abort publication and response failures combined",
                    )),
                }
            }
            None => self.canonical_abort_response.wait_for_response()?,
        };
        if self.canonical_abort_response.request_id() != Some(request_id) {
            let identity_failure = RuntimeError::new(Kind::InternalInvariant,
                "canonical Win16 USER Abort changed identity while shutdown retained its source");
            return match publication_failure {
                Some(publication_failure) => Err(combine_worker_failures(
                    shared_terminal_response_failure(
                        &publication_failure,
                        "canonical Abort wake publication failed",
                    ),
                    identity_failure,
                    "canonical Abort identity and publication failures combined",
                )),
                None => Err(identity_failure),
            };
        }
        Ok(Some((
            response,
            publication_failure.map(|failure| shared_terminal_response_failure(
                &failure,
                "canonical Abort wake publication failed",
            )),
        )))
    }
}
