//! Owner-scoped OLESVR shutdown progress.
//!
//! This is deliberately a server-side barrier. It retires the exact
//! OLESERVER/OLESERVERDOC registrations and their Release callbacks; it does
//! not claim that client-document/proxy state or unrelated task resources are
//! quiescent.

use dos_kernel::DosKernel;
use guest_core::{OwnerId, memory::Memory};
use x86_cpu::Cpu;

use super::super::win16_ole1_server_callback::Ole1ServerCallbackCompletion;
use super::super::win16_ole1_server_state::{
    Ole1DocumentState, Ole1ItemCallbackIdentity, Ole1PendingReleaseEvents, Ole1RegistrationState,
    Ole1ReleaseTarget, Ole1ServerDdeReleaseChain, Ole1ServerDocumentHandle, Ole1ServerHandle,
    Ole1ServerPreparedCallbackPhase, Ole1UnpublishedCleanup,
};
use super::Win16Ole1CallbackStage;
use crate::{RuntimeError, RuntimeHost};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerShutdownTarget {
    Item(Ole1ItemCallbackIdentity),
    Release(Ole1ReleaseTarget),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerShutdownPending {
    Callback {
        callback_id: u64,
        target: Ole1ServerShutdownTarget,
    },
    /// The OLE callback ledger contains a continuation whose stage does not
    /// prove it belongs to this OLESVR target. Do not enter a second checked
    /// callback or claim shutdown progress until it retires.
    UnscopedCallback {
        callback_id: u64,
    },
    /// Open/Create/Edit owns a provisional document through the classic-DDE
    /// callback ledger, including its retained returned-value finish retry.
    PreparedDocumentCallback {
        callback_id: Option<u64>,
        document: Ole1ServerDocumentHandle,
        generation: u64,
    },
    Protocol {
        target: Ole1ReleaseTarget,
        endpoint: crate::Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        conversations: Vec<crate::Win16ClassicDdeConversationId>,
    },
    DdeRelease(Ole1ServerDdeReleaseChain),
    UnpublishedCleanup(Ole1UnpublishedCleanup),
    BlockedServer {
        server: Ole1ServerHandle,
        generation: u64,
        endpoint: crate::Win16HostClassicDdeEndpoint,
        worker_generation: u64,
    },
    DeferredServerWork {
        server: Ole1ServerHandle,
        generation: u64,
        endpoint: crate::Win16HostClassicDdeEndpoint,
        worker_generation: u64,
    },
    ItemStillRegistered {
        identity: Ole1ItemCallbackIdentity,
        document: Ole1ServerDocumentHandle,
        document_generation: u64,
        endpoint: crate::Win16HostClassicDdeEndpoint,
        worker_generation: u64,
    },
    OrphanReleaseJournal {
        callback_id: u64,
        target: Ole1ReleaseTarget,
    },
    /// StdCloseDocument has an exact document-generation proof awaiting its
    /// ACK Post terminal. Do not claim the server-side inventory is drained
    /// until the DDE dispatcher consumes or cancels that proof.
    CloseDocumentProof {
        document: Ole1ServerDocumentHandle,
        generation: u64,
    },
}

/// One unit of server-side shutdown progress. `HostContinuation` carries the
/// exact RetireEndpoint EventId snapshot; the dispatcher must drain it and
/// call this hook again. `ServerSideDrained` says nothing about OLE client
/// tables, client proxies, or the rest of task teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerShutdownStep {
    GuestCallbackEntered {
        callback_id: u64,
        target: Ole1ServerShutdownTarget,
    },
    HostAdvanced,
    HostContinuation(Ole1PendingReleaseEvents),
    Pending(Ole1ServerShutdownPending),
    ServerSideDrained,
}

impl super::Win16State {
    /// Advance one exact server-side task-exit release step. The caller keeps
    /// its ordinary task/barrier owner alive and repeats this hook after a
    /// callback return, EventId acknowledgement, or protocol update.
    pub(in crate::win16_runtime) fn progress_ole1_server_shutdown(
        &mut self,
        owner: OwnerId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerShutdownStep, RuntimeError> {
        // These callbacks live in classic_dde.callbacks, not ole1_callbacks.
        // Let its checked return/finish path retire the frame before any
        // shutdown cascade can quarantine its parent or free guest scratch.
        if let Some((callback_id, proof)) =
            self.classic_dde.callbacks.iter().rev().find_map(|frame| {
                if frame.continuation.owner != owner {
                    return None;
                }
                match &frame.continuation.completion {
                    Ole1ServerCallbackCompletion::DdeExecute {
                        prepared_document: Some(proof),
                        ..
                    } => Some((frame.callback_id.0, *proof)),
                    _ => None,
                }
            })
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::PreparedDocumentCallback {
                    callback_id: Some(callback_id),
                    document: proof.document,
                    generation: proof.document_generation,
                },
            ));
        }
        if let Some((document, record)) =
            self.ole1_server_state
                .owner_documents(owner)
                .find(|(_, record)| {
                    record.prepared_callback_scratch.is_some()
                        && record.prepared_callback_completion.is_none()
                })
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::PreparedDocumentCallback {
                    callback_id: None,
                    document,
                    generation: record.generation,
                },
            ));
        }
        // A pre-entry cancellation can outlive its caller after a cleanup
        // failure. Its durable result authorizes finish progress; scratch
        // presence alone must not park this already-quarantined document.
        let prepared_cleanup =
            self.ole1_server_state
                .owner_documents(owner)
                .find_map(|(document, record)| {
                    record
                        .prepared_callback_completion
                        .filter(|completion| {
                            completion.phase != Ole1ServerPreparedCallbackPhase::Complete
                        })
                        .map(|_| (document, record.generation))
                });
        if let Some((document, generation)) = prepared_cleanup {
            return match self.advance_prepared_server_document_completion(
                owner, document, generation, memory, host,
            )? {
                Ok(_) => Ok(Ole1ServerShutdownStep::HostAdvanced),
                Err(pending) => Ok(Ole1ServerShutdownStep::HostContinuation(pending)),
            };
        }

        if self.retry_pending_ole1_server_release_cascade(owner, cpu, dos, memory)? {
            if let Some((callback_id, target, true)) = self.owner_server_callback(owner)? {
                return Ok(Ole1ServerShutdownStep::GuestCallbackEntered {
                    callback_id,
                    target,
                });
            }
            return Ok(Ole1ServerShutdownStep::HostAdvanced);
        }

        if let Some(cleanup) = self
            .pending_ole1_unpublished_cleanups(owner)
            .into_iter()
            .next()
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::UnpublishedCleanup(cleanup),
            ));
        }

        if let Some(chain) = self
            .ole1_server_state
            .owner_dde_release_chains(owner)
            .into_iter()
            .next()
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::DdeRelease(chain),
            ));
        }

        if let Some((callback_id, target, active)) = self.owner_server_callback(owner)? {
            if active {
                return Ok(Ole1ServerShutdownStep::Pending(
                    Ole1ServerShutdownPending::Callback {
                        callback_id,
                        target,
                    },
                ));
            }
            if !self.ole1_callback_is_top(callback_id) {
                return Ok(Ole1ServerShutdownStep::Pending(
                    Ole1ServerShutdownPending::Callback {
                        callback_id,
                        target,
                    },
                ));
            }
            if let Ole1ServerShutdownTarget::Release(release_target) = target {
                if let Some(pending) =
                    self.pending_release_events_for_shutdown(owner, release_target)?
                {
                    return Ok(Ole1ServerShutdownStep::HostContinuation(pending));
                }
            }
            self.finish_ole1_callback(cpu, dos, memory, host)?;
            return Ok(Ole1ServerShutdownStep::HostAdvanced);
        }
        if let Some((document, generation)) = self
            .ole1_server_state
            .owner_pending_close_document_proofs(owner)
            .into_iter()
            .next()
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::CloseDocumentProof {
                    document,
                    generation,
                },
            ));
        }
        if let Some(frame) = self.ole1_callbacks.last() {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::UnscopedCallback {
                    callback_id: frame.callback_id.0,
                },
            ));
        }

        // XP drains outstanding document/item notifications before it sends
        // TERMINATE or calls OLESERVERDOC::Release. Do not start an item
        // callback while the registered server is blocked or has deferred
        // work that still owns the endpoint.
        if let Some((handle, server)) = self
            .ole1_server_state
            .owner_servers(owner)
            .find(|(_, server)| server.blocked)
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::BlockedServer {
                    server: handle,
                    generation: server.generation,
                    endpoint: server.endpoint,
                    worker_generation: server.endpoint_worker_generation,
                },
            ));
        }
        if let Some((handle, server)) =
            self.ole1_server_state
                .owner_servers(owner)
                .find(|(_, server)| {
                    !server.deferred_events.is_empty()
                        || server.in_flight_deferred.is_some()
                        || server.processing_deferred_message
                })
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::DeferredServerWork {
                    server: handle,
                    generation: server.generation,
                    endpoint: server.endpoint,
                    worker_generation: server.endpoint_worker_generation,
                },
            ));
        }

        if let Some(entry) = self
            .ole1_server_state
            .owner_item_release_journals(owner)
            .into_iter()
            .next()
        {
            self.finish_server_item_release_completion(entry.callback_id, entry.identity, host)?;
            return Ok(Ole1ServerShutdownStep::HostAdvanced);
        }

        if let Some(entry) = self
            .ole1_server_state
            .owner_release_journals(owner)
            .into_iter()
            .next()
        {
            if entry.phase == super::super::win16_ole1_server_state::Ole1ReleasePhase::Committed {
                self.ole1_server_state
                    .finalize_release_completion(entry.callback_id, entry.target)
                    .map_err(|status| invariant("finalize orphan OLE1 release journal", status))?;
                return Ok(Ole1ServerShutdownStep::HostAdvanced);
            }
            if let Some(pending) = self.pending_release_events_for_shutdown(owner, entry.target)? {
                return Ok(Ole1ServerShutdownStep::HostContinuation(pending));
            }
            if self
                .ole1_callbacks
                .iter()
                .any(|frame| matches!(frame.stage, Win16Ole1CallbackStage::ServerRelease(target) if target == entry.target))
            {
                return Ok(Ole1ServerShutdownStep::Pending(
                    Ole1ServerShutdownPending::OrphanReleaseJournal {
                        callback_id: entry.callback_id,
                        target: entry.target,
                    },
                ));
            }
            match super::server_api::finish_release_without_guest_callback_for_dde(
                self,
                owner,
                entry.target,
                host,
            )? {
                super::server_api::Ole1ReleaseEndpointOutcome::Complete => {
                    return Ok(Ole1ServerShutdownStep::HostAdvanced);
                }
                super::server_api::Ole1ReleaseEndpointOutcome::PendingEvents(_) => {
                    let pending = self
                        .pending_release_events_for_shutdown(owner, entry.target)?
                        .ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "OLE1 shutdown endpoint wait has no exact EventId receipt",
                            )
                        })?;
                    return Ok(Ole1ServerShutdownStep::HostContinuation(pending));
                }
            }
        }

        if let Some((identity, expected_document_state, revoking)) = self.next_owner_item(owner) {
            if revoking {
                if let Some(entry) = self
                    .ole1_server_state
                    .owner_item_release_journals(owner)
                    .into_iter()
                    .find(|entry| entry.identity == identity)
                {
                    self.finish_server_item_release_completion(entry.callback_id, identity, host)?;
                    return Ok(Ole1ServerShutdownStep::HostAdvanced);
                }
                let document = self
                    .ole1_server_state
                    .document(owner, identity.document)
                    .ok_or_else(|| {
                        invariant(
                            "resolve OLE1 item document",
                            super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                        )
                    })?;
                return Ok(Ole1ServerShutdownStep::Pending(
                    Ole1ServerShutdownPending::ItemStillRegistered {
                        identity,
                        document: identity.document,
                        document_generation: identity.document_generation,
                        endpoint: document.endpoint,
                        worker_generation: document.endpoint_worker_generation,
                    },
                ));
            }
            if expected_document_state != Ole1DocumentState::Active {
                let document = self
                    .ole1_server_state
                    .document(owner, identity.document)
                    .ok_or_else(|| {
                        invariant(
                            "resolve OLE1 item document before task-exit Release",
                            super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                        )
                    })?;
                return Ok(Ole1ServerShutdownStep::Pending(
                    Ole1ServerShutdownPending::ItemStillRegistered {
                        identity,
                        document: identity.document,
                        document_generation: identity.document_generation,
                        endpoint: document.endpoint,
                        worker_generation: document.endpoint_worker_generation,
                    },
                ));
            }
            return self.begin_owner_item_release(identity, cpu, dos, memory);
        }

        // Mark every server before waiting on any one server's protocol
        // conversations. Otherwise a later Active server can own a
        // conversation that is never sent TERMINATE because an earlier
        // Revoking server is already waiting for its Release target.
        let active_server = self
            .ole1_server_state
            .owner_servers(owner)
            .find(|(_, record)| record.state == Ole1RegistrationState::Active)
            .map(|(handle, _)| handle);
        if let Some(handle) = active_server {
            self.ole1_server_state
                .mark_server_revoking(owner, handle)
                .map_err(|status| invariant("mark OLE1 server revoking for task exit", status))?;
            return Ok(Ole1ServerShutdownStep::HostAdvanced);
        }

        let next_post = {
            let mut next_post = None;
            for (server_handle, _) in self.ole1_server_state.owner_servers(owner) {
                let posts = self
                    .ole1_server_state
                    .pending_termination_posts(owner, server_handle)
                    .map_err(|status| invariant("read OLE1 task-exit TERMINATE journal", status))?;
                if let Some(post) = posts.into_iter().next() {
                    next_post = Some(post);
                    break;
                }
            }
            next_post
        };
        if let Some(post) = next_post {
            super::server_api::post_termination_exact(
                &mut self.ole1_server_state,
                owner,
                post,
                host,
            )?;
            return Ok(Ole1ServerShutdownStep::HostAdvanced);
        }

        if let Some((target, endpoint, worker_generation, conversations)) =
            self.next_owner_release_wait(owner)?
        {
            return Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::Protocol {
                    target,
                    endpoint,
                    worker_generation,
                    conversations,
                },
            ));
        }

        if let Some(target) = self.next_ready_document_release(owner)? {
            return self.advance_owner_release_target(owner, target, cpu, dos, memory, host);
        }

        let first_server = self
            .ole1_server_state
            .owner_servers(owner)
            .next()
            .map(|(handle, server)| (handle, server.documents.is_empty()));
        if let Some((handle, documents_empty)) = first_server {
            if documents_empty {
                match self.ole1_server_state.server_release_target(owner, handle) {
                    Ok(target) => {
                        return self
                            .advance_owner_release_target(owner, target, cpu, dos, memory, host);
                    }
                    Err(super::super::win16_ole1_server_state::OLE_WAIT_FOR_RELEASE) => {}
                    Err(status) => return Err(invariant("select OLE1 server Release", status)),
                }
            }
        }

        if self.ole1_server_state.owner_has_lifecycle_work(owner) {
            let first_document =
                self.ole1_server_state
                    .owner_documents(owner)
                    .next()
                    .map(|(document, record)| {
                        (
                            document,
                            record.server,
                            record.endpoint,
                            record.endpoint_worker_generation,
                            record.conversations.keys().copied().collect::<Vec<_>>(),
                        )
                    });
            if let Some((document, server, endpoint, worker_generation, conversations)) =
                first_document
            {
                if !self
                    .ole1_server_state
                    .owner_servers(owner)
                    .any(|(candidate, _)| candidate == server)
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 task-exit document has no owner-matched server parent",
                    ));
                }
                let target = self
                    .ole1_server_state
                    .document_release_target(owner, document)
                    .ok();
                if let Some(target) = target {
                    return self
                        .advance_owner_release_target(owner, target, cpu, dos, memory, host);
                }
                if !conversations.is_empty() {
                    return Ok(Ole1ServerShutdownStep::Pending(
                        Ole1ServerShutdownPending::Protocol {
                            target: self.document_release_identity(owner, document)?,
                            endpoint,
                            worker_generation,
                            conversations,
                        },
                    ));
                }
                return Ok(Ole1ServerShutdownStep::Pending(
                    Ole1ServerShutdownPending::DeferredServerWork {
                        server,
                        generation: self
                            .ole1_server_state
                            .server(owner, server)
                            .map(|parent| parent.generation)
                            .ok_or_else(|| {
                                invariant(
                                    "resolve OLE1 deferred document parent",
                                    super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                                )
                            })?,
                        endpoint,
                        worker_generation,
                    },
                ));
            }
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 server-side work remains without a live server, document, or owned cleanup journal",
            ));
        }

        Ok(Ole1ServerShutdownStep::ServerSideDrained)
    }

    pub(super) fn pending_release_events_for_shutdown(
        &self,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
    ) -> Result<Option<Ole1PendingReleaseEvents>, RuntimeError> {
        Ok(self
            .pending_ole1_release_for_endpoint(owner, release_target_endpoint(target))?
            .filter(|pending| !pending.pending_events.is_empty()))
    }

    /// Enter the next Release in the parent cascade after a task-exit
    /// callback has completed. Public Revoke APIs keep their own return frame;
    /// this path deliberately has no guest return address.
    pub(in crate::win16_runtime) fn begin_ole1_server_shutdown_release_callback(
        &mut self,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<u64, RuntimeError> {
        let (procedure, arguments) = self.release_procedure(owner, target, memory)?.ok_or_else(
            || {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLESVR Release cascade selected a target without a guest Release interface",
                )
            },
        )?;
        self.enter_no_return_server_callback(
            cpu,
            dos,
            memory,
            procedure,
            arguments,
            Win16Ole1CallbackStage::ServerRelease(target),
        )
    }
}

fn release_target_identity(target: Ole1ReleaseTarget) -> (crate::Win16HostClassicDdeEndpoint, u64) {
    match target {
        Ole1ReleaseTarget::Document {
            endpoint,
            endpoint_worker_generation,
            ..
        }
        | Ole1ReleaseTarget::Server {
            endpoint,
            endpoint_worker_generation,
            ..
        } => (endpoint, endpoint_worker_generation),
    }
}

pub(super) fn release_target_endpoint(
    target: Ole1ReleaseTarget,
) -> crate::Win16HostClassicDdeEndpoint {
    release_target_identity(target).0
}

pub(super) fn invariant(action: &str, status: u16) -> RuntimeError {
    RuntimeError::new(
        crate::DiagnosticKind::InternalInvariant,
        format!("{action} ({status})"),
    )
}
