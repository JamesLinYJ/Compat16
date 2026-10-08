//! Checked callbacks and exact Release-target helpers for OLESVR task exit.

use dos_kernel::DosKernel;
use guest_core::{OwnerId, memory::Memory};
use win16_abi::Access;
use x86_cpu::Cpu;

use super::super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackReturn,
};
use super::super::win16_ole1_server_callbacks::{
    ServerCallbackArguments, ServerCallbackMethod, ServerDocumentCallbackArguments,
    ServerDocumentCallbackMethod,
};
use super::super::win16_ole1_server_state::{
    Ole1DocumentState, Ole1ItemCallbackIdentity, Ole1ReleaseTarget, Ole1ServerDocumentHandle,
    Ole1ServerHandle,
};
use super::server_shutdown::{
    Ole1ServerShutdownPending, Ole1ServerShutdownStep, Ole1ServerShutdownTarget, invariant,
};
use super::{Win16Ole1CallbackFrame, Win16Ole1CallbackStage};
use crate::{RuntimeError, RuntimeHost};

impl super::Win16State {
    pub(super) fn owner_server_callback(
        &self,
        owner: OwnerId,
    ) -> Result<Option<(u64, Ole1ServerShutdownTarget, bool)>, RuntimeError> {
        for frame in self.ole1_callbacks.iter().rev() {
            let target = match frame.stage {
                Win16Ole1CallbackStage::ServerRevokeObject(identity) if identity.owner == owner => {
                    Some(Ole1ServerShutdownTarget::Item(identity))
                }
                Win16Ole1CallbackStage::ServerRelease(target)
                    if self.ole1_server_state.owner_of_release_target(target) == Some(owner)
                        || self
                            .ole1_server_state
                            .pending_release_completion(frame.callback_id.0)
                            .is_some_and(|entry| {
                                entry.owner == owner && entry.target == target
                            }) =>
                {
                    Some(Ole1ServerShutdownTarget::Release(target))
                }
                _ => None,
            };
            if let Some(target) = target {
                return Ok(Some((
                    frame.callback_id.0,
                    target,
                    frame.active_call.is_some(),
                )));
            }
        }
        Ok(None)
    }

    pub(super) fn ole1_callback_is_top(&self, callback_id: u64) -> bool {
        self.ole1_callbacks
            .last()
            .is_some_and(|frame| frame.callback_id.0 == callback_id)
    }

    pub(super) fn next_owner_item(
        &self,
        owner: OwnerId,
    ) -> Option<(Ole1ItemCallbackIdentity, Ole1DocumentState, bool)> {
        self.ole1_server_state
            .owner_documents(owner)
            .find_map(|(document, record)| {
                record.items.first().map(|item| {
                    (
                        Ole1ItemCallbackIdentity {
                            owner,
                            document,
                            document_generation: record.generation,
                            item_generation: item.generation,
                            client_far: item.client_far,
                            object_far: item.object_far,
                        },
                        record.state,
                        item.revoking,
                    )
                })
            })
    }

    pub(super) fn begin_owner_item_release(
        &mut self,
        expected: Ole1ItemCallbackIdentity,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Ole1ServerShutdownStep, RuntimeError> {
        let identity = self
            .ole1_server_state
            .begin_revoke_item(expected.owner, expected.client_far)
            .map_err(|status| invariant("claim OLE1 item Release for task exit", status))?;
        if identity != expected {
            let rollback = self.ole1_server_state.cancel_revoke_item(identity);
            if let Err(status) = rollback {
                return Err(invariant(
                    "rollback mismatched OLE1 item Release claim",
                    status,
                ));
            }
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 task-exit item lookup changed its exact document/object identity",
            ));
        }
        let procedure = match self.ole1_interface_method_address(expected.object_far, 1, 10, memory)
        {
            Ok(procedure) => procedure,
            Err(error) => {
                self.ole1_server_state
                    .cancel_revoke_item(expected)
                    .map_err(|status| {
                        invariant("restore OLE1 item after Release validation", status)
                    })?;
                return Err(super::super::win16_ole1_server_wire::into_runtime_error(
                    error,
                    "validate OLEOBJECT::Release for task shutdown",
                ));
            }
        };
        let arguments = vec![Win16FarCallbackArgument::GuestPointer {
            far: expected.object_far,
            access: Access::Read,
            bytes: 4,
        }];
        match self.enter_no_return_server_callback(
            cpu,
            dos,
            memory,
            procedure,
            arguments,
            Win16Ole1CallbackStage::ServerRevokeObject(expected),
        ) {
            Ok(callback_id) => Ok(Ole1ServerShutdownStep::GuestCallbackEntered {
                callback_id,
                target: Ole1ServerShutdownTarget::Item(expected),
            }),
            Err(primary) => {
                if let Err(status) = self.ole1_server_state.cancel_revoke_item(expected) {
                    return Err(primary.with_cleanup(
                        "restore OLE1 item after checked Release entry failed",
                        invariant("cancel OLE1 task-exit item Release", status),
                    ));
                }
                Err(primary)
            }
        }
    }

    pub(super) fn advance_owner_release_target(
        &mut self,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerShutdownStep, RuntimeError> {
        if let Some(journal) = self
            .ole1_server_state
            .release_completion_for_target(owner, target)
        {
            if let Some(pending) = self.pending_release_events_for_shutdown(owner, target)? {
                return Ok(Ole1ServerShutdownStep::HostContinuation(pending));
            }
            if let Some(frame) = self.ole1_callbacks.iter().find(|frame| {
                matches!(frame.stage, Win16Ole1CallbackStage::ServerRelease(candidate) if candidate == target)
            }) {
                if frame.active_call.is_some() || !self.ole1_callback_is_top(frame.callback_id.0) {
                    return Ok(Ole1ServerShutdownStep::Pending(
                        Ole1ServerShutdownPending::Callback {
                            callback_id: frame.callback_id.0,
                            target: Ole1ServerShutdownTarget::Release(target),
                        },
                    ));
                }
                if self.ole1_server_state.pending_release_completion(journal.callback_id).is_some() {
                    self.finish_ole1_callback(cpu, dos, memory, host)?;
                    return Ok(Ole1ServerShutdownStep::HostAdvanced);
                }
            }
            match super::server_api::finish_release_without_guest_callback_for_dde(
                self, owner, target, host,
            )? {
                super::server_api::Ole1ReleaseEndpointOutcome::Complete => {
                    Ok(Ole1ServerShutdownStep::HostAdvanced)
                }
                super::server_api::Ole1ReleaseEndpointOutcome::PendingEvents(_) => {
                    let pending = self
                        .pending_release_events_for_shutdown(owner, target)?
                        .ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "OLE1 release retry lost its pending EventId receipt",
                            )
                        })?;
                    Ok(Ole1ServerShutdownStep::HostContinuation(pending))
                }
            }
        } else if self
            .ole1_server_state
            .dde_release_chain_owns_target(owner, target)
            .map_err(|status| invariant("check OLE1 DDE release owner", status))?
        {
            let chain = self
                .ole1_server_state
                .owner_dde_release_chains(owner)
                .into_iter()
                .find(|chain| chain.next_target == Some(target))
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 DDE release target has no exact chain owner",
                    )
                })?;
            Ok(Ole1ServerShutdownStep::Pending(
                Ole1ServerShutdownPending::DdeRelease(chain),
            ))
        } else if let Some(procedure) = self.release_procedure(owner, target, memory)? {
            let callback_id = self.enter_no_return_server_callback(
                cpu,
                dos,
                memory,
                procedure.0,
                procedure.1,
                Win16Ole1CallbackStage::ServerRelease(target),
            )?;
            Ok(Ole1ServerShutdownStep::GuestCallbackEntered {
                callback_id,
                target: Ole1ServerShutdownTarget::Release(target),
            })
        } else {
            match super::server_api::finish_release_without_guest_callback_for_dde(
                self, owner, target, host,
            )? {
                super::server_api::Ole1ReleaseEndpointOutcome::Complete => {
                    Ok(Ole1ServerShutdownStep::HostAdvanced)
                }
                super::server_api::Ole1ReleaseEndpointOutcome::PendingEvents(_) => {
                    let pending = self
                        .pending_release_events_for_shutdown(owner, target)?
                        .ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "OLE1 endpoint cleanup lost its exact EventId receipt",
                            )
                        })?;
                    Ok(Ole1ServerShutdownStep::HostContinuation(pending))
                }
            }
        }
    }

    pub(super) fn release_procedure(
        &mut self,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        memory: &mut Memory,
    ) -> Result<Option<(u32, Vec<Win16FarCallbackArgument>)>, RuntimeError> {
        if self.ole1_server_state.owner_of_release_target(target) != Some(owner) {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 shutdown Release target is not owned by the requested task incarnation",
            ));
        }
        match target {
            Ole1ReleaseTarget::Document {
                handle,
                generation,
                server,
                server_generation,
                endpoint,
                endpoint_worker_generation,
                document_atom,
            } => {
                let (guest_handle_published, document_far) = {
                    let document = self
                        .ole1_server_state
                        .document(owner, handle)
                        .filter(|record| {
                            record.generation == generation
                                && record.server == server
                                && record.endpoint == endpoint
                                && record.endpoint_worker_generation == endpoint_worker_generation
                                && record.document_atom == document_atom
                        })
                        .ok_or_else(|| {
                            invariant(
                                "validate OLE1 shutdown document target",
                                super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                            )
                        })?;
                    (
                        document.guest_handle_published,
                        document.server_document_far,
                    )
                };
                let parent = self
                    .ole1_server_state
                    .server(owner, server)
                    .filter(|record| record.generation == server_generation)
                    .ok_or_else(|| {
                        invariant(
                            "validate OLE1 shutdown document parent",
                            super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                        )
                    })?;
                let _ = parent;
                if !guest_handle_published {
                    return Ok(None);
                }
                let Some(document_far) = document_far else {
                    return Ok(None);
                };
                self.release_server_document_callback_scratch(owner, handle, generation)?;
                let procedure = self
                    .ole1_server_document_method_address(
                        document_far,
                        ServerDocumentCallbackMethod::Release.vtable_slot(),
                        memory,
                    )
                    .map_err(|error| {
                        super::super::win16_ole1_server_wire::into_runtime_error(
                            error,
                            "validate OLESERVERDOC::Release for task shutdown",
                        )
                    })?;
                Ok(Some((
                    procedure,
                    ServerDocumentCallbackArguments::Release {
                        server_document_far: document_far,
                    }
                    .encode(),
                )))
            }
            Ole1ReleaseTarget::Server {
                handle,
                generation,
                endpoint,
                endpoint_worker_generation,
                class_atom,
                executable_atom,
            } => {
                let server = self
                    .ole1_server_state
                    .server(owner, handle)
                    .filter(|record| {
                        record.generation == generation
                            && record.endpoint == endpoint
                            && record.endpoint_worker_generation == endpoint_worker_generation
                            && record.class_atom == class_atom
                            && record.executable_atom == executable_atom
                    })
                    .ok_or_else(|| {
                        invariant(
                            "validate OLE1 shutdown server target",
                            super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                        )
                    })?;
                if !server.guest_handle_published {
                    return Ok(None);
                }
                let procedure = self
                    .ole1_server_method_address(
                        server.server_far,
                        ServerCallbackMethod::Release.vtable_slot(),
                        memory,
                    )
                    .map_err(|error| {
                        super::super::win16_ole1_server_wire::into_runtime_error(
                            error,
                            "validate OLESERVER::Release for task shutdown",
                        )
                    })?;
                Ok(Some((
                    procedure,
                    ServerCallbackArguments::Release {
                        server_far: server.server_far,
                    }
                    .encode(),
                )))
            }
        }
    }

    pub(super) fn enter_no_return_server_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        procedure: u32,
        arguments: Vec<Win16FarCallbackArgument>,
        stage: Win16Ole1CallbackStage,
    ) -> Result<u64, RuntimeError> {
        self.ole1_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve OLE1 task-exit Release callback continuation",
                error,
            )
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        self.ole1_callbacks.push(Win16Ole1CallbackFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to: None,
            return_kind: None,
            stage,
            object_effect: None,
            active_call: None,
            pending_proxy_retirement: None,
        });
        if let Err(error) = self.push_callback_kind(super::super::CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.pop();
            return Err(error);
        }
        let active_call = match self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            &arguments,
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        ) {
            Ok(active_call) => active_call,
            Err(primary) => {
                self.ole1_callbacks.pop();
                if let Err(cleanup) =
                    self.retire_callback_binding(super::super::CallbackKind::Ole1, callback_id)
                {
                    return Err(primary.with_cleanup(
                        "retire OLE1 task-exit callback binding after checked entry failed",
                        cleanup,
                    ));
                }
                return Err(primary);
            }
        };
        let Some(frame) = self.ole1_callbacks.last_mut() else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 task-exit callback continuation disappeared after guest entry",
            ));
        };
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 task-exit callback identity changed during checked entry",
            ));
        }
        frame.active_call = Some(active_call);
        Ok(callback_id.0)
    }

    pub(super) fn next_owner_release_wait(
        &self,
        owner: OwnerId,
    ) -> Result<
        Option<(
            Ole1ReleaseTarget,
            crate::Win16HostClassicDdeEndpoint,
            u64,
            Vec<crate::Win16ClassicDdeConversationId>,
        )>,
        RuntimeError,
    > {
        for (document, record) in self.ole1_server_state.owner_documents(owner) {
            if !record.conversations.is_empty() {
                let target = self.document_release_identity(owner, document)?;
                return Ok(Some((
                    target,
                    record.endpoint,
                    record.endpoint_worker_generation,
                    record.conversations.keys().copied().collect(),
                )));
            }
        }
        for (server, record) in self.ole1_server_state.owner_servers(owner) {
            if !record.conversations.is_empty() {
                let target = self.server_release_identity(owner, server)?;
                return Ok(Some((
                    target,
                    record.endpoint,
                    record.endpoint_worker_generation,
                    record.conversations.keys().copied().collect(),
                )));
            }
        }
        Ok(None)
    }

    pub(super) fn next_ready_document_release(
        &self,
        owner: OwnerId,
    ) -> Result<Option<Ole1ReleaseTarget>, RuntimeError> {
        for (handle, document) in self.ole1_server_state.owner_documents(owner) {
            if document.state != Ole1DocumentState::Revoking {
                continue;
            }
            match self
                .ole1_server_state
                .document_release_target(owner, handle)
            {
                Ok(target) => return Ok(Some(target)),
                Err(super::super::win16_ole1_server_state::OLE_WAIT_FOR_RELEASE) => {}
                Err(status) => return Err(invariant("select OLE1 document Release", status)),
            }
        }
        Ok(None)
    }

    pub(super) fn document_release_identity(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<Ole1ReleaseTarget, RuntimeError> {
        let document = self
            .ole1_server_state
            .document(owner, handle)
            .ok_or_else(|| {
                invariant(
                    "read OLE1 shutdown document identity",
                    super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                )
            })?;
        let server = self
            .ole1_server_state
            .server(owner, document.server)
            .ok_or_else(|| {
                invariant(
                    "read OLE1 shutdown document parent",
                    super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                )
            })?;
        Ok(Ole1ReleaseTarget::Document {
            handle,
            generation: document.generation,
            server: document.server,
            server_generation: server.generation,
            endpoint: document.endpoint,
            endpoint_worker_generation: document.endpoint_worker_generation,
            document_atom: document.document_atom,
        })
    }

    fn server_release_identity(
        &self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<Ole1ReleaseTarget, RuntimeError> {
        let server = self
            .ole1_server_state
            .server(owner, handle)
            .ok_or_else(|| {
                invariant(
                    "read OLE1 shutdown server identity",
                    super::super::win16_ole1_server_state::OLE_ERROR_HANDLE,
                )
            })?;
        Ok(Ole1ReleaseTarget::Server {
            handle,
            generation: server.generation,
            endpoint: server.endpoint,
            endpoint_worker_generation: server.endpoint_worker_generation,
            class_atom: server.class_atom,
            executable_atom: server.executable_atom,
        })
    }
}
