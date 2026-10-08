//! Checked dispatch for public Win16 OLE 1.0 object methods.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Access, Win16ReturnKind};
use x86_cpu::Cpu;

use super::super::far_callback::{Win16FarCallbackArgument, Win16FarCallbackConvention};
use super::super::{CallbackKind, Win16State};
use super::methods::{
    OLEOBJECT_BYTES, client_document_argument, client_pointer_argument, ole1_method_contract,
    required_protocol,
};
use super::{
    OLE1_ERROR_ADDRESS, OLE1_ERROR_HANDLE, OLE1_ERROR_OBJECT, OLE1_ERROR_PROTOCOL,
    Win16Ole1CallbackFrame, Win16Ole1CallbackStage,
    Win16Ole1AsyncCommand, Win16Ole1ClientDocHandle, Win16Ole1ObjectEffect,
    Win16Ole1ReleaseMethodExpectation, Win16Ole1SourceProbePolicy,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn begin_ole1_save_to_stream(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        _host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        object_far: u32,
        stream_far: u32,
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_ole1_object_method(
            cpu,
            dos,
            memory,
            _host,
            return_to,
            return_kind,
            3,
            object_far,
            &[stream_far],
        )
    }

    pub(super) fn begin_ole1_object_method(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        _host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        ordinal: u16,
        object_far: u32,
        arguments: &[u32],
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(contract) = ole1_method_contract(ordinal) else {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_ERROR_OBJECT),
                return_kind,
            );
        };
        if arguments.len() != contract.arguments.len() {
            let value = if contract.null_on_failure {
                0
            } else {
                u32::from(OLE1_ERROR_ADDRESS)
            };
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                value,
                return_kind,
            );
        }

        let vtable_far = match self.ole1_object_vtable(object_far, memory) {
            Ok(vtable) => vtable,
            Err(status) => {
                let value = if contract.null_on_failure {
                    0
                } else {
                    u32::from(status)
                };
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    value,
                    return_kind,
                );
            }
        };

        if let Some(document_argument) = client_document_argument(ordinal) {
            let Some(document) = arguments.get(document_argument).copied() else {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_ADDRESS),
                    return_kind,
                );
            };
            let handle = Win16Ole1ClientDocHandle::from_guest_long(document);
            if !self.ole1_client_documents.documents.contains_key(&handle) {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_HANDLE),
                    return_kind,
                );
            }
        }

        if let Some((protocol_argument, expected)) = required_protocol(ordinal) {
            let Some(protocol_far) = arguments.get(protocol_argument).copied() else {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_ADDRESS),
                    return_kind,
                );
            };
            let protocol_matches = match self.ole1_string_matches(protocol_far, expected, memory) {
                Ok(matches) => matches,
                Err(status) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        return_kind,
                    );
                }
            };
            if !protocol_matches {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_PROTOCOL),
                    return_kind,
                );
            }
        }

        let mut callback_arguments = Vec::new();
        callback_arguments
            .try_reserve(contract.arguments.len() + 1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 OLE1 callback arguments",
                    error,
                )
            })?;
        callback_arguments.push(Win16FarCallbackArgument::GuestPointer {
            far: object_far,
            access: Access::Read,
            bytes: OLEOBJECT_BYTES as u32,
        });
        if let Err(status) = self.append_ole1_callback_arguments(
            &mut callback_arguments,
            arguments,
            contract.arguments,
            memory,
        ) {
            let value = if contract.null_on_failure {
                0
            } else {
                u32::from(status)
            };
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                value,
                return_kind,
            );
        }

        let method = match self.ole1_method_address(vtable_far, contract.slot, memory) {
            Ok(method) => method,
            Err(status) => {
                let value = if contract.null_on_failure {
                    0
                } else {
                    u32::from(status)
                };
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    value,
                    return_kind,
                );
            }
        };

        let mut operation_identity = None;
        let mut client_callback_slot = None;
        if let Some(client_argument) = client_pointer_argument(ordinal) {
            let Some(client_far) = arguments.get(client_argument).copied() else {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_ADDRESS),
                    return_kind,
                );
            };
            if let Err(error) = self.ole1_client_callback_address(client_far, memory) {
                let status = error.status_or_runtime()?;
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    return_kind,
                );
            }
            let operation_id = match self.ole1_client_documents.reserve_operation() {
                Ok(operation_id) => operation_id,
                Err(status) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        return_kind,
                    );
                }
            };
            let callback_argument_index = 1 + contract.arguments[..client_argument]
                .iter()
                .filter(|argument| {
                    !matches!(
                        argument,
                        super::methods::Ole1MethodArgument::ValidateOnlyString
                    )
                })
                .count();
            match callback_arguments.get(callback_argument_index) {
                Some(Win16FarCallbackArgument::GuestPointer {
                    far,
                    access: Access::Read,
                    bytes: 4,
                }) if *far == client_far => {
                    operation_identity = Some(operation_id);
                    client_callback_slot = Some(callback_argument_index);
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client parameter did not map to its checked callback stack slot",
                    ));
                }
            }
        }

        let query_protocol = if ordinal == 30 {
            let Some(protocol_far) = arguments.first().copied() else {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    return_kind,
                );
            };
            match self.ole1_read_string(protocol_far, memory) {
                Ok(protocol) => Some(protocol),
                Err(_) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                }
            }
        } else {
            None
        };
        let protocol_alias_owner = if ordinal == 30 {
            match self
                .ole1_client_documents
                .reserve_protocol_alias(object_far)
            {
                Ok(owner) => Some(owner),
                Err(_) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                }
            }
        } else {
            None
        };
        let object_effect = match ordinal {
            6 | 7 | 32 => {
                let document_argument = match ordinal {
                    6 => 1,
                    7 | 32 => 2,
                    _ => unreachable!(),
                };
                let output_argument = match ordinal {
                    6 => 3,
                    7 | 32 => 4,
                    _ => unreachable!(),
                };
                let client_argument = client_pointer_argument(ordinal)
                    .expect("creation method has an LPOLECLIENT parameter");
                let Some(document) = arguments.get(document_argument).copied() else {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(OLE1_ERROR_ADDRESS),
                        return_kind,
                    );
                };
                let Some(output_far) = arguments.get(output_argument).copied() else {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(OLE1_ERROR_ADDRESS),
                        return_kind,
                    );
                };
                let Some(client_far) = arguments.get(client_argument).copied() else {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(OLE1_ERROR_ADDRESS),
                        return_kind,
                    );
                };
                if let Err(error) = self.ole1_client_callback_address(client_far, memory) {
                    let status = error.status_or_runtime()?;
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        return_kind,
                    );
                }
                let Some(operation_id) = operation_identity else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 creation method has no operation identity",
                    ));
                };
                Some(Win16Ole1ObjectEffect::Add {
                    document: Win16Ole1ClientDocHandle::from_guest_long(document),
                    output_far,
                    client_far,
                    operation_id,
                })
            }
            2 | 40 => {
                let pending_document = match self
                    .ole1_client_documents
                    .reserve_pending_release(object_far)
                {
                    Ok(document) => document,
                    Err(status) => {
                        return self.complete_return(
                            &mut cpu.regs,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            u32::from(status),
                            return_kind,
                        );
                    }
                };
                let operation_id = match self.ole1_client_documents.reserve_operation() {
                    Ok(operation_id) => operation_id,
                    Err(status) => {
                        return self.complete_return(
                            &mut cpu.regs,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            u32::from(status),
                            return_kind,
                        );
                    }
                };
                Some(Win16Ole1ObjectEffect::Remove {
                    object_far,
                    operation_id,
                    pending_document,
                })
            }
            30 => match query_protocol {
                Some(protocol) => Some(Win16Ole1ObjectEffect::ProtocolAlias {
                    owner: protocol_alias_owner,
                    protocol,
                }),
                None => None,
            },
            _ => None,
        };
        if let Some(Win16Ole1ObjectEffect::Add {
            document,
            output_far,
            ..
        }) = &object_effect
        {
            if let Err(status) = self.ole1_client_documents.reserve_object_slot(*document) {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    return_kind,
                );
            }
            if let Err(status) = self
                .ole1_client_documents
                .reserve_pending_operation(*document)
            {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    return_kind,
                );
            }
            let output = match self.checked_ole1_pointer(
                *output_far,
                Access::Write,
                4,
                OLE1_ERROR_ADDRESS,
                memory,
            ) {
                Ok(pointer) => pointer,
                Err(status) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        return_kind,
                    );
                }
            };
            if self.selectors.write(memory, output, &[0; 4]).is_err() {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_ADDRESS),
                    return_kind,
                );
            }
        }

        self.ole1_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 OLE1 callback continuation",
                error,
            )
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let mut operation_proxy_id = None;
        if let Some(Win16Ole1ObjectEffect::Add {
            document,
            client_far,
            operation_id,
            ..
        }) = &object_effect
        {
            if let Err(status) = self.ole1_client_documents.begin_pending_creation(
                *document,
                *operation_id,
                Some(callback_id.0),
                Some(object_far),
                source_probe_policy_for_method(ordinal),
                None,
                async_busy_command_for_method(ordinal),
                *client_far,
                expected_creation_release_method(ordinal),
            ) {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    return_kind,
                );
            }
            let Some(argument_index) = client_callback_slot else {
                self.ole1_client_documents.finish_operation(*operation_id);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 creation method lost its client callback slot",
                ));
            };
            if !matches!(
                callback_arguments.get(argument_index),
                Some(Win16FarCallbackArgument::GuestPointer {
                    far,
                    access: Access::Read,
                    bytes: 4,
                }) if *far == *client_far
            ) {
                self.ole1_client_documents.finish_operation(*operation_id);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client parameter changed before proxy substitution",
                ));
            }
            let (proxy_far, proxy_id) = match self
                .ole1_client_proxy_for_call(*client_far, Some(*operation_id), memory)
            {
                Ok(proxy) => proxy,
                Err(error) => {
                    self.ole1_client_documents.finish_operation(*operation_id);
                    let status = error.status_or_runtime()?;
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        return_kind,
                    );
                }
            };
            if let Err(status) = self
                .ole1_client_documents
                .set_pending_creation_proxy(*operation_id, proxy_id)
            {
                self.ole1_client_documents.finish_operation(*operation_id);
                let primary = RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("could not bind OLE1 operation proxy (status {status})"),
                );
                return Err(match self.retire_ole1_client_operation_proxy(proxy_id) {
                    Ok(()) => primary,
                    Err(cleanup) => primary.with_cleanup(
                        "retire operation-specific OLE1 proxy after pending binding failed",
                        cleanup,
                    ),
                });
            }
            match callback_arguments.get_mut(argument_index) {
                Some(Win16FarCallbackArgument::GuestPointer {
                    far,
                    access: Access::Read,
                    bytes: 4,
                }) if *far == *client_far => *far = proxy_far,
                _ => {
                    self.ole1_client_documents.finish_operation(*operation_id);
                    let primary = RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client parameter changed during proxy substitution",
                    );
                    return Err(match self.retire_ole1_client_operation_proxy(proxy_id) {
                        Ok(()) => primary,
                        Err(cleanup) => primary.with_cleanup(
                            "retire operation-specific OLE1 proxy after argument mapping failed",
                            cleanup,
                        ),
                    });
                }
            }
            operation_proxy_id = Some(proxy_id);
        }
        match &object_effect {
            Some(Win16Ole1ObjectEffect::Remove {
                object_far,
                operation_id,
                pending_document: Some(document),
            }) => {
                if let Err(status) = self.ole1_client_documents.begin_pending_release(
                    *document,
                    *operation_id,
                    Some(callback_id.0),
                    *object_far,
                ) {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        return_kind,
                    );
                }
            }
            _ => {}
        }
        let pending_operation_id = object_effect.as_ref().and_then(|effect| match effect {
            Win16Ole1ObjectEffect::Add { operation_id, .. }
            | Win16Ole1ObjectEffect::Remove { operation_id, .. } => Some(*operation_id),
            Win16Ole1ObjectEffect::ProtocolAlias { .. } => None,
        });
        self.ole1_callbacks.push(Win16Ole1CallbackFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to: Some(return_to),
            return_kind: Some(return_kind),
            stage: Win16Ole1CallbackStage::ObjectMethod,
            object_effect,
            pending_proxy_retirement: None,
            active_call: None,
        });
        if let Err(error) = self.push_callback_kind(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.pop();
            if let Some(operation_id) = pending_operation_id {
                self.ole1_client_documents.finish_operation(operation_id);
            }
            return Err(match operation_proxy_id {
                Some(proxy_id) => match self.retire_ole1_client_operation_proxy(proxy_id) {
                    Ok(()) => error,
                    Err(cleanup) => error.with_cleanup(
                        "retire operation-specific OLE1 proxy after callback setup failed",
                        cleanup,
                    ),
                },
                None => error,
            });
        }

        let active_call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            method,
            &callback_arguments,
            Win16FarCallbackConvention::Pascal,
            contract.callback_return,
        );
        match active_call {
            Ok(active_call) => {
                let frame = self.ole1_callbacks.last_mut().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 OLE1 callback frame disappeared after guest entry",
                    )
                })?;
                frame.active_call = Some(active_call);
                Ok(None)
            }
            Err(primary) => {
                if let Some(operation_id) = pending_operation_id {
                    self.ole1_client_documents.finish_operation(operation_id);
                }
                self.ole1_callbacks.pop().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 OLE1 callback frame disappeared during entry rollback",
                    )
                })?;
                let mut primary = primary;
                if let Err(cleanup) = self.retire_callback_binding(CallbackKind::Ole1, callback_id)
                {
                    primary = primary.with_cleanup(
                        "retire OLE1 callback binding after checked entry failed",
                        cleanup,
                    );
                }
                if let Some(proxy_id) = operation_proxy_id {
                    if let Err(cleanup) = self.retire_ole1_client_operation_proxy(proxy_id) {
                        primary = primary.with_cleanup(
                            "retire operation-specific OLE1 proxy after checked entry failed",
                            cleanup,
                        );
                    }
                }
                Err(primary)
            }
        }
    }
}

fn source_probe_policy_for_method(ordinal: u16) -> Win16Ole1SourceProbePolicy {
    match ordinal {
        // XP's Clone implementation calls PROBE_CREATE_ASYNC on its input.
        6 => Win16Ole1SourceProbePolicy::ProbeCreateAsync,
        // CopyFromLink and ObjectConvert use the ordinary PROBE_ASYNC contract.
        _ => Win16Ole1SourceProbePolicy::ProbeAsync,
    }
}

fn async_busy_command_for_method(ordinal: u16) -> Option<Win16Ole1AsyncCommand> {
    match ordinal {
        // XP's CopyFromLink installs OLE_COPYFROMLNK on the returned object.
        7 => Some(Win16Ole1AsyncCommand::CopyFromLink),
        _ => None,
    }
}

fn expected_creation_release_method(ordinal: u16) -> Win16Ole1ReleaseMethodExpectation {
    match ordinal {
        // OLE_COPYFROMLNK is value 19 in the SDK enum. Clone and ObjectConvert
        // have no dedicated enum value; their method must come from the
        // OLE_RELEASE callback for this exact pending generation.
        7 => Win16Ole1ReleaseMethodExpectation::Exact(19),
        6 | 32 => Win16Ole1ReleaseMethodExpectation::FromNotification,
        _ => Win16Ole1ReleaseMethodExpectation::FromNotification,
    }
}
