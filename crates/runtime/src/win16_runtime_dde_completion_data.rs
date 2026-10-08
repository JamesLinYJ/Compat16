//! DDE completion projection for returned data, strings, and conversations.

use super::*;
use crate::win16_dde::Win16DdeDataOrigin;
use crate::win16_runtime::guest_ranges::commit_guest_writes_with_selectors;
use compat_services::win16_dde::{DdeConvContext16, DdeConvInfo16};

impl super::DdeCompletionAccess<'_> {
    pub(super) fn finish_dde_success(
        &mut self,
        continuation: &Win16DdeContinuation,
        result: Win16HostDdeResult,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        use Win16DdeRequest as R;
        use Win16HostDdeValue as V;
        if !matches!(&continuation.request, R::ClientTransaction { .. })
            && result.transaction_result.is_some()
        {
            return Err(invariant(
                "non-transaction DDE completion carried a transaction-result payload",
            ));
        }
        let value = match (&continuation.request, result.value) {
            (R::Initialize { .. }, V::Instance(Some(host_instance))) => {
                let candidate = continuation.callback_candidate.ok_or_else(|| {
                    invariant("successful DdeInitialize lost its staged callback registration")
                })?;
                if candidate.reinitializing {
                    let previous = self
                        .dde
                        .commit_callback_registration(
                            candidate.guest_instance,
                            candidate.callback,
                            candidate.token.0,
                            candidate.route,
                        )
                        .ok_or_else(|| invariant("DDE callback re-registration commit failed"))?;
                    if previous != host_instance {
                        return Err(invariant(
                            "DDE re-registration changed native instance identity",
                        ));
                    }
                } else {
                    self.dde
                        .commit_initialization(
                            candidate.guest_instance,
                            host_instance,
                            candidate.route,
                        )
                        .ok_or_else(|| {
                            invariant("DDE initialization commit failed for provisional instance")
                        })?;
                }
                self.unregister_retired_dde_callbacks()?;
                let output =
                    continuation.outputs.instance.as_ref().ok_or_else(|| {
                        invariant("DdeInitialize lost its instance output capture")
                    })?;
                commit_guest_writes_with_selectors(
                    self.selectors(),
                    memory,
                    vec![(
                        output.clone(),
                        candidate.guest_instance.to_le_bytes().to_vec(),
                    )],
                )?;
                0
            }
            (R::Uninitialize { instance }, V::Boolean(succeeded)) => {
                if !succeeded {
                    return Ok(0);
                }
                self.reserve_dde_guest_block_retirements(self.dde.access_block_count())?;
                let (_, blocks) = self.dde.remove_instance(*instance).ok_or_else(|| {
                    invariant("successful DdeUninitialize lost its runtime instance")
                })?;
                self.queue_removed_dde_guest_blocks(blocks)?;
                self.retry_dde_guest_block_retirements()?;
                self.unregister_retired_dde_callbacks()?;
                1
            }
            (R::ConnectList { instance, .. }, V::ConversationList(Some(host_list))) => self
                .dde
                .add_conversation_list(*instance, host_list)
                .map(u32::from)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE conversation-list token table is full",
                    )
                })?,
            (R::ConnectList { .. }, V::ConversationList(None)) => 0,
            (R::QueryNextServer { list, .. }, V::Conversation(Some(host_conversation))) => {
                let instance = self
                    .dde
                    .instance_for_conversation_list(*list)
                    .ok_or_else(|| invariant("DDE conversation list disappeared during query"))?;
                let guest = self
                    .dde
                    .add_conversation(instance, host_conversation)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::ResourceExhausted,
                            "DDE conversation token table is full",
                        )
                    })?;
                if !self.dde.note_list_member(*list, guest) {
                    return Err(invariant(
                        "DDE list rejected its returned conversation token",
                    ));
                }
                guest
            }
            (R::QueryNextServer { .. }, V::Conversation(None)) => 0,
            (R::DisconnectList { list }, V::DisconnectedList { succeeded, members }) => {
                if !succeeded {
                    return Ok(0);
                }
                self.dde
                    .remove_disconnected_list(*list, &members)
                    .ok_or_else(|| invariant("successful DdeDisconnectList lost its guest list"))?;
                1
            }
            (R::Connect { instance, .. }, V::Conversation(Some(host_conversation))) => self
                .dde
                .add_conversation(*instance, host_conversation)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE conversation token table is full",
                    )
                })?,
            (R::Reconnect { conversation }, V::Conversation(Some(host_conversation))) => {
                let instance = self
                    .dde
                    .instance_for_conversation(*conversation)
                    .ok_or_else(|| {
                        invariant("DDE conversation disappeared before reconnect completion")
                    })?;
                if self.dde.host_conversation(*conversation) == Some(host_conversation) {
                    *conversation
                } else {
                    self.dde.remove_conversation(*conversation);
                    self.dde
                        .add_conversation(instance, host_conversation)
                        .ok_or_else(|| {
                            RuntimeError::new(
                                Kind::ResourceExhausted,
                                "DDE conversation token table is full",
                            )
                        })?
                }
            }
            (R::Connect { .. } | R::Reconnect { .. }, V::Conversation(None)) => 0,
            (R::Disconnect { conversation }, V::Boolean(succeeded)) => {
                if succeeded {
                    self.dde.remove_conversation(*conversation);
                }
                u32::from(succeeded)
            }
            (
                R::QueryConversationInfo {
                    conversation,
                    guest_size,
                    ..
                },
                V::ConversationInfo(info),
            ) => self.finish_conversation_info(
                *conversation,
                *guest_size,
                info,
                continuation.outputs.conversation_info.as_ref(),
                memory,
            )?,
            // DdeQueryConvInfo returns zero when the host reports no bytes
            // copied; DDEML may leave last-error as NO_ERROR in this case.
            // The captured guest buffer stays untouched.
            (R::QueryConversationInfo { .. }, V::None) => 0,
            (
                R::SetUserHandle { .. }
                | R::AbandonTransaction { .. }
                | R::PostAdvise { .. }
                | R::UnaccessData { .. }
                | R::FreeData { .. }
                | R::FreeString { .. }
                | R::KeepString { .. }
                | R::EnableCallback { .. },
                V::Boolean(succeeded),
            ) => {
                if succeeded {
                    match &continuation.request {
                        R::UnaccessData { data } => self.finish_unaccess(*data)?,
                        R::FreeData { data } => {
                            self.reserve_dde_guest_block_retirement()?;
                            let removed = self.dde.remove_data_after_guest_free(*data)
                                .map_err(|_| invariant(
                                    "successful DdeFreeDataHandle contradicted its guest token state"))?;
                            if let Some(removed) = removed {
                                if let Some(block) = removed.access_block {
                                    self.free_runtime_dde_block(block.identity)?;
                                }
                            }
                        }
                        R::FreeString { string, .. } => {
                            self.dde.release_string_reference(*string).ok_or_else(|| {
                                invariant("successful DdeFreeStringHandle lost its reference")
                            })?;
                        }
                        R::KeepString { string, .. } => {
                            self.dde.retain_string_reference(*string).ok_or_else(|| {
                                invariant("successful DdeKeepStringHandle lost its guest string")
                            })?;
                        }
                        _ => {}
                    }
                }
                u32::from(succeeded)
            }
            (
                R::ClientTransaction { result_output, .. },
                V::ClientTransaction {
                    data,
                    succeeded: true,
                    entered_native: true,
                },
            ) => {
                let instance = continuation
                    .instance
                    .ok_or_else(|| invariant("DDE transaction lost its captured instance owner"))?;
                match (
                    *result_output != 0,
                    result.transaction_result,
                    continuation.outputs.transaction_result.as_ref(),
                ) {
                    (true, Some(result_value), Some(output)) => commit_guest_writes_with_selectors(
                        self.selectors(),
                        memory,
                        vec![(output.clone(), result_value.to_le_bytes().to_vec())],
                    )?,
                    (false, None, None) => {}
                    (true, _, _) => {
                        return Err(invariant(
                            "DDE transaction omitted its requested pdwResult value",
                        ));
                    }
                    (false, Some(_), _) => {
                        return Err(invariant(
                            "DDE transaction returned an unrequested pdwResult value",
                        ));
                    }
                    (_, _, _) => {
                        return Err(invariant(
                            "DDE transaction result capture does not match its request",
                        ));
                    }
                }
                if let Some(host_data) = data {
                    self.dde
                        .add_client_result_data(instance, host_data)
                        .ok_or_else(|| {
                            RuntimeError::new(
                                Kind::ResourceExhausted,
                                "DDE transaction result data token table is full",
                            )
                        })?
                } else {
                    1
                }
            }
            (
                R::CreateData {
                    instance, flags, ..
                },
                V::Data(Some(data)),
            ) => self
                .dde
                .add_created_data(
                    *instance,
                    data,
                    *flags & compat_services::win16_dde::data_flag::HDATA_APPOWNED != 0,
                )
                .ok_or_else(|| {
                    RuntimeError::new(Kind::ResourceExhausted, "DDE data token table is full")
                })?,
            (R::AddData { data, .. }, V::Data(Some(host_data))) => {
                let instance = self
                    .dde
                    .instance_for_data(*data)
                    .ok_or_else(|| invariant("DDE AddData owner disappeared"))?;
                let prior_host = self
                    .dde
                    .host_data(*data)
                    .ok_or_else(|| invariant("DDE AddData host identity disappeared"))?;
                let origin = self
                    .dde
                    .data_origin(*data)
                    .ok_or_else(|| invariant("DDE AddData provenance disappeared"))?;
                let transferred = self.dde.data_is_writable(*data) == Some(false)
                    && matches!(origin, Win16DdeDataOrigin::Created { .. });
                if prior_host == host_data {
                    *data
                } else {
                    self.reserve_dde_guest_block_retirement()?;
                    let removed = self.dde.remove_data(*data).ok_or_else(|| {
                        invariant("DDE AddData could not retire its replaced alias")
                    })?;
                    if let Some(block) = removed.access_block {
                        self.free_runtime_dde_block(block.identity)?;
                    }
                    let guest =
                        self.dde
                            .add_data(instance, host_data, origin)
                            .ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::ResourceExhausted,
                                    "DDE data token table is full after AddData identity change",
                                )
                            })?;
                    if transferred {
                        self.dde.mark_data_transferred(guest).ok_or_else(|| {
                            invariant(
                                "replacement DDE AddData token could not retain transfer state",
                            )
                        })?;
                    }
                    guest
                }
            }
            (R::CreateData { .. } | R::AddData { .. }, V::Data(None)) => 0,
            (R::GetData { output, .. }, V::GetData { bytes, copied }) => {
                if output.far_pointer == 0 {
                    if !bytes.is_empty() {
                        return Err(invariant(
                            "DDE GetData query returned bytes without a destination",
                        ));
                    }
                } else if copied > output.capacity || bytes.len() != copied as usize {
                    return Err(invariant(
                        "DDE GetData returned an inconsistent copied length",
                    ));
                }
                if let Some(range) = continuation.outputs.data.as_ref() {
                    range.commit_with_selectors(self.selectors(), memory, bytes)?;
                } else if !bytes.is_empty() {
                    return Err(invariant(
                        "DDE GetData returned bytes without an output range",
                    ));
                }
                copied
            }
            (R::AccessData { .. }, _) => {
                return Err(invariant(
                    "DDE AccessData completion bypassed its native lease compensation handler",
                ));
            }
            (R::CreateString { instance, .. }, V::String(Some(string))) => {
                let guest = self.dde.add_string(*instance, string).ok_or_else(|| {
                    RuntimeError::new(Kind::ResourceExhausted, "DDE string token table is full")
                })?;
                self.dde.retain_string_reference(guest).ok_or_else(|| {
                    invariant("new DDE string token could not retain its native reference")
                })?;
                guest
            }
            (R::CreateString { .. }, V::String(None)) => 0,
            (R::QueryString { output, .. }, V::Text { bytes, characters }) => {
                if let Some(range) = continuation.outputs.string.as_ref() {
                    if output.capacity == 0 {
                        if !bytes.is_empty() {
                            return Err(invariant(
                                "DDE QueryString wrote bytes to a zero-capacity buffer",
                            ));
                        }
                    } else if characters >= output.capacity
                        || bytes.len() != characters as usize + 1
                        || bytes.last() != Some(&0)
                    {
                        return Err(invariant(
                            "DDE QueryString returned malformed guest text output",
                        ));
                    } else {
                        commit_guest_writes_with_selectors(self.selectors(), memory, vec![(range.clone(), bytes)])?;
                    }
                } else if !bytes.is_empty() {
                    return Err(invariant(
                        "DDE QueryString returned bytes without an output range",
                    ));
                }
                characters
            }
            (R::NameService { .. }, V::Boolean(succeeded)) => u32::from(succeeded),
            (R::CompareStrings { .. }, V::Scalar(value)) if value <= 1 || value == u32::MAX => {
                u32::from(value as i16 as u16)
            }
            (R::GetLastError { .. }, _) => {
                return Err(invariant(
                    "DdeGetLastError unexpectedly reached the native completion path",
                ));
            }
            (R::QueryNextServer { .. }, V::ConversationList(_))
            | (R::Initialize { .. }, V::Boolean(_))
            | (R::CreateString { .. }, V::Scalar(_)) => {
                return Err(invariant(
                    "DDEML host completion value type does not match the API",
                ));
            }
            _ => {
                return Err(invariant(
                    "DDEML host completion does not match its request",
                ));
            }
        };
        Ok(value)
    }

    fn finish_conversation_info(
        &mut self,
        guest_conversation: u32,
        guest_size: u32,
        info: crate::Win16HostDdeConversationInfo,
        output: Option<&GuestOutputRange>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let instance = self
            .dde
            .instance_for_conversation(guest_conversation)
            .ok_or_else(|| invariant("DDE conversation disappeared during CONVINFO projection"))?;
        let prefix_length = usize::try_from(guest_size.min(DdeConvInfo16::SIZE as u32))
            .map_err(|_| invariant("DDE CONVINFO prefix exceeds host address width"))?;
        // Handles are DWORDs, but CONVINFO copies an arbitrary byte prefix.
        // Project a handle whenever even its first byte is visible; encoding
        // then truncates the token at the caller's exact cb boundary.
        let partner = if prefix_length > 8 {
            let partner_instance =
                match (info.partner, info.partner_instance, info.partner_query_only) {
                    (None, None, false) => None,
                    (Some(_), None, true) => None,
                    (Some(_), Some(host_instance), false) => Some(
                        self.dde
                            .guest_instance_for_host(host_instance)
                            .ok_or_else(|| {
                                invariant(
                                    "DDE CONVINFO partner owner is not a known guest instance",
                                )
                            })?,
                    ),
                    _ => {
                        return Err(invariant(
                            "DDE CONVINFO partner owner flags contradict the partner handle",
                        ));
                    }
                };
            self.dde
                .ensure_conversation_info_partner(
                    guest_conversation,
                    info.partner,
                    partner_instance,
                    info.partner_query_only,
                )
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE CONVINFO partner token table is full",
                    )
                })?
                .unwrap_or(0)
        } else {
            0
        };
        let service_partner = if prefix_length > 12 {
            self.ensure_info_string(instance, guest_conversation, info.service_partner)?
        } else {
            0
        };
        let service_requested = if prefix_length > 16 {
            self.ensure_info_string(instance, guest_conversation, info.service_requested)?
        } else {
            0
        };
        let topic = if prefix_length > 20 {
            self.ensure_info_string(instance, guest_conversation, info.topic)?
        } else {
            0
        };
        let item = if prefix_length > 24 {
            self.ensure_info_string(instance, guest_conversation, info.item)?
        } else {
            0
        };
        let conversation_list = if prefix_length > 38 {
            match info.conversation_list {
                None => 0,
                Some(host_list) => self
                    .dde
                    .add_conversation_list(instance, host_list)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::ResourceExhausted,
                            "DDE CONVINFO list token table is full",
                        )
                    })?,
            }
        } else {
            0
        };
        let projection = DdeConvInfo16 {
            size: guest_size,
            user_handle: info.user_handle,
            conversation_partner: partner,
            service_partner,
            service_requested,
            topic,
            item,
            format: info.format,
            transaction_type: info.transaction_type,
            status: info.status,
            conversation_state: info.conversation_state,
            last_error: info.last_error,
            conversation_list,
            context: DdeConvContext16 {
                flags: info.context.flags,
                country_id: info.context.country_id,
                code_page: info.context.code_page,
                language_id: info.context.language_id,
                security: info.context.security,
            },
        };
        let bytes = projection.encode_prefix(prefix_length);
        if let Some(range) = output {
            commit_guest_writes_with_selectors(self.selectors(), memory, vec![(range.clone(), bytes)])?;
        } else if !bytes.is_empty() {
            return Err(invariant("DDE CONVINFO lost its captured guest output"));
        }
        Ok(prefix_length as u32)
    }

    fn ensure_info_string(
        &mut self,
        instance: u32,
        conversation: u32,
        host_string: Option<crate::Win16HostDdeString>,
    ) -> Result<u32, RuntimeError> {
        let guest = self
            .dde
            .ensure_string(instance, host_string)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "DDE CONVINFO string token table is full",
                )
            })?
            .unwrap_or(0);
        if guest != 0 && !self.dde.note_conversation_string(conversation, guest) {
            return Err(invariant(
                "DDE CONVINFO string could not be attached to its conversation",
            ));
        }
        Ok(guest)
    }
}
