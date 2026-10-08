//! Translate decoded DDEML API requests into typed owner-thread calls.

use super::*;
use crate::Win16HostDdeTransactionData;
use compat_services::win16_dde::DdeConvInfo16;
use win16_abi::Win16DdeTransactionData;

impl Win16State {
    pub(super) fn prepare_dde_call(
        &mut self,
        request: Win16DdeRequest,
        memory: &Memory,
    ) -> PrepareResult<PreparedDde> {
        use Win16DdeRequest as R;
        let mut outputs = DdeOutputs::default();
        let mut callback_candidate = None;
        let mut data_transfer_guard = None;
        let call = match request {
            R::Initialize {
                instance_output,
                initial_instance,
                callback,
                flags,
                reserved,
            } => {
                if reserved != 0 {
                    return Err(api_error(
                        Some(initial_instance),
                        dde_error::INVALIDPARAMETER,
                    ));
                }
                outputs.instance = Some(self.capture_dde_output(memory, instance_output, 4)?);
                if callback == 0 {
                    return Err(api_error(
                        Some(initial_instance),
                        dde_error::INVALIDPARAMETER,
                    ));
                }
                let existing = if initial_instance == 0 {
                    None
                } else {
                    Some(
                        self.dde
                            .existing_host_instance(initial_instance)
                            .ok_or_else(|| {
                                api_error(Some(initial_instance), dde_error::INVALIDPARAMETER)
                            })?,
                    )
                };
                let token = match self.register_guest_callback(
                    memory,
                    callback,
                    super::super::far_callback::Win16FarCallbackConvention::Pascal,
                    super::super::far_callback::Win16FarCallbackReturn::Dword,
                ) {
                    Ok(token) => token,
                    Err(error) => return Err(callback_registration_error(initial_instance, error)),
                };
                let staged = if initial_instance == 0 {
                    self.dde.stage_initialization(callback, token.0)
                } else {
                    self.dde
                        .stage_callback_registration(initial_instance, callback, token.0)
                        .map(|route| (initial_instance, route))
                };
                let Some((guest_instance, route)) = staged else {
                    let _ = self.unregister_guest_callback(token);
                    return Err(api_error(Some(initial_instance), dde_error::SYS_ERROR));
                };
                callback_candidate = Some(DdeCallbackCandidate {
                    guest_instance,
                    callback,
                    route,
                    token,
                    reinitializing: initial_instance != 0,
                });
                Win16HostDdeCall::Initialize {
                    existing,
                    callback_route: route,
                    flags,
                    reserved,
                }
            }
            R::Uninitialize { instance } => Win16HostDdeCall::Uninitialize {
                instance: self.require_instance(instance)?,
            },
            R::ConnectList {
                instance,
                service,
                topic,
                list,
                context,
            } => {
                let host_instance = self.require_instance(instance)?;
                let service = self.optional_string(instance, service)?;
                let topic = self.optional_string(instance, topic)?;
                let list = if list == 0 {
                    None
                } else {
                    Some(self.require_conversation_list(instance, list)?)
                };
                Win16HostDdeCall::ConnectList {
                    instance: host_instance,
                    service,
                    topic,
                    list,
                    context: decode_context(context.as_deref(), instance)?,
                }
            }
            R::QueryNextServer { list, previous } => {
                let owner = self
                    .dde
                    .instance_for_conversation_list(list)
                    .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?;
                let host_list = self
                    .dde
                    .host_conversation_list(list)
                    .ok_or_else(|| invariant("DDE list token lost its host identity"))?;
                let previous = if previous == 0 {
                    None
                } else {
                    Some(self.require_conversation(owner, previous)?)
                };
                Win16HostDdeCall::QueryNextServer {
                    list: host_list,
                    previous,
                }
            }
            R::DisconnectList { list } => Win16HostDdeCall::DisconnectList {
                list: self.require_conversation_list_any_instance(list)?,
            },
            R::Connect {
                instance,
                service,
                topic,
                context,
            } => {
                let host_instance = self.require_instance(instance)?;
                Win16HostDdeCall::Connect {
                    instance: host_instance,
                    service: service
                        .map(|guest| self.require_string(instance, guest))
                        .transpose()?,
                    topic: topic
                        .map(|guest| self.require_string(instance, guest))
                        .transpose()?,
                    context: decode_context(context.as_deref(), instance)?,
                }
            }
            R::Disconnect { conversation } => Win16HostDdeCall::Disconnect {
                conversation: self.require_conversation_any_instance(conversation)?,
            },
            R::QueryConversationInfo {
                conversation,
                transaction,
                output,
                guest_size,
            } => {
                let length = usize::try_from(guest_size.min(DdeConvInfo16::SIZE as u32))
                    .map_err(|_| api_error(None, dde_error::INVALIDPARAMETER))?;
                outputs.conversation_info = Some(self.capture_dde_output(memory, output, length)?);
                Win16HostDdeCall::QueryConversationInfo {
                    conversation: self
                        .dde
                        .host_conversation_for_info(conversation)
                        .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?,
                    transaction,
                }
            }
            R::SetUserHandle {
                conversation,
                transaction,
                user_data,
            } => Win16HostDdeCall::SetUserHandle {
                conversation: self.require_conversation_any_instance(conversation)?,
                transaction,
                user_data,
            },
            R::ClientTransaction {
                data,
                conversation,
                item,
                format,
                transaction_type,
                timeout,
                result_output,
            } => {
                let owner = self
                    .dde
                    .instance_for_conversation(conversation)
                    .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?;
                let host_conversation = self.require_conversation(owner, conversation)?;
                // XTYP_EXECUTE ignores hszItem. Do not validate a guest token
                // for a field that DDEML does not consume.
                let item = if compat_services::win16_dde::transaction_type::base(u32::from(
                    transaction_type,
                )) == 0x50
                {
                    None
                } else {
                    self.optional_string(owner, item)?
                };
                if result_output != 0 {
                    outputs.transaction_result =
                        Some(self.capture_dde_output(memory, result_output, 4)?);
                }
                let mut copyback = None;
                let data = match data {
                    Win16DdeTransactionData::None => Win16HostDdeTransactionData::None,
                    Win16DdeTransactionData::Bytes(bytes) => {
                        Win16HostDdeTransactionData::Bytes(bytes)
                    }
                    Win16DdeTransactionData::DataHandle(guest) => {
                        if let Some(block) = self.dde.access_block(guest).filter(|block| {
                            block.writable && self.dde.data_is_writable(guest) == Some(true)
                        }) {
                            // Keep DdeAccessData's lease count intact while
                            // publishing the guest's current writable object
                            // contents to the native owner before transaction.
                            copyback = Some(self.read_dde_snapshot(
                                memory,
                                block.far_pointer,
                                block.byte_length,
                            )?);
                        }
                        let host = self
                            .dde
                            .host_data_for_conversation(conversation, guest)
                            .ok_or_else(|| api_error(Some(owner), dde_error::INVALIDPARAMETER))?;
                        let origin = self.dde.data_origin(guest).ok_or_else(|| {
                            invariant("DDE data provenance disappeared before transaction")
                        })?;
                        let previously_transferred =
                            self.dde.data_transfer_state(guest).ok_or_else(|| {
                                invariant("DDE transfer state disappeared before transaction")
                            })?;
                        let guard_id =
                            self.dde.allocate_data_transfer_guard().ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::ResourceExhausted,
                                    "DDE input transfer guard identifiers are exhausted",
                                )
                            })?;
                        self.dde.register_data_transfer_guard(guest, guard_id, host, owner,
                            origin, previously_transferred).ok_or_else(|| invariant(
                                "DDE input transfer guard could not capture its source identity"))?;
                        let transfer_marked =
                            matches!(origin, crate::win16_dde::Win16DdeDataOrigin::Created { .. });
                        if self
                            .dde
                            .begin_data_transfer(guest, guard_id, host, owner, origin)
                            .is_none()
                        {
                            self.dde
                                .cancel_data_transfer_guard(guard_id)
                                .ok_or_else(|| {
                                    invariant(
                                        "failed DDE transfer setup could not cancel its guard",
                                    )
                                })?;
                            return Err(
                                invariant("DDE data token disappeared before transaction").into()
                            );
                        }
                        data_transfer_guard = Some(DdeDataTransferGuard {
                            guard_id,
                            guest_data: guest,
                            host_data: host,
                            owner,
                            origin,
                            previously_transferred,
                            transfer_marked,
                        });
                        Win16HostDdeTransactionData::Data(host)
                    }
                };
                Win16HostDdeCall::ClientTransaction {
                    instance: self.require_instance(owner)?,
                    data,
                    conversation: host_conversation,
                    item,
                    format,
                    transaction_type,
                    timeout,
                    return_result: result_output != 0,
                    copyback,
                }
            }
            R::AbandonTransaction {
                instance,
                conversation,
                transaction,
            } => {
                let host_instance = self.require_instance(instance)?;
                let conversation = conversation
                    .map(|guest| self.require_conversation(instance, guest))
                    .transpose()?;
                Win16HostDdeCall::AbandonTransaction {
                    instance: host_instance,
                    conversation,
                    transaction,
                }
            }
            R::PostAdvise {
                instance,
                topic,
                item,
            } => {
                let host_instance = self.require_instance(instance)?;
                Win16HostDdeCall::PostAdvise {
                    instance: host_instance,
                    topic: topic
                        .map(|guest| self.require_string(instance, guest))
                        .transpose()?,
                    item: item
                        .map(|guest| self.require_string(instance, guest))
                        .transpose()?,
                }
            }
            R::CreateData {
                instance,
                data,
                count,
                offset,
                item,
                format,
                flags,
            } => Win16HostDdeCall::CreateData {
                instance: self.require_instance(instance)?,
                data,
                count,
                offset,
                item: self.optional_string(instance, item)?,
                format,
                flags,
            },
            R::AddData {
                data,
                bytes,
                offset,
            } => {
                let (owner, host_data) = self.require_data_any_instance(data)?;
                if self.dde.access_block(data).is_some() {
                    return Err(PrepareFailure::CompatibilityGap(
                        "DdeAddData during an active DdeAccessData lease cannot be safely mirrored",
                    ));
                }
                if self.dde.data_is_writable(data) != Some(true) {
                    return Err(api_error(Some(owner), dde_error::INVALIDPARAMETER));
                }
                Win16HostDdeCall::AddData {
                    data: host_data,
                    bytes,
                    offset,
                }
            }
            R::GetData {
                data,
                output,
                offset,
            } => {
                let (owner, host_data) = self.require_data_any_instance(data)?;
                if output.far_pointer != 0 {
                    outputs.data = Some(
                        self.capture_dde_huge_output(
                            memory,
                            output.far_pointer,
                            usize::try_from(output.capacity)
                                .map_err(|_| api_error(Some(owner), dde_error::INVALIDPARAMETER))?,
                        )?,
                    );
                }
                Win16HostDdeCall::GetData {
                    data: host_data,
                    capacity: (output.far_pointer != 0).then_some(output.capacity),
                    offset,
                }
            }
            R::AccessData { data, size_output } => {
                let (_, host_data) = self.require_data_any_instance(data)?;
                if size_output != 0 {
                    outputs.access_size = Some(self.capture_dde_output(memory, size_output, 4)?);
                }
                Win16HostDdeCall::AccessData { data: host_data }
            }
            R::UnaccessData { data } => {
                let owner = self
                    .dde
                    .instance_for_data(data)
                    .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?;
                if self.dde.access_block(data).is_none() {
                    return Err(api_error(Some(owner), dde_error::INVALIDPARAMETER));
                }
                let host_data = self
                    .dde
                    .host_data_for_unaccess(data)
                    .ok_or_else(|| invariant("DDE access lease lost its host data identity"))?;
                let can_copyback = self.dde.data_is_writable(data) == Some(true);
                let copyback = self
                    .dde
                    .access_block(data)
                    .filter(|block| block.writable && can_copyback)
                    .map(|block| {
                        self.read_dde_snapshot(memory, block.far_pointer, block.byte_length)
                    })
                    .transpose()
                    .map_err(PrepareFailure::Runtime)?;
                Win16HostDdeCall::UnaccessData {
                    data: host_data,
                    copyback,
                }
            }
            R::FreeData { data } => {
                let (owner, host_data) = self.require_data_any_instance(data)?;
                if self.dde.can_free_data(data) != Some(true) {
                    return Err(api_error(Some(owner), dde_error::INVALIDPARAMETER));
                }
                if self.dde.access_block(data).is_some() {
                    return Err(PrepareFailure::CompatibilityGap(
                        "DdeFreeDataHandle during an active DdeAccessData lease cannot be safely mirrored",
                    ));
                }
                Win16HostDdeCall::FreeData { data: host_data }
            }
            R::CreateString {
                instance,
                value,
                code_page,
            } => Win16HostDdeCall::CreateString {
                instance: self.require_instance(instance)?,
                value,
                code_page,
            },
            R::FreeString { instance, string } => {
                let host_instance = self.require_instance(instance)?;
                let references = self
                    .dde
                    .string_reference_count(string)
                    .filter(|_| self.dde.instance_for_string(string) == Some(instance))
                    .ok_or_else(|| api_error(Some(instance), dde_error::INVALIDPARAMETER))?;
                if references == 0 {
                    return Err(api_error(Some(instance), dde_error::INVALIDPARAMETER));
                }
                Win16HostDdeCall::FreeString {
                    instance: host_instance,
                    string: self.require_string(instance, string)?,
                }
            }
            R::QueryString {
                instance,
                string,
                output,
                code_page,
            } => {
                let host_instance = self.require_instance(instance)?;
                if output.far_pointer != 0 {
                    outputs.string =
                        Some(self.capture_dde_output(
                            memory,
                            output.far_pointer,
                            usize::try_from(output.capacity).map_err(|_| {
                                api_error(Some(instance), dde_error::INVALIDPARAMETER)
                            })?,
                        )?);
                }
                Win16HostDdeCall::QueryString {
                    instance: host_instance,
                    string: self.require_string(instance, string)?,
                    capacity: (output.far_pointer != 0).then_some(output.capacity),
                    code_page,
                }
            }
            R::KeepString { instance, string } => Win16HostDdeCall::KeepString {
                instance: self.require_instance(instance)?,
                string: self.require_string(instance, string)?,
            },
            R::EnableCallback {
                instance,
                conversation,
                command,
            } => Win16HostDdeCall::EnableCallback {
                instance: self.require_instance(instance)?,
                conversation: if conversation == 0 {
                    None
                } else {
                    Some(self.require_conversation(instance, conversation)?)
                },
                command,
            },
            R::NameService {
                instance,
                service,
                reserved,
                command,
            } => Win16HostDdeCall::NameService {
                instance: self.require_instance(instance)?,
                service: self.optional_string(instance, service)?,
                reserved: self.optional_string(instance, reserved)?,
                command,
            },
            R::CompareStrings { left, right } => Win16HostDdeCall::CompareStrings {
                left: self
                    .dde
                    .host_string(left)
                    .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?,
                right: self
                    .dde
                    .host_string(right)
                    .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?,
            },
            R::Reconnect { conversation } => Win16HostDdeCall::Reconnect {
                conversation: self.require_conversation_any_instance(conversation)?,
            },
            R::GetLastError { .. } => {
                return Err(PrepareFailure::Runtime(invariant(
                    "DdeGetLastError must complete from runtime instance state",
                )));
            }
        };
        Ok(PreparedDde {
            call,
            outputs,
            callback_candidate,
            data_transfer_guard,
        })
    }
}
