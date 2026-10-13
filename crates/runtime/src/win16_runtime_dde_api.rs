//! DDE export request validation and exact operation-frame preparation.

use super::*;

pub(super) enum PrepareFailure {
    Api { instance: Option<u32>, error: u16 },
    CompatibilityGap(&'static str),
    Runtime(RuntimeError),
}

pub(super) type PrepareResult<T> = Result<T, PrepareFailure>;

impl From<RuntimeError> for PrepareFailure {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl Win16State {
    /// Prepare one DDEML export and put it on the existing owner-thread
    /// operation stack. Callback-capable calls never use a synchronous host
    /// shortcut.
    pub(in crate::win16_runtime) fn begin_dde_request(
        &mut self,
        request: Win16DdeRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        descriptor_return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let return_kind = dde_return_kind(&request);
        if return_kind != descriptor_return_kind {
            return Err(invariant(
                "Win16 DDEML export has an unexpected ABI return kind",
            ));
        }

        if matches!(&request, Win16DdeRequest::Initialize { reserved, .. } if *reserved != 0) {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(dde_error::INVALIDPARAMETER),
                return_kind,
            );
        }

        // Win16 monitor callbacks require guest wire structures that this
        // bridge cannot represent. Preserve the SDK-defined SYS_ERROR return
        // without registering a callback, touching the output, or calling the
        // native monitor-class initializer.
        if matches!(&request, Win16DdeRequest::Initialize { flags, .. }
            if flags & compat_services::win16_dde::initialization_flag::APPCLASS_MONITOR != 0)
        {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "Win16 DDE APPCLASS_MONITOR is not available because its guest monitor callback records are not bridged; returned DMLERR_SYS_ERROR"));
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(dde_error::SYS_ERROR),
                return_kind,
            );
        }

        if let Win16DdeRequest::GetData {
            data,
            output,
            offset,
        } = &request
        {
            if let Some(block) = self
                .dde
                .access_block(*data)
                .filter(|block| block.writable && self.dde.data_is_writable(*data) == Some(true))
            {
                let instance = self
                    .dde
                    .instance_for_data(*data)
                    .ok_or_else(|| invariant("active DDE access snapshot lost its data owner"))?;
                let snapshot =
                    self.read_dde_snapshot(memory, block.far_pointer, block.byte_length)?;
                let start = usize::try_from(*offset).map_err(|_| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE GetData offset exceeds host address width",
                    )
                })?;
                let available = snapshot.get(start..).unwrap_or_default();
                let copied = if output.far_pointer == 0 {
                    snapshot.len()
                } else {
                    available
                        .len()
                        .min(usize::try_from(output.capacity).map_err(|_| {
                            RuntimeError::new(
                                Kind::ResourceExhausted,
                                "DDE GetData capacity exceeds host address width",
                            )
                        })?)
                };
                let copied_dword = u32::try_from(copied).map_err(|_| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE GetData snapshot result exceeds DWORD",
                    )
                })?;
                if output.far_pointer != 0 {
                    let pointer = self
                        .selectors
                        .pointer_from_far(output.far_pointer)
                        .map_err(crate::runtime_error)?;
                    let range = DdeHugeOutputRange::capture(
                        self,
                        memory,
                        pointer,
                        usize::try_from(output.capacity).map_err(|_| {
                            RuntimeError::new(
                                Kind::ResourceExhausted,
                                "DDE GetData capacity exceeds host address width",
                            )
                        })?,
                    )?;
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(copied).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "copy DDE GetData access snapshot result",
                            error,
                        )
                    })?;
                    bytes.extend_from_slice(&available[..copied]);
                    range.commit(self, memory, bytes)?;
                }
                self.dde.set_last_error(instance, dde_error::NO_ERROR);
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    copied_dword,
                    return_kind,
                );
            }
        }

        if let Win16DdeRequest::GetLastError { instance } = &request {
            let instance = *instance;
            let value = if self.dde.existing_host_instance(instance).is_some() {
                let error = self.dde.last_error(instance);
                self.dde.set_last_error(instance, dde_error::NO_ERROR);
                u32::from(error)
            } else {
                u32::from(dde_error::DLL_NOT_INITIALIZED)
            };
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                value,
                return_kind,
            );
        }

        let request_for_error = request.clone();
        let prepared = match self.prepare_dde_call(request, memory) {
            Ok(prepared) => prepared,
            Err(PrepareFailure::Api { instance, error }) => {
                if let Some(instance) = instance {
                    self.dde.set_last_error(instance, error);
                }
                if matches!(&request_for_error, Win16DdeRequest::Initialize { .. })
                    && error == dde_error::SYS_ERROR
                {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "Win16 DdeInitialize could not establish the guest callback route; returned the SDK-permitted DMLERR_SYS_ERROR"));
                }
                let value = if matches!(&request_for_error, Win16DdeRequest::Initialize { .. }) {
                    u32::from(error)
                } else {
                    0
                };
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    value,
                    return_kind,
                );
            }
            Err(PrepareFailure::CompatibilityGap(message)) => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, message));
                return Err(RuntimeError::new(Kind::CompatibilityGap, message));
            }
            Err(PrepareFailure::Runtime(error)) => return Err(error),
        };
        let instance = prepared
            .callback_candidate
            .map(|candidate| candidate.guest_instance)
            .or_else(|| self.dde_instance_for_request(&request_for_error));
        let mut continuation = Win16DdeContinuation {
            request: request_for_error,
            return_kind,
            host_operation: None,
            host_owner: None,
            worker_generation: None,
            started_failure: None,
            instance,
            native_input_instance: None,
            outputs: prepared.outputs,
            callback_candidate: prepared.callback_candidate,
            data_transfer_guard: prepared.data_transfer_guard,
            operation_retirement_proof: None,
            transfer_guard_retired: false,
            operation_retirement_acknowledged: false,
            normal_source_retirements: Vec::new(),
            guest_return_transfers: Vec::new(),
            cached_normal_completion: None,
            finish_failure: None,
            purpose: Win16DdeCompletionPurpose::GuestApi,
            cleanup_error: None,
        };
        continuation.capture_native_input_identity(&self.dde)?;
        continuation.reserve_source_retirement_record()?;
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::Dde(prepared.call),
            WindowReturn::Dde(continuation),
            return_to,
        )
    }

    pub(super) fn require_instance(&self, guest: u32) -> PrepareResult<Win16HostDdeInstance> {
        self.dde
            .host_instance(guest)
            .ok_or_else(|| api_error(Some(guest), dde_error::DLL_NOT_INITIALIZED))
    }

    pub(super) fn require_string(&self, instance: u32, guest: u32) -> PrepareResult<Win16HostDdeString> {
        if self.dde.instance_for_string(guest) != Some(instance) {
            return Err(api_error(Some(instance), dde_error::INVALIDPARAMETER));
        }
        self.dde
            .host_string(guest)
            .ok_or_else(|| invariant("DDE string token lost its host identity").into())
    }

    pub(super) fn optional_string(
        &self,
        instance: u32,
        guest: u32,
    ) -> PrepareResult<Option<Win16HostDdeString>> {
        if guest == 0 {
            Ok(None)
        } else {
            self.require_string(instance, guest).map(Some)
        }
    }

    pub(super) fn require_conversation(
        &self,
        instance: u32,
        guest: u32,
    ) -> PrepareResult<crate::Win16HostDdeConversation> {
        if self.dde.instance_for_conversation(guest) != Some(instance) {
            return Err(api_error(Some(instance), dde_error::INVALIDPARAMETER));
        }
        if let Some(host) = self.dde.host_conversation(guest) {
            return Ok(host);
        }
        if self.dde.host_conversation_for_info(guest).is_some() {
            return Err(api_error(Some(instance), dde_error::INVALIDPARAMETER));
        }
        Err(invariant("DDE conversation token lost its host identity").into())
    }

    pub(super) fn require_conversation_any_instance(
        &self,
        guest: u32,
    ) -> PrepareResult<crate::Win16HostDdeConversation> {
        let Some(instance) = self.dde.instance_for_conversation(guest) else {
            return Err(api_error(None, dde_error::INVALIDPARAMETER));
        };
        if let Some(host) = self.dde.host_conversation(guest) {
            return Ok(host);
        }
        if self.dde.host_conversation_for_info(guest).is_some() {
            return Err(api_error(Some(instance), dde_error::INVALIDPARAMETER));
        }
        Err(invariant("DDE conversation token lost its host identity").into())
    }

    pub(super) fn require_conversation_list(
        &self,
        instance: u32,
        guest: u32,
    ) -> PrepareResult<crate::Win16HostDdeConversationList> {
        if self.dde.instance_for_conversation_list(guest) != Some(instance) {
            return Err(api_error(Some(instance), dde_error::INVALIDPARAMETER));
        }
        self.dde
            .host_conversation_list(guest)
            .ok_or_else(|| invariant("DDE list token lost its host identity").into())
    }

    pub(super) fn require_conversation_list_any_instance(
        &self,
        guest: u32,
    ) -> PrepareResult<crate::Win16HostDdeConversationList> {
        self.dde
            .host_conversation_list(guest)
            .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))
    }

    pub(super) fn require_data_any_instance(&self, guest: u32) -> PrepareResult<(u32, Win16HostDdeData)> {
        let owner = self
            .dde
            .instance_for_data(guest)
            .ok_or_else(|| api_error(None, dde_error::INVALIDPARAMETER))?;
        let host = self
            .dde
            .host_data(guest)
            .ok_or_else(|| api_error(Some(owner), dde_error::INVALIDPARAMETER))?;
        Ok((owner, host))
    }

    pub(super) fn dde_instance_for_request(&self, request: &Win16DdeRequest) -> Option<u32> {
        use Win16DdeRequest as R;
        match *request {
            R::Initialize {
                initial_instance, ..
            } => (initial_instance != 0).then_some(initial_instance),
            R::Uninitialize { instance }
            | R::ConnectList { instance, .. }
            | R::Connect { instance, .. }
            | R::AbandonTransaction { instance, .. }
            | R::PostAdvise { instance, .. }
            | R::CreateData { instance, .. }
            | R::GetLastError { instance }
            | R::CreateString { instance, .. }
            | R::FreeString { instance, .. }
            | R::QueryString { instance, .. }
            | R::KeepString { instance, .. }
            | R::EnableCallback { instance, .. }
            | R::NameService { instance, .. } => Some(instance),
            R::ClientTransaction { conversation, .. }
            | R::Disconnect { conversation }
            | R::QueryConversationInfo { conversation, .. }
            | R::SetUserHandle { conversation, .. }
            | R::Reconnect { conversation } => self.dde.instance_for_conversation(conversation),
            R::AddData { data, .. }
            | R::GetData { data, .. }
            | R::AccessData { data, .. }
            | R::UnaccessData { data }
            | R::FreeData { data } => self.dde.instance_for_data(data),
            R::QueryNextServer { list, .. } | R::DisconnectList { list } => {
                self.dde.instance_for_conversation_list(list)
            }
            R::CompareStrings { .. } => None,
        }
    }
}

pub(super) struct PreparedDde {
    pub(super) call: Win16HostDdeCall,
    pub(super) outputs: DdeOutputs,
    pub(super) callback_candidate: Option<DdeCallbackCandidate>,
    pub(super) data_transfer_guard: Option<DdeDataTransferGuard>,
}

pub(super) fn api_error(instance: Option<u32>, error: u16) -> PrepareFailure {
    PrepareFailure::Api { instance, error }
}

pub(super) fn callback_registration_error(instance: u32, error: RuntimeError) -> PrepareFailure {
    match error.kind() {
        Kind::GuestFault | Kind::InvalidInput => {
            api_error(Some(instance), dde_error::INVALIDPARAMETER)
        }
        Kind::ResourceExhausted => api_error(Some(instance), dde_error::SYS_ERROR),
        _ => PrepareFailure::Runtime(error),
    }
}

pub(super) fn decode_context(
    bytes: Option<&[u8]>,
    instance: u32,
) -> PrepareResult<Option<Win16HostDdeContext>> {
    bytes
        .map(|bytes| {
            DdeConvContext16::decode(bytes)
                .map(|context| Win16HostDdeContext {
                    flags: context.flags,
                    country_id: context.country_id,
                    code_page: context.code_page,
                    language_id: context.language_id,
                    security: context.security,
                })
                .map_err(|_| api_error(Some(instance), dde_error::INVALIDPARAMETER))
        })
        .transpose()
}

pub(super) fn dde_return_kind(request: &Win16DdeRequest) -> Win16ReturnKind {
    use Win16DdeRequest as R;
    match request {
        R::Initialize { .. }
        | R::Uninitialize { .. }
        | R::DisconnectList { .. }
        | R::Disconnect { .. }
        | R::QueryConversationInfo { .. }
        | R::SetUserHandle { .. }
        | R::AbandonTransaction { .. }
        | R::PostAdvise { .. }
        | R::UnaccessData { .. }
        | R::FreeData { .. }
        | R::GetLastError { .. }
        | R::FreeString { .. }
        | R::KeepString { .. }
        | R::EnableCallback { .. }
        | R::CompareStrings { .. } => Win16ReturnKind::Word,
        R::AccessData { .. } => Win16ReturnKind::FarPointer,
        R::ConnectList { .. }
        | R::QueryNextServer { .. }
        | R::Connect { .. }
        | R::ClientTransaction { .. }
        | R::CreateData { .. }
        | R::AddData { .. }
        | R::GetData { .. }
        | R::CreateString { .. }
        | R::QueryString { .. }
        | R::NameService { .. }
        | R::Reconnect { .. } => Win16ReturnKind::Dword,
    }
}
