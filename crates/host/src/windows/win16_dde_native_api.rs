//! Native DDEML instance, conversation, and string operations.

use super::*;

#[path = "win16_dde_native_api_strings.rs"]
mod strings;

pub(super) fn initialize(
    context: &WorkerContext,
    existing: Option<Win16HostDdeInstance>,
    callback_route: u64,
    flags: u32,
    reserved: u32,
) -> Result<Win16HostDdeResult, RuntimeError> {
    if callback_route == 0 {
        return Err(protocol_error("DDE callback route must be nonzero"));
    }
    let (host_instance, mut native_instance, callback_slot, previous_route) = {
        let mut state = context.state.borrow_mut();
        let host_instance = match existing {
            Some(token) => {
                let _ = state.native_instance(token)?;
                token
            }
            None => Win16HostDdeInstance(state.token()?),
        };
        let (native_instance, callback_slot, previous_route) = match existing {
            Some(token) => {
                let record = state.instances.get(&token).copied().ok_or_else(|| {
                    protocol_error(
                        "DDE reinitialization instance disappeared before staging its callback",
                    )
                })?;
                let registration = state
                    .callbacks_by_slot
                    .get(&record.callback_slot)
                    .filter(|registration| registration.instance == token)
                    .ok_or_else(|| {
                        protocol_error(
                            "DDE reinitialization lost its stable callback-slot registration",
                        )
                    })?;
                // Capture the exact slot contents. A nested reinitialization
                // may stage/commit a newer route before this call returns.
                (
                    record.native,
                    record.callback_slot,
                    Some(registration.route),
                )
            }
            None => (0, state.allocate_callback_slot()?, None),
        };
        state.callbacks_by_slot.insert(
            callback_slot,
            CallbackRegistration {
                instance: host_instance,
                route: callback_route,
            },
        );
        if existing.is_none() {
            state.instances.insert(
                host_instance,
                super::InstanceRecord {
                    native: 0,
                    callback_route,
                    callback_slot,
                },
            );
        }
        (
            host_instance,
            native_instance,
            callback_slot,
            previous_route,
        )
    };
    let callback = super::callback::CALLBACKS[usize::from(callback_slot)];
    worker::push_initializing_instance(context, host_instance, &mut native_instance)?;
    // SAFETY: DdeInitializeW writes a caller-owned instance id and installs the declared callback.
    let result_code = unsafe { DdeInitializeW(&mut native_instance, callback, flags, reserved) };
    worker::pop_initializing_instance(context, host_instance)?;
    if result_code != DMLERR_NO_ERROR {
        let mut state = context.state.borrow_mut();
        let still_ours = state
            .callbacks_by_slot
            .get(&callback_slot)
            .is_some_and(|registration| {
                registration.instance == host_instance && registration.route == callback_route
            });
        if still_ours {
            if let Some(route) = previous_route {
                if let Some(registration) = state.callbacks_by_slot.get_mut(&callback_slot) {
                    registration.route = route;
                }
            } else {
                state.callbacks_by_slot.remove(&callback_slot);
                state.remove_instance(host_instance);
            }
        }
        return Ok(result(
            Win16HostDdeValue::Instance(None),
            result_code as u16,
        ));
    }
    let mut state = context.state.borrow_mut();
    if let Some(existing) = existing {
        let record = state.instances.get_mut(&existing).ok_or_else(|| {
            protocol_error("DDE reinitialization instance disappeared during DdeInitialize")
        })?;
        if record.native != native_instance {
            state.callbacks_by_slot.remove(&callback_slot);
            return Err(protocol_error(
                "DDE reinitialization changed the native instance identifier",
            ));
        }
        record.callback_route = callback_route;
        if record.callback_slot != callback_slot {
            return Err(protocol_error(
                "DDE reinitialization changed its stable callback slot",
            ));
        }
        let registration = state
            .callbacks_by_slot
            .get_mut(&callback_slot)
            .filter(|registration| registration.instance == existing)
            .ok_or_else(|| {
                protocol_error("DDE reinitialization lost its callback-slot registration at commit")
            })?;
        registration.route = callback_route;
    } else {
        if state
            .instances_by_native
            .get(&native_instance)
            .is_some_and(|owner| *owner != host_instance)
        {
            state.remove_instance(host_instance);
            drop(state);
            // The native value aliases an already-owned DDEML instance. It
            // cannot safely be uninitialized here because that would retire
            // the other live owner as well.
            return Err(protocol_error(
                "DDEML reused a live native instance identifier",
            ));
        }
        let record = state.instances.get_mut(&host_instance).ok_or_else(|| {
            protocol_error("provisional DDE instance disappeared during native initialization")
        })?;
        record.native = native_instance;
        record.callback_route = callback_route;
        record.callback_slot = callback_slot;
        let registration = state
            .callbacks_by_slot
            .get_mut(&callback_slot)
            .filter(|registration| registration.instance == host_instance)
            .ok_or_else(|| protocol_error("initial DDE callback slot disappeared before commit"))?;
        registration.route = callback_route;
        state
            .instances_by_native
            .insert(native_instance, host_instance);
    }
    Ok(result(Win16HostDdeValue::Instance(Some(host_instance)), 0))
}

pub(super) fn connect_list(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    service: Option<Win16HostDdeString>,
    topic: Option<Win16HostDdeString>,
    list: Option<Win16HostDdeConversationList>,
    context_value: Option<Win16HostDdeContext>,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, service, topic, previous) = {
        let state = context.state.borrow();
        let previous = match list {
            Some(token) => {
                let owner = state
                    .conversation_lists
                    .get(&token)
                    .ok_or_else(|| {
                        protocol_error(
                            "DDE operation references an unknown host conversation-list token",
                        )
                    })?
                    .instance;
                if owner != instance {
                    return Err(protocol_error(
                        "DDE previous conversation list belongs to another instance",
                    ));
                }
                state.native_list(token)?
            }
            None => ptr::null_mut(),
        };
        (
            state.native_instance(instance)?,
            state.native_optional_string(instance, service)?,
            state.native_optional_string(instance, topic)?,
            previous,
        )
    };
    let native_context = context_value.map(to_native_context);
    let context_pointer = native_context
        .as_ref()
        .map_or(ptr::null(), |value| value as *const _);
    let native =
        // SAFETY: `DdeConnectList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { DdeConnectList(native_instance, service, topic, previous, context_pointer) };
    if native.is_null() {
        return Ok(result(
            Win16HostDdeValue::ConversationList(None),
            native_error(native_instance),
        ));
    }
    match context.state.borrow_mut().intern_list(instance, native) {
        Ok(token) => Ok(result(Win16HostDdeValue::ConversationList(token), 0)),
        Err(error) => {
            // SAFETY: `DdeDisconnectList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe {
                DdeDisconnectList(native);
            }
            Err(error)
        }
    }
}

pub(super) fn connect(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    service: Option<Win16HostDdeString>,
    topic: Option<Win16HostDdeString>,
    context_value: Option<Win16HostDdeContext>,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, service, topic) = {
        let state = context.state.borrow();
        (
            state.native_instance(instance)?,
            state.native_optional_string(instance, service)?,
            state.native_optional_string(instance, topic)?,
        )
    };
    let native_context = context_value.map(to_native_context);
    let context_pointer = native_context
        .as_ref()
        .map_or(ptr::null(), |value| value as *const _);
    // SAFETY: DdeConnect reads caller-owned service and topic strings.
    let native = unsafe { DdeConnect(native_instance, service, topic, context_pointer) };
    if native.is_null() {
        return Ok(result(
            Win16HostDdeValue::Conversation(None),
            native_error(native_instance),
        ));
    }
    match context
        .state
        .borrow_mut()
        .intern_conversation(instance, native)
    {
        Ok(token) => Ok(result(Win16HostDdeValue::Conversation(token), 0)),
        Err(error) => {
            // SAFETY: DdeDisconnect ends a conversation this owner opened.
            unsafe {
                DdeDisconnect(native);
            }
            Err(error)
        }
    }
}

pub(super) fn query_conversation_info(
    context: &WorkerContext,
    conversation: Win16HostDdeConversation,
    transaction: u32,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_conversation, instance, native_instance) = {
        let state = context.state.borrow();
        let (instance, native_conversation) = state.conversation_for_info(conversation)?;
        (
            native_conversation,
            instance,
            state.native_instance(instance)?,
        )
    };
    // SAFETY: The type is a C struct of integers and raw pointers, so the all-zero bit pattern is a valid value.
    let mut native_info: CONVINFO = unsafe { zeroed() };
    native_info.cb = u32::try_from(size_of::<CONVINFO>()).expect("CONVINFO size fits DWORD");
    native_info.ConvCtxt.cb =
        u32::try_from(size_of::<CONVCONTEXT>()).expect("CONVCONTEXT size fits DWORD");
    // SAFETY: `DdeQueryConvInfo` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let copied = unsafe { DdeQueryConvInfo(native_conversation, transaction, &mut native_info) };
    if copied == 0 {
        return Ok(result(
            Win16HostDdeValue::None,
            native_error(native_instance),
        ));
    }
    let mut state = context.state.borrow_mut();
    let host_list = state.intern_list(instance, native_info.hConvList)?;
    if let Some(list) = host_list {
        state
            .list_members
            .entry(list)
            .or_default()
            .insert(conversation);
    }
    let user_handle = u32::try_from(native_info.hUser).map_err(|_| {
        RuntimeError::new(
            Kind::CompatibilityGap,
            "DDE conversation user value does not fit the Win16 DWORD field",
        )
    })?;
    let format = word_value(native_info.wFmt, "DDE conversation format")?;
    let transaction_type = word_value(native_info.wType, "DDE conversation transaction type")?;
    let status = word_value(native_info.wStatus, "DDE conversation status")?;
    let conversation_state = word_value(native_info.wConvst, "DDE conversation state")?;
    let last_error = word_value(native_info.wLastError, "DDE conversation last-error value")?;
    let native_context = from_native_context(&native_info.ConvCtxt)?;
    let (partner, partner_query_only) =
        state.intern_conversation_info_partner(instance, native_info.hConvPartner)?;
    let partner_instance = match (partner, partner_query_only) {
        (Some(token), false) => Some(state.owner_for_conversation(token)?),
        (None, false) | (Some(_), true) => None,
        (None, true) => {
            return Err(protocol_error(
                "null DDE conversation partner was marked query-only",
            ));
        }
    };
    let service_partner = state.intern_string(instance, native_info.hszSvcPartner)?;
    let service_requested = state.intern_string(instance, native_info.hszServiceReq)?;
    let topic = state.intern_string(instance, native_info.hszTopic)?;
    let item = state.intern_string(instance, native_info.hszItem)?;
    for string in [service_partner, service_requested, topic, item]
        .into_iter()
        .flatten()
    {
        state.note_conversation_string(conversation, string)?;
    }
    let info = Win16HostDdeConversationInfo {
        user_handle,
        partner,
        partner_instance,
        partner_query_only,
        service_partner,
        service_requested,
        topic,
        item,
        format,
        transaction_type,
        status,
        conversation_state,
        last_error,
        conversation_list: host_list,
        context: native_context,
    };
    Ok(result(Win16HostDdeValue::ConversationInfo(info), 0))
}

pub(super) fn enable_callback(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    conversation: Option<Win16HostDdeConversation>,
    command: u16,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, native_conversation) = {
        let state = context.state.borrow();
        let native_conversation = conversation.map_or(Ok(ptr::null_mut()), |token| {
            if state.owner_for_conversation(token)? != instance {
                return Err(protocol_error("DDE conversation and instance do not match"));
            }
            state.native_conversation(token)
        })?;
        (state.native_instance(instance)?, native_conversation)
    };
    let succeeded =
        // SAFETY: `DdeEnableCallback` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { DdeEnableCallback(native_instance, native_conversation, u32::from(command)) } != 0;
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
}

pub(super) fn name_service(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    service: Option<Win16HostDdeString>,
    reserved: Option<Win16HostDdeString>,
    command: u16,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, service, reserved) = {
        let state = context.state.borrow();
        (
            state.native_instance(instance)?,
            state.native_optional_string(instance, service)?,
            state.native_optional_string(instance, reserved)?,
        )
    };
    // SAFETY: DdeNameService reads a caller-owned service name.
    let native = unsafe { DdeNameService(native_instance, service, reserved, u32::from(command)) };
    let succeeded = !native.is_null();
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
}

pub(super) fn compare_strings(
    context: &WorkerContext,
    left: Win16HostDdeString,
    right: Win16HostDdeString,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_left, native_right) = {
        let state = context.state.borrow();
        let left_instance = state
            .strings
            .get(&left)
            .ok_or_else(|| protocol_error("unknown left DDE string token"))?
            .instance;
        let right_instance = state
            .strings
            .get(&right)
            .ok_or_else(|| protocol_error("unknown right DDE string token"))?
            .instance;
        (
            state.native_string(left_instance, left)?,
            state.native_string(right_instance, right)?,
        )
    };
    // SAFETY: `DdeCmpStringHandles` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let comparison = unsafe { DdeCmpStringHandles(native_left, native_right) };
    Ok(result(Win16HostDdeValue::Scalar(comparison as u32), 0))
}

pub(super) fn reconnect(
    context: &WorkerContext,
    conversation: Win16HostDdeConversation,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_conversation, instance, native_instance) = {
        let state = context.state.borrow();
        let instance = state.owner_for_conversation(conversation)?;
        (
            state.native_conversation(conversation)?,
            instance,
            state.native_instance(instance)?,
        )
    };
    // SAFETY: `DdeReconnect` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let native = unsafe { DdeReconnect(native_conversation) };
    if native.is_null() {
        return Ok(result(
            Win16HostDdeValue::Conversation(None),
            native_error(native_instance),
        ));
    }
    match context
        .state
        .borrow_mut()
        .intern_conversation(instance, native)
    {
        Ok(token) => Ok(result(Win16HostDdeValue::Conversation(token), 0)),
        Err(error) => {
            // SAFETY: DdeDisconnect ends a conversation this owner opened.
            unsafe {
                DdeDisconnect(native);
            }
            Err(error)
        }
    }
}

pub(in super::super) fn execute_call(
    context: &WorkerContext,
    call: Win16HostDdeCall,
) -> Result<Win16HostDdeResult, RuntimeError> {
    match call {
        Win16HostDdeCall::Initialize {
            existing,
            callback_route,
            flags,
            reserved,
        } => initialize(context, existing, callback_route, flags, reserved),
        Win16HostDdeCall::Uninitialize { instance } => {
            let native_instance = context.state.borrow().native_instance(instance)?;
            // SAFETY: DdeUninitialize releases a DDE instance this owner initialized.
            let succeeded = unsafe { DdeUninitialize(native_instance) } != 0;
            let error = if succeeded {
                0
            } else {
                native_error(native_instance)
            };
            if succeeded {
                context.state.borrow_mut().remove_instance(instance);
            }
            Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
        }
        Win16HostDdeCall::ConnectList {
            instance,
            service,
            topic,
            list,
            context: conversation_context,
        } => connect_list(
            context,
            instance,
            service,
            topic,
            list,
            conversation_context,
        ),
        Win16HostDdeCall::QueryNextServer { list, previous } => {
            let (native_list, native_previous, owner) = {
                let state = context.state.borrow();
                let native_list = state.native_list(list)?;
                let owner = state
                    .conversation_lists
                    .get(&list)
                    .expect("list was just validated")
                    .instance;
                let native_previous = previous.map_or(Ok(ptr::null_mut()), |token| {
                    let previous_owner = state.owner_for_conversation(token)?;
                    if previous_owner != owner {
                        return Err(protocol_error(
                            "DDE previous conversation belongs to another instance",
                        ));
                    }
                    state.native_conversation(token)
                })?;
                (native_list, native_previous, owner)
            };
            // SAFETY: `DdeQueryNextServer` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let native = unsafe { DdeQueryNextServer(native_list, native_previous) };
            let value = context
                .state
                .borrow_mut()
                .intern_conversation(owner, native)?;
            if let Some(conversation) = value {
                if let Some(members) = context.state.borrow_mut().list_members.get_mut(&list) {
                    members.insert(conversation);
                }
            }
            Ok(result(Win16HostDdeValue::Conversation(value), 0))
        }
        Win16HostDdeCall::DisconnectList { list } => {
            let (native, host_owner, owner) = {
                let state = context.state.borrow();
                let native = state.native_list(list)?;
                let owner = state
                    .conversation_lists
                    .get(&list)
                    .expect("list was just validated")
                    .instance;
                (native, owner, state.native_instance(owner)?)
            };
            // DdeDisconnectList may retire members the guest never visited
            // through DdeQueryNextServer. Snapshot every native conversation
            // before the list is consumed so the runtime can retire tokens.
            let mut native_previous = ptr::null_mut();
            let mut members = Vec::new();
            loop {
                // SAFETY: `DdeQueryNextServer` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                let next = unsafe { DdeQueryNextServer(native, native_previous) };
                if next.is_null() {
                    break;
                }
                let token = {
                    let mut state = context.state.borrow_mut();
                    let token = state.intern_conversation(host_owner, next)?;
                    if let Some(token) = token {
                        state.list_members.entry(list).or_default().insert(token);
                    }
                    token
                };
                if let Some(token) = token {
                    members.push(token);
                }
                native_previous = next;
            }
            // SAFETY: `DdeDisconnectList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let succeeded = unsafe { DdeDisconnectList(native) } != 0;
            let error = if succeeded { 0 } else { native_error(owner) };
            if succeeded {
                context.state.borrow_mut().remove_list(list);
            }
            Ok(result(
                Win16HostDdeValue::DisconnectedList { succeeded, members },
                error,
            ))
        }
        Win16HostDdeCall::Connect {
            instance,
            service,
            topic,
            context: conversation_context,
        } => connect(context, instance, service, topic, conversation_context),
        Win16HostDdeCall::Disconnect { conversation } => {
            let (native, owner) = {
                let state = context.state.borrow();
                let native = state.native_conversation(conversation)?;
                (native, state.owner_for_conversation(conversation)?)
            };
            let error_instance = context.state.borrow().native_instance(owner)?;
            // SAFETY: DdeDisconnect ends a conversation this owner opened.
            let succeeded = unsafe { DdeDisconnect(native) } != 0;
            let error = if succeeded {
                0
            } else {
                native_error(error_instance)
            };
            if succeeded {
                context.state.borrow_mut().remove_conversation(conversation);
            }
            Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
        }
        Win16HostDdeCall::QueryConversationInfo {
            conversation,
            transaction,
        } => query_conversation_info(context, conversation, transaction),
        Win16HostDdeCall::SetUserHandle {
            conversation,
            transaction,
            user_data,
        } => {
            let (native, owner) = {
                let state = context.state.borrow();
                let owner = state.owner_for_conversation(conversation)?;
                (
                    state.native_conversation(conversation)?,
                    state.native_instance(owner)?,
                )
            };
            // SAFETY: `DdeSetUserHandle` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let succeeded = unsafe {
                DdeSetUserHandle(
                    native,
                    transaction,
                    usize::try_from(user_data).expect("u32 fits usize"),
                )
            } != 0;
            let error = if succeeded { 0 } else { native_error(owner) };
            Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
        }
        Win16HostDdeCall::ClientTransaction {
            instance,
            data,
            conversation,
            item,
            format,
            transaction_type,
            timeout,
            return_result,
            copyback,
        } => super::transaction::client_transaction(
            context,
            instance,
            data,
            conversation,
            item,
            format,
            transaction_type,
            timeout,
            return_result,
            copyback,
        ),
        Win16HostDdeCall::AbandonTransaction {
            instance,
            conversation,
            transaction,
        } => {
            let (native_instance, native_conversation) = {
                let state = context.state.borrow();
                let native_conversation = conversation.map_or(Ok(ptr::null_mut()), |token| {
                    let owner = state.owner_for_conversation(token)?;
                    if owner != instance {
                        return Err(protocol_error("DDE conversation and instance do not match"));
                    }
                    state.native_conversation(token)
                })?;
                (state.native_instance(instance)?, native_conversation)
            };
            let succeeded =
                // SAFETY: `DdeAbandonTransaction` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                unsafe { DdeAbandonTransaction(native_instance, native_conversation, transaction) }
                    != 0;
            let error = if succeeded {
                0
            } else {
                native_error(native_instance)
            };
            Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
        }
        Win16HostDdeCall::PostAdvise {
            instance,
            topic,
            item,
        } => {
            let (native_instance, native_topic, native_item) = {
                let state = context.state.borrow();
                (
                    state.native_instance(instance)?,
                    state.native_optional_string(instance, topic)?,
                    state.native_optional_string(instance, item)?,
                )
            };
            let succeeded =
                // SAFETY: DdePostAdvise reads caller-owned topic and item strings.
                unsafe { DdePostAdvise(native_instance, native_topic, native_item) } != 0;
            let error = if succeeded {
                0
            } else {
                native_error(native_instance)
            };
            Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
        }
        Win16HostDdeCall::CreateData {
            instance,
            data,
            count,
            offset,
            item,
            format,
            flags,
        } => super::data::create_data(context, instance, data, count, offset, item, format, flags),
        Win16HostDdeCall::AddData {
            data,
            bytes,
            offset,
        } => super::data::add_data(context, data, bytes, offset),
        Win16HostDdeCall::GetData {
            data,
            capacity,
            offset,
        } => super::data::get_data(context, data, capacity, offset),
        Win16HostDdeCall::AccessData { data } => super::data::access_data(context, data),
        Win16HostDdeCall::UnaccessData { data, copyback } => {
            super::data::unaccess_data(context, data, copyback)
        }
        Win16HostDdeCall::FreeData { data } => super::data::free_data(context, data),
        Win16HostDdeCall::GetLastError { instance } => {
            let native_instance = context.state.borrow().native_instance(instance)?;
            let error = (crate::windows::win32_safe::dde_last_error(native_instance)) as u16;
            Ok(result(Win16HostDdeValue::Scalar(u32::from(error)), 0))
        }
        Win16HostDdeCall::CreateString {
            instance,
            value,
            code_page,
        } => strings::create_string(context, instance, value, code_page),
        Win16HostDdeCall::FreeString { instance, string } => {
            strings::free_string(context, instance, string)
        }
        Win16HostDdeCall::QueryString {
            instance,
            string,
            capacity,
            code_page,
        } => strings::query_string(context, instance, string, capacity, code_page),
        Win16HostDdeCall::KeepString { instance, string } => {
            strings::keep_string(context, instance, string)
        }
        Win16HostDdeCall::EnableCallback {
            instance,
            conversation,
            command,
        } => enable_callback(context, instance, conversation, command),
        Win16HostDdeCall::NameService {
            instance,
            service,
            reserved,
            command,
        } => name_service(context, instance, service, reserved, command),
        Win16HostDdeCall::CompareStrings { left, right } => compare_strings(context, left, right),
        Win16HostDdeCall::Reconnect { conversation } => reconnect(context, conversation),
    }
}
