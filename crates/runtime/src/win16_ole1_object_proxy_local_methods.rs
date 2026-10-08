//! Local OLE1 object fields whose Win16 SDK semantics do not require a host call.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16Argument};

use super::super::{
    OLE1_BUSY, OLE1_OK, Win16Ole1PendingOperation, Win16Ole1ReleaseEvidence,
    Win16Ole1ReleaseMethodExpectation, Win16Ole1Status, Win16State,
};
use super::{Win16Ole1NativeObjectKind, Win16Ole1NativeObjectProxyRecord};

pub(super) fn query_link_update_options(
    state: &Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
    arguments: &[Win16Argument],
    memory: &mut Memory,
) -> Win16Ole1Status {
    if record.kind != Win16Ole1NativeObjectKind::Link {
        return super::OLE1_ERROR_NOT_LINK;
    }
    let Some(Win16Argument::Dword(output_far)) = arguments.get(1) else {
        return super::OLE1_ERROR_ADDRESS;
    };
    let Ok(pointer) = state.selectors.pointer_from_far(*output_far) else {
        return super::OLE1_ERROR_ADDRESS;
    };
    if state
        .selectors
        .address_within(pointer, Access::Write, 2, memory.size_bytes())
        .is_err()
    {
        return super::OLE1_ERROR_ADDRESS;
    }
    state
        .selectors
        .write(memory, pointer, &record.link_update_options.to_le_bytes())
        .map_or(super::OLE1_ERROR_ADDRESS, |_| OLE1_OK)
}

pub(super) fn set_link_update_options(
    record: Win16Ole1NativeObjectProxyRecord,
    arguments: &[Win16Argument],
) -> (Win16Ole1Status, Option<&'static str>) {
    if record.kind != Win16Ole1NativeObjectKind::Link {
        return (super::OLE1_ERROR_NOT_LINK, None);
    }
    let Some(Win16Argument::Word(options)) = arguments.get(1) else {
        return (super::OLE1_ERROR_ADDRESS, None);
    };
    if *options > 3 {
        return (super::OLE1_ERROR_OPTION, None);
    }
    if *options == record.link_update_options {
        return (OLE1_OK, None);
    }
    (
        super::OLE1_ERROR_GENERIC,
        Some("changing link update options requires the OLE1 advise DDE transaction"),
    )
}

pub(super) fn object_long(
    state: &mut Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
    arguments: &[Win16Argument],
    memory: &mut Memory,
) -> Win16Ole1Status {
    if !matches!(
        record.kind,
        Win16Ole1NativeObjectKind::Embedded | Win16Ole1NativeObjectKind::Link
    ) {
        return super::OLE1_ERROR_OBJECT;
    }
    let Some(Win16Argument::Word(flags)) = arguments.get(1) else {
        return super::OLE1_ERROR_ADDRESS;
    };
    let Some(Win16Argument::Dword(data_far)) = arguments.get(2) else {
        return super::OLE1_ERROR_ADDRESS;
    };
    let get = *flags & 0x0002 != 0;
    let set = *flags & 0x0001 != 0;
    if !get && !set {
        return OLE1_OK;
    }
    let Ok(pointer) = state.selectors.pointer_from_far(*data_far) else {
        return super::OLE1_ERROR_ADDRESS;
    };
    let input_is_valid = !set
        || state
            .selectors
            .address_within(pointer, Access::Read, 4, memory.size_bytes())
            .is_ok();
    let output_is_valid = !get
        || state
            .selectors
            .address_within(pointer, Access::Write, 4, memory.size_bytes())
            .is_ok();
    if !input_is_valid || !output_is_valid {
        return super::OLE1_ERROR_ADDRESS;
    }
    let replacement = if set {
        let mut bytes = [0_u8; 4];
        if state.selectors.read(memory, pointer, &mut bytes).is_err() {
            return super::OLE1_ERROR_ADDRESS;
        }
        Some(i32::from_le_bytes(bytes))
    } else {
        None
    };
    let old_value = if *flags & 0x0004 != 0 {
        record.handler_data
    } else {
        record.app_data
    };
    if get
        && state
            .selectors
            .write(memory, pointer, &old_value.to_le_bytes())
            .is_err()
    {
        return super::OLE1_ERROR_ADDRESS;
    }
    if let Some(value) = replacement {
        let Some(current) = state
            .ole1_client_documents
            .native_object_proxies
            .iter_mut()
            .find(|current| current.id == record.id)
        else {
            return super::OLE1_ERROR_OBJECT;
        };
        if *flags & 0x0004 != 0 {
            current.handler_data = value;
        } else {
            current.app_data = value;
        }
    }
    OLE1_OK
}

/// Return the exact release status/error/method retained for this object's
/// current release-notification generation. Before a notification arrives,
/// an awaiting operation reports OLE_BUSY; with no pending generation the
/// status/error are OLE_OK and the method is OLE_NONE.
fn release_query_state(
    state: &Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
) -> (Option<Win16Ole1ReleaseEvidence>, bool, Option<u16>) {
    let canonical = state
        .ole1_client_documents
        .canonical_object(record.object_far);
    let mut delivery = state
        .ole1_client_documents
        .release_deliveries
        .iter()
        .filter(|delivery| {
            delivery.document == record.document
                && state
                    .ole1_client_documents
                    .canonical_object(delivery.evidence.object_far)
                    == canonical
        });
    let evidence = delivery.next().map(|delivery| delivery.evidence);
    if delivery.next().is_some() {
        return (None, true, None);
    }

    let Some(document) = state.ole1_client_documents.documents.get(&record.document) else {
        return (evidence, false, None);
    };
    let mut pending = false;
    let mut method = None;
    for operation in &document.pending_operations {
        let (operation_pending, operation_method) = match *operation {
            Win16Ole1PendingOperation::Creation {
                source_object,
                release_object,
                expected_release_method,
                awaiting_release,
                ..
            } => {
                let belongs = source_object.is_some_and(|object| {
                    state.ole1_client_documents.canonical_object(object) == canonical
                }) || release_object.is_some_and(|object| {
                    state.ole1_client_documents.canonical_object(object) == canonical
                });
                if !awaiting_release || !belongs {
                    (false, None)
                } else {
                    let method = match expected_release_method {
                        Win16Ole1ReleaseMethodExpectation::Exact(value) => Some(value),
                        Win16Ole1ReleaseMethodExpectation::FromNotification => None,
                    };
                    (true, method)
                }
            }
            Win16Ole1PendingOperation::Release {
                object_far,
                expected_release_method,
                awaiting_release,
                ..
            } => (
                awaiting_release
                    && state
                        .ole1_client_documents
                        .canonical_object(object_far)
                        == canonical,
                Some(expected_release_method),
            ),
        };
        if operation_pending {
            if pending {
                return (evidence, true, None);
            }
            pending = true;
            method = operation_method;
        }
    }

    if let Some(slot) = state.pending_ole1_object_method_slot(record.id) {
        pending = true;
        method = Some(match slot {
            1 => 1,  // OLE_DELETE
            20 => 8, // OLE_CLOSE
            21 => 7, // OLE_UPDATE
            _ => 15, // OLE_OTHER
        });
    }
    (evidence, pending, method)
}

pub(super) fn query_release_status(
    state: &Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
) -> Win16Ole1Status {
    let (evidence, pending, _) = release_query_state(state, record);
    evidence.map_or_else(|| if pending { OLE1_BUSY } else { OLE1_OK }, |e| e.status)
}

pub(super) fn query_release_error(
    state: &Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
) -> Win16Ole1Status {
    let (evidence, pending, _) = release_query_state(state, record);
    evidence.map_or_else(|| if pending { OLE1_BUSY } else { OLE1_OK }, |e| e.error)
}

pub(super) fn query_release_method(
    state: &Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
) -> u16 {
    let (evidence, _, method) = release_query_state(state, record);
    evidence.map_or_else(|| method.unwrap_or(0), |e| e.method) // OLE_NONE = 0
}
