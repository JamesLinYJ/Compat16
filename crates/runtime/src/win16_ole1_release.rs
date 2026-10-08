//! OLE1 asynchronous client-release evidence and lifecycle bookkeeping.
//!
//! Notifications are claimed against an exact pending generation. Successful
//! Release/Delete membership is detached before guest callback entry.

use super::client::canonical_in;
use super::{
    OLE1_BUSY, OLE1_ERROR_HANDLE, OLE1_ERROR_MEMORY, OLE1_ERROR_OBJECT, OLE1_OK,
    Win16Ole1AsyncBusyOwner, Win16Ole1ClientDocHandle,
    Win16Ole1ClientDocuments, Win16Ole1PendingOperation, Win16Ole1OperationId,
    Win16Ole1ReleaseDelivery, Win16Ole1ReleaseMethodExpectation,
    Win16Ole1Status,
};

/// Completion data published by the producer of one exact asynchronous OLE
/// operation. Query APIs remain ordinary checked vtable calls and do not
/// create or complete a notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win16Ole1ReleaseEvidence {
    pub operation_id: Win16Ole1OperationId,
    /// Callback frame for the initiating object-method call, when present.
    /// DDE-originated creation has no such frame and uses `None`.
    pub initiating_callback_id: Option<u64>,
    pub object_far: u32,
    pub status: u16,
    pub error: u16,
    pub method: u16,
}

impl Win16Ole1ClientDocuments {
    /// Resolve producer data to exactly one pending operation. The completion
    /// operation id is captured when OLE returned OLE_WAIT_FOR_RELEASE; a
    /// producer must publish that exact operation and the object it completed.
    pub(super) fn release_notification_target(
        &self,
        evidence: Win16Ole1ReleaseEvidence,
    ) -> Option<(
        Win16Ole1ClientDocHandle,
        u32,
        bool,
        Option<super::Win16Ole1ClientProxyId>,
    )> {
        if evidence.operation_id.0 == 0
            || evidence.initiating_callback_id == Some(0)
            || evidence.object_far == 0
            || evidence.status != OLE1_OK
            || !(1..=21).contains(&evidence.method)
        {
            return None;
        }
        let canonical = self.canonical_object(evidence.object_far);
        let aliases = &self.protocol_aliases;
        let mut target = None;
        for (handle, document) in &self.documents {
            for operation in &document.pending_operations {
                let candidate = match *operation {
                    Win16Ole1PendingOperation::Creation {
                        operation_id,
                        initiating_callback_id,
                        proxy_id,
                        release_object,
                        client_far,
                        expected_release_method,
                        awaiting_release: true,
                        ..
                    } if operation_id == evidence.operation_id
                        && callback_id_matches(
                            initiating_callback_id,
                            evidence.initiating_callback_id,
                        )
                        && client_far != 0
                        && release_method_matches(expected_release_method, evidence.method)
                        && release_object
                            .map_or(true, |object| canonical_in(aliases, object) == canonical) =>
                    {
                        let needs_registration = self.owner_of(evidence.object_far).is_none();
                        let proxy_matches = proxy_id.is_none_or(|proxy_id| {
                            self.client_proxies.iter().any(|binding| {
                                binding.id == proxy_id
                                    && binding.operation_id == Some(operation_id)
                                    && binding.client_far == client_far
                            })
                        });
                        let association_matches = if needs_registration {
                            // WAIT+NULL may publish the newly created object
                            // only with this exact operation proxy/evidence.
                            let object_conflicts = self.documents.values().any(|document| {
                                document.pending_operations.iter().any(|pending| {
                                    pending_operation_id(*pending) != operation_id
                                        && (pending_conflict_object(*pending).is_some_and(
                                            |object| {
                                                canonical_in(aliases, object) == canonical
                                            },
                                        ) || matches!(pending, Win16Ole1PendingOperation::Creation { release_object: Some(object), .. } if canonical_in(aliases, *object) == canonical))
                                })
                            });
                            release_object.is_none()
                                && canonical == evidence.object_far
                                && proxy_matches
                                && !object_conflicts
                        } else {
                            document.objects.contains(&canonical)
                                && self.client_for_object(evidence.object_far) == Some(client_far)
                                && proxy_id.map_or(true, |proxy_id| {
                                    self.proxy_for_object(evidence.object_far) == Some(proxy_id)
                                })
                        };
                        association_matches.then_some((
                            *handle,
                            client_far,
                            needs_registration,
                            proxy_id,
                        ))
                    }
                    Win16Ole1PendingOperation::Release {
                        operation_id,
                        initiating_callback_id,
                        object_far,
                        expected_release_method,
                        awaiting_release: true,
                        ..
                    } if operation_id == evidence.operation_id
                        && callback_id_matches(
                            initiating_callback_id,
                            evidence.initiating_callback_id,
                        )
                        && canonical_in(aliases, object_far) == canonical
                        && expected_release_method == evidence.method =>
                    {
                        self.client_for_object(evidence.object_far)
                            .filter(|_| {
                                self.owner_of(evidence.object_far).map(|x| x.0) == Some(*handle)
                            })
                            .map(|client_far| {
                                (
                                    *handle,
                                    client_far,
                                    false,
                                    self.proxy_for_object(evidence.object_far),
                                )
                            })
                    }
                    _ => None,
                };
                if let Some(candidate) = candidate {
                    if target.replace(candidate).is_some() {
                        return None;
                    }
                }
            }
        }
        target
    }

    /// Identify the exact operation an OLE client proxy callback can complete.
    /// Creation completion is selected by the operation-specific proxy, never
    /// by the client FAR or document alone.
    pub(super) fn release_callback_generation(
        &self,
        proxy_id: super::Win16Ole1ClientProxyId,
        object_far: u32,
    ) -> Option<(Win16Ole1OperationId, Option<u64>)> {
        if object_far == 0 {
            return None;
        }
        let binding = self.client_proxies.iter().find(|binding| binding.id == proxy_id)?;
        if let Some(operation_id) = binding.operation_id {
            let mut creation = None;
            for (handle, document) in &self.documents {
                for operation in &document.pending_operations {
                    if let Win16Ole1PendingOperation::Creation {
                        operation_id: pending_id,
                        initiating_callback_id,
                        proxy_id: pending_proxy,
                        release_object,
                        client_far,
                        awaiting_release: true,
                        ..
                    } = *operation
                    {
                        let object_matches = match release_object {
                            Some(pending_object) => {
                                canonical_in(&self.protocol_aliases, pending_object) == canonical_in(&self.protocol_aliases, object_far)
                                    && self.owner_of(object_far).is_some_and(|(owner, _)| owner == *handle)
                                    && self.client_for_object(object_far) == Some(binding.client_far)
                                    && self.proxy_for_object(object_far) == Some(proxy_id)
                            }
                            None => {
                                self.owner_of(object_far).is_none()
                                    && self.canonical_object(object_far) == object_far
                            }
                        };
                        if pending_id == operation_id
                            && pending_proxy == Some(proxy_id)
                            && client_far == binding.client_far
                            && object_matches
                        {
                            if creation.replace((pending_id, initiating_callback_id)).is_some() {
                                return None;
                            }
                        }
                    }
                }
            }
            if creation.is_some() {
                return creation;
            }
            // A completed creation binding remains associated with its exact
            // object; only a pending Release on that object can match now.
            let Some((owner, bound_object)) = binding.object else {
                return None;
            };
            if self.owner_of(object_far) != Some((owner, bound_object))
                || canonical_in(&self.protocol_aliases, bound_object)
                    != canonical_in(&self.protocol_aliases, object_far)
            {
                return None;
            }
        } else if binding.object.is_some_and(|(owner, bound_object)| {
            self.owner_of(object_far) != Some((owner, bound_object))
                || canonical_in(&self.protocol_aliases, bound_object)
                    != canonical_in(&self.protocol_aliases, object_far)
        }) {
            return None;
        }
        let canonical = self.canonical_object(object_far);
        let aliases = &self.protocol_aliases;
        let mut generation = None;
        for (handle, document) in &self.documents {
            for operation in &document.pending_operations {
                let candidate = match *operation {
                    Win16Ole1PendingOperation::Release {
                        operation_id,
                        initiating_callback_id,
                        object_far: pending_object,
                        awaiting_release: true,
                        ..
                    } if canonical_in(aliases, pending_object) == canonical
                        && self
                            .owner_of(object_far)
                            .is_some_and(|(owner, _)| owner == *handle)
                        && self.client_for_object(object_far) == Some(binding.client_far) =>
                    {
                        Some((operation_id, initiating_callback_id))
                    }
                    _ => None,
                };
                if let Some(candidate) = candidate {
                    if generation.replace(candidate).is_some() {
                        return None;
                    }
                }
            }
        }
        generation
    }

    /// Move one exact operation into the notification-delivery set before
    /// entering guest code. It no longer blocks a reentrant operation on the
    /// object. WAIT+NULL objects are registered now, before the callback can
    /// delete them, so callback completion cannot resurrect a deleted token.
    pub(super) fn claim_release_notification(
        &mut self,
        evidence: Win16Ole1ReleaseEvidence,
    ) -> Result<u32, Win16Ole1Status> {
        let (handle, client_far, was_unbound, proxy_id) = self
            .release_notification_target(evidence)
            .ok_or(OLE1_ERROR_OBJECT)?;
        if self
            .release_deliveries
            .iter()
            .any(|delivery| delivery.evidence.operation_id == evidence.operation_id)
        {
            return Err(OLE1_BUSY);
        }
        self.release_deliveries
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        if was_unbound {
            let document = self.documents.get_mut(&handle).ok_or(OLE1_ERROR_HANDLE)?;
            document
                .objects
                .try_reserve(1)
                .map_err(|_| OLE1_ERROR_MEMORY)?;
            document
                .object_clients
                .try_reserve(1)
                .map_err(|_| OLE1_ERROR_MEMORY)?;
            if proxy_id.is_some() {
                document
                    .object_proxy_bindings
                    .try_reserve(1)
                    .map_err(|_| OLE1_ERROR_MEMORY)?;
            }
        }

        let (operation_index, mut operation) = {
            let document = self.documents.get(&handle).ok_or(OLE1_ERROR_HANDLE)?;
            let mut matches =
                document
                    .pending_operations
                    .iter()
                    .enumerate()
                    .filter(|(_, operation)| match operation {
                        Win16Ole1PendingOperation::Creation { operation_id, .. }
                        | Win16Ole1PendingOperation::Release { operation_id, .. } => {
                            *operation_id == evidence.operation_id
                        }
                    });
            let (index, operation) = matches.next().ok_or(OLE1_ERROR_OBJECT)?;
            if matches.next().is_some() {
                return Err(OLE1_ERROR_OBJECT);
            }
            (index, *operation)
        };
        if let Win16Ole1PendingOperation::Creation {
            release_object,
            async_busy_command_on_return,
            async_busy,
            ..
        } = &mut operation
        {
            if release_object.is_none() {
                *release_object = Some(evidence.object_far);
                if let Some(command) = *async_busy_command_on_return {
                    *async_busy = Some(Win16Ole1AsyncBusyOwner {
                        object_far: evidence.object_far,
                        command,
                    });
                }
            }
        }

        let canonical_object = self.canonical_object(evidence.object_far);
        let release_succeeded = matches!(operation, Win16Ole1PendingOperation::Release { .. })
            && evidence.status == OLE1_OK
            && evidence.error == OLE1_OK
            && evidence.method == 1;
        if release_succeeded {
            if was_unbound {
                return Err(OLE1_ERROR_OBJECT);
            }
            let document = self.documents.get(&handle).ok_or(OLE1_ERROR_HANDLE)?;
            if !document.objects.contains(&canonical_object)
                || !document
                    .object_clients
                    .iter()
                    .any(|(object, client)| *object == canonical_object && *client == client_far)
            {
                return Err(OLE1_ERROR_OBJECT);
            }
        }

        let removed_object_proxy = if release_succeeded {
            self.proxy_for_object(evidence.object_far)
        } else {
            None
        };

        let mut removed_aliases = Vec::new();
        if release_succeeded {
            let alias_count = self
                .protocol_aliases
                .iter()
                .filter(|alias| alias.canonical_object == canonical_object)
                .count();
            removed_aliases
                .try_reserve(alias_count)
                .map_err(|_| OLE1_ERROR_MEMORY)?;
        }

        {
            let document = self.documents.get_mut(&handle).ok_or(OLE1_ERROR_HANDLE)?;
            document.pending_operations.remove(operation_index);
            if was_unbound {
                document.objects.push(evidence.object_far);
                document
                    .object_clients
                    .push((evidence.object_far, client_far));
                if let Some(proxy_id) = proxy_id {
                    document
                        .object_proxy_bindings
                        .push((evidence.object_far, proxy_id));
                }
            }
            if release_succeeded {
                document
                    .objects
                    .retain(|object| *object != canonical_object);
                document
                    .object_clients
                    .retain(|(object, _)| *object != canonical_object);
                document
                    .object_proxy_bindings
                    .retain(|(object, _)| *object != canonical_object);
            }
        }
        if let Some(proxy_id) = proxy_id.filter(|_| was_unbound) {
            self.set_proxy_object(proxy_id, Some((handle, evidence.object_far)))
                .map_err(|_| OLE1_ERROR_OBJECT)?;
        }
        if let Some(proxy_id) = removed_object_proxy {
            self.set_proxy_object(proxy_id, None)
                .map_err(|_| OLE1_ERROR_OBJECT)?;
        }
        if release_succeeded {
            for index in (0..self.protocol_aliases.len()).rev() {
                if self.protocol_aliases[index].canonical_object == canonical_object {
                    removed_aliases.push(self.protocol_aliases.remove(index));
                }
            }
            removed_aliases.reverse();
        }
        self.release_deliveries.push(Win16Ole1ReleaseDelivery {
            evidence,
            document: handle,
            operation,
            removed_object_client: release_succeeded.then_some((canonical_object, client_far)),
            removed_object_proxy,
            removed_aliases,
        });
        Ok(client_far)
    }

    /// Restore a claimed completion only when checked callback setup failed
    /// before guest execution. The object disclosed by WAIT+NULL remains
    /// registered and the pending operation is rebound to it for retry.
    pub(super) fn unclaim_release_notification(
        &mut self,
        operation_id: Win16Ole1OperationId,
    ) {
        let Some(index) = self
            .release_deliveries
            .iter()
            .position(|delivery| delivery.evidence.operation_id == operation_id)
        else {
            return;
        };
        let delivery = self.release_deliveries.remove(index);
        let mut restored_proxy = None;
        if let Some(document) = self.documents.get_mut(&delivery.document) {
            if let Some((object_far, client_far)) = delivery.removed_object_client {
                if !document.objects.contains(&object_far) {
                    document.objects.push(object_far);
                    document.object_clients.push((object_far, client_far));
                }
                if let Some(proxy_id) = delivery.removed_object_proxy {
                    if !document
                        .object_proxy_bindings
                        .iter()
                        .any(|(object, _)| *object == object_far)
                    {
                        document.object_proxy_bindings.push((object_far, proxy_id));
                    }
                    restored_proxy = Some((proxy_id, object_far));
                }
            }
            document.pending_operations.push(delivery.operation);
        } else {
            return;
        }
        if let Some((proxy_id, object_far)) = restored_proxy {
            let _ = self.set_proxy_object(proxy_id, Some((delivery.document, object_far)));
        }
        for alias in delivery.removed_aliases {
            if !self.protocol_aliases.contains(&alias) {
                self.protocol_aliases.push(alias);
            }
        }
    }

    /// Commit only the notification's saved generation. Reentrant operations
    /// started by the client callback stay in the pending list untouched.
    pub(super) fn complete_release_notification(
        &mut self,
        evidence: Win16Ole1ReleaseEvidence,
    ) -> Result<Option<super::Win16Ole1ClientProxyId>, Win16Ole1Status> {
        if evidence.object_far == 0
            || evidence.operation_id.0 == 0
            || evidence.initiating_callback_id == Some(0)
            || evidence.status != OLE1_OK
            || !(1..=21).contains(&evidence.method)
        {
            return Err(OLE1_ERROR_OBJECT);
        }
        let Some(index) = self
            .release_deliveries
            .iter()
            .position(|delivery| delivery.evidence == evidence)
        else {
            return Err(OLE1_ERROR_OBJECT);
        };
        let delivery = self.release_deliveries.remove(index);
        Ok(delivery.removed_object_proxy)
    }
}

fn callback_id_matches(expected: Option<u64>, actual: Option<u64>) -> bool {
    expected == actual
}

fn pending_operation_id(operation: Win16Ole1PendingOperation) -> Win16Ole1OperationId {
    match operation {
        Win16Ole1PendingOperation::Creation { operation_id, .. }
        | Win16Ole1PendingOperation::Release { operation_id, .. } => operation_id,
    }
}

fn pending_conflict_object(operation: Win16Ole1PendingOperation) -> Option<u32> {
    match operation {
        Win16Ole1PendingOperation::Creation { async_busy, .. }
        | Win16Ole1PendingOperation::Release { async_busy, .. } => {
            async_busy.map(|owner| owner.object_far)
        }
    }
}

fn release_method_matches(expectation: Win16Ole1ReleaseMethodExpectation, actual: u16) -> bool {
    match expectation {
        Win16Ole1ReleaseMethodExpectation::Exact(expected) => expected == actual,
        Win16Ole1ReleaseMethodExpectation::FromNotification => true,
    }
}
