//! Native-backed OLE 1.0 object wire records and their checked method gates.
//!
//! The guest-visible object is an OLE.H `OLEOBJECT` followed by the client
//! 39-entry `OLEOBJECTVTBL`. The table contains runtime gates, never native
//! function pointers. Each record retains the exact owned COM references and
//! STA owner needed by the adapter; none of those IDs are FAR addresses.

#[path = "win16_ole1_object_proxy_method_gate.rs"]
mod method_gate;
#[path = "win16_ole1_object_proxy_retirement.rs"]
mod retirement;

use guest_core::{OwnerId, memory::Memory};
use win16_abi::{
    AllocationFlags, GlobalHandle, ReturnAddressWidth, SegmentedPointer, Win16Argument,
    Win16CallFrame, Win16CallingConvention, Win16ReturnKind,
};
use x86_cpu::Cpu;

use super::{
    OLE1_ERROR_ADDRESS, OLE1_ERROR_HANDLE, OLE1_ERROR_MEMORY, OLE1_ERROR_OBJECT,
    Win16Ole1ClientDocHandle, Win16Ole1ClientProxyId, Win16Ole1OperationId, Win16Ole1Status,
    Win16State, Win16Ole1ClientDocuments,
};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

#[path = "win16_ole1_object_proxy_local_methods.rs"]
mod local_methods;
#[path = "win16_ole1_object_method_abi.rs"]
mod method_abi;
#[path = "win16_ole1_object_proxy_validation.rs"]
mod validation;
use method_abi::{OBJECT_METHOD_ABI, OLE1ObjectMethodReturn, method_signature};

pub(super) fn object_method_gap_status(slot: u8) -> Option<u16> {
    method_abi::method_compatibility_status(slot)
}

pub(super) fn object_method_gap_context(slot: u8) -> Option<&'static str> {
    method_abi::method_compatibility_gap(slot)
}

const OLE1_OBJECT_PROXY_OWNER: OwnerId = OwnerId(u32::MAX - 2);
const OLE1_OBJECT_BYTES: u32 = 4;
const OLE1_OBJECT_VTABLE_SLOTS: u8 = 39;
const OLE1_OBJECT_VTABLE_BYTES: u32 = (OLE1_OBJECT_VTABLE_SLOTS as u32) * 4;
const OLE1_OBJECT_PROXY_BYTES: u32 = OLE1_OBJECT_BYTES + OLE1_OBJECT_VTABLE_BYTES;
const OLE1_ERROR_OPTION: Win16Ole1Status = 14;
const OLE1_ERROR_STREAM: Win16Ole1Status = 5;
use super::OLE1_ERROR_NOT_LINK;
const OLE1_ERROR_SIZE: Win16Ole1Status = 26;
const OLE1_ERROR_DRAW: Win16Ole1Status = 8;
const OLE1_ERROR_CLIPBOARD: Win16Ole1Status = 11;
const OLE1_ERROR_FORMAT: Win16Ole1Status = 12;
const OLE1_ERROR_DATATYPE: Win16Ole1Status = 22;
const OLE1_ERROR_PALETTE: Win16Ole1Status = 23;
const OLE1_ERROR_NAME: Win16Ole1Status = 29;
const OLE1_ERROR_NEW: Win16Ole1Status = 31;
const OLE1_ERROR_COMM: Win16Ole1Status = 36;
const OLE1_ERROR_CLASS: Win16Ole1Status = 20;
const OLE1_ERROR_COMMAND: Win16Ole1Status = 38;
const OLE1_ERROR_SHOW: Win16Ole1Status = 39;
const OLE1_ERROR_DOVERB: Win16Ole1Status = 40;
const OLE1_ERROR_SETDATA_FORMAT: Win16Ole1Status = 54;
const OLE1_ERROR_GENERIC: Win16Ole1Status = 19;
const OLE1_CHANGED: u16 = 0;
const OLE1_SAVED: u16 = 1;
const OLE1_CLOSED: u16 = 2;
const OLE1_RENAMED: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16Ole1NativeObjectKind {
    Embedded,
    Link,
}

/// The runtime OLE1 object identity is deliberately distinct from the COM
/// object identity, its callback route, and the FAR value exposed to Win16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1NativeObjectProxyRecord {
    pub(super) id: u64,
    pub(super) allocation: GlobalHandle,
    pub(super) object_far: u32,
    pub(super) vtable_far: u32,
    pub(super) object_pointer: SegmentedPointer,
    pub(super) vtable_pointer: SegmentedPointer,
    pub(super) document: Win16Ole1ClientDocHandle,
    pub(super) client_far: u32,
    pub(super) client_proxy_id: Win16Ole1ClientProxyId,
    pub(super) client_proxy_allocation: GlobalHandle,
    pub(super) operation_id: Win16Ole1OperationId,
    pub(super) callback_route: crate::Win16ComHostCallbackRoute,
    pub(super) object: crate::Win16ComHostInterface,
    pub(super) storage: Option<crate::Win16ComHostInterface>,
    pub(super) client_site: crate::Win16ComHostInterface,
    pub(super) advise_sink: crate::Win16ComHostInterface,
    pub(super) kind: Win16Ole1NativeObjectKind,
    pub(super) link_update_options: u16,
    pub(super) advise_cookie: Option<u32>,
    pub(super) handler_data: i32,
    pub(super) app_data: i32,
}

/// References transferred here must all be owned by one live host COM owner.
/// The caller retains responsibility for releasing them unless this value is
/// accepted and the corresponding guest proxy is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1NativeObjectResources {
    pub(super) callback_route: crate::Win16ComHostCallbackRoute,
    pub(super) object: crate::Win16ComHostInterface,
    pub(super) storage: Option<crate::Win16ComHostInterface>,
    pub(super) client_site: crate::Win16ComHostInterface,
    pub(super) advise_sink: crate::Win16ComHostInterface,
    /// OLE1 object class comes from the exact create/load API path. It is not
    /// inferred from a COM CLSID or native pointer.
    pub(super) kind: Win16Ole1NativeObjectKind,
    /// Win16 OLEOPT_UPDATE value, meaningful only for Link objects.
    pub(super) link_update_options: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1PendingObjectProxyRetirement {
    pub(in crate::win16_runtime) owner: crate::Win16ComHostOwnerIdentity,
    pub(super) allocation: GlobalHandle,
    /// Identity retained when this is the public native-backed object wire.
    pub(super) native_proxy_id: Option<u64>,
    /// Identity retained when this is its operation-specific OLECLIENT wire.
    pub(super) client_proxy_id: Option<Win16Ole1ClientProxyId>,
    /// Exact outstanding internal locks reported by GlobalHeap. Retrying
    /// retirement pays only these locks before it attempts the free.
    pub(super) unlocks_pending: u16,
}

fn canonical_selector(selector: u16) -> u16 {
    selector & !0x7
}

fn canonical_far(address: u32) -> u32 {
    (u32::from(canonical_selector((address >> 16) as u16)) << 16) | (address & 0xffff)
}

impl Win16State {
    /// Resolve one native AdviseSink callback to the exact live guest client
    /// proxy and OLEOBJECT identity. This only prepares the checked guest call;
    /// the dispatcher still owns callback execution and exact COM-frame reply.
    pub(in crate::win16_runtime) fn prepare_ole1_com_advise_callback(
        &self,
        step: &crate::Win16ComHostCallbackStep,
        memory: &mut Memory,
    ) -> Result<
        (
            super::Win16Ole1ClientProxyCall,
            super::Win16Ole1ComCallbackIdentity,
        ),
        RuntimeError,
    > {
        if !step.has_valid_identity() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM callback has an invalid owner, frame, or route identity",
            ));
        }
        let mut matching = self
            .ole1_client_documents
            .native_object_proxies
            .iter()
            .filter(|record| record.callback_route == step.route);
        let Some(record) = matching.next().copied() else {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "COM callback route has no live OLE1 object adapter",
            ));
        };
        if matching.next().is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 COM callback route is registered more than once",
            ));
        }
        if record.object.owner != step.owner
            || record.client_site.owner != step.owner
            || record.advise_sink.owner != step.owner
        {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM callback owner differs from the OLE1 object's owner incarnation",
            ));
        }
        let (sink, callback_object, notification) = match &step.callback {
            crate::Win16ComHostCallbackCall::AdviseSink {
                sink,
                object,
                method,
            } => {
                let notification = match method {
                    crate::Win16ComHostAdviseSinkCall::OnDataChange { .. }
                    | crate::Win16ComHostAdviseSinkCall::OnViewChange { .. } => OLE1_CHANGED,
                    crate::Win16ComHostAdviseSinkCall::OnRename { .. } => OLE1_RENAMED,
                    crate::Win16ComHostAdviseSinkCall::OnSave => OLE1_SAVED,
                    crate::Win16ComHostAdviseSinkCall::OnClose => OLE1_CLOSED,
                };
                (*sink, *object, notification)
            }
            crate::Win16ComHostCallbackCall::ClientSiteSaveObject { .. } => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "OLE1 client APIs provide no verified OLE1 notification equivalent for IOleClientSite::SaveObject",
                ));
            }
        };
        if sink != record.advise_sink.object
            || callback_object.is_some_and(|object| object != record.object.object)
        {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM AdviseSink callback does not match the recorded OLE1 object adapter",
            ));
        }

        let Some(binding) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == record.client_proxy_id)
            .copied()
        else {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "OLE1 COM callback's guest client proxy has retired",
            ));
        };
        if binding.retire_requested
            || binding.client_far != record.client_far
            || binding.object != Some((record.document, record.object_far))
            || binding.operation_id != Some(record.operation_id)
            || !self
                .ole1_client_documents
                .documents
                .get(&record.document)
                .is_some_and(|document| document.objects.contains(&record.object_far))
        {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "OLE1 COM callback's client/object association is no longer live",
            ));
        }
        if !validation::validate(self, record, 0, memory)? {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "OLE1 COM callback's guest object proxy or vtable is stale",
            ));
        }

        let call = super::Win16Ole1ClientProxyCall {
            proxy_id: binding.id,
            proxy_operation_id: binding.operation_id,
            proxy_far: binding.proxy_far,
            client_far: binding.client_far,
            client_pointer: binding.client_pointer,
            notification,
            object_far: record.object_far,
            pending_operation: None,
            release_status: None,
            release_error: None,
        };
        let identity = super::Win16Ole1ComCallbackIdentity {
            frame: step.frame,
            parent: step.parent,
            owner: step.owner,
            route: step.route,
        };
        Ok((call, identity))
    }

    /// Publish a guest OLEOBJECT only after the caller has completed all real
    /// native setup. On error the caller retains every COM reference and must
    /// release it through the owning STA; this method owns only its guest
    /// allocation. The method never treats a COM object ID as a FAR pointer.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_ole1_native_object_proxy(
        &mut self,
        document: Win16Ole1ClientDocHandle,
        client_far: u32,
        client_proxy_id: Win16Ole1ClientProxyId,
        operation_id: Win16Ole1OperationId,
        resources: Win16Ole1NativeObjectResources,
        memory: &mut Memory,
    ) -> Result<u32, Win16Ole1ObjectProxyError> {
        self.retry_native_object_proxy_retirements()
            .map_err(Win16Ole1ObjectProxyError::Runtime)?;
        if resources.callback_route.0 == 0
            || !resources.object.owner.is_valid()
            || resources.object.object.0 == 0
            || resources.object.iid != iid_ole_object()
            || resources.object.disposition != compat_services::com::ReferenceDisposition::Owned
            || resources.client_site.object.0 == 0
            || resources.client_site.owner != resources.object.owner
            || resources.client_site.iid != compat_services::com::IID_IOLE_CLIENT_SITE
            || resources.client_site.disposition
                != compat_services::com::ReferenceDisposition::Owned
            || resources.advise_sink.object.0 == 0
            || resources.advise_sink.owner != resources.object.owner
            || resources.advise_sink.iid != iid_iadvise_sink()
            || resources.advise_sink.disposition
                != compat_services::com::ReferenceDisposition::Owned
            || resources.storage.is_some_and(|storage| {
                storage.object.0 == 0
                    || storage.owner != resources.object.owner
                    || storage.iid != compat_services::com::IID_ISTORAGE
                    || storage.disposition != compat_services::com::ReferenceDisposition::Owned
            })
        {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_OBJECT));
        }
        if client_far == 0 {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_ADDRESS));
        }
        if resources.kind == Win16Ole1NativeObjectKind::Link && resources.link_update_options > 3 {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_OPTION));
        }
        if !self.ole1_client_documents.documents.contains_key(&document) {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_HANDLE));
        }
        let Some(document_record) = self.ole1_client_documents.documents.get(&document) else {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_HANDLE));
        };
        if !document_record.pending_operations.iter().any(|pending| {
            matches!(pending,
                super::Win16Ole1PendingOperation::Creation {
                    operation_id: pending_id,
                    proxy_id: Some(pending_proxy),
                    client_far: pending_client,
                    ..
                } if *pending_id == operation_id
                    && *pending_proxy == client_proxy_id
                    && *pending_client == client_far
            )
        }) {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_OBJECT));
        }
        let Some(client_binding) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == client_proxy_id)
            .copied()
        else {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_OBJECT));
        };
        if client_binding.operation_id != Some(operation_id)
            || client_binding.client_far != client_far
            || client_binding.object.is_some()
            || client_binding.retire_requested
        {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_OBJECT));
        }

        self.ole1_client_documents
            .native_object_proxies
            .try_reserve(1)
            .map_err(|_| Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY))?;
        self.ole1_client_documents
            .pending_native_object_proxy_retirements
            .try_reserve(1)
            .map_err(|_| Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY))?;
        self.ole1_client_documents
            .reserve_object_slot(document)
            .map_err(Win16Ole1ObjectProxyError::Status)?;

        let id = self
            .ole1_client_documents
            .next_native_object_proxy_id
            .ok_or(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY))?;
        if id == 0 {
            return Err(Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY));
        }
        // Never reuse an identity, including after a later guest-memory or
        // gate allocation fails. Orphaned gates therefore resolve stale.
        self.ole1_client_documents.next_native_object_proxy_id =
            id.checked_add(1).filter(|next| *next != 0);

        if let Err(error) =
            self.reserve_ole1_object_method_gates(usize::from(OLE1_OBJECT_VTABLE_SLOTS), memory)
        {
            return Err(Win16Ole1ObjectProxyError::from_runtime(
                error.with_context("reserve all OLE1 public object method gates"),
            ));
        }

        let allocation = self
            .heap
            .alloc(
                memory,
                OLE1_OBJECT_PROXY_OWNER,
                OLE1_OBJECT_PROXY_BYTES,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(|error| {
                let runtime = crate::runtime_error(error)
                    .with_context("allocate OLE1 object and 39-slot client vtable");
                if runtime.kind() == Kind::ResourceExhausted {
                    Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY)
                } else {
                    Win16Ole1ObjectProxyError::Runtime(runtime)
                }
            })?;
        let base = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => {
                let primary = crate::runtime_error(error)
                    .with_context("lock OLE1 object and vtable allocation");
                return Err(self.rollback_unlocked_proxy_build(
                    allocation,
                    resources.object.owner,
                    id,
                    Win16Ole1ObjectProxyError::from_runtime(primary),
                ));
            }
        };

        let object_far = base.far_value();
        let vtable_pointer = match self.selectors.add_bytes(base, OLE1_OBJECT_BYTES) {
            Ok(pointer) => pointer,
            Err(error) => {
                return Err(self.rollback_locked_proxy_build(
                    allocation,
                    resources.object.owner,
                    id,
                    Win16Ole1ObjectProxyError::Runtime(
                        crate::runtime_error(error)
                            .with_context("derive OLE1 vtable pointer from object allocation"),
                    ),
                    true,
                ));
            }
        };
        let vtable_far = vtable_pointer.far_value();
        let mut wire = Vec::new();
        if let Err(error) = wire.try_reserve_exact(OLE1_OBJECT_PROXY_BYTES as usize) {
            return Err(self.rollback_locked_proxy_build(
                allocation,
                resources.object.owner,
                id,
                Win16Ole1ObjectProxyError::from_runtime(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve OLE1 object wire image",
                    error,
                )),
                true,
            ));
        }
        wire.extend_from_slice(&vtable_far.to_le_bytes());
        for slot in 0..OLE1_OBJECT_VTABLE_SLOTS {
            let method_far = match self.ole1_object_method_gate(id, slot, memory) {
                Ok(address) => address,
                Err(error) => {
                    return Err(self.rollback_locked_proxy_build(
                        allocation,
                        resources.object.owner,
                        id,
                        Win16Ole1ObjectProxyError::from_runtime(error),
                        true,
                    ));
                }
            };
            wire.extend_from_slice(&method_far.to_le_bytes());
        }
        if wire.len() != OLE1_OBJECT_PROXY_BYTES as usize {
            return Err(self.rollback_locked_proxy_build(
                allocation,
                resources.object.owner,
                id,
                Win16Ole1ObjectProxyError::Runtime(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 public object vtable wire size changed",
                )),
                true,
            ));
        }
        if let Err(error) = self.selectors.write(memory, base, &wire) {
            return Err(self.rollback_locked_proxy_build(
                allocation,
                resources.object.owner,
                id,
                Win16Ole1ObjectProxyError::Runtime(
                    crate::runtime_error(error).with_context("write OLE1 object proxy wire image"),
                ),
                true,
            ));
        }
        let remaining_pins = match self.heap.unlock(allocation, &mut self.selectors) {
            Ok(remaining) => remaining,
            Err(error) => {
                let primary = crate::runtime_error(error)
                    .with_context("unlock newly published OLE1 object wire image");
                self.ole1_client_documents
                    .pending_native_object_proxy_retirements
                    .push(Win16Ole1PendingObjectProxyRetirement {
                        owner: resources.object.owner,
                        allocation,
                        native_proxy_id: Some(id),
                        client_proxy_id: None,
                        unlocks_pending: 1,
                    });
                return Err(Win16Ole1ObjectProxyError::Runtime(primary));
            }
        };
        if remaining_pins != 0 {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "new OLE1 object proxy retained an unexpected heap pin",
            );
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(Win16Ole1PendingObjectProxyRetirement {
                    owner: resources.object.owner,
                    allocation,
                    native_proxy_id: Some(id),
                    client_proxy_id: None,
                    unlocks_pending: remaining_pins,
                });
            return Err(Win16Ole1ObjectProxyError::Runtime(primary));
        }

        // Membership is committed only after all guest-visible bytes and
        // gates exist. The earlier capacity reservation keeps this step
        // allocation-free; a failed association retires the guest allocation.
        if let Err(status) = self.ole1_client_documents.add_object_with_proxy(
            document,
            object_far,
            client_far,
            Some(client_proxy_id),
            Some(operation_id),
        ) {
            let primary = Win16Ole1ObjectProxyError::Status(status);
            if let Err(error) = self.free_unlocked_object_proxy(allocation) {
                self.ole1_client_documents
                    .pending_native_object_proxy_retirements
                    .push(Win16Ole1PendingObjectProxyRetirement {
                        owner: resources.object.owner,
                        allocation,
                        native_proxy_id: Some(id),
                        client_proxy_id: None,
                        unlocks_pending: 0,
                    });
                return Err(primary.with_cleanup(
                    "OLE1 proxy association failed and guest allocation free also failed",
                    error,
                ));
            }
            return Err(primary);
        }

        let record = Win16Ole1NativeObjectProxyRecord {
            id,
            allocation,
            object_far,
            vtable_far,
            object_pointer: base,
            vtable_pointer,
            document,
            client_far,
            client_proxy_id,
            client_proxy_allocation: client_binding.allocation,
            operation_id,
            callback_route: resources.callback_route,
            object: resources.object,
            storage: resources.storage,
            client_site: resources.client_site,
            advise_sink: resources.advise_sink,
            kind: resources.kind,
            link_update_options: resources.link_update_options,
            advise_cookie: None,
            handler_data: 0,
            app_data: 0,
        };
        self.ole1_client_documents
            .native_object_proxies
            .push(record);
        Ok(object_far)
    }

    fn free_unlocked_object_proxy(&mut self, allocation: GlobalHandle) -> Result<(), RuntimeError> {
        self.heap
            .free(allocation, &mut self.selectors)
            .map_err(crate::runtime_error)
    }

    fn rollback_unlocked_proxy_build(
        &mut self,
        allocation: GlobalHandle,
        owner: crate::Win16ComHostOwnerIdentity,
        native_proxy_id: u64,
        primary: Win16Ole1ObjectProxyError,
    ) -> Win16Ole1ObjectProxyError {
        if let Err(error) = self.heap.free(allocation, &mut self.selectors) {
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(Win16Ole1PendingObjectProxyRetirement {
                    owner,
                    allocation,
                    native_proxy_id: Some(native_proxy_id),
                    client_proxy_id: None,
                    unlocks_pending: 0,
                });
            return primary.with_cleanup(
                "OLE1 proxy creation failed and guest allocation free also failed",
                crate::runtime_error(error),
            );
        }
        primary
    }

    fn rollback_locked_proxy_build(
        &mut self,
        allocation: GlobalHandle,
        owner: crate::Win16ComHostOwnerIdentity,
        native_proxy_id: u64,
        primary: Win16Ole1ObjectProxyError,
        still_locked: bool,
    ) -> Win16Ole1ObjectProxyError {
        let remaining = if still_locked {
            match self.heap.unlock(allocation, &mut self.selectors) {
                Ok(remaining) => remaining,
                Err(error) => {
                    self.ole1_client_documents
                        .pending_native_object_proxy_retirements
                        .push(Win16Ole1PendingObjectProxyRetirement {
                            owner,
                            allocation,
                            native_proxy_id: Some(native_proxy_id),
                            client_proxy_id: None,
                            unlocks_pending: 1,
                        });
                    return primary.with_cleanup(
                        "OLE1 proxy creation failed and guest allocation unlock also failed",
                        crate::runtime_error(error),
                    );
                }
            }
        } else {
            0
        };
        if remaining != 0 {
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(Win16Ole1PendingObjectProxyRetirement {
                    owner,
                    allocation,
                    native_proxy_id: Some(native_proxy_id),
                    client_proxy_id: None,
                    unlocks_pending: remaining,
                });
            return primary.with_cleanup(
                "OLE1 proxy creation left unexpected outstanding heap locks",
                RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("{remaining} OLE1 object-proxy heap locks remain"),
                ),
            );
        }
        if let Err(error) = self.heap.free(allocation, &mut self.selectors) {
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(Win16Ole1PendingObjectProxyRetirement {
                    owner,
                    allocation,
                    native_proxy_id: Some(native_proxy_id),
                    client_proxy_id: None,
                    unlocks_pending: 0,
                });
            return primary.with_cleanup(
                "OLE1 proxy creation failed and guest allocation free also failed",
                crate::runtime_error(error),
            );
        }
        primary
    }

    pub(in crate::win16_runtime) fn retry_native_object_proxy_retirements(
        &mut self,
    ) -> Result<(), RuntimeError> {
        let index = 0;
        while index
            < self
                .ole1_client_documents
                .pending_native_object_proxy_retirements
                .len()
        {
            let retirement = self
                .ole1_client_documents
                .pending_native_object_proxy_retirements[index];
            let mut unlocks_pending = retirement.unlocks_pending;
            while unlocks_pending != 0 {
                let previous = unlocks_pending;
                unlocks_pending = self
                    .heap
                    .unlock(retirement.allocation, &mut self.selectors)
                    .map_err(crate::runtime_error)
                    .map_err(|error| {
                        error.with_context("retry OLE1 object-proxy allocation unlock")
                    })?;
                if unlocks_pending >= previous {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retrying OLE1 object-proxy unlock made no progress",
                    ));
                }
                self.ole1_client_documents
                    .pending_native_object_proxy_retirements[index]
                    .unlocks_pending = unlocks_pending;
            }
            self.heap
                .free(retirement.allocation, &mut self.selectors)
                .map_err(crate::runtime_error)
                .map_err(|error| error.with_context("retry OLE1 object-proxy allocation free"))?;
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .remove(index);
        }
        Ok(())
    }
}

fn iid_ole_object() -> compat_services::com::Guid {
    compat_services::com::Guid::new(0x0000_0112, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46])
}

fn iid_iadvise_sink() -> compat_services::com::Guid {
    compat_services::com::Guid::new(0x0000_010f, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46])
}

#[derive(Debug)]
pub(super) enum Win16Ole1ObjectProxyError {
    Status(Win16Ole1Status),
    Runtime(RuntimeError),
}

impl Win16Ole1ObjectProxyError {
    fn with_cleanup(self, context: &'static str, cleanup: RuntimeError) -> Self {
        let primary = match self {
            Self::Status(status) => RuntimeError::new(
                if status == OLE1_ERROR_MEMORY {
                    Kind::ResourceExhausted
                } else {
                    Kind::HostFailure
                },
                format!("OLE1 proxy setup produced status {status} before cleanup failed"),
            ),
            Self::Runtime(error) => error,
        };
        Self::Runtime(primary.with_cleanup(context, cleanup))
    }

    pub(super) fn from_runtime(error: RuntimeError) -> Self {
        if error.kind() == Kind::ResourceExhausted {
            Self::Status(OLE1_ERROR_MEMORY)
        } else {
            Self::Runtime(error)
        }
    }

    pub(super) fn status_or_runtime(self) -> Result<Win16Ole1Status, RuntimeError> {
        match self {
            Self::Status(status) => Ok(status),
            Self::Runtime(error) => Err(error),
        }
    }
}
