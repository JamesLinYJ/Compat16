//! DDE-backed OLE1 object identity and the checked guest OLEOBJECT wire view.

#[path = "win16_ole1_dde_object_proxy_retirement.rs"]
mod retirement;

use guest_core::{OwnerId, memory::Memory};
use win16_abi::{Access, AllocationFlags, GlobalHandle, SegmentedPointer};

use super::{
    OLE1_ERROR_MEMORY, OLE1_ERROR_OBJECT, Win16Ole1ClientDocHandle, Win16Ole1ClientProxyId,
    Win16Ole1InitiateResponder, Win16Ole1OperationId, Win16State,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16ClassicDdeConversationId,
    Win16HostClassicDdeEndpoint, Win16HostClassicDdePeer,
};

const OBJECT_BYTES: u32 = 4;
const VTABLE_SLOTS: u8 = 39;
const VTABLE_BYTES: u32 = VTABLE_SLOTS as u32 * 4;
const PROXY_BYTES: u32 = OBJECT_BYTES + VTABLE_BYTES;
const ALLOCATION_OWNER: OwnerId = OwnerId(u32::MAX - 2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1PendingDdeObjectProxyRetirement {
    pub(super) owner: OwnerId,
    pub(super) allocation: GlobalHandle,
    pub(super) unlocks_pending: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1PendingDdeClientProxyRetirement {
    pub(super) owner: OwnerId,
    pub(super) client_proxy_id: Win16Ole1ClientProxyId,
    pub(super) allocation: GlobalHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1DdeObjectProxyRecord {
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
    pub(super) owner: OwnerId,
    pub(super) endpoint: Win16HostClassicDdeEndpoint,
    pub(super) system_peer: Win16HostClassicDdePeer,
    pub(super) system_conversation: Win16ClassicDdeConversationId,
    pub(super) document_peer: Win16HostClassicDdePeer,
    pub(super) document_conversation: Win16ClassicDdeConversationId,
    pub(super) document_conversation_retired: bool,
    pub(super) system_conversation_retired: bool,
    pub(super) server_application: Vec<u8>,
    pub(super) client_application: Vec<u8>,
    pub(super) document_name: Vec<u8>,
    pub(super) class_name: Vec<u8>,
    pub(super) object_name: Vec<u8>,
    pub(super) document_topic: Vec<u8>,
    pub(super) handler_data: i32,
    pub(super) app_data: i32,
    pub(super) closed: bool,
    pub(super) membership_retired: bool,
    pub(super) allocation_retired: bool,
    pub(super) client_proxy_retire_requested: bool,
    pub(super) client_proxy_retired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1DdeObjectProxySpec {
    pub(super) document: Win16Ole1ClientDocHandle,
    pub(super) client_far: u32,
    pub(super) client_proxy_id: Win16Ole1ClientProxyId,
    pub(super) operation_id: Win16Ole1OperationId,
    pub(super) owner: OwnerId,
    pub(super) endpoint: Win16HostClassicDdeEndpoint,
    pub(super) system_responder: Win16Ole1InitiateResponder,
    pub(super) document_responder: Win16Ole1InitiateResponder,
    pub(super) server_application: Vec<u8>,
    pub(super) client_application: Vec<u8>,
    pub(super) document_name: Vec<u8>,
    pub(super) class_name: Vec<u8>,
    pub(super) object_name: Vec<u8>,
    pub(super) document_topic: Vec<u8>,
}

impl Win16State {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_ole1_dde_object_proxy(
        &mut self,
        spec: Win16Ole1DdeObjectProxySpec,
        output: SegmentedPointer,
        memory: &mut Memory,
    ) -> Result<u32, super::object_proxy::Win16Ole1ObjectProxyError> {
        if spec.owner.0 == 0 || spec.endpoint.0 == 0 || spec.client_far == 0 {
            return Err(super::object_proxy::Win16Ole1ObjectProxyError::Status(
                OLE1_ERROR_OBJECT,
            ));
        }
        let documents = &self.ole1_client_documents;
        let Some(document) = documents.documents.get(&spec.document) else {
            return Err(super::object_proxy::Win16Ole1ObjectProxyError::Status(
                super::OLE1_ERROR_HANDLE,
            ));
        };
        if !document.pending_operations.iter().any(|pending| {
            matches!(pending,
                super::Win16Ole1PendingOperation::Creation {
                    operation_id, proxy_id: Some(proxy_id), client_far, ..
                } if *operation_id == spec.operation_id
                    && *proxy_id == spec.client_proxy_id
                    && *client_far == spec.client_far)
        }) {
            return Err(super::object_proxy::Win16Ole1ObjectProxyError::Status(
                OLE1_ERROR_OBJECT,
            ));
        }
        let Some(binding) = documents.client_proxies.iter().find(|binding| {
            binding.id == spec.client_proxy_id
                && binding.operation_id == Some(spec.operation_id)
                && binding.client_far == spec.client_far
                && binding.object.is_none()
                && !binding.retire_requested
        }) else {
            return Err(super::object_proxy::Win16Ole1ObjectProxyError::Status(
                OLE1_ERROR_OBJECT,
            ));
        };
        let client_proxy_allocation = binding.allocation;
        self.ole1_client_documents
            .dde_object_proxies
            .try_reserve(1)
            .map_err(|_| {
                super::object_proxy::Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY)
            })?;
        self.ole1_client_documents
            .pending_dde_object_proxy_retirements
            .try_reserve(1)
            .map_err(|_| {
                super::object_proxy::Win16Ole1ObjectProxyError::Status(OLE1_ERROR_MEMORY)
            })?;
        self.ole1_client_documents
            .reserve_object_slot(spec.document)
            .map_err(super::object_proxy::Win16Ole1ObjectProxyError::Status)?;

        let id = self
            .ole1_client_documents
            .next_native_object_proxy_id
            .ok_or(super::object_proxy::Win16Ole1ObjectProxyError::Status(
                OLE1_ERROR_MEMORY,
            ))?;
        if id == 0 {
            return Err(super::object_proxy::Win16Ole1ObjectProxyError::Status(
                OLE1_ERROR_MEMORY,
            ));
        }
        self.ole1_client_documents.next_native_object_proxy_id =
            id.checked_add(1).filter(|next| *next != 0);
        self.reserve_ole1_object_method_gates(usize::from(VTABLE_SLOTS), memory)
            .map_err(super::object_proxy::Win16Ole1ObjectProxyError::from_runtime)?;

        let allocation = self
            .heap
            .alloc(
                memory,
                ALLOCATION_OWNER,
                PROXY_BYTES,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(|error| {
                super::object_proxy::Win16Ole1ObjectProxyError::from_runtime(
                    crate::runtime_error(error)
                        .with_context("allocate DDE-backed OLE1 object proxy"),
                )
            })?;
        let base = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => {
                return Err(rollback_unlocked(
                    self,
                    spec.owner,
                    allocation,
                    super::object_proxy::Win16Ole1ObjectProxyError::from_runtime(
                        crate::runtime_error(error)
                            .with_context("lock DDE-backed OLE1 object proxy"),
                    ),
                ));
            }
        };
        let vtable_pointer = match self.selectors.add_bytes(base, OBJECT_BYTES) {
            Ok(pointer) => pointer,
            Err(error) => {
                return Err(rollback_locked(
                    self,
                    spec.owner,
                    allocation,
                    crate::runtime_error(error).with_context("derive DDE-backed OLE1 vtable"),
                ));
            }
        };
        let mut wire = Vec::new();
        wire.try_reserve_exact(PROXY_BYTES as usize)
            .map_err(|error| {
                rollback_locked(
                    self,
                    spec.owner,
                    allocation,
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve DDE-backed OLE1 proxy bytes",
                        error,
                    ),
                )
            })?;
        wire.extend_from_slice(&vtable_pointer.far_value().to_le_bytes());
        for slot in 0..VTABLE_SLOTS {
            let gate = self
                .ole1_object_method_gate(id, slot, memory)
                .map_err(|error| {
                    rollback_locked(
                        self,
                        spec.owner,
                        allocation,
                        error.with_context("create DDE-backed OLE1 method gate"),
                    )
                })?;
            wire.extend_from_slice(&gate.to_le_bytes());
        }
        if wire.len() != PROXY_BYTES as usize {
            return Err(rollback_locked(
                self,
                spec.owner,
                allocation,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE-backed OLE1 proxy wire size changed",
                ),
            ));
        }
        self.selectors.write(memory, base, &wire).map_err(|error| {
            rollback_locked(
                self,
                spec.owner,
                allocation,
                crate::runtime_error(error).with_context("write DDE-backed OLE1 object and slots"),
            )
        })?;
        let unlocks = self
            .heap
            .unlock(allocation, &mut self.selectors)
            .map_err(|error| {
                self.ole1_client_documents
                    .pending_dde_object_proxy_retirements
                    .push(Win16Ole1PendingDdeObjectProxyRetirement {
                        owner: spec.owner,
                        allocation,
                        unlocks_pending: 1,
                    });
                super::object_proxy::Win16Ole1ObjectProxyError::from_runtime(
                    crate::runtime_error(error).with_context("unlock DDE-backed OLE1 object proxy"),
                )
            })?;
        if unlocks != 0 {
            self.ole1_client_documents
                .pending_dde_object_proxy_retirements
                .push(Win16Ole1PendingDdeObjectProxyRetirement {
                    owner: spec.owner,
                    allocation,
                    unlocks_pending: unlocks,
                });
            return Err(super::object_proxy::Win16Ole1ObjectProxyError::Runtime(
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE-backed OLE1 proxy retained heap locks",
                ),
            ));
        }
        let record = Win16Ole1DdeObjectProxyRecord {
            id,
            allocation,
            object_far: base.far_value(),
            vtable_far: vtable_pointer.far_value(),
            object_pointer: base,
            vtable_pointer,
            document: spec.document,
            client_far: spec.client_far,
            client_proxy_id: spec.client_proxy_id,
            client_proxy_allocation,
            operation_id: spec.operation_id,
            owner: spec.owner,
            endpoint: spec.endpoint,
            system_peer: spec.system_responder.peer,
            system_conversation: spec.system_responder.conversation,
            document_peer: spec.document_responder.peer,
            document_conversation: spec.document_responder.conversation,
            document_conversation_retired: false,
            system_conversation_retired: false,
            server_application: spec.server_application,
            client_application: spec.client_application,
            document_name: spec.document_name,
            class_name: spec.class_name,
            object_name: spec.object_name,
            document_topic: spec.document_topic,
            handler_data: 0,
            app_data: 0,
            closed: false,
            membership_retired: false,
            allocation_retired: false,
            client_proxy_retire_requested: false,
            client_proxy_retired: false,
        };
        let object_far = record.object_far;
        if let Err(error) = self
            .selectors
            .write(memory, output, &object_far.to_le_bytes())
        {
            return Err(rollback_unlocked(
                self,
                spec.owner,
                allocation,
                super::object_proxy::Win16Ole1ObjectProxyError::Runtime(
                    crate::runtime_error(error)
                        .with_context("write completed DDE-backed OLE1 object FAR"),
                ),
            ));
        }
        if let Err(status) = self.ole1_client_documents.add_object_with_proxy(
            record.document,
            object_far,
            record.client_far,
            Some(record.client_proxy_id),
            Some(record.operation_id),
        ) {
            let _ = self.selectors.write(memory, output, &[0; 4]);
            return Err(rollback_unlocked(
                self,
                spec.owner,
                allocation,
                super::object_proxy::Win16Ole1ObjectProxyError::Status(status),
            ));
        }
        self.ole1_client_documents.dde_object_proxies.push(record);
        Ok(object_far)
    }

    pub(super) fn validate_ole1_dde_object_proxy(
        &self,
        record: &Win16Ole1DdeObjectProxyRecord,
        slot: u8,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        if record.id == 0 || record.owner.0 == 0 || record.endpoint.0 == 0 {
            return Ok(false);
        }
        let info = self
            .heap
            .info(record.allocation)
            .map_err(crate::runtime_error)?;
        if info.owner != ALLOCATION_OWNER
            || info.size != PROXY_BYTES
            || info.movable
            || info.discarded
        {
            return Ok(false);
        }
        let object = self
            .selectors
            .address_within(
                record.object_pointer,
                Access::Read,
                OBJECT_BYTES as usize,
                memory.size_bytes(),
            )
            .map_err(crate::runtime_error)?;
        let vtable = self
            .selectors
            .address_within(
                record.vtable_pointer,
                Access::Read,
                VTABLE_BYTES as usize,
                memory.size_bytes(),
            )
            .map_err(crate::runtime_error)?;
        if object != info.base || info.base.0.checked_add(OBJECT_BYTES) != Some(vtable.0) {
            return Ok(false);
        }
        let object_pointer = self
            .selectors
            .pointer_from_far(record.object_far)
            .map_err(crate::runtime_error)?;
        let vtable_pointer = self
            .selectors
            .pointer_from_far(record.vtable_far)
            .map_err(crate::runtime_error)?;
        if object_pointer != record.object_pointer || vtable_pointer != record.vtable_pointer {
            return Ok(false);
        }
        let mut wire = [0_u8; 4];
        self.selectors
            .read(memory, object_pointer, &mut wire)
            .map_err(crate::runtime_error)?;
        if u32::from_le_bytes(wire) != record.vtable_far {
            return Ok(false);
        }
        let slot_pointer = self
            .selectors
            .add_bytes(vtable_pointer, u32::from(slot) * 4)
            .map_err(crate::runtime_error)?;
        self.selectors
            .read(memory, slot_pointer, &mut wire)
            .map_err(crate::runtime_error)?;
        let expected = self.ole1_object_method_gate_address(record.id, slot);
        Ok(expected.is_some_and(|gate| u32::from_le_bytes(wire) == gate))
    }
}

fn rollback_unlocked(
    state: &mut Win16State,
    owner: OwnerId,
    allocation: GlobalHandle,
    primary: super::object_proxy::Win16Ole1ObjectProxyError,
) -> super::object_proxy::Win16Ole1ObjectProxyError {
    if let Err(error) = state.heap.free(allocation, &mut state.selectors) {
        state
            .ole1_client_documents
            .pending_dde_object_proxy_retirements
            .push(Win16Ole1PendingDdeObjectProxyRetirement {
                owner,
                allocation,
                unlocks_pending: 0,
            });
        return super::object_proxy::Win16Ole1ObjectProxyError::Runtime(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE-backed OLE1 proxy setup failed and guest allocation retirement remains pending",
        ).with_cleanup("retire failed DDE-backed object proxy", crate::runtime_error(error)));
    }
    primary
}

fn rollback_locked(
    state: &mut Win16State,
    owner: OwnerId,
    allocation: GlobalHandle,
    primary: RuntimeError,
) -> super::object_proxy::Win16Ole1ObjectProxyError {
    match state.heap.unlock(allocation, &mut state.selectors) {
        Ok(remaining) if remaining == 0 => rollback_unlocked(
            state,
            owner,
            allocation,
            super::object_proxy::Win16Ole1ObjectProxyError::Runtime(primary),
        ),
        Ok(remaining) => {
            state
                .ole1_client_documents
                .pending_dde_object_proxy_retirements
                .push(Win16Ole1PendingDdeObjectProxyRetirement {
                    owner,
                    allocation,
                    unlocks_pending: remaining,
                });
            super::object_proxy::Win16Ole1ObjectProxyError::Runtime(
                primary
                    .with_context("DDE-backed OLE1 proxy setup retained heap locks after rollback"),
            )
        }
        Err(error) => {
            state
                .ole1_client_documents
                .pending_dde_object_proxy_retirements
                .push(Win16Ole1PendingDdeObjectProxyRetirement {
                    owner,
                    allocation,
                    unlocks_pending: 1,
                });
            super::object_proxy::Win16Ole1ObjectProxyError::Runtime(primary.with_cleanup(
                "unlock failed DDE-backed OLE1 proxy",
                crate::runtime_error(error),
            ))
        }
    }
}
