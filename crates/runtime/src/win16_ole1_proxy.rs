//! Checked guest-memory proxies for the OLE 1.0 client callback interface.
//!
//! OLE objects are guest interfaces, so this module never constructs native
//! COM pointers. It gives a guest object a real Win16 OLECLIENT record whose
//! single callback vtable slot is a checked runtime gate.

use guest_core::{OwnerId, memory::Memory};
use win16_abi::{Access, AllocationFlags, GlobalHandle, Win16Error};

use super::{
    OLE1_ERROR_ADDRESS, OLE1_ERROR_MEMORY, OLE1_ERROR_OBJECT, Win16Ole1ClientProxyBinding,
    Win16Ole1CallbackStage, Win16Ole1ClientProxyId, Win16Ole1PendingProxyRetirement,
    Win16Ole1Status, Win16State,
};
use crate::{DiagnosticKind as Kind, RuntimeError};

const OLE1_CLIENT_PROXY_OWNER: OwnerId = OwnerId(u32::MAX - 1);
const OLE1_CLIENT_PROXY_BYTES: u32 = 8;
const OLE1_CLIENT_VTABLE_OFFSET: u16 = 4;

/// Keep guest ABI outcomes separate from stopped runtime operations. A
/// capacity error is downgraded only at a boundary that knows cleanup
/// succeeded; attaching any cleanup cause changes it to Runtime.
pub(super) enum Win16Ole1ProxyError {
    GuestStatus(Win16Ole1Status),
    Capacity(RuntimeError),
    Runtime(RuntimeError),
}

impl Win16Ole1ProxyError {
    pub(super) fn status_or_runtime(self) -> Result<Win16Ole1Status, RuntimeError> {
        match self {
            Self::GuestStatus(status) => Ok(status),
            Self::Capacity(_cause) => Ok(OLE1_ERROR_MEMORY),
            Self::Runtime(error) => Err(error),
        }
    }

    fn into_runtime(self) -> RuntimeError {
        match self {
            Self::GuestStatus(status) => RuntimeError::new(
                Kind::InternalInvariant,
                format!("unexpected guest OLE1 status {status} during proxy cleanup"),
            ),
            Self::Capacity(error) | Self::Runtime(error) => error,
        }
    }
}

fn capacity_or_owned_runtime(error: Win16Error, context: &'static str) -> Win16Ole1ProxyError {
    // Classify the original typed heap error before any cleanup chain exists.
    // A later RuntimeError kind is insufficient because with_cleanup can
    // preserve ResourceExhausted when cleanup also fails.
    let runtime = crate::runtime_error(error).with_context(context);
    match runtime.kind() {
        Kind::ResourceExhausted => Win16Ole1ProxyError::Capacity(runtime),
        Kind::GuestFault | Kind::InvalidInput => Win16Ole1ProxyError::Runtime(
            RuntimeError::with_source(Kind::InternalInvariant, context, runtime),
        ),
        _ => Win16Ole1ProxyError::Runtime(runtime),
    }
}

fn guest_selector_error(error: Win16Error, status: Win16Ole1Status) -> Win16Ole1ProxyError {
    let runtime = crate::runtime_error(error);
    match runtime.kind() {
        Kind::GuestFault | Kind::InvalidInput => Win16Ole1ProxyError::GuestStatus(status),
        Kind::ResourceExhausted => Win16Ole1ProxyError::Capacity(runtime),
        _ => Win16Ole1ProxyError::Runtime(runtime),
    }
}

fn owned_heap_error(error: Win16Error, context: &'static str) -> Win16Ole1ProxyError {
    capacity_or_owned_runtime(error, context)
}

fn release_delivery_owns_removed_proxy(
    deliveries: &[super::Win16Ole1ReleaseDelivery],
    proxy_id: Win16Ole1ClientProxyId,
) -> bool {
    deliveries
        .iter()
        .any(|delivery| delivery.removed_object_proxy == Some(proxy_id))
}

impl Win16State {
    /// Return the checked guest method address from an OLECLIENT interface.
    /// Bad guest FARs and wire contents return documented OLE statuses;
    /// sticky storage failures and runtime-owned failures remain typed.
    pub(super) fn ole1_client_callback_address(
        &self,
        client_far: u32,
        memory: &mut Memory,
    ) -> Result<u32, Win16Ole1ProxyError> {
        if client_far == 0 {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_ADDRESS));
        }
        let client = self
            .selectors
            .pointer_from_far(client_far)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_ADDRESS))?;
        self.selectors
            .translate(client, Access::Read, 4, memory)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_ADDRESS))?;
        let mut vtable_bytes = [0_u8; 4];
        self.selectors
            .read(memory, client, &mut vtable_bytes)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_ADDRESS))?;
        let vtable_far = u32::from_le_bytes(vtable_bytes);
        if vtable_far == 0 {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_OBJECT));
        }

        let vtable = self
            .selectors
            .pointer_from_far(vtable_far)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_OBJECT))?;
        self.selectors
            .translate(vtable, Access::Read, 4, memory)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_OBJECT))?;
        let mut method_bytes = [0_u8; 4];
        self.selectors
            .read(memory, vtable, &mut method_bytes)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_OBJECT))?;
        let method_far = u32::from_le_bytes(method_bytes);
        if method_far == 0 {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_OBJECT));
        }
        let method = self
            .selectors
            .pointer_from_far(method_far)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_OBJECT))?;
        self.selectors
            .translate(method, Access::Execute, 1, memory)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_OBJECT))?;
        Ok(method_far)
    }

    /// Return the stable guest OLECLIENT proxy for one exact guest client
    /// address. The proxy is kept under a subsystem owner because callback
    /// gates and guest objects can outlive the task's task-owner sweep.
    pub(super) fn ole1_client_proxy_for_call(
        &mut self,
        client_far: u32,
        operation_id: Option<super::Win16Ole1OperationId>,
        memory: &mut Memory,
    ) -> Result<(u32, Win16Ole1ClientProxyId), Win16Ole1ProxyError> {
        self.retry_pending_ole1_proxy_retirements()
            .map_err(Win16Ole1ProxyError::Runtime)?;

        let client_pointer = self
            .selectors
            .pointer_from_far(client_far)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_ADDRESS))?;
        if let Some(binding) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| {
                operation_id.is_none()
                    && binding.operation_id.is_none()
                    && binding.client_far == client_far
                    && binding.client_pointer == client_pointer
            })
            .copied()
        {
            self.validate_ole1_client_proxy(binding, memory)?;
            return Ok((binding.proxy_far, binding.id));
        }

        self.ole1_client_documents
            .client_proxies
            .try_reserve(1)
            .map_err(|error| {
                Win16Ole1ProxyError::Capacity(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve OLE1 client proxy binding",
                    error,
                ))
            })?;
        // Reserve one retirement slot for every live binding plus the
        // allocation being started. A live proxy can later fail retirement
        // while earlier exact handles remain queued, so `try_reserve(1)`
        // alone would not guarantee storage for all outstanding obligations.
        let retirement_slots = self
            .ole1_client_documents
            .client_proxies
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                Win16Ole1ProxyError::Capacity(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "OLE1 client proxy retirement capacity is exhausted",
                ))
            })?;
        self.ole1_client_documents
            .pending_proxy_retirements
            .try_reserve(retirement_slots)
            .map_err(|error| {
                Win16Ole1ProxyError::Capacity(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve OLE1 client proxy retirement slot",
                    error,
                ))
            })?;

        let id_value = self
            .ole1_client_documents
            .next_client_proxy_id
            .ok_or_else(|| {
                Win16Ole1ProxyError::Capacity(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "OLE1 client proxy identifiers are exhausted",
                ))
            })?;
        let id = Win16Ole1ClientProxyId(id_value);
        let next_id = id_value.checked_add(1).filter(|next| *next != 0);

        let allocation = self
            .heap
            .alloc(
                memory,
                OLE1_CLIENT_PROXY_OWNER,
                OLE1_CLIENT_PROXY_BYTES,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(|error| {
                capacity_or_owned_runtime(error, "allocate OLE1 client proxy guest memory")
            })?;
        let base = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => {
                let primary =
                    capacity_or_owned_runtime(error, "lock OLE1 client proxy guest memory");
                return Err(self.cleanup_unlocked_proxy_failure(
                    allocation,
                    primary,
                    "free OLE1 client proxy after lock failed",
                ));
            }
        };

        let callback_gate = match self.ole1_client_callback_gate(memory) {
            Ok(address) => address,
            Err(primary) => {
                return Err(self.cleanup_locked_proxy_failure(
                    allocation,
                    Win16Ole1ProxyError::Runtime(primary),
                    "clean up OLE1 client proxy after callback gate allocation failed",
                ));
            }
        };

        let vtable_far = (u32::from(base.selector().raw().0) << 16)
            | u32::from(base.offset() + OLE1_CLIENT_VTABLE_OFFSET);
        let mut contents = [0_u8; OLE1_CLIENT_PROXY_BYTES as usize];
        // The guest record is two fixed DWORDs; explicit little-endian bytes
        // keep Rust struct padding out of this small stable Win16 wire ABI.
        contents[..4].copy_from_slice(&vtable_far.to_le_bytes());
        contents[4..].copy_from_slice(&callback_gate.to_le_bytes());
        if let Err(error) = self.selectors.write(memory, base, &contents) {
            let primary = owned_heap_error(error, "write OLE1 client proxy wire record");
            return Err(self.cleanup_locked_proxy_failure(
                allocation,
                primary,
                "clean up OLE1 client proxy after wire write failed",
            ));
        }

        let remaining = match self.heap.unlock(allocation, &mut self.selectors) {
            Ok(remaining) => remaining,
            Err(error) => {
                let primary = owned_heap_error(error, "unlock OLE1 client proxy after write")
                    .into_runtime()
                    .with_context("exact OLE1 proxy handle retained for an unlock retry");
                // This unlock failed, so the one outstanding unlock is now
                // represented in the retained entry. Do not retry it here.
                self.ole1_client_documents.pending_proxy_retirements.push(
                    Win16Ole1PendingProxyRetirement {
                        allocation,
                        unlock_pending: true,
                    },
                );
                return Err(Win16Ole1ProxyError::Runtime(primary));
            }
        };
        if remaining != 0 {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "fresh OLE1 client proxy retained unexpected internal pins after unlock",
            );
            self.ole1_client_documents.pending_proxy_retirements.push(
                Win16Ole1PendingProxyRetirement {
                    allocation,
                    unlock_pending: false,
                },
            );
            let cleanup = self
                .retry_pending_proxy_retirement_at(
                    self.ole1_client_documents.pending_proxy_retirements.len() - 1,
                )
                .err();
            return Err(match cleanup {
                Some(cleanup) => Win16Ole1ProxyError::Runtime(primary.with_cleanup(
                    "OLE1 proxy pin invariant and retirement both failed",
                    cleanup,
                )),
                None => Win16Ole1ProxyError::Runtime(primary),
            });
        }

        let binding = Win16Ole1ClientProxyBinding {
            id,
            operation_id,
            object: None,
            retire_requested: false,
            client_far,
            client_pointer,
            proxy_far: base.far_value(),
            allocation,
        };
        self.ole1_client_documents.client_proxies.push(binding);
        self.ole1_client_documents.next_client_proxy_id = next_id;
        Ok((binding.proxy_far, id))
    }

    pub(super) fn ole1_client_proxy(
        &self,
        id: Win16Ole1ClientProxyId,
    ) -> Option<Win16Ole1ClientProxyBinding> {
        self.ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == id)
            .copied()
    }

    /// Retire one operation-specific proxy after its failed creation or after
    /// the exact associated object has completed Release/Delete. A live object
    /// must first have detached its proxy association; freeing here never
    /// overrides heap pins and a failed free remains queued by exact handle.
    pub(super) fn retire_ole1_client_operation_proxy(
        &mut self,
        proxy_id: Win16Ole1ClientProxyId,
    ) -> Result<(), RuntimeError> {
        self.retire_ole1_client_operation_proxy_inner(proxy_id, false)
    }

    /// Transfer proxy retirement to the process teardown queue without
    /// touching guest memory. Selector-backed aliases may still pin the heap
    /// handle until release_all_selector_backing runs.
    pub(super) fn queue_ole1_client_operation_proxy_for_teardown(
        &mut self,
        proxy_id: Win16Ole1ClientProxyId,
    ) -> Result<(), RuntimeError> {
        self.retire_ole1_client_operation_proxy_inner(proxy_id, true)
    }

    fn retire_ole1_client_operation_proxy_inner(
        &mut self,
        proxy_id: Win16Ole1ClientProxyId,
        defer_physical_free: bool,
    ) -> Result<(), RuntimeError> {
        let Some(binding_index) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .position(|binding| binding.id == proxy_id)
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "operation-specific OLE1 proxy disappeared before retirement",
            ));
        };
        let binding = self.ole1_client_documents.client_proxies[binding_index];
        if binding.operation_id.is_none() || binding.object.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "attempted to retire a shared or still object-associated OLE1 proxy",
            ));
        }
        if self.ole1_client_documents.documents.values().any(|document| {
            document
                .object_proxy_bindings
                .iter()
                .any(|(_, associated)| *associated == proxy_id)
                || document.pending_operations.iter().any(|operation| {
                    matches!(operation, super::Win16Ole1PendingOperation::Creation { proxy_id: Some(associated), .. } if *associated == proxy_id)
                })
        }) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "attempted to retire an OLE1 proxy still owned by a pending operation or object",
            ));
        }
        if self.ole1_callbacks.iter().any(|frame| {
            match frame.stage {
                Win16Ole1CallbackStage::ClientProxyQueryStatus(call)
                | Win16Ole1CallbackStage::ClientProxyQueryError(call)
                | Win16Ole1CallbackStage::ClientProxyQueryMethod(call)
                | Win16Ole1CallbackStage::ClientProxyNotification { call, .. } => {
                    call.proxy_id == proxy_id
                }
                _ => false,
            }
        }) {
            self.ole1_client_documents.client_proxies[binding_index].retire_requested = true;
            return Ok(());
        }
        if release_delivery_owns_removed_proxy(
            &self.ole1_client_documents.release_deliveries,
            proxy_id,
        ) {
            // The exact claimed Release notification still owns this detached
            // proxy until its guest callback ACKs; leave the binding available
            // so that completion can hand it to the retirement queue.
            self.ole1_client_documents.client_proxies[binding_index].retire_requested = true;
            return Ok(());
        }
        if let Err(error) = self
            .ole1_client_documents
            .pending_proxy_retirements
            .try_reserve(1)
        {
            self.ole1_client_documents.client_proxies[binding_index].retire_requested = true;
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact OLE1 operation proxy retirement; binding retained for retry",
                error,
            ));
        }
        self.ole1_client_documents
            .client_proxies
            .remove(binding_index);
        self.ole1_client_documents
            .pending_proxy_retirements
            .push(Win16Ole1PendingProxyRetirement {
                allocation: binding.allocation,
                unlock_pending: false,
            });
        if defer_physical_free {
            return Ok(());
        }
        let index = self.ole1_client_documents.pending_proxy_retirements.len() - 1;
        self.retry_pending_proxy_retirement_at(index)
    }

    pub(super) fn ole1_client_proxy_for_far(
        &self,
        proxy_far: u32,
    ) -> Option<Win16Ole1ClientProxyBinding> {
        self.ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| binding.proxy_far == proxy_far)
            .copied()
    }

    pub(super) fn validate_ole1_client_proxy(
        &mut self,
        binding: Win16Ole1ClientProxyBinding,
        memory: &mut Memory,
    ) -> Result<(), Win16Ole1ProxyError> {
        let client_pointer = self
            .selectors
            .pointer_from_far(binding.client_far)
            .map_err(|error| guest_selector_error(error, OLE1_ERROR_ADDRESS))?;
        if client_pointer != binding.client_pointer {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_ADDRESS));
        }

        let info = self
            .heap
            .info(binding.allocation)
            .map_err(|error| owned_heap_error(error, "read owned OLE1 proxy allocation"))?;
        if info.owner != OLE1_CLIENT_PROXY_OWNER
            || info.size != OLE1_CLIENT_PROXY_BYTES
            || info.movable
            || info.discarded
            || info.executable
        {
            return Err(Win16Ole1ProxyError::Runtime(RuntimeError::new(
                Kind::InternalInvariant,
                "owned OLE1 client proxy allocation changed its fixed layout",
            )));
        }

        let pointer = self
            .selectors
            .pointer_from_far(binding.proxy_far)
            .map_err(|error| owned_heap_error(error, "resolve owned OLE1 client proxy address"))?;
        let selector = pointer.selector();
        let descriptor = self.selectors.describe(selector).map_err(|error| {
            owned_heap_error(error, "describe owned OLE1 client proxy selector")
        })?;
        if !descriptor.present
            || descriptor.base != info.base
            || !descriptor.rights.readable()
            || !descriptor.rights.writable()
            || descriptor.rights.executable()
        {
            return Err(Win16Ole1ProxyError::Runtime(RuntimeError::new(
                Kind::InternalInvariant,
                "owned OLE1 client proxy selector changed its descriptor",
            )));
        }
        self.selectors
            .translate(
                pointer,
                Access::Read,
                OLE1_CLIENT_PROXY_BYTES as usize,
                memory,
            )
            .map_err(|error| owned_heap_error(error, "translate owned OLE1 client proxy record"))?;

        let vtable_far = (u32::from(pointer.selector().raw().0) << 16)
            | u32::from(pointer.offset() + OLE1_CLIENT_VTABLE_OFFSET);
        let mut record = [0_u8; OLE1_CLIENT_PROXY_BYTES as usize];
        self.selectors
            .read(memory, pointer, &mut record)
            .map_err(|error| owned_heap_error(error, "read owned OLE1 proxy wire record"))?;
        if u32::from_le_bytes([record[0], record[1], record[2], record[3]]) != vtable_far {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_OBJECT));
        }
        let expected_gate = self
            .ole1_client_callback_gate(memory)
            .map_err(Win16Ole1ProxyError::Runtime)?;
        if u32::from_le_bytes([record[4], record[5], record[6], record[7]]) != expected_gate {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_OBJECT));
        }
        let callback = self.ole1_client_callback_address(binding.proxy_far, memory)?;
        if callback != expected_gate {
            return Err(Win16Ole1ProxyError::GuestStatus(OLE1_ERROR_OBJECT));
        }
        Ok(())
    }

    /// Retry exact pending retirements without invalidating any pins. This is
    /// called on proxy entry and must also be called after selector-backed
    /// aliases and callback buffers retire, before process selector teardown.
    pub(in crate::win16_runtime) fn retry_pending_ole1_proxy_retirements(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.drain_retired_ole1_client_operation_proxies()?;
        let index = 0;
        while index < self.ole1_client_documents.pending_proxy_retirements.len() {
            self.retry_pending_proxy_retirement_at(index)?;
        }
        Ok(())
    }

    pub(super) fn drain_retired_ole1_client_operation_proxies(
        &mut self,
    ) -> Result<(), RuntimeError> {
        loop {
            let release_deliveries = &self.ole1_client_documents.release_deliveries;
            let candidate = self
                .ole1_client_documents
                .client_proxies
                .iter()
                .filter(|binding| binding.retire_requested)
                .find(|binding| {
                    !self.ole1_callbacks.iter().any(|frame| match frame.stage {
                        Win16Ole1CallbackStage::ClientProxyQueryStatus(call)
                        | Win16Ole1CallbackStage::ClientProxyQueryError(call)
                        | Win16Ole1CallbackStage::ClientProxyQueryMethod(call)
                        | Win16Ole1CallbackStage::ClientProxyNotification { call, .. } => {
                            call.proxy_id == binding.id
                        }
                        _ => false,
                    }) && !release_delivery_owns_removed_proxy(release_deliveries, binding.id)
                })
                .map(|binding| binding.id);
            let Some(proxy_id) = candidate else {
                return Ok(());
            };
            self.retire_ole1_client_operation_proxy(proxy_id)?;
        }
    }

    fn retry_pending_proxy_retirement_at(&mut self, index: usize) -> Result<(), RuntimeError> {
        let pending = *self
            .ole1_client_documents
            .pending_proxy_retirements
            .get(index)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 proxy retirement index disappeared",
                )
            })?;
        if pending.unlock_pending {
            match self.heap.unlock(pending.allocation, &mut self.selectors) {
                Ok(_remaining) => {
                    // One unlock is complete. Any additional pin belongs to a
                    // separate owner; later attempts must only try normal free.
                    self.ole1_client_documents.pending_proxy_retirements[index].unlock_pending =
                        false;
                }
                Err(error) => {
                    return Err(owned_heap_error(error, "retrying OLE1 proxy unlock failed")
                        .into_runtime()
                        .with_context("exact handle remains retained"));
                }
            }
        }

        match self.heap.free(pending.allocation, &mut self.selectors) {
            Ok(()) => {
                self.ole1_client_documents
                    .pending_proxy_retirements
                    .remove(index);
                Ok(())
            }
            Err(error) => Err(owned_heap_error(error, "normal OLE1 proxy free failed")
                .into_runtime()
                .with_context("exact handle remains retained")),
        }
    }

    fn cleanup_unlocked_proxy_failure(
        &mut self,
        allocation: GlobalHandle,
        primary: Win16Ole1ProxyError,
        context: &'static str,
    ) -> Win16Ole1ProxyError {
        self.ole1_client_documents.pending_proxy_retirements.push(
            Win16Ole1PendingProxyRetirement {
                allocation,
                unlock_pending: false,
            },
        );
        let index = self.ole1_client_documents.pending_proxy_retirements.len() - 1;
        match self.retry_pending_proxy_retirement_at(index) {
            Ok(()) => primary,
            Err(cleanup) => {
                Win16Ole1ProxyError::Runtime(primary.into_runtime().with_cleanup(context, cleanup))
            }
        }
    }

    fn cleanup_locked_proxy_failure(
        &mut self,
        allocation: GlobalHandle,
        primary: Win16Ole1ProxyError,
        context: &'static str,
    ) -> Win16Ole1ProxyError {
        match self.heap.unlock(allocation, &mut self.selectors) {
            Err(error) => {
                let cleanup =
                    owned_heap_error(error, "unlocking unpublished OLE1 client proxy failed")
                        .into_runtime()
                        .with_context("exact handle retained");
                self.ole1_client_documents.pending_proxy_retirements.push(
                    Win16Ole1PendingProxyRetirement {
                        allocation,
                        unlock_pending: true,
                    },
                );
                Win16Ole1ProxyError::Runtime(primary.into_runtime().with_cleanup(context, cleanup))
            }
            Ok(remaining) => {
                self.ole1_client_documents.pending_proxy_retirements.push(
                    Win16Ole1PendingProxyRetirement {
                        allocation,
                        unlock_pending: false,
                    },
                );
                let index = self.ole1_client_documents.pending_proxy_retirements.len() - 1;
                let invariant = (remaining != 0).then(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "unpublished OLE1 proxy retained unexpected internal pins after unlock",
                    )
                });
                match self.retry_pending_proxy_retirement_at(index) {
                    Ok(()) => match invariant {
                        Some(invariant) => Win16Ole1ProxyError::Runtime(
                            primary.into_runtime().with_cleanup(context, invariant),
                        ),
                        None => primary,
                    },
                    Err(cleanup) => {
                        let cleanup = match invariant {
                            Some(invariant) => invariant.with_cleanup(
                                "unexpected OLE1 proxy pins and normal free both failed",
                                cleanup,
                            ),
                            None => cleanup,
                        };
                        Win16Ole1ProxyError::Runtime(
                            primary.into_runtime().with_cleanup(context, cleanup),
                        )
                    }
                }
            }
        }
    }
}
