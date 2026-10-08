//! Win16 OLE 1.0 client-document metadata and checked object callbacks.
//!
//! `LHCLIENTDOC` values are per-runtime opaque 32-bit tokens. The table owns
//! copied guest-encoding names and object FAR tokens. FAR pointers remain guest
//! tokens; public object methods enter their guest vtable slots through one
//! checked callback continuation. Native host resources are not represented as
//! guest OLE objects.

use std::collections::BTreeMap;

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, Win16Ole1Request, Win16ReturnKind};
use x86_cpu::Cpu;

use super::Win16State;
use crate::{RuntimeError, RuntimeHost};

#[path = "win16_ole1_callback.rs"]
mod callback;
#[path = "win16_ole1_client.rs"]
mod client;
#[path = "win16_ole1_client_dde.rs"]
mod client_dde;
#[path = "win16_ole1_creation.rs"]
mod creation;
#[path = "win16_ole1_creation_dde.rs"]
mod creation_dde;
#[path = "win16_ole1_creation_dde_helpers.rs"]
mod creation_dde_helpers;
#[path = "win16_ole1_dde_object_method.rs"]
mod dde_object_method;
#[path = "win16_ole1_dde_object_proxy.rs"]
mod dde_object_proxy;
#[path = "win16_ole1_methods.rs"]
mod methods;
#[path = "win16_ole1_object_dispatch.rs"]
mod object_dispatch;
#[path = "win16_ole1_object_method.rs"]
mod object_method;
#[path = "win16_ole1_object_method_journal.rs"]
mod object_method_journal;
#[path = "win16_ole1_object_method_release.rs"]
mod object_method_release;
#[path = "win16_ole1_object_proxy.rs"]
mod object_proxy;
#[path = "win16_ole1_proxy.rs"]
mod proxy;
#[path = "win16_ole1_proxy_callback.rs"]
mod proxy_callback;
#[path = "win16_ole1_registry_resolver.rs"]
mod registry_resolver;
#[path = "win16_ole1_release.rs"]
mod release;
#[path = "win16_ole1_server_api.rs"]
mod server_api;
#[path = "win16_ole1_server_item_callback.rs"]
mod server_item_callback;
#[path = "win16_ole1_server_shutdown.rs"]
mod server_shutdown;
#[path = "win16_ole1_server_shutdown_helpers.rs"]
mod server_shutdown_helpers;
#[path = "win16_ole1_stdexecute.rs"]
mod stdexecute;
pub(super) use callback::Win16Ole1CallbackFrame;
pub(super) use client_dde::{
    Win16Ole1ClientDdeConversationAtoms, Win16Ole1ClientDdeDisposition,
    Win16Ole1ClientDdeEventCommit, Win16Ole1ClientDdeJournal, Win16Ole1InitiateResponder,
};
pub(super) use release::Win16Ole1ReleaseEvidence;
pub(super) use server_api::{
    Ole1ReleaseEndpointOutcome, finish_release_without_guest_callback_for_dde,
    finish_server_release_completion, finish_server_release_completion_for_dde,
};
pub(in crate::win16_runtime) use server_shutdown::{
    Ole1ServerShutdownPending, Ole1ServerShutdownStep,
};

pub(crate) type Win16Ole1Status = u16;

pub(crate) const OLE1_OK: Win16Ole1Status = 0;
pub(crate) const OLE1_WAIT_FOR_RELEASE: Win16Ole1Status = 1;
pub(crate) const OLE1_ERROR_MEMORY: Win16Ole1Status = 4;
pub(crate) const OLE1_ERROR_HANDLE: Win16Ole1Status = 18;
pub(crate) const OLE1_ERROR_ADDRESS: Win16Ole1Status = 16;
pub(crate) const OLE1_ERROR_NAME: Win16Ole1Status = 29;
pub(crate) const OLE1_ERROR_OBJECT: Win16Ole1Status = 13;
pub(crate) const OLE1_ERROR_PROTOCOL: Win16Ole1Status = 15;
pub(crate) const OLE1_ERROR_NOT_EMPTY: Win16Ole1Status = 25;
pub(crate) const OLE1_ERROR_NOT_LINK: Win16Ole1Status = 24;
pub(crate) const OLE1_ERROR_COMMAND: Win16Ole1Status = 38;
pub(crate) const OLE1_ERROR_TERMINATE: Win16Ole1Status = 37;
pub(crate) const OLE1_ERROR_UPDATE: Win16Ole1Status = 53;
pub(crate) const OLE1_ERROR_OPTION: Win16Ole1Status = 14;
pub(crate) const OLE1_ERROR_STREAM: Win16Ole1Status = 5;
pub(crate) const OLE1_ERROR_DRAW: Win16Ole1Status = 8;
pub(crate) const OLE1_ERROR_FORMAT: Win16Ole1Status = 12;
pub(crate) const OLE1_ERROR_LAUNCH: Win16Ole1Status = 36;
pub(crate) const OLE1_ERROR_OPEN: Win16Ole1Status = 33;
pub(crate) const OLE1_ERROR_TEMPLATE: Win16Ole1Status = 30;
pub(crate) const OLE1_ERROR_EDIT: Win16Ole1Status = 32;
pub(crate) const OLE1_ERROR_CLASS: Win16Ole1Status = 20;
pub(crate) const OLE1_ERROR_DOVERB: Win16Ole1Status = 40;
pub(crate) const OLE1_BUSY: Win16Ole1Status = 2;
pub(super) const OLE1_RELEASE_NOTIFICATION: u16 = 5;

/// Monotonic identity for one public OLE1 operation. It is shared by object
/// methods and the DDE/client API journal; callback frames and DDE calls keep
/// their own identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Win16Ole1OperationId(pub(crate) u64);

// SDK 3.1 Vol. 2 (1992), pp. 702 and 711, defines the returned DWORD as
// major in the low byte and minor in the next byte, with the high word
// reserved. This compatibility profile reports the actual XP SP1 WOW16 OLE
// DLL values (`client/main.c:dwOleVer`, `server/srvr.c:OLE_VERSION`). They are
// library-reported versions, not a claim that the same set of OLE features is
// implemented here.
const OLE1_NTVDM_CLIENT_VERSION: u32 = 0x0000_2001;
const OLE1_NTVDM_SERVER_VERSION: u32 = 0x0000_1001;

/// The Win16 `LHCLIENTDOC` value returned through `OleRegisterClientDoc`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Win16Ole1ClientDocHandle(i32);

impl Win16Ole1ClientDocHandle {
    /// Preserve the guest LONG bit pattern when validating an incoming handle.
    pub(crate) const fn from_guest_long(value: u32) -> Self {
        Self(value as i32)
    }

    pub(crate) const fn to_guest_long(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16Ole1ClientDocument {
    class_name: Vec<u8>,
    document_name: Vec<u8>,
    reserved: i32,
    modified: bool,
    objects: Vec<u32>,
    /// The `LPOLECLIENT` supplied when each object was created. OLE keeps
    /// this association so an asynchronous completion can call the correct
    /// client after the initiating API frame has returned.
    object_clients: Vec<(u32, u32)>,
    /// Exact operation-specific callback proxy retained by each created
    /// object. The client FAR alone is not enough when one client owns many
    /// objects with simultaneous asynchronous operations.
    object_proxy_bindings: Vec<(u32, Win16Ole1ClientProxyId)>,
    pending_operations: Vec<Win16Ole1PendingOperation>,
}

/// OLE1 client-document registrations belong to one Win16 runtime/task.
///
/// The table does not own document contents or native COM state. It records
/// guest object tokens returned by checked object callbacks so enumeration and
/// revoke status reflect the guest-visible OLE1 lifetime.
#[derive(Debug)]
pub(crate) struct Win16Ole1ClientDocuments {
    next_handle: Option<i32>,
    documents: BTreeMap<Win16Ole1ClientDocHandle, Win16Ole1ClientDocument>,
    protocol_aliases: Vec<Win16Ole1ProtocolAlias>,
    release_deliveries: Vec<Win16Ole1ReleaseDelivery>,
    next_operation_id: Option<u64>,
    next_embedded_topic_serial: client_dde::Win16Ole1EmbeddedTopicSerial,
    next_protocol_alias_generation: Option<u64>,
    next_client_proxy_id: Option<u64>,
    client_proxies: Vec<Win16Ole1ClientProxyBinding>,
    pending_proxy_retirements: Vec<Win16Ole1PendingProxyRetirement>,
    next_native_object_proxy_id: Option<u64>,
    native_object_proxies: Vec<object_proxy::Win16Ole1NativeObjectProxyRecord>,
    pub(super) pending_native_object_proxy_retirements:
        Vec<object_proxy::Win16Ole1PendingObjectProxyRetirement>,
    /// Exact owner-scoped callback failures consumed from the sealed native
    /// callback ingress. Keep the complete steps until that owner has a real
    /// shutdown receipt; operation-parented failures are also retained in the
    /// operation journal for terminal reconciliation.
    pub(super) sealed_com_callback_receipts: Vec<crate::Win16ComHostStep>,
    pending_creations: Vec<creation::Win16Ole1CreateSequence>,
    pending_dde_creations: Vec<creation_dde::Win16Ole1DdeCreateSequence>,
    pending_dde_methods: Vec<dde_object_method::Win16Ole1DdeObjectMethodSequence>,
    dde_object_proxies: Vec<dde_object_proxy::Win16Ole1DdeObjectProxyRecord>,
    pending_dde_object_proxy_retirements:
        Vec<dde_object_proxy::Win16Ole1PendingDdeObjectProxyRetirement>,
    pending_dde_client_proxy_retirements:
        Vec<dde_object_proxy::Win16Ole1PendingDdeClientProxyRetirement>,
    pending_object_methods: Vec<object_method::Win16Ole1ObjectMethodSequence>,
    client_dde: Win16Ole1ClientDdeJournal,
    prefer_object_method_safe_point: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ClientProxyId(pub(super) u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ClientProxyBinding {
    pub(super) id: Win16Ole1ClientProxyId,
    /// Present only for an operation-specific proxy. The identity remains on
    /// the binding after it is promoted to an object association.
    pub(super) operation_id: Option<Win16Ole1OperationId>,
    pub(super) object: Option<(Win16Ole1ClientDocHandle, u32)>,
    /// Deferred until no callback frame can still validate/use this proxy.
    pub(super) retire_requested: bool,
    pub(super) client_far: u32,
    pub(super) client_pointer: SegmentedPointer,
    pub(super) proxy_far: u32,
    pub(super) allocation: win16_abi::GlobalHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1PendingProxyRetirement {
    pub(super) allocation: win16_abi::GlobalHandle,
    /// True only while this runtime still owes the one unlock whose attempt
    /// previously failed. Once unlock succeeds, retries only use normal free.
    pub(super) unlock_pending: bool,
}

#[derive(Clone)]
pub(super) enum Win16Ole1ObjectEffect {
    Add {
        document: Win16Ole1ClientDocHandle,
        output_far: u32,
        client_far: u32,
        operation_id: Win16Ole1OperationId,
    },
    Remove {
        object_far: u32,
        operation_id: Win16Ole1OperationId,
        pending_document: Option<Win16Ole1ClientDocHandle>,
    },
    ProtocolAlias {
        owner: Option<Win16Ole1ProtocolAliasOwner>,
        protocol: Vec<u8>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum Win16Ole1CallbackStage {
    ObjectMethod,
    ServerRevokeObject(super::win16_ole1_server_state::Ole1ItemCallbackIdentity),
    ServerRelease(super::win16_ole1_server_state::Ole1ReleaseTarget),
    ClientProxyQueryStatus(Win16Ole1ClientProxyCall),
    ClientProxyQueryError(Win16Ole1ClientProxyCall),
    ClientProxyQueryMethod(Win16Ole1ClientProxyCall),
    ClientProxyNotification {
        call: Win16Ole1ClientProxyCall,
        completion: Option<Win16Ole1ReleaseEvidence>,
    },
    ClientComAdviseNotification {
        call: Win16Ole1ClientProxyCall,
        callback: Win16Ole1ComCallbackIdentity,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ComCallbackIdentity {
    pub(super) frame: crate::Win16ComHostCallbackFrame,
    pub(super) parent: Option<crate::Win16ComHostOperationIdentity>,
    pub(super) owner: crate::Win16ComHostOwnerIdentity,
    pub(super) route: crate::Win16ComHostCallbackRoute,
}

#[derive(Clone, Copy)]
pub(super) struct Win16Ole1ClientProxyCall {
    pub(super) proxy_id: Win16Ole1ClientProxyId,
    pub(super) proxy_operation_id: Option<Win16Ole1OperationId>,
    pub(super) proxy_far: u32,
    pub(super) client_far: u32,
    pub(super) client_pointer: SegmentedPointer,
    pub(super) notification: u16,
    pub(super) object_far: u32,
    pub(super) pending_operation: Option<(Win16Ole1OperationId, Option<u64>)>,
    pub(super) release_status: Option<u16>,
    pub(super) release_error: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ProtocolAliasOwner {
    pub(super) document: Option<Win16Ole1ClientDocHandle>,
    pub(super) canonical_object: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ProtocolAlias {
    pub(super) far: u32,
    pub(super) canonical_object: u32,
    pub(super) protocol: Vec<u8>,
    pub(super) document: Option<Win16Ole1ClientDocHandle>,
    /// Monotonic runtime identity; semantic alias fields can be reused after
    /// an object is detached and a callback reenters OLE.
    pub(super) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16Ole1ReleaseMethodExpectation {
    /// The SDK or the standard object profile assigns a specific release
    /// method to this operation.
    Exact(u16),
    /// Clone and ObjectConvert have no dedicated value in OLE_RELEASE_METHOD.
    /// Their method is accepted only from the real OLE_RELEASE notification
    /// bound to this exact pending callback generation.
    FromNotification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16Ole1SourceProbePolicy {
    /// `PROBE_ASYNC`: any command on the concrete source object conflicts.
    ProbeAsync,
    /// `PROBE_CREATE_ASYNC`: only OLE_CREATE through OLE_CREATEINVISIBLE conflict.
    ProbeCreateAsync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16Ole1AsyncCommand {
    Delete,
    CopyFromLink,
}

impl Win16Ole1AsyncCommand {
    pub(super) const fn wire_value(self) -> u16 {
        match self {
            Self::Delete => 1,
            Self::CopyFromLink => 19,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1AsyncBusyOwner {
    pub(super) object_far: u32,
    pub(super) command: Win16Ole1AsyncCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16Ole1PendingOperation {
    Creation {
        operation_id: Win16Ole1OperationId,
        /// The callback frame that initiated an object-method creation, when
        /// one exists. Public DDE creation APIs do not invent a callback id.
        initiating_callback_id: Option<u64>,
        /// XP tracks asynchronous commands on the concrete source object.
        /// DDE-driven creation has no OLEOBJECT source.
        source_object: Option<u32>,
        source_probe_policy: Win16Ole1SourceProbePolicy,
        proxy_id: Option<Win16Ole1ClientProxyId>,
        /// XP CopyFromLink installs command 19 on the returned object only
        /// after the guest method returns OLE_WAIT_FOR_RELEASE.
        async_busy_command_on_return: Option<Win16Ole1AsyncCommand>,
        /// Exact OLE object whose async operation raised OLE_RELEASE. A
        /// newly returned object replaces the initiating object here; these
        /// identities are never alternatives for one completion.
        /// `None` means the async API returned OLE_WAIT_FOR_RELEASE without
        /// publishing its output object. Never substitute the source object.
        release_object: Option<u32>,
        /// XP asyncCmd owner and command are installed and cleared together.
        /// This is independent of both the source and completion object.
        async_busy: Option<Win16Ole1AsyncBusyOwner>,
        client_far: u32,
        expected_release_method: Win16Ole1ReleaseMethodExpectation,
        awaiting_release: bool,
    },
    Release {
        operation_id: Win16Ole1OperationId,
        initiating_callback_id: Option<u64>,
        object_far: u32,
        /// Set only when this release actually returns WAIT_FOR_RELEASE.
        async_busy: Option<Win16Ole1AsyncBusyOwner>,
        expected_release_method: u16,
        awaiting_release: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ReleaseDelivery {
    pub(super) evidence: Win16Ole1ReleaseEvidence,
    pub(super) document: Win16Ole1ClientDocHandle,
    pub(super) operation: Win16Ole1PendingOperation,
    /// Membership detached before a successful Release callback. It is
    /// restored only if checked callback entry fails before guest execution.
    pub(super) removed_object_client: Option<(u32, u32)>,
    pub(super) removed_object_proxy: Option<Win16Ole1ClientProxyId>,
    pub(super) removed_aliases: Vec<Win16Ole1ProtocolAlias>,
}

impl Default for Win16Ole1ClientDocuments {
    fn default() -> Self {
        Self::new()
    }
}

impl Win16Ole1ClientDocuments {
    pub(crate) fn new() -> Self {
        Self {
            next_handle: Some(1),
            documents: BTreeMap::new(),
            protocol_aliases: Vec::new(),
            release_deliveries: Vec::new(),
            next_operation_id: Some(1),
            next_embedded_topic_serial: client_dde::Win16Ole1EmbeddedTopicSerial::default(),
            next_protocol_alias_generation: Some(1),
            next_client_proxy_id: Some(1),
            client_proxies: Vec::new(),
            pending_proxy_retirements: Vec::new(),
            next_native_object_proxy_id: Some(1),
            native_object_proxies: Vec::new(),
            pending_native_object_proxy_retirements: Vec::new(),
            sealed_com_callback_receipts: Vec::new(),
            pending_creations: Vec::new(),
            pending_dde_creations: Vec::new(),
            pending_dde_methods: Vec::new(),
            dde_object_proxies: Vec::new(),
            pending_dde_object_proxy_retirements: Vec::new(),
            pending_dde_client_proxy_retirements: Vec::new(),
            pending_object_methods: Vec::new(),
            client_dde: Win16Ole1ClientDdeJournal::default(),
            prefer_object_method_safe_point: false,
        }
    }

    /// Register a client document and return its nonzero `LHCLIENTDOC` token.
    /// Win3.1 SDK Vol. 2 says this LONG must be zero. NTVDM's `doc.c` ignores
    /// its `future` parameter, so accepting and preserving a nonzero value is
    /// an NTVDM-compatibility choice, not an SDK guarantee.
    ///
    /// NTVDM also creates a fresh record for every call without rejecting a
    /// duplicate class/document name. Duplicate registrations are accepted
    /// here as an NTVDM behavior; the SDK does not promise duplicate keys.
    pub(crate) fn register(
        &mut self,
        class_name: Vec<u8>,
        document_name: Vec<u8>,
        reserved: i32,
    ) -> Result<Win16Ole1ClientDocHandle, Win16Ole1Status> {
        if document_name.is_empty() {
            return Err(OLE1_ERROR_NAME);
        }
        let handle_value = self.next_handle.ok_or(OLE1_ERROR_MEMORY)?;
        let handle = Win16Ole1ClientDocHandle(handle_value);
        self.documents.insert(
            handle,
            Win16Ole1ClientDocument {
                class_name,
                document_name,
                reserved,
                modified: false,
                objects: Vec::new(),
                object_clients: Vec::new(),
                object_proxy_bindings: Vec::new(),
                pending_operations: Vec::new(),
            },
        );
        self.next_handle = handle_value.checked_add(1).filter(|next| *next > 0);
        Ok(handle)
    }

    /// Undo a registration whose guest handle could not be written back.
    /// Call only immediately after `register`, before exposing the handle.
    pub(crate) fn rollback_unpublished_registration(&mut self, handle: Win16Ole1ClientDocHandle) {
        if self.documents.remove(&handle).is_some() {
            self.next_handle = Some(handle.0);
        }
    }

    /// Revoke a registered client document.
    ///
    /// Refuse to revoke a document while tracked guest objects still belong to
    /// it, matching OLE_ERROR_NOT_EMPTY from the OLE 1.0 client library.
    pub(crate) fn revoke(&mut self, handle: Win16Ole1ClientDocHandle) -> Win16Ole1Status {
        let Some(document) = self.documents.get(&handle) else {
            return OLE1_ERROR_HANDLE;
        };
        if !document.objects.is_empty()
            || !document.pending_operations.is_empty()
            || self
                .protocol_aliases
                .iter()
                .any(|alias| alias.document == Some(handle))
        {
            return OLE1_ERROR_NOT_EMPTY;
        }
        self.documents.remove(&handle);
        OLE1_OK
    }

    /// Update the registered name after the caller has completed its rename.
    /// Win3.1 SDK Vol. 2 lists invalid-handle as the failure status for this
    /// call; NTVDM probes the name only after validating the handle and accepts
    /// an empty name. Object-name notification still requires the unconnected
    /// guest callback bridge.
    pub(crate) fn rename(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
        document_name: Vec<u8>,
    ) -> Win16Ole1Status {
        let Some(document) = self.documents.get_mut(&handle) else {
            return OLE1_ERROR_HANDLE;
        };
        if document.document_name == document_name {
            return OLE1_OK;
        }
        document.document_name = document_name;
        OLE1_OK
    }

    /// Validate the registration. Reverting the actual document is the
    /// client's work; OLE1 does not restore the registration name here.
    pub(crate) fn revert(&mut self, handle: Win16Ole1ClientDocHandle) -> Win16Ole1Status {
        let Some(document) = self.documents.get_mut(&handle) else {
            return OLE1_ERROR_HANDLE;
        };
        document.clear_modified();
        OLE1_OK
    }

    /// Validate the registration after the client completes its save.
    pub(crate) fn saved(&mut self, handle: Win16Ole1ClientDocHandle) -> Win16Ole1Status {
        let Some(document) = self.documents.get_mut(&handle) else {
            return OLE1_ERROR_HANDLE;
        };
        document.clear_modified();
        OLE1_OK
    }
}

impl Win16Ole1ClientDocument {
    fn clear_modified(&mut self) {
        if self.modified {
            self.modified = false;
        }
    }
}

impl Win16State {
    /// Begin one OLE1 call. Calls that enter a guest object method suspend the
    /// outer API call and return through the shared checked-callback gate.
    pub(super) fn begin_ole1_request(
        &mut self,
        request: Win16Ole1Request,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match request {
            Win16Ole1Request::ItemCallback {
                client_far,
                notification,
                object_far,
            } => self.begin_ole1_item_callback_import(
                cpu,
                return_to,
                client_far,
                notification,
                object_far,
            ),
            request @ (Win16Ole1Request::Create { .. }
            | Win16Ole1Request::CreateFromFile { .. }
            | Win16Ole1Request::CreateFromTemplate { .. }
            | Win16Ole1Request::CreateLinkFromFile { .. }
            | Win16Ole1Request::LoadFromStream { .. }
            | Win16Ole1Request::CreationInvalidAddress { .. }) => {
                self.begin_ole1_creation(request, cpu, dos, memory, host, return_to, return_kind)
            }
            Win16Ole1Request::ObjectMethod {
                ordinal,
                object,
                arguments,
            } => self.begin_ole1_object_method(
                cpu,
                dos,
                memory,
                host,
                return_to,
                return_kind,
                ordinal,
                object,
                &arguments,
            ),
            Win16Ole1Request::SaveToStream { object, stream } => self.begin_ole1_save_to_stream(
                cpu,
                dos,
                memory,
                host,
                return_to,
                return_kind,
                object,
                stream,
            ),
            Win16Ole1Request::QueryClientVersion => self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                OLE1_NTVDM_CLIENT_VERSION,
                return_kind,
            ),
            Win16Ole1Request::QueryServerVersion => self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                OLE1_NTVDM_SERVER_VERSION,
                return_kind,
            ),
            Win16Ole1Request::IsDcMeta { dc } => {
                let is_metafile = match self.guest_gdi.dc(dc) {
                    Some(dc) => match host
                        .win16_gdi_services(crate::Win16GdiServicesOperation::IsMetafileDc { dc })?
                    {
                        crate::Win16GdiServicesResult::Bool(value) => value,
                        _ => {
                            return Err(RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "Win16 OleIsDcMeta received the wrong GDI result",
                            ));
                        }
                    },
                    None => false,
                };
                self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(is_metafile),
                    return_kind,
                )
            }
            Win16Ole1Request::RegisterServer { .. }
            | Win16Ole1Request::RevokeServer { .. }
            | Win16Ole1Request::BlockServer { .. }
            | Win16Ole1Request::UnblockServer { .. }
            | Win16Ole1Request::RegisterServerDoc { .. }
            | Win16Ole1Request::RevokeServerDoc { .. }
            | Win16Ole1Request::RenameServerDoc { .. }
            | Win16Ole1Request::RevertServerDoc { .. }
            | Win16Ole1Request::SavedServerDoc { .. }
            | Win16Ole1Request::RevokeObject { .. } => self.begin_ole1_server_request(
                request,
                cpu,
                dos,
                memory,
                host,
                return_to,
                return_kind,
            ),
            metadata_request => {
                let status = self.ole1_client_document_api(metadata_request, memory);
                self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    status,
                    return_kind,
                )
            }
        }
    }

    /// Execute the OLE1 client-document metadata subset without crossing into
    /// the native OLE host. `RegisterClientDoc` checks and clears its output
    /// LONG before mutating task state, then rolls back if final writeback
    /// fails after a successful preflight.
    pub(super) fn ole1_client_document_api(
        &mut self,
        request: Win16Ole1Request,
        memory: &mut Memory,
    ) -> u32 {
        match request {
            Win16Ole1Request::QueryClientVersion => OLE1_NTVDM_CLIENT_VERSION,
            Win16Ole1Request::QueryServerVersion => OLE1_NTVDM_SERVER_VERSION,
            Win16Ole1Request::IsDcMeta { .. } => {
                unreachable!("OleIsDcMeta must use its checked native GDI query")
            }
            Win16Ole1Request::ObjectMethod { .. } => {
                unreachable!("OLE1 object callbacks must use begin_ole1_request")
            }
            Win16Ole1Request::SaveToStream { .. } => {
                unreachable!("OLE1 callback calls must use begin_ole1_request")
            }
            Win16Ole1Request::RegisterServer { .. }
            | Win16Ole1Request::RevokeServer { .. }
            | Win16Ole1Request::BlockServer { .. }
            | Win16Ole1Request::UnblockServer { .. }
            | Win16Ole1Request::RegisterServerDoc { .. }
            | Win16Ole1Request::RevokeServerDoc { .. }
            | Win16Ole1Request::RenameServerDoc { .. }
            | Win16Ole1Request::RevertServerDoc { .. }
            | Win16Ole1Request::SavedServerDoc { .. }
            | Win16Ole1Request::RevokeObject { .. }
            | Win16Ole1Request::ItemCallback { .. } => {
                unreachable!("OLE1 server callbacks must use begin_ole1_request")
            }
            Win16Ole1Request::Create { .. }
            | Win16Ole1Request::CreateFromFile { .. }
            | Win16Ole1Request::CreateFromTemplate { .. }
            | Win16Ole1Request::CreateLinkFromFile { .. }
            | Win16Ole1Request::LoadFromStream { .. }
            | Win16Ole1Request::CreationInvalidAddress { .. } => {
                unreachable!("OLE1 creation calls must use begin_ole1_request")
            }
            Win16Ole1Request::RegisterClientDocInvalidAddress { output, status } => {
                if self.clear_client_doc_output(output, memory).is_err() {
                    return u32::from(OLE1_ERROR_ADDRESS);
                }
                u32::from(status)
            }
            Win16Ole1Request::RenameClientDocInvalidAddress { document, status } => {
                let handle = Win16Ole1ClientDocHandle::from_guest_long(document as u32);
                if !self.ole1_client_documents.documents.contains_key(&handle) {
                    return u32::from(OLE1_ERROR_HANDLE);
                }
                u32::from(status)
            }
            Win16Ole1Request::RegisterClientDoc {
                class_name,
                document_name,
                reserved,
                output,
            } => {
                let pointer = match self.clear_client_doc_output(output, memory) {
                    Ok(pointer) => pointer,
                    Err(status) => return u32::from(status),
                };

                let handle =
                    match self
                        .ole1_client_documents
                        .register(class_name, document_name, reserved)
                    {
                        Ok(handle) => handle,
                        Err(status) => return u32::from(status),
                    };
                if self
                    .selectors
                    .write(memory, pointer, &handle.to_guest_long().to_le_bytes())
                    .is_err()
                {
                    self.ole1_client_documents
                        .rollback_unpublished_registration(handle);
                    return u32::from(OLE1_ERROR_ADDRESS);
                }
                u32::from(OLE1_OK)
            }
            Win16Ole1Request::RevokeClientDoc { document } => u32::from(
                self.ole1_client_documents
                    .revoke(Win16Ole1ClientDocHandle::from_guest_long(document as u32)),
            ),
            Win16Ole1Request::RenameClientDoc {
                document,
                document_name,
            } => u32::from(self.ole1_client_documents.rename(
                Win16Ole1ClientDocHandle::from_guest_long(document as u32),
                document_name,
            )),
            Win16Ole1Request::RevertClientDoc { document } => u32::from(
                self.ole1_client_documents
                    .revert(Win16Ole1ClientDocHandle::from_guest_long(document as u32)),
            ),
            Win16Ole1Request::SavedClientDoc { document } => u32::from(
                self.ole1_client_documents
                    .saved(Win16Ole1ClientDocHandle::from_guest_long(document as u32)),
            ),
            Win16Ole1Request::EnumObjects {
                document,
                object_inout,
            } => u32::from(self.ole1_enum_objects(document, object_inout, memory)),
        }
    }

    fn clear_client_doc_output(
        &self,
        output: u32,
        memory: &mut Memory,
    ) -> Result<SegmentedPointer, Win16Ole1Status> {
        let pointer = self
            .selectors
            .pointer_from_far(output)
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        self.selectors
            .translate(pointer, Access::Write, 4, memory)
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        self.selectors
            .write(memory, pointer, &[0; 4])
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        Ok(pointer)
    }
}

#[cfg(test)]
#[path = "win16_ole1_tests.rs"]
mod tests;
