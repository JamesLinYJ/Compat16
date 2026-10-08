//! Typed OLE1 object creation through the owning COM STA.
//!
//! This module deliberately implements only the object-creation path whose
//! semantics are represented by the current host DTOs: `OleCreate` with
//! `StdFileEditing` and `OLE_RENDER_NONE`. The returned FAR object is written
//! only after every typed COM call has completed and its exact terminal has
//! been acknowledged.

#[path = "win16_ole1_creation_safe_point.rs"]
mod safe_point;
#[path = "win16_ole1_creation_validation.rs"]
mod validation;
use validation::status_runtime;

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, Win16Ole1Request, Win16ReturnKind};
use x86_cpu::{CallEffectPolicy, CallResumeBoundary, Cpu};

use super::object_proxy::{Win16Ole1NativeObjectKind, Win16Ole1NativeObjectResources};
use super::{
    OLE1_ERROR_ADDRESS, OLE1_ERROR_COMMAND, OLE1_ERROR_DOVERB, OLE1_ERROR_DRAW, OLE1_ERROR_FORMAT,
    OLE1_ERROR_HANDLE, OLE1_ERROR_NAME, OLE1_ERROR_OPEN, OLE1_ERROR_OPTION, OLE1_ERROR_PROTOCOL,
    OLE1_ERROR_STREAM, OLE1_ERROR_TEMPLATE, OLE1_OK, Win16Ole1ClientDocHandle,
    Win16Ole1ClientProxyId, Win16Ole1OperationId, Win16State,
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ComHostCallbackRoute,
    Win16ComHostInterface, Win16ComHostRequest, Win16ComHostResult, Win16ComHostStep,
    Win16OleHostOperation, Win16OleHostValue, Win16StorageHostOperation,
};

const OLE_RENDER_NONE: u16 = 0;
const CLSCTX_SERVER: u32 = 0x15;
const STGM_READWRITE_SHARE_EXCLUSIVE: u32 = 0x12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateStage {
    Clsid,
    CreateObject,
    CallbackProxy,
    Storage,
    PublishProxy,
    SetClientSite,
    SetHostNames,
    InitializeStorage,
    Advise,
    Return,
}

/// A pending OLE1 create retains both the checked guest caller and every host
/// reference until the exact per-step terminal has been interpreted. A
/// stranded result remains here on any reconciliation failure so task exit
/// cannot report the owner drained.
#[derive(Debug)]
pub(super) struct Win16Ole1CreateSequence {
    pub(super) owner: crate::Win16ComHostOwnerIdentity,
    pub(super) operation_id: Win16Ole1OperationId,
    pub(super) route: Win16ComHostCallbackRoute,
    pub(super) document: Win16Ole1ClientDocHandle,
    pub(super) client_far: u32,
    pub(super) client_proxy_id: Win16Ole1ClientProxyId,
    pub(super) client_proxy_allocation: win16_abi::GlobalHandle,
    pub(super) output: SegmentedPointer,
    pub(super) return_to: (u16, u16, u32),
    pub(super) return_kind: Win16ReturnKind,
    pub(super) callback_depth: usize,
    stage: CreateStage,
    current: Option<super::super::com_operations::Win16ComGuestOperationId>,
    class_id: Option<compat_services::com::Guid>,
    object: Option<Win16ComHostInterface>,
    storage: Option<Win16ComHostInterface>,
    client_site: Option<Win16ComHostInterface>,
    advise_sink: Option<Win16ComHostInterface>,
    object_far: Option<u32>,
    advise_cookie: Option<u32>,
    host_application: Vec<u16>,
    host_document: Vec<u16>,
    stranded_result: Option<Win16ComHostResult>,
    stranded_step: Option<Win16ComHostStep>,
    stranded_failure: Option<String>,
}

/// Exact owner-incarnation inventory for OLE1 work which owns native COM
/// references or callback/operation continuations. Unscoped client-document
/// metadata is not inferred from this result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Ole1ClientOwnerPending {
    pub(in crate::win16_runtime) owner: crate::Win16ComHostOwnerIdentity,
    pub(in crate::win16_runtime) pending_com_operations: usize,
    pub(in crate::win16_runtime) pending_com_callback_resumes: usize,
    pub(in crate::win16_runtime) sealed_com_callback_receipts: usize,
    pub(in crate::win16_runtime) pending_creation_sequences: usize,
    pub(in crate::win16_runtime) pending_object_method_sequences: usize,
    pub(in crate::win16_runtime) native_object_proxies: usize,
    pub(in crate::win16_runtime) pending_native_proxy_retirements: usize,
    pub(in crate::win16_runtime) active_com_callback_frames: usize,
}

impl Win16State {
    pub(in crate::win16_runtime) fn ole1_client_owner_pending(
        &self,
        owner: crate::Win16ComHostOwnerIdentity,
    ) -> Option<Ole1ClientOwnerPending> {
        if !owner.is_valid() {
            return None;
        }
        let pending = Ole1ClientOwnerPending {
            owner,
            pending_com_operations: self.pending_com_guest_operations_for_owner(owner),
            pending_com_callback_resumes: self
                .ole1_com_callback_resumes
                .iter()
                .filter(|resume| resume.owner == owner)
                .count(),
            sealed_com_callback_receipts: self
                .ole1_client_documents
                .sealed_com_callback_receipts
                .iter()
                .filter(|step| sealed_callback_owner(step) == Some(owner))
                .count(),
            pending_creation_sequences: self
                .ole1_client_documents
                .pending_creations
                .iter()
                .filter(|sequence| sequence.owner == owner)
                .count(),
            pending_object_method_sequences: self
                .ole1_client_documents
                .pending_object_methods
                .iter()
                .filter(|sequence| sequence.owner == owner)
                .count(),
            native_object_proxies: self
                .ole1_client_documents
                .native_object_proxies
                .iter()
                .filter(|record| record.object.owner == owner)
                .count(),
            pending_native_proxy_retirements: self
                .ole1_client_documents
                .pending_native_object_proxy_retirements
                .iter()
                .filter(|retirement| retirement.owner == owner)
                .count(),
            active_com_callback_frames: self
                .ole1_callbacks
                .iter()
                .filter(|frame| match frame.stage {
                    super::Win16Ole1CallbackStage::ClientComAdviseNotification {
                        callback, ..
                    } => callback.owner == owner,
                    _ => false,
                })
                .count(),
        };
        Some(pending)
    }

    pub(super) fn begin_ole1_creation(
        &mut self,
        request: Win16Ole1Request,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let output_far = match &request {
            Win16Ole1Request::Create { object_output, .. }
            | Win16Ole1Request::CreateFromFile { object_output, .. }
            | Win16Ole1Request::CreateFromTemplate { object_output, .. }
            | Win16Ole1Request::CreateLinkFromFile { object_output, .. }
            | Win16Ole1Request::LoadFromStream { object_output, .. } => *object_output,
            Win16Ole1Request::CreationInvalidAddress {
                object_output,
                status,
            } => {
                let cleared = self.clear_creation_output(*object_output, memory);
                let result = if cleared.is_ok() {
                    *status
                } else {
                    OLE1_ERROR_ADDRESS
                };
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(result),
                    return_kind,
                );
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "non-creation request reached the OLE1 creation dispatcher",
                ));
            }
        };
        let output = match self.preflight_creation_output(output_far, memory) {
            Ok(pointer) => pointer,
            Err(status) => {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    return_kind,
                );
            }
        };
        self.selectors
            .write(memory, output, &[0; 4])
            .map_err(crate::runtime_error)?;

        let (class_name_bytes, protocol, client, document, item_name, render_option, activate) =
            match request {
                Win16Ole1Request::Create {
                    class_name,
                    protocol,
                    client,
                    document,
                    item_name,
                    render_option,
                    activate,
                    ..
                } => (
                    class_name,
                    protocol,
                    client,
                    document,
                    item_name,
                    render_option,
                    activate,
                ),
                Win16Ole1Request::CreateFromFile { .. } => {
                    return self.return_creation_gap(
                        cpu,
                        host,
                        return_to,
                        return_kind,
                        OLE1_ERROR_OPEN,
                        "OleCreateFromFile needs a guest DOS-path to host-storage mapping and native-type load contract",
                    );
                }
                Win16Ole1Request::CreateFromTemplate { .. } => {
                    return self.return_creation_gap(
                        cpu,
                        host,
                        return_to,
                        return_kind,
                        OLE1_ERROR_TEMPLATE,
                        "OleCreateFromTemplate requires template storage class and load reconciliation",
                    );
                }
                Win16Ole1Request::CreateLinkFromFile { .. } => {
                    return self.return_creation_gap(
                        cpu,
                        host,
                        return_to,
                        return_kind,
                        OLE1_ERROR_OPEN,
                        "OleCreateLinkFromFile requires moniker and link advise transaction support",
                    );
                }
                Win16Ole1Request::LoadFromStream { .. } => {
                    return self.return_creation_gap(
                        cpu,
                        host,
                        return_to,
                        return_kind,
                        OLE1_ERROR_STREAM,
                        "OleLoadFromStream requires a checked OLESTREAM adapter and class/protocol conversion",
                    );
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "non-create request reached OLE1 creation setup",
                    ));
                }
            };
        if render_option > 2 {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_ERROR_OPTION),
                return_kind,
            );
        }
        if activate {
            return self.return_creation_gap(
                cpu,
                host,
                return_to,
                return_kind,
                OLE1_ERROR_DOVERB,
                "OleCreateInvisible activation requires the OLE1 verb/window/activation reconciliation path",
            );
        }
        if render_option != OLE_RENDER_NONE {
            let (status, reason) = if render_option == 1 {
                (
                    OLE1_ERROR_DRAW,
                    "OleCreate render-draw needs a checked guest drawing-data transfer",
                )
            } else {
                (
                    OLE1_ERROR_FORMAT,
                    "OleCreate render-format needs checked guest clip-format data transfer",
                )
            };
            return self.return_creation_gap(cpu, host, return_to, return_kind, status, reason);
        }
        if !protocol.eq_ignore_ascii_case(b"StdFileEditing") {
            if protocol.eq_ignore_ascii_case(b"StdExecute") {
                return self.return_creation_gap(
                    cpu,
                    host,
                    return_to,
                    return_kind,
                    OLE1_ERROR_COMMAND,
                    "OleCreate StdExecute requires the OLE1 DDE execute protocol",
                );
            }
            return self.return_creation_gap(
                cpu,
                host,
                return_to,
                return_kind,
                OLE1_ERROR_PROTOCOL,
                "OleCreate protocol is not implemented by the checked native creation route",
            );
        }
        let document_handle = Win16Ole1ClientDocHandle::from_guest_long(document as u32);
        let Some(document_record) = self.ole1_client_documents.documents.get(&document_handle)
        else {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_ERROR_HANDLE),
                return_kind,
            );
        };
        let application_name = host.decode_win16_ansi(&document_record.class_name)?;
        let document_name = host.decode_win16_ansi(&document_record.document_name)?;
        let decoded_class_name = host.decode_win16_ansi(&class_name_bytes)?;
        if decoded_class_name.is_empty() || application_name.is_empty() || document_name.is_empty()
        {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_ERROR_NAME),
                return_kind,
            );
        }
        // OLE1 classes with an actual StdFileEditing server registration use
        // the checked DDE protocol and publish the DDE-backed 39-slot object
        // proxy only after exact execute and embedded-topic receipts. Classes
        // without that OLE1 registration may still use the independent native
        // COM adapter below.
        if let Some(resolved) = super::registry_resolver::resolve_class_application(
            host,
            &class_name_bytes,
            b"StdFileEditing",
        )? {
            let owner = self.tasks.current().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 DDE creation has no current Win16 task owner",
                )
            })?;
            return self.begin_dde_ole1_creation(
                owner,
                document_handle,
                client,
                output,
                return_to,
                return_kind,
                resolved.application_name,
                resolved.class_name,
                item_name.unwrap_or_default(),
                cpu,
                dos,
                memory,
                host,
            );
        }
        let host_owner = host.win16_com_owner()?;
        if !host_owner.is_valid() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "RuntimeHost returned an invalid Win16 COM owner incarnation",
            ));
        }
        self.ole1_client_documents
            .pending_creations
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve OLE1 create sequence",
                    error,
                )
            })?;
        self.ole1_client_documents
            .reserve_pending_operation(document_handle)
            .map_err(status_runtime)?;
        let operation_id = match self.ole1_client_documents.reserve_operation() {
            Ok(id) => id,
            Err(status) => return Err(status_runtime(status)),
        };
        let route = Win16ComHostCallbackRoute(operation_id.0);
        self.ole1_client_documents
            .begin_pending_creation(
                document_handle,
                operation_id,
                None,
                None,
                super::Win16Ole1SourceProbePolicy::ProbeCreateAsync,
                None,
                None,
                client,
                super::Win16Ole1ReleaseMethodExpectation::FromNotification,
            )
            .map_err(status_runtime)?;
        let (_client_proxy_far, client_proxy_id) =
            match self.ole1_client_proxy_for_call(client, Some(operation_id), memory) {
                Ok(proxy) => proxy,
                Err(primary) => {
                    self.ole1_client_documents.finish_operation(operation_id);
                    return Err(match primary.status_or_runtime() {
                        Ok(status) => status_runtime(status),
                        Err(error) => error,
                    });
                }
            };
        let client_proxy_allocation = self
            .ole1_client_proxy(client_proxy_id)
            .ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "new OLE1 client proxy disappeared before creation journaling",
            ))?
            .allocation;
        if let Err(status) = self
            .ole1_client_documents
            .set_pending_creation_proxy(operation_id, client_proxy_id)
        {
            self.ole1_client_documents.finish_operation(operation_id);
            let primary = status_runtime(status);
            return Err(
                match self.retire_ole1_client_operation_proxy(client_proxy_id) {
                    Ok(()) => primary,
                    Err(cleanup) => primary.with_cleanup(
                        "retire OLE1 client callback proxy after creation binding failed",
                        cleanup,
                    ),
                },
            );
        }
        let request = Win16ComHostRequest::Ole(Win16OleHostOperation::ClsidFromProgId {
            progid: class_name_bytes,
            code_page: host.win16_ansi_code_page(),
        });
        let current = match self.reserve_com_guest_operation(
            cpu,
            dos,
            memory,
            host_owner,
            route,
            return_to,
            return_kind,
            super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                client_operation: operation_id.0,
            },
            request,
        ) {
            Ok(current) => current,
            Err(primary) => {
                self.ole1_client_documents.finish_operation(operation_id);
                return Err(
                    match self.retire_ole1_client_operation_proxy(client_proxy_id) {
                        Ok(()) => primary,
                        Err(cleanup) => primary.with_cleanup(
                            "retire OLE1 client callback proxy after caller capture failed",
                            cleanup,
                        ),
                    },
                );
            }
        };
        self.ole1_client_documents
            .pending_creations
            .push(Win16Ole1CreateSequence {
                owner: host_owner,
                operation_id,
                route,
                document: document_handle,
                client_far: client,
                client_proxy_id,
                client_proxy_allocation,
                output,
                return_to,
                return_kind,
                callback_depth: self.ole1_callbacks.len(),
                stage: CreateStage::Clsid,
                current: Some(current),
                class_id: None,
                object: None,
                storage: None,
                client_site: None,
                advise_sink: None,
                object_far: None,
                advise_cookie: None,
                host_application: application_name.encode_utf16().collect(),
                host_document: document_name.encode_utf16().collect(),
                stranded_result: None,
                stranded_step: None,
                stranded_failure: None,
            });
        // `OleCreateInvisible` with `activate == false` uses this path; the
        // active case was rejected until its HWND/verb contract is modeled.
        Ok(None)
    }

    fn return_creation_gap(
        &mut self,
        cpu: &mut Cpu,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        status: u16,
        context: &'static str,
    ) -> Result<Option<u8>, RuntimeError> {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            format!("OLE1 creation returned guest status {status}: {context}"),
        ));
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            u32::from(status),
            return_kind,
        )
    }
}

fn sealed_callback_owner(step: &Win16ComHostStep) -> Option<crate::Win16ComHostOwnerIdentity> {
    match step {
        Win16ComHostStep::CallbackFailed { owner, .. }
        | Win16ComHostStep::CallbackFrameComplete { owner, .. } => Some(*owner),
        Win16ComHostStep::Callback(callback) => Some(callback.owner),
        Win16ComHostStep::Running(_)
        | Win16ComHostStep::Complete(_)
        | Win16ComHostStep::OperationFailed { .. } => None,
    }
}
