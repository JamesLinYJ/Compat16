//! Checked callback continuations for public Win16 OLE 1.0 methods.

use dos_kernel::DosKernel;
use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ReturnKind};
use x86_cpu::Cpu;

use super::super::far_callback::Win16FarCallbackFrame;
use super::super::{CallbackFrameId, CallbackKind, Win16State};
use super::methods::is_known_oleobject_protocol;
use super::{
    OLE1_ERROR_ADDRESS, OLE1_ERROR_OBJECT, OLE1_OK,
    OLE1_WAIT_FOR_RELEASE, Win16Ole1CallbackStage, Win16Ole1ClientProxyId,
    Win16Ole1ObjectEffect,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

pub(in crate::win16_runtime) struct Win16Ole1CallbackFrame {
    pub(super) callback_id: CallbackFrameId,
    pub(super) saved: Registers,
    pub(super) return_to: Option<(u16, u16, u32)>,
    pub(super) return_kind: Option<Win16ReturnKind>,
    pub(super) stage: Win16Ole1CallbackStage,
    pub(super) object_effect: Option<Win16Ole1ObjectEffect>,
    /// Exact proxy to retry if teardown retirement could not be handed off.
    /// Keeping the id here prevents cancellation from losing its retry owner.
    pub(super) pending_proxy_retirement: Option<Win16Ole1ClientProxyId>,
    pub(super) active_call: Option<Win16FarCallbackFrame>,
}

impl Win16Ole1CallbackFrame {
    pub(in crate::win16_runtime) fn identity(&self) -> CallbackFrameId {
        self.callback_id
    }

    pub(in crate::win16_runtime) fn com_identity(&self) -> Option<super::Win16Ole1ComCallbackIdentity> {
        match self.stage {
            Win16Ole1CallbackStage::ClientComAdviseNotification { callback, .. } => Some(callback),
            _ => None,
        }
    }
}

// Keep the callback lifecycle in one module so its private frame state and
// shared callback binding stay exact; the source fragments keep each file
// within the repository's handwritten-file size limit.
include!("win16_ole1_callback_release_entry.rs");
include!("win16_ole1_callback_completion.rs");
include!("win16_ole1_callback_teardown.rs");
