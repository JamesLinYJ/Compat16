//! OLESVR #26 internal item-notification thunk.
//!
//! XP installs this routine as `OLECLIENTVTBL::CallBack`; it is the server's
//! DDE advise dispatcher, not a trampoline back into that same slot. Until the
//! advise ledger and typed DATA/ACK path are present, valid item notifications
//! return an explicit unsupported status rather than recursively calling the
//! client callback or claiming that subscribers were notified.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::Win16ReturnKind;
use x86_cpu::Cpu;

use super::super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackReturn,
};
use super::super::{CallbackKind, Win16State};
use super::{Win16Ole1CallbackFrame, Win16Ole1CallbackStage};
use crate::{DiagnosticKind as Kind, RuntimeError};

use super::super::win16_ole1_server_state::{
    OLE_ERROR_COMMAND, OLE_ERROR_HANDLE, OLE_ERROR_OPTION,
};

impl Win16State {
    /// The private OLESVR.26 entry is an internal notification dispatch, not a
    /// normal callback. It validates that its client/object pair belongs to
    /// this task, then reports that the DDE advise state machine is not yet
    /// implemented. The result follows the SDK's 16-bit `int` return ABI.
    pub(super) fn begin_ole1_item_callback_import(
        &mut self,
        cpu: &mut Cpu,
        return_to: (u16, u16, u32),
        client_far: u32,
        notification: u16,
        object_far: u32,
    ) -> Result<Option<u8>, RuntimeError> {
        let owner = self.current_task_owner()?;
        let status = match self
            .ole1_server_state
            .item_callback_identity(owner, client_far, object_far)
        {
            Some(identity)
                if self
                    .ole1_server_state
                    .validate_item_callback_identity(identity) =>
            {
                if notification <= 6 {
                    OLE_ERROR_COMMAND
                } else {
                    OLE_ERROR_OPTION
                }
            }
            _ => OLE_ERROR_HANDLE,
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            u32::from(status),
            Win16ReturnKind::Word,
        )
    }

    /// Enter one checked guest OLESERVER/OLESERVERDOC method while retaining
    /// the exact public API return registers and callback binding.
    pub(super) fn enter_server_api_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        return_to: (u16, u16, u32),
        procedure: u32,
        arguments: Vec<Win16FarCallbackArgument>,
        stage: Win16Ole1CallbackStage,
    ) -> Result<Option<u8>, RuntimeError> {
        self.ole1_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve OLESVR API callback continuation",
                error,
            )
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        self.ole1_callbacks.push(Win16Ole1CallbackFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to: Some(return_to),
            return_kind: Some(Win16ReturnKind::Word),
            stage,
            object_effect: None,
            active_call: None,
            pending_proxy_retirement: None,
        });
        if let Err(error) = self.push_callback_kind(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.pop();
            return Err(error);
        }

        let active_call = match self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            &arguments,
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        ) {
            Ok(active_call) => active_call,
            Err(primary) => {
                self.ole1_callbacks.pop();
                if let Err(cleanup) = self.retire_callback_binding(CallbackKind::Ole1, callback_id)
                {
                    return Err(primary.with_cleanup(
                        "retire OLESVR API callback binding after checked entry failed",
                        cleanup,
                    ));
                }
                return Err(primary);
            }
        };
        let Some(frame) = self.ole1_callbacks.last_mut() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLESVR API callback continuation disappeared after guest entry",
            ));
        };
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLESVR API callback changed its exact continuation during entry",
            ));
        }
        frame.active_call = Some(active_call);
        Ok(None)
    }
}
