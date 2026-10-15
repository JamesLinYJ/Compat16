//! Typed asynchronous FAR-call callback entry.

use guest_core::memory::Memory;
use dos_kernel::DosKernel;
use x86_cpu::{Cpu, CallEffectPolicy};

use super::callback_scheduler::Win16AsynchronousCallbackArgument;
use super::far_callback::{
    Win16FarCallbackConvention, Win16FarCallbackFrame, Win16FarCallbackReturn,
};
use super::Win16State;
use crate::RuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16GuestCallbackAbi {
    FarCall {
        convention: Win16FarCallbackConvention,
        return_kind: Win16FarCallbackReturn,
    },
}

pub(super) enum Win16CallbackEntry {
    FarCall {
        arguments: Vec<Win16AsynchronousCallbackArgument>,
    },
}

#[derive(Clone, Debug)]
pub(super) enum Win16CallbackEntryFrame {
    FarCall(Win16FarCallbackFrame),
}

impl Win16CallbackEntryFrame {
    pub(super) fn code_references(&self) -> [u32; 2] {
        match self {
            Self::FarCall(frame) => frame.code_references(),
        }
    }
}

impl Win16State {
    pub(super) fn finish_guest_callback_entry_checked(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        frame: &mut Win16CallbackEntryFrame,
    ) -> Result<(), RuntimeError> {
        match frame {
            Win16CallbackEntryFrame::FarCall(frame) => {
                self.finish_guest_far_callback_checked_with_policy(
                    cpu, dos, memory, frame, CallEffectPolicy::RestoreSavedX87,
                ).map(|_| ())
            }
        }
    }

    pub(super) fn release_guest_callback_entry_owner(
        &mut self, frame: &mut Win16CallbackEntryFrame,
        dos: &mut DosKernel, memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        match frame {
            Win16CallbackEntryFrame::FarCall(frame) =>
                self.release_guest_far_callback_owner(frame, dos, memory),
        }
    }

    pub(super) fn abort_guest_callback_entry_after_task_execution_ended(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        callback_id: super::CallbackFrameId,
        cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        frame: &mut Win16CallbackEntryFrame,
    ) -> Result<(), RuntimeError> {
        match frame {
            Win16CallbackEntryFrame::FarCall(frame) =>
                self.abort_guest_far_callback_after_task_execution_ended(
                    ended, super::CallbackKind::Asynchronous, callback_id,
                    cpu, dos, memory, frame,
                ),
        }
    }
}
