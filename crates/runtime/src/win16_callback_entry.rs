//! Typed asynchronous FAR-call callback entry.

use guest_core::Registers;

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
    pub(super) fn finish_guest_callback_entry(
        &self,
        registers: &mut Registers,
        frame: Win16CallbackEntryFrame,
    ) -> Result<(), RuntimeError> {
        match frame {
            Win16CallbackEntryFrame::FarCall(frame) => {
                self.finish_guest_far_callback(registers, frame).map(|_| ())
            }
        }
    }
}
