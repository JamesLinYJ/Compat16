//! Retained ToolHelp callback frames and their checked guest references.

use super::far_callback::Win16FarCallbackFrame;
use super::toolhelp_notify::Win16ToolhelpNotifyRegistration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16ToolhelpNotifyProgress {
    CallbackEntered,
    Complete { handled: bool },
}

pub(super) struct Win16ToolhelpNotifyEventFrame {
    pub(super) callback_id: super::CallbackFrameId,
    pub(super) task: u16,
    pub(super) notification: u16,
    pub(super) data: u32,
    pub(super) registrations: Vec<Win16ToolhelpNotifyRegistration>,
    pub(super) next_registration: usize,
    pub(super) active_call: Option<Win16FarCallbackFrame>,
    /// The callback returned, but releasing its checked owner may still need
    /// a retry. Preserve its ACK result so a retry never executes the same
    /// guest callback twice.
    pub(super) returned_call: Option<(Win16FarCallbackFrame, bool)>,
    /// Callback result already accepted; used while entering the next chain
    /// member or retrying completion-side cleanup.
    pub(super) completed_handled: Option<bool>,
    pub(super) payload_buffers: Vec<super::callback_scheduler::CallbackBuffer>,
    pub(super) module_root: Option<u16>,
    /// A FREESEG/DELMODULE callback is part of the module's retirement
    /// transaction. The count is kept live until every registered callback
    /// has returned, then the held module root may be released to the reaper.
    pub(super) module_retirement: Option<u16>,
    pub(super) termination_id: Option<u64>,
    /// Exact DLL-load continuation that owned a scoped event before its
    /// ToolHelp callback was published above the Module frame.
    pub(super) module_entry_parent:
        Option<super::toolhelp_notify::Win16ToolhelpModuleEntryParent>,
}

impl Win16ToolhelpNotifyEventFrame {
    pub(super) fn retained_payload_buffer_count(&self) -> usize {
        self.payload_buffers.iter().filter(|buffer| buffer.owns_guest_allocation()).count()
    }

    pub(super) fn code_references(&self) -> impl Iterator<Item = u32> + '_ {
        self.registrations.iter().map(|registration| registration.callback.far_value())
            .chain(self.active_call.iter().flat_map(Win16FarCallbackFrame::code_references))
            .chain(self.module_root.map(|module| u32::from(module) << 16))
    }
}
