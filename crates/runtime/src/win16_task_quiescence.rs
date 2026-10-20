//! Native-source quiescence gate for process-owned selector retirement.

use super::{WindowTeardownState, Win16State};

impl Win16State {
    pub(super) fn can_retire_task_selector_views(&self) -> bool {
        self.com_owner_guest_state_retired()
            && self.legacy_cpu_frames.is_empty()
            && self.task_event_waits.is_empty()
            && self.window_teardown_state == WindowTeardownState::Closed
            && self.dde_runtime_quiesced
            && self.callback_scheduler.native_sources_quiescent()
            && self.mci.native_sources_quiescent()
            && self.acm.native_sources_quiescent()
            && self.media_services.native_sources_quiescent()
            && self.mixer.native_sources_quiescent()
            && self.comm_ports.is_empty()
            && self.wave_audio.native_sources_quiescent()
            && self.sound.native_sources_quiescent()
            && self.network.native_sources_quiescent()
            && self.dde_callbacks.is_empty()
            && self.dde_guest_contexts.is_empty()
            && self.dde_context_restores.is_empty()
            && self.callback_kinds.is_empty()
            && self.font_callbacks.is_empty()
            && self.object_callbacks.is_empty()
            && self.line_dda_callbacks.is_empty()
            && self.print_abort_callbacks.is_empty()
            && self.window_enumerations.is_empty()
            && self.window_callbacks.is_empty()
            && self.native_function_callbacks.is_empty()
            && self.window_operations.is_empty()
            && self.module_callbacks.is_empty()
            && self.resource_callbacks.is_empty()
            && self.far_returns.is_empty()
            && self.interrupt_returns.is_empty()
    }
}
