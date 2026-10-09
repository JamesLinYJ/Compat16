//! Source-owned activity that requires native polling or retained cleanup.

use super::Win16State;

impl Win16State {
    /// Keep producer registrations, callbacks, and pending retirement owners
    /// visible while callback entry is blocked. Each family's existing driver
    /// remains responsible for its dispatch and acknowledgement order.
    pub(super) fn has_scheduler_work(&self) -> bool {
        self.wave_audio.needs_scheduler_progress()
            || self.sound.needs_scheduler_progress()
            || self.midi.needs_scheduler_progress()
            || self.network.needs_scheduler_progress()
            || self.netbios.needs_scheduler_progress()
            || self.classic_dde.needs_scheduler_progress()
            || self.ole1_client_documents.needs_scheduler_progress()
            || self.ole1_server_state.needs_scheduler_progress()
            || self.dde.needs_scheduler_progress()
            || self.toolhelp_notify.needs_scheduler_progress()
            || self.callback_scheduler.needs_scheduler_progress()
            || self.network_print_jobs.values().any(|jobs| jobs.needs_scheduler_progress())
            || self.toolhelp_task_exit.pending_id().is_some()
            || !self.toolhelp_notify_frames.is_empty()
            || !self.ole1_callbacks.is_empty()
            || !self.ole1_server_release_cascades.is_empty()
            || !self.ole1_com_callback_resumes.is_empty()
            || !self.ole1_com_callback_resume_failures.is_empty()
            || !self.dde_callbacks.is_empty()
            || !self.dde_guest_contexts.is_empty()
            || !self.dde_context_restores.is_empty()
            || !self.dde_retired_callback_tokens.is_empty()
            || !self.dde_retired_guest_blocks.is_empty()
    }
}
