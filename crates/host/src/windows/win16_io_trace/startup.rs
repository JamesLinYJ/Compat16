//! A small live tail for startup that outlasts the ordinary trace prefix.
use runtime::{
    Win16IoEvent, Win16ServiceBoundaryStage, Win16WindowCallbackPhase,
    Win16WindowCallbackProcedure, Win16WindowCallbackReturn,
};

pub(super) const MAX_LIVE_NULL_RETURNS: usize = 8;

#[derive(Default)]
pub(super) struct StartupProgress {
    message_loop_seen: bool,
    null_returns: usize,
}

impl StartupProgress {
    pub(super) fn observe(&mut self, event: &Win16IoEvent<'_>) -> bool {
        match event {
            Win16IoEvent::ServiceBoundary {
                module,
                name,
                ordinal,
                stage: Win16ServiceBoundaryStage::DispatchEnter,
                ..
            } if !self.message_loop_seen
                && module.eq_ignore_ascii_case(b"USER")
                && (name.is_some_and(|name| name.eq_ignore_ascii_case(b"GetMessage"))
                    || *ordinal == Some(108)) =>
            {
                self.message_loop_seen = true;
                true
            }
            Win16IoEvent::WindowCallback {
                procedure: Win16WindowCallbackProcedure::WindowProcedure,
                phase: Win16WindowCallbackPhase::GuestReturn,
                message: 0,
                return_value: Some(Win16WindowCallbackReturn::WindowProcedure(_)),
                ..
            } if self.message_loop_seen && self.null_returns < MAX_LIVE_NULL_RETURNS => {
                self.null_returns += 1;
                true
            }
            _ => false,
        }
    }
}
