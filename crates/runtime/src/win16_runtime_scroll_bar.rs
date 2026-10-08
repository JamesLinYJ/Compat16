//! USER scroll-bar APIs through the native window worker.

use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ReturnKind, Win16UserScrollBarRequest};

use super::{Win16State, guest_ranges::GuestOutputRange,
    windows::WindowReturn};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostScrollBarOperation as Operation,
    Win16HostWindow, Win16WindowOperation};

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) enum ScrollBarResultKind { Position, Range, Void, Enabled }

pub(in crate::win16_runtime) struct Win16ScrollBarContinuation {
    pub(in crate::win16_runtime) result_kind: ScrollBarResultKind,
    pub(in crate::win16_runtime) return_kind: Win16ReturnKind,
    pub(in crate::win16_runtime) minimum_output: Option<GuestOutputRange>,
    pub(in crate::win16_runtime) maximum_output: Option<GuestOutputRange>,
}

impl Win16State {
    pub(in crate::win16_runtime) fn begin_scroll_bar_request(
        &mut self,
        request: Win16UserScrollBarRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        descriptor_return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let (result_kind, return_kind) = result_shape(request);
        if descriptor_return_kind != return_kind {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER scroll-bar export has an unexpected ABI return kind"));
        }
        let window = match request {
            Win16UserScrollBarRequest::SetPosition { window, .. }
            | Win16UserScrollBarRequest::GetPosition { window, .. }
            | Win16UserScrollBarRequest::SetRange { window, .. }
            | Win16UserScrollBarRequest::GetRange { window, .. }
            | Win16UserScrollBarRequest::Show { window, .. }
            | Win16UserScrollBarRequest::Enable { window, .. } if window != 0 => {
                self.window_handles.get(&window).copied()
            }
            _ => None,
        };
        let Some(window) = window else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, return_kind);
        };

        let (operation, minimum_output, maximum_output) =
            match self.prepare_scroll_bar_operation(request, window, memory) {
                Ok(prepared) => prepared,
                Err(error) if guest_api_failure(&error) => {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, return_kind);
                }
                Err(error) => return Err(error),
            };
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::ScrollBar(operation),
            WindowReturn::ScrollBar(Win16ScrollBarContinuation {
                result_kind, return_kind, minimum_output, maximum_output,
            }), return_to)
    }

    fn prepare_scroll_bar_operation(
        &self,
        request: Win16UserScrollBarRequest,
        window: Win16HostWindow,
        memory: &Memory,
    ) -> Result<(Operation, Option<GuestOutputRange>, Option<GuestOutputRange>), RuntimeError> {
        match request {
            Win16UserScrollBarRequest::SetPosition { bar, position, redraw, .. } => Ok((
                Operation::SetPosition { window, bar, position, redraw }, None, None)),
            Win16UserScrollBarRequest::GetPosition { bar, .. } => Ok((
                Operation::GetPosition { window, bar }, None, None)),
            Win16UserScrollBarRequest::SetRange { bar, minimum, maximum, redraw, .. } => {
                // SDK 3.1 Programmer's Reference Vol. 2, pp. 861-862 limits
                // nMax - nMin to a signed Win16 int. A modern host permits a
                // wider range, so that target constraint belongs here.
                if i32::from(maximum) - i32::from(minimum) > i32::from(i16::MAX) {
                    return Err(RuntimeError::new(Kind::InvalidInput,
                        "Win16 SetScrollRange span exceeds the target int range"));
                }
                Ok((Operation::SetRange { window, bar, minimum, maximum, redraw }, None, None))
            }
            Win16UserScrollBarRequest::GetRange { bar, minimum, maximum, .. } => {
                if minimum == 0 || maximum == 0 {
                    return Err(RuntimeError::new(Kind::GuestFault,
                        "Win16 GetScrollRange requires both output FAR pointers"));
                }
                let minimum = self.capture_scroll_bar_word(memory, minimum)?;
                let maximum = self.capture_scroll_bar_word(memory, maximum)?;
                Ok((Operation::GetRange { window, bar }, Some(minimum), Some(maximum)))
            }
            Win16UserScrollBarRequest::Show { bar, show, .. } => Ok((
                Operation::Show { window, bar, show }, None, None)),
            Win16UserScrollBarRequest::Enable { bar, flags, .. } => Ok((
                Operation::Enable { window, bar, flags }, None, None)),
        }
    }

    fn capture_scroll_bar_word(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<GuestOutputRange, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        // An int FAR* is one scalar in one descriptor, unlike a huge buffer.
        self.selectors.translate(pointer, Access::Write, 2, memory)
            .map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, 2)
    }

}

fn result_shape(request: Win16UserScrollBarRequest) -> (ScrollBarResultKind, Win16ReturnKind) {
    use Win16UserScrollBarRequest as Request;
    match request {
        Request::SetPosition { .. } | Request::GetPosition { .. } =>
            (ScrollBarResultKind::Position, Win16ReturnKind::Word),
        Request::GetRange { .. } => (ScrollBarResultKind::Range, Win16ReturnKind::Void),
        Request::SetRange { .. } | Request::Show { .. } =>
            (ScrollBarResultKind::Void, Win16ReturnKind::Void),
        Request::Enable { .. } => (ScrollBarResultKind::Enabled, Win16ReturnKind::Word),
    }
}

fn guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}
