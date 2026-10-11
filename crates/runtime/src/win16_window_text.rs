//! Window-text API marshalling and guest callback continuations.

use guest_core::{memory::Memory, Registers};
use win16_abi::{Win16OutputBuffer, Win16ReturnKind};

use super::{Win16State, windows::WindowReturn};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16WindowOperation};

impl Win16State {
    pub(super) fn begin_set_window_text(&mut self, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, window: u16,
        return_kind: Win16ReturnKind,
        text: Option<Vec<u8>>, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if return_kind != Win16ReturnKind::Void {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 SetWindowText descriptor must return void"));
        }
        let Some(&window) = self.window_handles.get(&window) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, return_kind);
        };
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::SetWindowText { window, text },
            WindowReturn::SetWindowText, return_to)
    }

    pub(super) fn begin_get_window_text(&mut self, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, window: u16,
        output: u32, count: i16, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let window = self.window_handles.get(&window).copied();
        let Some(window) = window.filter(|_| count > 0 && output != 0) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        self.preflight_text_write(memory, pointer, count as usize)?;
        let output_range = super::guest_ranges::GuestOutputRange::capture(
            self, memory, pointer, count as usize,
        )?;
        let buffer = self.read_text_bytes(memory, pointer, count as usize)?;
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::GetWindowText { window, buffer },
            WindowReturn::GetWindowText {
                output: Win16OutputBuffer { pointer, capacity: count as u16 },
                output_range,
            }, return_to)
    }

    pub(super) fn begin_get_window_text_length(&mut self, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, window: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(&window) = self.window_handles.get(&window) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::GetWindowTextLength { window },
            WindowReturn::GetWindowTextLength, return_to)
    }

}
