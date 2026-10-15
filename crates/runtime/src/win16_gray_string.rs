//! Win16 GrayString: copied text, original LPARAM and resumable FAR callback.

use super::{Win16State, windows::WindowReturn};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16WindowOperation};
use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ReturnKind, Win16UserDrawingRequest};

impl Win16State {
    pub(super) fn begin_gray_string(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16UserDrawingRequest,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Win16UserDrawingRequest::GrayString {
            dc,
            brush,
            procedure,
            data,
            count,
            x,
            y,
            width,
            height,
        } = request
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "GrayString dispatcher received another drawing operation",
            ));
        };
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        let brush = if brush == 0 {
            None
        } else {
            let Some(brush) = self.guest_gdi.object(brush) else {
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Word,
                );
            };
            Some(brush)
        };
        if count < -1 || (count == -1 && (procedure == 0 || width == 0 || height == 0)) {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        }
        if procedure != 0 {
            let target = self
                .selectors
                .pointer_from_far(procedure)
                .map_err(crate::runtime_error)?;
            self.selectors
                .translate(target, Access::Execute, 1, memory)
                .map_err(crate::runtime_error)?;
        }
        // Even with a callback, zero count or automatic dimensions make
        // lpData a string under the SDK contract. Otherwise it is opaque.
        let text = if procedure == 0 || count == 0 || width == 0 || height == 0 {
            if count == 0 {
                let Some(text) = self.read_z_string(memory, data, 0x10000)? else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        Win16ReturnKind::Word,
                    );
                };
                Some(text)
            } else {
                let pointer = self
                    .selectors
                    .pointer_from_far(data)
                    .map_err(crate::runtime_error)?;
                Some(self.read_text_bytes(memory, pointer, count as usize)?)
            }
        } else {
            None
        };
        let count = if count == 0 {
            text.as_ref().map_or(0, Vec::len) as i32
        } else {
            i32::from(count)
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::GrayString {
                dc,
                brush,
                text,
                count,
                x,
                y,
                width,
                height,
                callback: procedure != 0,
            },
            WindowReturn::GrayString {
                procedure,
                data,
                count: count as i16,
            },
            return_to,
        )
    }
}
