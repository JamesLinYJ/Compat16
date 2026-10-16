//! Queue-owned caret marshalling; native USER owns shape, nesting and position.

use super::*;
use win16_abi::Win16UserWindowRequest;

impl Win16State {
    pub(super) fn begin_caret_request(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16UserWindowRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16UserWindowRequest as Request;

        let call = match request {
            Request::CreateCaret { window, bitmap, width, height } => {
                let shape = match bitmap {
                    0 => crate::Win16CaretShape::Solid,
                    1 => crate::Win16CaretShape::Gray,
                    _ => return Err(RuntimeError::new(
                        Kind::CompatibilityGap,
                        "Win16 bitmap carets require a retained native bitmap owner; the existing caret was not changed",
                    )),
                };
                Win16WindowCall::CreateCaret {
                    window: self.native_window(window), shape, width, height,
                }
            }
            Request::DestroyCaret => Win16WindowCall::DestroyCaret,
            Request::SetCaretPos { x, y } => Win16WindowCall::SetCaretPos { x, y },
            Request::HideCaret { window } => Win16WindowCall::HideCaret {
                window: self.native_window(window),
            },
            Request::ShowCaret { window } => Win16WindowCall::ShowCaret {
                window: self.native_window(window),
            },
            Request::GetCaretPos { point } => {
                let pointer = self.checked_guest_range(point, Point16::SIZE, Access::Write, memory)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, Point16::SIZE,
                )?;
                return self.submit_call(
                    registers, memory, host, Win16WindowCall::GetCaretPos,
                    Win16WindowCallOutput::Point(output), return_to, return_kind, None,
                );
            }
            _ => return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-caret request reached the Win16 caret bridge",
            )),
        };
        // Win16 returns void for all six APIs. Native BOOL outcomes remain
        // internal and do not overwrite guest AX/DX, including native failure.
        self.submit_value_call(registers, memory, host, call, return_to, return_kind)
    }
}
