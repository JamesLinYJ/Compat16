//! Text requests handled by the direct Win16 GDI adapter.

use super::*;

impl Win16State {
    pub(super) fn drawing_text_requests(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetBkColor { dc, color }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(u32::MAX);
                };
                match host.win16_gdi(Operation::SetBkColor { dc, color })? {
                    HostResult::Color(color) => Ok(color),
                    _ => Err(wrong_result("SetBkColor")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetBkMode { dc, mode }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetBkMode {
                    dc,
                    mode: i32::from(mode),
                })? {
                    HostResult::Mode(previous) => Ok(previous as u16 as u32),
                    _ => Err(wrong_result("SetBkMode")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextColor {
                dc,
                color,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(u32::MAX);
                };
                match host.win16_gdi(Operation::SetTextColor { dc, color })? {
                    HostResult::Color(color) => Ok(color),
                    _ => Err(wrong_result("SetTextColor")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::TextOut {
                dc,
                x,
                y,
                text,
                count,
            }) => {
                let Some(text) = counted_text(count, text, "TextOut")? else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::TextOut {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                    text,
                    code_page: None,
                })? {
                    HostResult::Bool(result) => Ok(u32::from(u16::from(result))),
                    _ => Err(wrong_result("TextOut")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextExtent {
                dc,
                text,
                count,
            }) => {
                let Some(text) = counted_text(count, text, "GetTextExtent")? else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::GetTextExtent { dc, text, code_page: None })? {
                    HostResult::Size { width, height } => Ok(pack_words(width, height)),
                    _ => Err(wrong_result("GetTextExtent")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextAlign { dc }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::GetTextAlign { dc })? {
                    HostResult::Mode(alignment) => Ok(win31_text_align(alignment)),
                    _ => Err(wrong_result("GetTextAlign")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextAlign {
                dc,
                alignment,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                // Windows 3.1 `WINDOWS.H` defines TA_UPDATECP through TA_BASELINE.
                // TA_RTLREADING (256) is a later flag and is not applied.
                match host.win16_gdi(Operation::SetTextAlign {
                    dc,
                    alignment: u32::from(alignment) & WIN31_TEXT_ALIGN,
                })? {
                    HostResult::Mode(previous) => Ok(win31_text_align(previous)),
                    _ => Err(wrong_result("SetTextAlign")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextCharacterExtra {
                dc,
                extra,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetTextCharacterExtra {
                    dc,
                    extra: i32::from(extra),
                })? {
                    HostResult::Mode(previous) => Ok(previous as u16 as u32),
                    _ => Err(wrong_result("SetTextCharacterExtra")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextCharacterExtra {
                dc,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::GetTextCharacterExtra { dc })? {
                    HostResult::Mode(extra) => Ok(extra as u16 as u32),
                    _ => Err(wrong_result("GetTextCharacterExtra")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextJustification {
                dc,
                extra,
                breaks,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetTextJustification {
                    dc,
                    extra: i32::from(extra),
                    breaks: i32::from(breaks),
                })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("SetTextJustification")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextExtentPoint {
                dc,
                text,
                count,
                output,
            }) => {
                let Some(text) = counted_text(count, text, "GetTextExtentPoint")? else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = self.preflight_drawing_output(memory, output, 4)?;
                match host.win16_gdi(Operation::GetTextExtentPoint { dc, text })? {
                    HostResult::BoolSize {
                        success,
                        width,
                        height,
                    } => {
                        if success {
                            self.write_drawing_size(memory, output, width, height)?;
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("GetTextExtentPoint")),
                }
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::ExtTextOut {
                dc,
                x,
                y,
                options,
                rect,
                text,
                count,
                spacing,
            }) => {
                if text.len() != usize::from(count) {
                    return Err(wrong_result("ExtTextOut byte count"));
                }
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let rect = rect.map(rect_to_host);
                let spacing = spacing.map(|values| values.into_iter().map(i32::from).collect());
                match host.win16_gdi(Operation::ExtTextOut {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                    options: u32::from(options),
                    rect,
                    text,
                    spacing,
                    code_page: None,
                })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("ExtTextOut")),
                }
            }
            request => self.drawing_extended(request, memory, host),
        }
    }
}

/// Bits of the Windows 3.1 text-alignment options. `TA_RTLREADING` is 256.
const WIN31_TEXT_ALIGN: u32 = 0x001F;

/// A negative host result is Win32 `GDI_ERROR` (`0xFFFFFFFF`). Truncating it
/// is the Win16 sentinel `0xFFFF`. Zero is a successful `TA_LEFT | TA_TOP`
/// alignment, so a failure must not become zero. A nonnegative result keeps
/// only the alignment bits published by the Windows 3.1 SDK.
fn win31_text_align(value: i32) -> u32 {
    if value < 0 {
        u32::from(value as u16)
    } else {
        (value as u32) & WIN31_TEXT_ALIGN
    }
}

#[cfg(test)]
#[path = "win31_gdi_constant_tests.rs"]
mod win31_gdi_constant_tests;
