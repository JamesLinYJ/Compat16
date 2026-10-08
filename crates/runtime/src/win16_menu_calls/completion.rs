//! Menu request submission and completion projection.

use super::*;

impl Win16State {
    pub(super) fn menu_immediate(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
        value: u32,
        kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(
            registers,
            return_to.0,
            return_to.1,
            return_to.2,
            value,
            kind,
        )
    }

    pub(super) fn submit_menu_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        operation: Win16MenuOperation,
        kind: MenuCallKind,
        return_kind: Win16ReturnKind,
        output: Option<super::super::guest_ranges::GuestOutputRange>,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::Menu(operation),
            WindowReturn::Menu(MenuCall {
                kind,
                return_kind,
                output,
            }),
            return_to,
        )
    }

    pub(super) fn prepare_menu_item(
        &self,
        item_id: u16,
        new_item: u32,
        item_flags: u16,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16MenuItem>, RuntimeError> {
        let identity = if item_flags & flags::MF_POPUP != 0 {
            let Some(menu) = self.guest_menus.resolve(item_id) else {
                return Ok(None);
            };
            Win16MenuItemIdentity::Submenu(menu)
        } else {
            Win16MenuItemIdentity::Command(item_id)
        };
        let content = if item_flags & flags::MF_SEPARATOR != 0 {
            Win16MenuItemContent::Separator
        } else if item_flags & flags::MF_BITMAP != 0 {
            let bitmap = new_item as u16;
            let object = if bitmap == 0 {
                None
            } else {
                let Some(object) = self.guest_gdi.object(bitmap) else {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "MF_BITMAP menu item has no mapped guest HBITMAP",
                    ));
                    return Ok(None);
                };
                Some(object)
            };
            Win16MenuItemContent::Bitmap(object)
        } else if item_flags & flags::MF_OWNERDRAW != 0 {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "owner-draw menu items require Win16 WM_MEASUREITEM and WM_DRAWITEM conversion",
            ));
            return Ok(None);
        } else {
            let text = if new_item == 0 {
                None
            } else {
                Some(
                    win16_abi::strings::read_ansi_z(
                        &self.selectors,
                        memory,
                        new_item,
                        MAX_WIN16_STRING_BYTES,
                    )
                    .map_err(crate::runtime_error)?,
                )
            };
            Win16MenuItemContent::Text(text)
        };
        Ok(Some(Win16MenuItem { identity, content }))
    }

    pub(super) fn menu_bitmap(
        &self,
        guest: u16,
        host: &mut impl RuntimeHost,
    ) -> Option<Option<crate::Win16HostGdiObject>> {
        if guest == 0 {
            return Some(None);
        }
        match self.guest_gdi.object(guest) {
            Some(bitmap) => Some(Some(bitmap)),
            None => {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "menu bitmap handle has no mapped guest HBITMAP",
                ));
                None
            }
        }
    }

    pub(super) fn read_menu_rect(
        &self,
        far: u32,
        memory: &Memory,
    ) -> Result<Option<Win16HostRect>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        const RECT16_BYTES: usize = 8;
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, RECT16_BYTES)?;
        let word = |offset: usize| i16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        Ok(Some(Win16HostRect {
            left: i32::from(word(0)),
            top: i32::from(word(2)),
            right: i32::from(word(4)),
            bottom: i32::from(word(6)),
        }))
    }

}
