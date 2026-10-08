//! VBE mode transitions share the VGA framebuffer and the BIOS text cache.

use super::*;
use crate::bios::BDA_BASE;
use guest_core::PhysAddr;

impl VideoDevice {
    pub(crate) fn dispatch_vbe(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DeviceError> {
        let function = regs.al();
        let requested = regs.bx();
        let restore = function == 4 && regs.dl() == 2;
        let restore_bios = restore && regs.cx() & 2 != 0;

        // VBE mode setting also accepts standard VGA mode numbers. Use the
        // ordinary BIOS transition so text pages and cursor caches stay valid.
        if function == 2 && requested & 0x3fff < 0x100 {
            if requested & 0x4000 != 0 || !self.set_mode(requested as u8, requested & 0x8000 == 0) {
                regs.set_ax(0x014f);
                return Ok(());
            }
            if self.is_text() {
                if requested & 0x8000 == 0 { self.sync_to_guest(memory)?; }
                else { self.refresh_from_guest(memory)?; }
            }
            regs.set_ax(0x004f);
            return Ok(());
        }

        crate::vga::vbe::dispatch(&self.vga, regs, memory)?;
        if regs.ax() != 0x004f { return Ok(()); }
        if function == 2 {
            self.active_page = 0;
            self.cursors = [TextCursor::default(); MAX_TEXT_PAGES];
            self.rebuild_cache();
            self.bump_version();
        } else if restore {
            if restore_bios {
                let page = memory.read_u8(PhysAddr(BDA_BASE + 0x62))?;
                self.active_page = if usize::from(page) < MAX_TEXT_PAGES { page } else { 0 };
                for (page, cursor) in self.cursors.iter_mut().enumerate() {
                    let address = BDA_BASE + 0x50 + page as u32 * 2;
                    cursor.column = memory.read_u8(PhysAddr(address))?;
                    cursor.row = memory.read_u8(PhysAddr(address + 1))?;
                }
            }
            self.cursor_shape = self.cursor_shape();
            self.last_display_start_cell = self.crtc_start_cell();
            self.rebuild_cache();
            self.refresh_from_guest(memory)?;
            self.bump_version();
        }
        Ok(())
    }

    pub(super) fn current_info(&self) -> ModeInfo {
        let state = self.vga.borrow();
        if let Some(svga) = &state.svga {
            if let Some(mode) = crate::vga::svga::mode_info(svga.mode) {
                return ModeInfo {
                    mode: 0xff,
                    width: mode.width,
                    height: mode.height,
                    columns: mode.width / 8,
                    rows: mode.height / 16,
                    char_height: 16,
                    kind: ModeKind::Chain4,
                    // Legacy BDA page size has no representation for these
                    // framebuffers. VBE mode information owns their sizes.
                    page_bytes: 0,
                };
            }
        }
        mode_info(state.bios_mode).or_else(|| mode_info(3)).unwrap_or(ModeInfo {
            mode: 3, width: 720, height: 400,
            columns: TEXT_COLS as u16, rows: TEXT_ROWS as u16,
            char_height: 16, kind: ModeKind::Text, page_bytes: 0x1000,
        })
    }
}
