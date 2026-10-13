use crate::bios::{high_byte, low_byte, set_high_byte, set_low_byte};
use crate::vga::{modes::{mode_info, ModeInfo, ModeKind}, VgaDevice};
use crate::DeviceError;
use guest_core::{GuestMemory, MemoryError, Registers};

#[path = "video_text_memory.rs"]
mod text_memory;
#[path = "video_vbe.rs"]
mod vbe;

/// Maximum dimensions among the supported BIOS text modes. Runtime geometry
/// comes from `mode_info`; these constants remain for existing text clients.
pub const TEXT_COLS: usize = 80;
pub const TEXT_ROWS: usize = 25;
const CELL_COUNT: usize = TEXT_COLS * TEXT_ROWS;
const MAX_TEXT_PAGES: usize = 8;
const MONO_TEXT_MEMORY: u32 = 0xb0000;
const COLOR_TEXT_MEMORY: u32 = 0xb8000;
const COLOR_TEXT_BYTES: u32 = 0x8000;
const MONO_TEXT_BYTES: u32 = 0x8000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextCell {
    pub character: u8,
    pub attribute: u8,
}

impl Default for TextCell {
    fn default() -> Self { Self { character: b' ', attribute: 0x07 } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleSnapshot {
    pub mode: u8,
    pub columns: u8,
    pub rows: u8,
    pub cells: Vec<TextCell>,
    pub cursor_column: u8,
    pub cursor_row: u8,
    pub cursor_shape: u16,
    pub version: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TextCursor {
    column: u8,
    row: u8,
}

/// INT 10h text services backed by the same VGA device that owns guest VGA
/// memory and scanout state. `cells` is only a cache of the visible text page;
/// GuestMemory/VGA state remains authoritative.
#[derive(Clone, Debug)]
pub struct VideoDevice {
    vga: VgaDevice,
    cells: Vec<TextCell>,
    cursors: [TextCursor; MAX_TEXT_PAGES],
    active_page: u8,
    /// Last cursor shape observed in the actual CRTC registers.
    cursor_shape: u16,
    /// Last display start observed in CRTC 0Ch/0Dh.
    last_display_start_cell: usize,
    version: u64,
    suppress_version: bool,
    suppress_crtc_sync: bool,
    cga_background: u8,
    cga_palette: u8,
}

impl Default for VideoDevice {
    fn default() -> Self { Self::new() }
}

impl VideoDevice {
    pub fn new() -> Self {
        let vga = VgaDevice::new();
        let _ = vga.borrow_mut().set_mode(3, true);
        Self::with_vga(vga)
    }

    /// Attach video BIOS services to the machine's already-shared VGA device.
    pub fn with_vga(vga: VgaDevice) -> Self {
        let mode = vga.borrow().bios_mode;
        let info = mode_info(mode).or_else(|| mode_info(3));
        let cell_count = info.map_or(CELL_COUNT, |info| usize::from(info.columns) * usize::from(info.rows));
        let default_shape = info.map_or(0x0607, default_cursor_shape);
        let state = vga.borrow();
        let start_cell = usize::from(crtc_word(&state.crtc, 0x0c));
        let register_shape = u16::from_be_bytes([state.crtc[0x0a], state.crtc[0x0b]]);
        let cursor_shape = if register_shape == 0 { default_shape } else { register_shape };
        drop(state);
        Self {
            vga,
            cells: vec![TextCell::default(); cell_count],
            cursors: [TextCursor::default(); MAX_TEXT_PAGES],
            active_page: 0,
            cursor_shape,
            last_display_start_cell: start_cell,
            version: 0,
            suppress_version: false,
            suppress_crtc_sync: false,
            cga_background: 0,
            cga_palette: 0,
        }
    }

    pub fn vga(&self) -> &VgaDevice { &self.vga }
    pub fn mode(&self) -> u8 { self.vga.borrow().bios_mode }
    pub fn version(&self) -> u64 { self.version }
    pub fn active_page(&self) -> u8 { self.active_page }
    pub fn cursor(&self) -> (u8, u8) {
        if self.is_text() && !self.suppress_crtc_sync {
            let state = self.vga.borrow();
            let start = crtc_word(&state.crtc, 0x0c);
            let cursor = crtc_word(&state.crtc, 0x0e);
            let cell = usize::from(cursor.wrapping_sub(start));
            let (columns, rows) = self.dimensions();
            if cell < columns.saturating_mul(rows) {
                return ((cell % columns) as u8, (cell / columns) as u8);
            }
        }
        let cursor = self.cursors[usize::from(self.active_page)];
        (cursor.column, cursor.row)
    }
    pub fn cursor_for_page(&self, page: u8) -> Option<(u8, u8)> {
        let page_index = usize::from(page);
        if page_index >= self.page_count() { return None; }
        if self.is_text() && self.visible_page() == page_index {
            let start = self.crtc_start_cell();
            let cursor = self.crtc_cursor_cell();
            let cell = cursor.wrapping_sub(start);
            let (columns, rows) = self.dimensions();
            if cell < columns.saturating_mul(rows) {
                return Some(((cell % columns) as u8, (cell / columns) as u8));
            }
        }
        let cursor = self.cursors[page_index];
        Some((cursor.column, cursor.row))
    }
    pub fn display_start_bytes(&self) -> usize { self.display_start_cell_wrapped().saturating_mul(2) }
    pub fn cursor_shape(&self) -> u16 {
        let state = self.vga.borrow();
        u16::from_be_bytes([state.crtc[0x0a], state.crtc[0x0b]])
    }
    pub fn is_text(&self) -> bool {
        self.vga.borrow().svga.is_none()
            && mode_info(self.mode()).is_some_and(|info| info.kind == ModeKind::Text)
    }

    pub fn text_layout(&self) -> (u32, usize, usize, usize) {
        let info = self.current_info();
        let base = self.text_base();
        (
            base,
            usize::from(info.columns),
            usize::from(info.rows),
            usize::try_from(info.page_bytes).unwrap_or(0),
        )
    }

    pub fn char_height(&self) -> u8 { self.current_info().char_height }
    pub fn crtc_base(&self) -> u16 {
        if self.vga.borrow().misc_output & 0x01 == 0 { 0x03b4 } else { 0x03d4 }
    }

    pub fn snapshot(&self) -> ConsoleSnapshot {
        let info = self.current_info();
        let is_text = info.kind == ModeKind::Text;
        let cells = if is_text { self.cells.clone() } else { Vec::new() };
        let (cursor_column, cursor_row) = if is_text { self.cursor() } else { (0, 0) };
        ConsoleSnapshot {
            mode: self.mode(),
            columns: if is_text { info.columns.min(u16::from(u8::MAX)) as u8 } else { 0 },
            rows: if is_text { info.rows.min(u16::from(u8::MAX)) as u8 } else { 0 },
            cells,
            cursor_column,
            cursor_row,
            cursor_shape: self.cursor_shape(),
            version: self.version,
        }
    }

    pub(super) fn dispatch_int10(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DeviceError> {
        let function = u16::from(regs.ah());
        match function {
            0x00 => {
                let requested = regs.al();
                let clear = requested & 0x80 == 0;
                let mode = requested & 0x7f;
                if !self.set_mode(mode, clear) {
                    // INT 10h mode selection is a probeable BIOS service.
                    // Leave the current mode and VRAM unchanged when the
                    // requested mode is unavailable, then IRET.
                    return Ok(());
                }
                if clear && self.is_text() {
                    self.sync_to_guest(memory)?;
                } else if self.is_text() {
                    self.refresh_from_guest(memory)?;
                }
            }
            0x01 => self.set_cursor_shape(high_byte(regs.ecx), low_byte(regs.ecx)),
            0x02 => {
                let page = high_byte(regs.ebx);
                if !self.page_valid(page) { return Ok(()); }
                self.with_page(page, memory, function, |video| {
                    video.set_cursor(low_byte(regs.edx), high_byte(regs.edx));
                })?;
            }
            0x03 => {
                let page = high_byte(regs.ebx);
                if !self.page_valid(page) { return Ok(()); }
                let cursor = self.cursors[usize::from(page)];
                set_high_byte(&mut regs.edx, cursor.row);
                set_low_byte(&mut regs.edx, cursor.column);
                regs.set_cx(self.cursor_shape());
            }
            0x05 => {
                if self.page_valid(regs.al()) { self.set_active_page(regs.al(), memory)?; }
            }
            0x06 | 0x07 => {
                self.ensure_text(function)?;
                let old_cells = self.cells.clone();
                self.scroll(
                    high_byte(regs.ecx),
                    low_byte(regs.ecx),
                    high_byte(regs.edx),
                    low_byte(regs.edx),
                    regs.al(),
                    high_byte(regs.ebx),
                    function == 0x07,
                );
                if self.cells != old_cells { self.sync_to_guest(memory)?; }
            }
            0x08 => {
                let page = high_byte(regs.ebx);
                if !self.page_valid(page) { return Ok(()); }
                self.with_page(page, memory, function, |video| {
                    let cell = video.cell_at_cursor();
                    regs.set_al(cell.character);
                    regs.set_ah(cell.attribute);
                })?;
            }
            0x09 | 0x0a => {
                let page = high_byte(regs.ebx);
                if !self.page_valid(page) { return Ok(()); }
                self.with_page(page, memory, function, |video| {
                    let (column, row) = video.cursor();
                    let attribute = if function == 0x09 { Some(low_byte(regs.ebx)) } else { None };
                    video.write_repeated(column, row, regs.al(), attribute, regs.cx());
                })?;
            }
            0x0c => {
                let (width, height) = {
                    let state = self.vga.borrow();
                    mode_info(state.bios_mode).map(|info| (info.width, info.height)).unwrap_or((0, 0))
                };
                if regs.cx() < width && regs.dx() < height {
                    let _ = self.vga.borrow_mut().write_pixel(regs.cx(), regs.dx(), high_byte(regs.ebx), regs.al());
                }
            }
            0x0d => {
                let (width, height) = {
                    let state = self.vga.borrow();
                    mode_info(state.bios_mode).map(|info| (info.width, info.height)).unwrap_or((0, 0))
                };
                let color = if regs.cx() < width && regs.dx() < height {
                    self.vga.borrow_mut().read_pixel(regs.cx(), regs.dx(), high_byte(regs.ebx)).unwrap_or(0)
                } else {
                    0
                };
                regs.set_al(color);
            }
            0x0b => {
                if high_byte(regs.ebx) == 0 {
                    self.cga_background = low_byte(regs.ebx) & 0x1f;
                } else {
                    self.cga_palette = low_byte(regs.ebx) & 0x01;
                }
            }
            0x0e => {
                self.ensure_text(function)?;
                let old_cells = self.cells.clone();
                self.teletype(regs.al(), low_byte(regs.ebx));
                if self.cells != old_cells { self.sync_to_guest(memory)?; }
            }
            0x0f => {
                let info = self.current_info();
                regs.set_al(self.mode());
                regs.set_ah(info.columns.min(u16::from(u8::MAX)) as u8);
                set_high_byte(&mut regs.ebx, self.active_page);
            }
            0x13 => {
                let page = high_byte(regs.ebx);
                if !self.page_valid(page) { return Ok(()); }
                let count = usize::from(regs.cx());
                let bytes_per_char = if regs.al() & 0x02 != 0 { 2 } else { 1 };
                let length = count.checked_mul(bytes_per_char).ok_or(DeviceError::InvalidRequest {
                    interrupt: 0x10,
                    function,
                    detail: "string length overflow",
                })?;
                let address = guest_core::real_address(regs.es, regs.bp());
                let mut bytes = vec![0; length];
                memory.read(address, &mut bytes)?;
                let update_cursor = regs.al() & 0x01 != 0;
                let default_attribute = low_byte(regs.ebx);
                let start_column = low_byte(regs.edx);
                let start_row = high_byte(regs.edx);
                self.with_page(page, memory, function, |video| {
                    let old_cursor = video.cursor();
                    let (columns, rows) = video.dimensions();
                    if usize::from(start_column) >= columns || usize::from(start_row) >= rows { return; }
                    let (mut column, mut row) = (usize::from(start_column), usize::from(start_row));
                    for pair in bytes.chunks_exact(bytes_per_char) {
                        let attribute = if bytes_per_char == 2 { pair[1] } else { default_attribute };
                        video.put_cell(column, row, pair[0], attribute);
                        column += 1;
                        if column >= columns {
                            column = 0;
                            if row + 1 < rows {
                                row += 1;
                            } else {
                                video.scroll(0, 0, (rows - 1) as u8, (columns - 1) as u8, 1, attribute, false);
                            }
                        }
                    }
                    if update_cursor {
                        video.set_cursor(column as u8, row as u8);
                    } else {
                        video.set_cursor(old_cursor.0, old_cursor.1);
                    }
                })?;
            }
            // Unimplemented INT 10h extensions are optional BIOS capabilities.
            // A real-mode caller can probe them without making the whole guest
            // fail; preserve all registers and leave the machine state alone.
            _ => {}
        }
        Ok(())
    }

    /// Reset the existing shared VGA object to the BIOS startup mode. This
    /// deliberately does not replace the device handle wired to guest RAM.
    pub fn reset_text_mode(&mut self) {
        let _ = self.vga.borrow_mut().set_mode(3, true);
        self.active_page = 0;
        self.cursors = [TextCursor::default(); MAX_TEXT_PAGES];
        self.cursor_shape = self.cursor_shape();
        self.last_display_start_cell = self.crtc_start_cell();
        self.rebuild_cache();
        self.bump_version();
    }

    pub fn set_cursor_shape(&mut self, start: u8, end: u8) {
        let mut state = self.vga.borrow_mut();
        // CH bit 5 disables the hardware cursor; pass it through while keeping
        // the CRTC's reserved high bits and replacing the low five scan lines.
        let new_start = (state.crtc[0x0a] & 0xc0) | (start & 0x3f);
        let new_end = (state.crtc[0x0b] & 0xe0) | (end & 0x1f);
        if state.crtc[0x0a] != new_start || state.crtc[0x0b] != new_end {
            state.crtc[0x0a] = new_start;
            state.crtc[0x0b] = new_end;
            state.mark_changed();
            drop(state);
            self.cursor_shape = u16::from_be_bytes([new_start, new_end]);
            self.bump_version();
        } else {
            drop(state);
        }
    }

    pub fn set_cursor(&mut self, column: u8, row: u8) {
        let (columns, rows) = self.dimensions();
        let column = column.min(columns.saturating_sub(1) as u8);
        let row = row.min(rows.saturating_sub(1) as u8);
        let changed = {
            let cursor = &mut self.cursors[usize::from(self.active_page)];
            if cursor.column != column || cursor.row != row {
                cursor.column = column;
                cursor.row = row;
                true
            } else {
                false
            }
        };
        if changed {
            self.update_crtc_cursor();
            self.bump_version();
        }
    }

    pub fn cell_at_cursor(&self) -> TextCell {
        let (column, row) = self.cursor();
        let columns = self.dimensions().0;
        self.cells.get(usize::from(row) * columns + usize::from(column)).copied().unwrap_or_default()
    }

    pub fn write_repeated(&mut self, column: u8, row: u8, character: u8, attribute: Option<u8>, count: u16) {
        let (columns, rows) = self.dimensions();
        let start = usize::from(row.min(rows.saturating_sub(1) as u8)) * columns
            + usize::from(column.min(columns.saturating_sub(1) as u8));
        let changed = write_repeated_cells(&mut self.cells, start, character, attribute, usize::from(count));
        if changed { self.bump_version(); }
    }

    pub fn put_cell(&mut self, column: usize, row: usize, character: u8, attribute: u8) {
        let (columns, rows) = self.dimensions();
        if column >= columns || row >= rows { return; }
        let cell = &mut self.cells[row * columns + column];
        if cell.character != character || cell.attribute != attribute {
            *cell = TextCell { character, attribute };
            self.bump_version();
        }
    }

    /// BIOS scroll/clear rectangle, inclusive at all four edges. Coordinates
    /// outside the active mode's text geometry are clipped as BIOS does.
    pub fn scroll(&mut self, top: u8, left: u8, bottom: u8, right: u8, lines: u8, attribute: u8, down: bool) {
        let (columns, rows) = self.dimensions();
        let changed = scroll_cells(
            &mut self.cells,
            columns,
            rows,
            top,
            left,
            bottom,
            right,
            lines,
            attribute,
            down,
        );
        if changed { self.bump_version(); }
    }

    /// BIOS teletype output uses the active text attribute (initially 07h).
    pub fn teletype(&mut self, character: u8, _bl: u8) {
        let (columns, rows) = self.dimensions();
        let cursor = self.cursors[usize::from(self.active_page)];
        match character {
            b'\r' => self.set_cursor(0, cursor.row),
            b'\n' => self.advance_line(),
            0x08 => {
                if cursor.column > 0 { self.set_cursor(cursor.column - 1, cursor.row); }
            }
            0x07 => {} // No emulated speaker; BEL has no display effect.
            _ => {
                let index = usize::from(cursor.row) * columns + usize::from(cursor.column);
                if let Some(cell) = self.cells.get_mut(index) {
                    if cell.character != character || cell.attribute != 0x07 {
                        *cell = TextCell { character, attribute: 0x07 };
                        self.bump_version();
                    }
                }
                let next_column = usize::from(cursor.column) + 1;
                if next_column >= columns {
                    self.set_cursor(0, cursor.row);
                    self.advance_line();
                } else {
                    self.set_cursor(next_column as u8, cursor.row);
                }
            }
        }
        let _ = rows;
    }

    pub fn sync_to_guest(&self, memory: &mut impl GuestMemory) -> Result<(), MemoryError> {
        if !self.is_text() { return Ok(()); }
        let (base, offset, _, _, _) = self.active_page_address();
        let mut bytes = Vec::with_capacity(self.cells.len() * 2);
        for cell in &self.cells {
            bytes.push(cell.character);
            bytes.push(cell.attribute);
        }
        text_memory::write_wrapped(memory, base, offset, &bytes)
    }

    pub fn refresh_from_guest(&mut self, memory: &impl GuestMemory) -> Result<(), MemoryError> {
        if !self.is_text() { return Ok(()); }
        self.ensure_cache_geometry();
        if !self.suppress_crtc_sync { self.synchronize_page_and_cursor_from_crtc(); }
        let (base, offset, columns, rows, _) = self.active_page_address();
        let mut bytes = vec![0; columns * rows * 2];
        text_memory::read_wrapped(memory, base, offset, &mut bytes)?;
        let mut changed = false;
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let cell = TextCell { character: pair[0], attribute: pair[1] };
            if self.cells[index] != cell {
                self.cells[index] = cell;
                changed = true;
            }
        }
        if changed { self.bump_version(); }
        Ok(())
    }

    fn set_mode(&mut self, mode: u8, clear: bool) -> bool {
        if mode_info(mode).is_none() { return false; }
        if !self.vga.borrow_mut().set_mode(mode, clear) { return false; }
        self.active_page = 0;
        self.cursors = [TextCursor::default(); MAX_TEXT_PAGES];
        self.cursor_shape = self.cursor_shape();
        self.last_display_start_cell = self.crtc_start_cell();
        self.rebuild_cache();
        self.bump_version();
        true
    }

    fn set_active_page(&mut self, page: u8, memory: &impl GuestMemory) -> Result<(), DeviceError> {
        if !self.page_valid(page) { return Ok(()); }
        let changed = self.active_page != page;
        self.active_page = page;
        self.update_crtc_start_for_page(page);
        if changed {
            self.refresh_from_guest(memory)?;
            self.bump_version();
        } else {
            self.refresh_from_guest(memory)?;
        }
        Ok(())
    }

    fn page_valid(&self, page: u8) -> bool { usize::from(page) < self.page_count() }

    fn ensure_text(&self, function: u16) -> Result<(), DeviceError> {
        if self.is_text() { Ok(()) } else {
            Err(DeviceError::InvalidRequest { interrupt: 0x10, function, detail: "service requires a text video mode" })
        }
    }

    fn with_page<T>(
        &mut self,
        page: u8,
        memory: &mut impl GuestMemory,
        function: u16,
        operation: impl FnOnce(&mut Self) -> T,
    ) -> Result<T, DeviceError> {
        self.ensure_text(function)?;
        if !self.page_valid(page) {
            return Err(DeviceError::InvalidRequest {
                interrupt: 0x10,
                function,
                detail: "internal text-page selection is outside video memory",
            });
        }
        if page == self.active_page {
            self.refresh_from_guest(memory)?;
            let old_cells = self.cells.clone();
            let result = operation(self);
            if self.cells != old_cells { self.sync_to_guest(memory)?; }
            return Ok(result);
        }

        let original_page = self.active_page;
        let cell_count = self.screen_cell_count();
        let original_cells = std::mem::replace(&mut self.cells, vec![TextCell::default(); cell_count]);
        let original_suppression = self.suppress_version;
        let original_crtc_suppression = self.suppress_crtc_sync;
        self.active_page = page;
        self.suppress_version = true;
        self.suppress_crtc_sync = true;
        let result = (|| {
            self.refresh_from_guest(memory)?;
            let old_cells = self.cells.clone();
            let result = operation(self);
            if self.cells != old_cells { self.sync_to_guest(memory)?; }
            Ok::<T, MemoryError>(result)
        })();
        self.active_page = original_page;
        self.cells = original_cells;
        self.suppress_version = original_suppression;
        self.suppress_crtc_sync = original_crtc_suppression;
        result.map_err(DeviceError::from)
    }

    fn active_page_address(&self) -> (u32, usize, usize, usize, usize) {
        let (base, columns, rows, page_bytes) = self.text_layout();
        let offset = if self.suppress_crtc_sync {
            usize::from(self.active_page).saturating_mul(page_bytes)
        } else {
            self.display_start_cell_wrapped().saturating_mul(2)
        };
        (base, offset, columns, rows, page_bytes)
    }

    fn page_count(&self) -> usize {
        let info = self.current_info();
        if info.kind != ModeKind::Text { return 0; }
        let (_, _, _, page_bytes) = self.text_layout();
        if page_bytes == 0 { return 1; }
        let available = (if self.mode() == 7 { MONO_TEXT_BYTES } else { COLOR_TEXT_BYTES }) as usize;
        (available / page_bytes).clamp(1, MAX_TEXT_PAGES)
    }

    fn dimensions(&self) -> (usize, usize) {
        let info = self.current_info();
        (usize::from(info.columns.max(1)), usize::from(info.rows.max(1)))
    }

    fn screen_cell_count(&self) -> usize {
        let (columns, rows) = self.dimensions();
        columns.saturating_mul(rows)
    }

    fn text_base(&self) -> u32 { if self.mode() == 7 { MONO_TEXT_MEMORY } else { COLOR_TEXT_MEMORY } }

    fn page_cells(&self) -> usize { self.text_layout().3 / 2 }

    fn crtc_start_cell(&self) -> usize {
        usize::from(crtc_word(&self.vga.borrow().crtc, 0x0c))
    }

    fn crtc_cursor_cell(&self) -> usize {
        usize::from(crtc_word(&self.vga.borrow().crtc, 0x0e))
    }

    fn visible_page(&self) -> usize {
        let page_cells = self.page_cells();
        if page_cells == 0 { 0 } else { self.display_start_cell_wrapped() / page_cells }
    }

    fn display_start_cell_wrapped(&self) -> usize {
        let text_memory_bytes = (if self.mode() == 7 { MONO_TEXT_BYTES } else { COLOR_TEXT_BYTES }) as usize;
        let addressable_cells = (text_memory_bytes / 2).max(1);
        self.crtc_start_cell() % addressable_cells
    }

    fn synchronize_page_and_cursor_from_crtc(&mut self) {
        let start = self.crtc_start_cell();
        if self.last_display_start_cell != start {
            self.last_display_start_cell = start;
            self.bump_version();
        }
        let shape = self.cursor_shape();
        if self.cursor_shape != shape {
            self.cursor_shape = shape;
            self.bump_version();
        }
        let page = self.visible_page();
        if page >= self.page_count() { return; }
        let page = page as u8;
        if self.active_page != page {
            self.active_page = page;
            self.bump_version();
        }
        let cursor = self.crtc_cursor_cell();
        let cell = cursor.wrapping_sub(start);
        let (columns, rows) = self.dimensions();
        if cell < columns.saturating_mul(rows) {
            let new_cursor = TextCursor { column: (cell % columns) as u8, row: (cell / columns) as u8 };
            let slot = &mut self.cursors[usize::from(page)];
            if *slot != new_cursor {
                *slot = new_cursor;
                self.bump_version();
            }
        }
    }

    fn update_crtc_start_for_page(&self, page: u8) {
        let page_start = usize::from(page).saturating_mul(self.page_cells());
        let _ = self.write_crtc_word(0x0c, page_start);
        let cursor = self.cursors[usize::from(page)];
        let (columns, _) = self.dimensions();
        let position = page_start
            .saturating_add(usize::from(cursor.row).saturating_mul(columns))
            .saturating_add(usize::from(cursor.column));
        let _ = self.write_crtc_word(0x0e, position);
    }

    fn update_crtc_cursor(&self) {
        if self.visible_page() != usize::from(self.active_page) { return; }
        let page_start = self.crtc_start_cell();
        let cursor = self.cursors[usize::from(self.active_page)];
        let (columns, _) = self.dimensions();
        let position = page_start
            .saturating_add(usize::from(cursor.row).saturating_mul(columns))
            .saturating_add(usize::from(cursor.column));
        let _ = self.write_crtc_word(0x0e, position);
    }

    fn write_crtc_word(&self, index: usize, value: usize) -> (u8, u8, bool) {
        let value = value.min(usize::from(u16::MAX)) as u16;
        let high = (value >> 8) as u8;
        let low = value as u8;
        let mut state = self.vga.borrow_mut();
        let changed = state.crtc[index] != high || state.crtc[index + 1] != low;
        if changed {
            state.crtc[index] = high;
            state.crtc[index + 1] = low;
            state.mark_changed();
        }
        (high, low, changed)
    }

    fn rebuild_cache(&mut self) {
        let count = if self.is_text() { self.screen_cell_count() } else { 0 };
        self.cells.resize(count, TextCell::default());
        self.cells.fill(TextCell::default());
    }

    fn ensure_cache_geometry(&mut self) {
        let count = self.screen_cell_count();
        if self.cells.len() != count {
            self.cells.resize(count, TextCell::default());
            self.cells.fill(TextCell::default());
        }
    }

    fn advance_line(&mut self) {
        let (columns, rows) = self.dimensions();
        let cursor = self.cursors[usize::from(self.active_page)];
        if usize::from(cursor.row) + 1 < rows {
            self.set_cursor(cursor.column, cursor.row + 1);
        } else {
            self.scroll(0, 0, (rows - 1) as u8, (columns - 1) as u8, 1, 0x07, false);
            self.set_cursor(cursor.column, (rows - 1) as u8);
        }
    }

    fn bump_version(&mut self) {
        if !self.suppress_version {
            self.version = self.version.wrapping_add(1);
        }
    }
}

fn default_cursor_shape(info: ModeInfo) -> u16 {
    let end = info.char_height.saturating_sub(1);
    let start = end.saturating_sub(1);
    u16::from_be_bytes([start, end])
}

fn crtc_word(registers: &[u8; 25], index: usize) -> u16 {
    u16::from_be_bytes([registers[index], registers[index + 1]])
}

fn write_repeated_cells(cells: &mut [TextCell], start: usize, character: u8, attribute: Option<u8>, count: usize) -> bool {
    let mut changed = false;
    for cell in cells.iter_mut().skip(start).take(count) {
        if cell.character != character || attribute.is_some_and(|value| value != cell.attribute) {
            cell.character = character;
            if let Some(value) = attribute { cell.attribute = value; }
            changed = true;
        }
    }
    changed
}

fn scroll_cells(
    cells: &mut Vec<TextCell>,
    columns: usize,
    rows: usize,
    top: u8,
    left: u8,
    bottom: u8,
    right: u8,
    lines: u8,
    attribute: u8,
    down: bool,
) -> bool {
    let (top, left) = (usize::from(top), usize::from(left));
    if rows == 0 || columns == 0 || top >= rows || left >= columns { return false; }
    let bottom = usize::from(bottom).min(rows - 1);
    let right = usize::from(right).min(columns - 1);
    if top > bottom || left > right { return false; }
    let height = bottom - top + 1;
    let shift = if lines == 0 { height } else { usize::from(lines).min(height) };
    let fill = TextCell { character: b' ', attribute };
    let mut next = cells.clone();
    for row in top..=bottom {
        for column in left..=right {
            let source_row = if down {
                row.checked_sub(shift).filter(|source| *source >= top)
            } else {
                row.checked_add(shift).filter(|source| *source <= bottom)
            };
            let destination = row * columns + column;
            next[destination] = source_row.map(|source| cells[source * columns + column]).unwrap_or(fill);
        }
    }
    if *cells != next {
        *cells = next;
        true
    } else {
        false
    }
}

#[cfg(test)]
#[path = "video_text_tests.rs"]
mod text_tests;
