//! Console-cell to DOS mouse coordinates for text-mode sessions.

use devices::mouse::MouseInput;
use windows_sys::Win32::System::Console::{
    FROM_LEFT_1ST_BUTTON_PRESSED, FROM_LEFT_2ND_BUTTON_PRESSED,
    RIGHTMOST_BUTTON_PRESSED,
};

const LOGICAL_WIDTH: i32 = 640;
const LOGICAL_HEIGHT: i32 = 200;

/// Maps console screen-buffer cells to the DOS text-mode mouse space.
///
/// The mapping stays absolute: DOS INT 33h function 04h changes the guest
/// cursor position, but does not move the Windows pointer or change the origin
/// of subsequent console mouse events.
#[derive(Debug)]
pub(super) struct MouseMapper {
    columns: u16,
    rows: u16,
}

impl MouseMapper {
    pub(super) const fn new() -> Self {
        Self {
            columns: 80,
            rows: 25,
        }
    }

    pub(super) fn set_text_size(&mut self, columns: u16, rows: u16) {
        if columns != 0 && rows != 0 {
            self.columns = columns;
            self.rows = rows;
        }
    }

    pub(super) fn map_cell(&mut self, column: i16, row: i16, buttons: u16) -> MouseInput {
        let cell_x = i32::from(column).clamp(0, i32::from(self.columns) - 1);
        let cell_y = i32::from(row).clamp(0, i32::from(self.rows) - 1);
        let (x, y) = self.logical_position(cell_x, cell_y);
        MouseInput { x, y, buttons }
    }

    fn logical_position(&self, cell_x: i32, cell_y: i32) -> (i32, i32) {
        (
            cell_x * LOGICAL_WIDTH / i32::from(self.columns),
            cell_y * LOGICAL_HEIGHT / i32::from(self.rows),
        )
    }
}

pub(super) fn map_button_state(console_state: u32) -> u16 {
    let mut buttons = 0;
    if console_state & FROM_LEFT_1ST_BUTTON_PRESSED != 0 {
        buttons |= 1;
    }
    if console_state & RIGHTMOST_BUTTON_PRESSED != 0 {
        buttons |= 2;
    }
    if console_state & FROM_LEFT_2ND_BUTTON_PRESSED != 0 {
        buttons |= 4;
    }
    buttons
}

#[cfg(test)]
mod tests;
