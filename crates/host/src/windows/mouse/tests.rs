use super::{map_button_state, MouseMapper};
use windows_sys::Win32::System::Console::{
    FROM_LEFT_1ST_BUTTON_PRESSED, FROM_LEFT_2ND_BUTTON_PRESSED,
    RIGHTMOST_BUTTON_PRESSED,
};

#[test]
fn maps_eighty_by_twenty_five_text_cells_to_640_by_200() {
    let mut mapper = MouseMapper::new();
    let input = mapper.map_cell(79, 24, 0);
    assert_eq!((input.x, input.y), (632, 192));
}

#[test]
fn scales_coordinates_for_the_latest_text_dimensions() {
    let mut mapper = MouseMapper::new();
    mapper.set_text_size(40, 25);
    let input = mapper.map_cell(39, 24, 0);
    assert_eq!((input.x, input.y), (624, 192));
}

#[test]
fn console_buttons_map_to_dos_left_right_middle_bits() {
    assert_eq!(
        map_button_state(
            FROM_LEFT_1ST_BUTTON_PRESSED
                | RIGHTMOST_BUTTON_PRESSED
                | FROM_LEFT_2ND_BUTTON_PRESSED,
        ),
        0b111,
    );
}
