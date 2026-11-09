//! Guest bytes for virtual-key codes Appendix B leaves undefined.
//!
//! `SetKeyboardState` copies one system keyboard-state table. Bytes Win32
//! later assigned stay in this table so the host key is neither published
//! nor cleared. `GetKeyboardState` and `GetKeyState` read those bytes back.
//! `GetAsyncKeyState` does not: it reports the key at the call, and Appendix
//! B gives these codes no key.

use std::cell::RefCell;

thread_local! {
    static GUEST_KEYBOARD_SLOTS: RefCell<[u8; 256]> = RefCell::new([0; 256]);
}

pub(super) fn overlay_guest_slots(keys: &mut [u8; 256]) {
    GUEST_KEYBOARD_SLOTS.with(|slots| {
        runtime::overlay_win31_keyboard_slots(keys, &slots.borrow());
    });
}

/// Host table for `SetKeyboardState`: Windows 3.1 virtual keys come from the
/// guest, and every other byte keeps the current host key.
pub(super) fn host_keys_for_set(host: &[u8; 256], guest: &[u8; 256]) -> [u8; 256] {
    runtime::merge_win31_keyboard_state(host, guest)
}

pub(super) fn remember_guest_slots(guest: &[u8; 256]) {
    GUEST_KEYBOARD_SLOTS.with(|slots| {
        let mut saved = slots.borrow_mut();
        for index in 0..=u8::MAX {
            if !runtime::win31_virtual_key(i32::from(index)) {
                let slot = usize::from(index);
                saved[slot] = guest[slot];
            }
        }
    });
}

/// `GetKeyState` for a code that is not a Windows 3.1 virtual key.
pub(super) fn guest_key_state(key: i32) -> i16 {
    let Ok(index) = u8::try_from(key) else {
        return 0;
    };
    GUEST_KEYBOARD_SLOTS
        .with(|slots| runtime::win31_key_state_word(slots.borrow()[usize::from(index)]))
}

#[cfg(test)]
mod tests {
    use super::{guest_key_state, overlay_guest_slots, remember_guest_slots};

    #[test]
    fn remembered_unassigned_slot_round_trips_without_replacing_a_win31_key() {
        let mut clear = [0_u8; 256];
        remember_guest_slots(&clear);
        clear[0x5B] = 0x81;
        clear[0x10] = 0x80;
        remember_guest_slots(&clear);
        let mut published = [0x7F_u8; 256];
        overlay_guest_slots(&mut published);
        assert_eq!(published[0x5B], 0x81);
        assert_eq!(published[0x10], 0x7F);
        assert_eq!(guest_key_state(0x5B), -32767);
        assert_eq!(guest_key_state(0x10), 0);
        assert_eq!(guest_key_state(-1), 0);
        assert_eq!(guest_key_state(256), 0);
    }
}
