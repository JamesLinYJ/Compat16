//! Synthesized USER keyboard and mouse input.
//!
//! `extra_info` is the guest DWORD carried in SI:DI. It is never a host
//! pointer and is never dereferenced.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16UserInputRequest {
    /// USER.289. `flags` contains only `KEYEVENTF_KEYUP` and
    /// `KEYEVENTF_EXTENDEDKEY` promoted from the register image.
    KeybdEvent {
        virtual_key: u8,
        scan: u8,
        flags: u32,
        extra_info: u32,
    },
    /// USER.299. `flags` is the low half of AX. `dx` and `dy` are absolute
    /// when bit 0x8000 is set and signed relative deltas otherwise. `buttons`
    /// is the low half of DX, the 3.1 button-count word.
    MouseEvent {
        flags: u16,
        dx: i32,
        dy: i32,
        buttons: u16,
        extra_info: u32,
    },
}
