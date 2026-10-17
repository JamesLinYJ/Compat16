//! Pointer-free joystick host contract.
//!
//! Device identifiers and window words stay guest values. Capability names
//! are owned bytes. This boundary does not open a physical joystick.

/// Fixed 32-byte product name from the Windows 3.1 `JOYCAPS.szPname` array.
pub const JOYSTICK_NAME_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostJoystickCaps {
    pub manufacturer: u16,
    pub product: u16,
    pub name: [u8; JOYSTICK_NAME_BYTES],
    pub x_min: u16,
    pub x_max: u16,
    pub y_min: u16,
    pub y_max: u16,
    pub z_min: u16,
    pub z_max: u16,
    pub buttons: u16,
    pub period_min: u16,
    pub period_max: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostJoystickOperation {
    DeviceCount,
    DevCaps {
        device: u16,
    },
    Position {
        device: u16,
    },
    ThresholdGet {
        device: u16,
    },
    ThresholdSet {
        device: u16,
        threshold: u16,
    },
    /// `window` is the guest `HWND`. It is not a host window pointer.
    SetCapture {
        window: u16,
        device: u16,
        period: u16,
        changed: bool,
    },
    ReleaseCapture {
        device: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostJoystickResult {
    Count(u16),
    Caps {
        result: u16,
        caps: Option<Win16HostJoystickCaps>,
    },
    Position {
        result: u16,
        x: u16,
        y: u16,
        z: u16,
        buttons: u16,
    },
    Threshold {
        result: u16,
        value: u16,
    },
    Status(u16),
}
