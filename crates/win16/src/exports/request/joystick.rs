//! Windows 3.1 joystick records. `UINT` is a 16-bit word.
//!
//! `JOYCAPS` and `JOYINFO` follow the 3.1 `MMSYSTEM.H` layout. `JOYINFOEX` is
//! absent from that header; the 52-byte record is the first published public
//! structure for `joyGetPosEx`, with `DWORD` fields.

use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MAX_JOYSTICK_NAME: usize = 32;
pub const JOYINFO16_SIZE: usize = 8;
pub const JOYCAPS16_SIZE: usize = 54;
pub const JOYINFOEX16_SIZE: usize = 52;
pub const JOYINFOEX16_X_OFFSET: usize = 8;
pub const JOYINFOEX16_Y_OFFSET: usize = 12;
pub const JOYINFOEX16_Z_OFFSET: usize = 16;
pub const JOYINFOEX16_BUTTONS_OFFSET: usize = 32;

/// `MMSYSERR_NODRIVER` from the Windows 3.1 multimedia error base.
pub const MMSYSERR_NODRIVER: u16 = 6;
/// `JOYERR_BASE + 5`.
pub const JOYERR_PARMS: u16 = 165;
/// `JOYERR_BASE + 6`.
pub const JOYERR_NOCANDO: u16 = 166;
/// `JOYERR_BASE + 7`.
pub const JOYERR_UNPLUGGED: u16 = 167;

/// Axes and buttons that `JOYINFO` can supply. Later `JOY_RETURN*` bits are
/// outside this set.
pub const JOY_RETURNX: u32 = 0x0000_0001;
pub const JOY_RETURNY: u32 = 0x0000_0002;
pub const JOY_RETURNZ: u32 = 0x0000_0004;
pub const JOY_RETURNBUTTONS: u32 = 0x0000_0080;
pub const JOY_RETURN_SUPPORTED: u32 = JOY_RETURNX | JOY_RETURNY | JOY_RETURNZ | JOY_RETURNBUTTONS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16JoyInfo16 {
    pub x: u16,
    pub y: u16,
    pub z: u16,
    pub buttons: u16,
}

impl Win16JoyInfo16 {
    pub fn encode(self) -> [u8; JOYINFO16_SIZE] {
        zerocopy::transmute!(JoyInfo16Wire {
            x: U16::new(self.x),
            y: U16::new(self.y),
            z: U16::new(self.z),
            buttons: U16::new(self.buttons),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16JoyCaps16 {
    pub manufacturer: u16,
    pub product: u16,
    pub name: [u8; MAX_JOYSTICK_NAME],
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

impl Win16JoyCaps16 {
    pub fn encode(self) -> [u8; JOYCAPS16_SIZE] {
        zerocopy::transmute!(JoyCaps16Wire {
            manufacturer: U16::new(self.manufacturer),
            product: U16::new(self.product),
            name: self.name,
            x_min: U16::new(self.x_min),
            x_max: U16::new(self.x_max),
            y_min: U16::new(self.y_min),
            y_max: U16::new(self.y_max),
            z_min: U16::new(self.z_min),
            z_max: U16::new(self.z_max),
            buttons: U16::new(self.buttons),
            period_min: U16::new(self.period_min),
            period_max: U16::new(self.period_max),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16JoystickRequest {
    GetNumDevs,
    GetDevCaps {
        device: u16,
        caps: u32,
        size: u16,
    },
    GetPos {
        device: u16,
        info: u32,
    },
    GetThreshold {
        device: u16,
        threshold: u32,
    },
    ReleaseCapture {
        device: u16,
    },
    SetCapture {
        window: u16,
        device: u16,
        period: u16,
        changed: u16,
    },
    SetThreshold {
        device: u16,
        threshold: u16,
    },
    SetCalibration {
        device: u16,
    },
    GetPosEx {
        device: u16,
        info: u32,
    },
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct JoyInfo16Wire {
    x: U16,
    y: U16,
    z: U16,
    buttons: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct JoyCaps16Wire {
    manufacturer: U16,
    product: U16,
    name: [u8; MAX_JOYSTICK_NAME],
    x_min: U16,
    x_max: U16,
    y_min: U16,
    y_max: U16,
    z_min: U16,
    z_max: U16,
    buttons: U16,
    period_min: U16,
    period_max: U16,
}

const _: () = {
    assert!(core::mem::size_of::<JoyInfo16Wire>() == JOYINFO16_SIZE);
    assert!(core::mem::align_of::<JoyInfo16Wire>() == 1);
    assert!(core::mem::size_of::<JoyCaps16Wire>() == JOYCAPS16_SIZE);
    assert!(core::mem::align_of::<JoyCaps16Wire>() == 1);
    assert!(core::mem::offset_of!(JoyCaps16Wire, name) == 4);
    assert!(core::mem::offset_of!(JoyCaps16Wire, x_min) == 36);
    assert!(core::mem::offset_of!(JoyCaps16Wire, period_max) == 52);
};
