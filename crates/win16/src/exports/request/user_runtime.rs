//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserRuntimeRequest {
    WNetGetCaps { index: u16 },
    GetTickCount,

    GetCurrentTime,

    MessageBeep { beep_type: u16 },

    GetKeyState { virtual_key: i16 },

    GetSystemMetrics { index: i16 },

    GetAsyncKeyState { virtual_key: i16 },
}
