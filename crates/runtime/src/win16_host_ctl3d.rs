//! Pointer-free identity for a future native CTL3D host operation.
//!
//! No Win16 HWND, HINSTANCE, FAR pointer, or LPARAM is carried here: the
//! current adapter has no CTL3D-native operation to receive those values.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostCtl3dModule { Ctl3d, Ctl3dV2 }

/// Identifies only the imported export. It intentionally carries no guest
/// arguments because CTL3D drawing and callback arguments are not translated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostCtl3dCall {
    pub module: Win16HostCtl3dModule,
    pub ordinal: u16,
    pub name: Option<&'static str>,
}

/// Ordinary guest failure value plus an optional recoverable warning.
/// `value` is projected using the guest export descriptor's return width;
/// void exports preserve the caller's AX/DX independently of this field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostCtl3dResult {
    pub value: u32,
    pub warning: Option<&'static str>,
}
