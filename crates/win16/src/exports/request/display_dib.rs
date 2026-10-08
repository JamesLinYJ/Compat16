//! Checked stack values for the optional full-screen DIB display service.

/// Guest arguments for `DISPDIB.1 DisplayDib`.
///
/// FAR values stay in Win16 segment:offset form until a runtime path needs to
/// access guest bytes. The current host does not provide the API's full-screen
/// VGA takeover, so the service returns its documented unsupported result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16DisplayDibRequest {
    pub info: u32,
    pub bits: u32,
    pub flags: u16,
}
