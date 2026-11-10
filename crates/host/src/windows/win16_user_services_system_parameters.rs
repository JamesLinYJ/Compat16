//! Native Windows implementation of the pointer-free Win16 SPI requests.

use runtime::{
    RuntimeError, Win16HostLogFont, Win16HostSystemParametersResult,
    Win16SystemParametersRequest as Request, Win16SystemParametersValue as Value,
};
use windows_sys::Win32::Graphics::Gdi::LOGFONTW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SPI_GETICONTITLELOGFONT, SPI_GETMOUSE, SPI_SETDESKPATTERN, SPI_SETDESKWALLPAPER,
    SPI_SETICONTITLELOGFONT, SPI_SETMOUSE, SystemParametersInfoW,
};

/// Execute one fully copied USER.483 operation. The worker supplies owned
/// bytes and typed Win16 values; this adapter never accepts guest pointers.
pub(super) fn execute(
    codec: crate::windows::guest_text::GuestTextCodec,
    request: Request,
) -> Result<Win16HostSystemParametersResult, RuntimeError> {
    let result = match request {
        Request::GetBool(action) => {
            let mut value = 0_i32;
            let parameter = (&mut value as *mut i32).cast();
            // SAFETY: `parameter` points at the owned `value` i32, which stays
            // live for this call. SystemParametersInfoW writes the BOOL there
            // and returns zero on failure. It retains no pointer. No pointer
            // is a guest address.
            let succeeded =
                unsafe { SystemParametersInfoW(u32::from(action), 0, parameter, 0) } != 0;
            make_result(succeeded, Value::Bool(value != 0))
        }
        Request::SetBool {
            action,
            value,
            flags,
        } => {
            let parameter = std::ptr::null_mut();
            // SAFETY: `parameter` is null. The Win16 value travels in uiParam,
            // so this call has no buffer. SystemParametersInfoW returns zero
            // on failure and retains no pointer. No pointer is a guest address.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    u32::from(action),
                    u32::from(value),
                    parameter,
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::GetWord(action) => {
            let mut value = 0_i32;
            let parameter = (&mut value as *mut i32).cast();
            // SAFETY: `parameter` points at the owned `value` i32, which stays
            // live for this call. SystemParametersInfoW writes the integer
            // there and returns zero on failure. It retains no pointer. No
            // pointer is a guest address.
            let succeeded =
                unsafe { SystemParametersInfoW(u32::from(action), 0, parameter, 0) } != 0;
            let Some(value) = guest_i16(value) else {
                return Ok(make_result(false, Value::None));
            };
            make_result(succeeded, Value::Word(value as u16))
        }
        Request::SetWord {
            action,
            value,
            flags,
        } => {
            let parameter = std::ptr::null_mut();
            // SAFETY: `parameter` is null. The Win16 value travels in uiParam,
            // so this call has no buffer. SystemParametersInfoW returns zero
            // on failure and retains no pointer. No pointer is a guest address.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    u32::from(action),
                    u32::from(value),
                    parameter,
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::GetMouse => {
            let mut values = [0_i32; 3];
            let parameter = values.as_mut_ptr().cast();
            // SAFETY: `parameter` points at the owned three-i32 `values` array,
            // which stays live for this call. SystemParametersInfoW writes the
            // three mouse thresholds there and returns zero on failure. It
            // retains no pointer. No pointer is a guest address.
            let succeeded = unsafe { SystemParametersInfoW(SPI_GETMOUSE, 0, parameter, 0) } != 0;
            let [Some(first), Some(second), Some(third)] = values.map(guest_i16) else {
                return Ok(make_result(false, Value::None));
            };
            make_result(succeeded, Value::Mouse([first, second, third]))
        }
        Request::SetMouse { values, flags } => {
            let mut native = values.map(i32::from);
            let parameter = native.as_mut_ptr().cast();
            // SAFETY: `parameter` points at the owned three-i32 `native` array,
            // which stays live for this call. SystemParametersInfoW reads those
            // mouse thresholds and returns zero on failure. It retains no
            // pointer. No pointer is a guest address.
            let succeeded =
                unsafe { SystemParametersInfoW(SPI_SETMOUSE, 0, parameter, u32::from(flags)) } != 0;
            make_result(succeeded, Value::None)
        }
        // `SPI_LANGDRIVER` is a legacy Windows 3.x operation. This adapter
        // has no verified native mapping, so report ordinary failure instead
        // of synthesizing a language-driver name.
        Request::GetLanguageDriver { capacity: _ } => {
            make_result(false, Value::LanguageDriver(Vec::new()))
        }
        Request::SetDesktopWallpaper { path, flags } => {
            if path.contains(&0) {
                return Ok(make_result(false, Value::None));
            }
            let mut path_z = codec.to_wide_z(&path)?;
            let parameter = path_z.as_mut_ptr().cast();
            // SAFETY: `parameter` points at the owned NUL-terminated UTF-16
            // wallpaper path in `path_z`, which stays live for this call.
            // SystemParametersInfoW reads that path and returns zero on
            // failure. It retains no pointer. No pointer is a guest address.
            let succeeded = unsafe {
                SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, parameter, u32::from(flags))
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::SetDesktopPattern { flags } => {
            let parameter = std::ptr::null_mut();
            // SAFETY: `parameter` is null. This call passes no caller buffer.
            // SystemParametersInfoW returns zero on failure and retains no
            // pointer. No pointer is a guest address.
            let succeeded = unsafe {
                SystemParametersInfoW(SPI_SETDESKPATTERN, 0, parameter, u32::from(flags))
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::GetIconTitleLogFont => {
            let mut native = LOGFONTW::default();
            let parameter = (&mut native as *mut LOGFONTW).cast();
            // SAFETY: `parameter` points at the owned `native` LOGFONTW, which
            // stays live for this call. uiParam is the size of that structure.
            // SystemParametersInfoW writes the icon-title font there and
            // returns zero on failure. It retains no pointer. No pointer is a
            // guest address.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_GETICONTITLELOGFONT,
                    std::mem::size_of::<LOGFONTW>() as u32,
                    parameter,
                    0,
                )
            } != 0;
            let Some(font) = logfont_from_native(codec, native)? else {
                return Ok(make_result(false, Value::None));
            };
            make_result(succeeded, Value::LogFont(font))
        }
        Request::SetIconTitleLogFont { font, flags } => {
            let Some(mut native) = logfont_to_native(codec, font)? else {
                return Ok(make_result(false, Value::None));
            };
            let parameter = (&mut native as *mut LOGFONTW).cast();
            // SAFETY: `parameter` points at the owned `native` LOGFONTW, which
            // stays live for this call. uiParam is the size of that structure.
            // SystemParametersInfoW reads the icon-title font and returns zero
            // on failure. It retains no pointer. No pointer is a guest address.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_SETICONTITLELOGFONT,
                    std::mem::size_of::<LOGFONTW>() as u32,
                    parameter,
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
    };
    Ok(result)
}

fn make_result(succeeded: bool, value: Value) -> Win16HostSystemParametersResult {
    Win16HostSystemParametersResult { succeeded, value }
}

/// Win16 `int` fields in these results are signed 16-bit. A host integer
/// outside that range cannot be stored, so the call fails and guest memory
/// stays unchanged.
fn guest_i16(value: i32) -> Option<i16> {
    i16::try_from(value).ok()
}

fn logfont_to_native(
    codec: crate::windows::guest_text::GuestTextCodec,
    font: Win16HostLogFont,
) -> Result<Option<LOGFONTW>, RuntimeError> {
    let mut native = LOGFONTW::default();
    native.lfHeight = i32::from(font.height);
    native.lfWidth = i32::from(font.width);
    native.lfEscapement = i32::from(font.escapement);
    native.lfOrientation = i32::from(font.orientation);
    native.lfWeight = i32::from(font.weight);
    native.lfItalic = font.italic;
    native.lfUnderline = font.underline;
    native.lfStrikeOut = font.strikeout;
    native.lfCharSet = font.char_set;
    native.lfOutPrecision = font.out_precision;
    native.lfClipPrecision = font.clip_precision;
    native.lfQuality = font.quality;
    native.lfPitchAndFamily = font.pitch_and_family;
    let Some(face_name) =
        crate::windows::win16_gdi::fonts::create_logfont_face_wide(codec, &font.face_name)?
    else {
        return Ok(None);
    };
    native.lfFaceName = face_name;
    Ok(Some(native))
}

fn logfont_from_native(
    codec: crate::windows::guest_text::GuestTextCodec,
    native: LOGFONTW,
) -> Result<Option<Win16HostLogFont>, RuntimeError> {
    let (
        Some(height),
        Some(width),
        Some(escapement),
        Some(orientation),
        Some(weight),
    ) = (
        guest_i16(native.lfHeight),
        guest_i16(native.lfWidth),
        guest_i16(native.lfEscapement),
        guest_i16(native.lfOrientation),
        guest_i16(native.lfWeight),
    ) else {
        return Ok(None);
    };
    Ok(Some(Win16HostLogFont {
        height,
        width,
        escapement,
        orientation,
        weight,
        italic: native.lfItalic,
        underline: native.lfUnderline,
        strikeout: native.lfStrikeOut,
        char_set: native.lfCharSet,
        out_precision: native.lfOutPrecision,
        clip_precision: native.lfClipPrecision,
        quality: native.lfQuality,
        pitch_and_family: native.lfPitchAndFamily,
        face_name: crate::windows::win16_gdi::fonts::guest_face_name(codec, &native.lfFaceName)?,
    }))
}
