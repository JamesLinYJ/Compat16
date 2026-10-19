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
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(u32::from(action), 0, (&mut value as *mut i32).cast(), 0)
            } != 0;
            make_result(succeeded, Value::Bool(value != 0))
        }
        Request::SetBool {
            action,
            value,
            flags,
        } => {
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    u32::from(action),
                    u32::from(value),
                    std::ptr::null_mut(),
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::GetWord(action) => {
            let mut value = 0_u32;
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(u32::from(action), 0, (&mut value as *mut u32).cast(), 0)
            } != 0;
            make_result(succeeded, Value::Word(value as u16))
        }
        Request::SetWord {
            action,
            value,
            flags,
        } => {
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    u32::from(action),
                    u32::from(value),
                    std::ptr::null_mut(),
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::GetMouse => {
            let mut values = [0_i32; 3];
            let succeeded =
                // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
                unsafe { SystemParametersInfoW(SPI_GETMOUSE, 0, values.as_mut_ptr().cast(), 0) }
                    != 0;
            make_result(succeeded, Value::Mouse(values.map(|value| value as i16)))
        }
        Request::SetMouse { values, flags } => {
            let mut native = values.map(i32::from);
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_SETMOUSE,
                    0,
                    native.as_mut_ptr().cast(),
                    u32::from(flags),
                )
            } != 0;
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
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_SETDESKWALLPAPER,
                    0,
                    path_z.as_mut_ptr().cast(),
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::SetDesktopPattern { flags } => {
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_SETDESKPATTERN,
                    0,
                    std::ptr::null_mut(),
                    u32::from(flags),
                )
            } != 0;
            make_result(succeeded, Value::None)
        }
        Request::GetIconTitleLogFont => {
            let mut native = LOGFONTW::default();
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_GETICONTITLELOGFONT,
                    std::mem::size_of::<LOGFONTW>() as u32,
                    (&mut native as *mut LOGFONTW).cast(),
                    0,
                )
            } != 0;
            make_result(
                succeeded,
                Value::LogFont(logfont_from_native(codec, native)?),
            )
        }
        Request::SetIconTitleLogFont { font, flags } => {
            let Some(mut native) = logfont_to_native(codec, font)? else {
                return Ok(make_result(false, Value::None));
            };
            // SAFETY: SystemParametersInfoW uses a caller-owned buffer when the action requires one, and that buffer stays live for the call.
            let succeeded = unsafe {
                SystemParametersInfoW(
                    SPI_SETICONTITLELOGFONT,
                    std::mem::size_of::<LOGFONTW>() as u32,
                    (&mut native as *mut LOGFONTW).cast(),
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
) -> Result<Win16HostLogFont, RuntimeError> {
    Ok(Win16HostLogFont {
        height: native
            .lfHeight
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        width: native
            .lfWidth
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        escapement: native
            .lfEscapement
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        orientation: native
            .lfOrientation
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        weight: native
            .lfWeight
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        italic: native.lfItalic,
        underline: native.lfUnderline,
        strikeout: native.lfStrikeOut,
        char_set: native.lfCharSet,
        out_precision: native.lfOutPrecision,
        clip_precision: native.lfClipPrecision,
        quality: native.lfQuality,
        pitch_and_family: native.lfPitchAndFamily,
        face_name: crate::windows::win16_gdi::fonts::guest_face_name(codec, &native.lfFaceName)?,
    })
}
