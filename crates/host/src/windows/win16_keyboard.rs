//! Keyboard driver character conversion using the fixed guest codec.

use super::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError};
use runtime::{Win16HostKeyboardCall, Win16HostKeyboardResult};
use windows_sys::Win32::Globalization::IsDBCSLeadByteEx;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyNameTextW, GetKeyboardLayout, GetKeyboardType, MAPVK_VK_TO_CHAR, MAPVK_VK_TO_VSC,
    MapVirtualKeyExW, MapVirtualKeyW, ToUnicodeEx, VkKeyScanExW, VkKeyScanW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SPI_GETKEYBOARDSPEED, SPI_SETKEYBOARDSPEED, SystemParametersInfoW,
};

/// Execute a copied KEYBOARD-family request through the native Windows
/// code-page and keyboard APIs. `guest_oem_page` is the configured page for
/// the emulated machine, not a host pointer or guest-supplied native handle.
pub(super) fn execute(
    call: Win16HostKeyboardCall,
    ansi_codec: GuestTextCodec,
    guest_oem_page: u32,
) -> Result<Win16HostKeyboardResult, RuntimeError> {
    let result = match call {
        Win16HostKeyboardCall::AnsiToOem { source } => {
            Win16HostKeyboardResult::Converted(ansi_to_oem(ansi_codec, &source, guest_oem_page)?)
        }
        Win16HostKeyboardCall::OemToAnsi { source } => {
            Win16HostKeyboardResult::Converted(oem_to_ansi(ansi_codec, &source, guest_oem_page)?)
        }
        Win16HostKeyboardCall::IsDbcsLeadByte { code_page, value } => {
            Win16HostKeyboardResult::IsDbcsLeadByte(is_dbcs_lead_byte(code_page, value))
        }
        Win16HostKeyboardCall::OemKeyScan { character } => Win16HostKeyboardResult::OemKeyScan(
            oem_key_scan(GuestTextCodec::new(guest_oem_page)?, character)?,
        ),
        Win16HostKeyboardCall::VirtualKeyScan { ansi_character } => {
            Win16HostKeyboardResult::VirtualKeyScan(virtual_key_scan(ansi_codec, ansi_character)?)
        }
        Win16HostKeyboardCall::KeyboardType { selector } => {
            Win16HostKeyboardResult::KeyboardType(keyboard_type(selector))
        }
        Win16HostKeyboardCall::MapVirtualKey { code, map_type } => {
            Win16HostKeyboardResult::MapVirtualKey(map_virtual_key(ansi_codec, code, map_type)?)
        }
        Win16HostKeyboardCall::GetCodePage => Win16HostKeyboardResult::CodePage(guest_oem_page),
        Win16HostKeyboardCall::ToAscii {
            virtual_key,
            scan_code,
            key_state,
            flags,
        } => {
            let (count, characters) =
                to_ascii(ansi_codec, virtual_key, scan_code, &key_state, flags)?;
            Win16HostKeyboardResult::ToAscii { count, characters }
        }
        Win16HostKeyboardCall::SetSpeed { speed } => {
            Win16HostKeyboardResult::SetSpeed(set_keyboard_speed(speed))
        }
        Win16HostKeyboardCall::KeyNameText { parameter, output } => {
            let (output, written) = key_name_text(ansi_codec, parameter, output)?;
            Win16HostKeyboardResult::KeyNameText { output, written }
        }
    };
    Ok(result)
}

/// Match the keyboard driver's SetSpeed contract using Windows' keyboard
/// repeat-rate setting: 0xffff queries support; other values select the low
/// five-bit rate and return the rate Windows reports after setting it.
fn set_keyboard_speed(speed: u16) -> u16 {
    if speed == u16::MAX {
        // Microsoft Windows 3.0 DDK Adaptation Guide, section 8.10, defines
        // -1 as a capability query. This adapter implements software repeat
        // settings through Windows; read availability without invoking the
        // setter, which could overwrite a concurrent user setting.
        // https://www.pcjs.org/documents/books/mspl13/win/w3ddkadp/
        return if query_keyboard_speed().is_some() {
            0
        } else {
            u16::MAX
        };
    }

    let requested = u32::from(speed & 0x001f);
    if !set_native_keyboard_speed(requested) {
        return u16::MAX;
    }
    query_keyboard_speed().unwrap_or(u16::MAX)
}

fn set_native_keyboard_speed(speed: u32) -> bool {
    // SAFETY: This action consumes a scalar rate; no caller pointer is used.
    unsafe { SystemParametersInfoW(SPI_SETKEYBOARDSPEED, speed, std::ptr::null_mut(), 0) != 0 }
}

fn query_keyboard_speed() -> Option<u16> {
    let mut speed = 0_u32;
    // SAFETY: SPI_GETKEYBOARDSPEED writes one UINT into this live local.
    let succeeded = unsafe {
        SystemParametersInfoW(SPI_GETKEYBOARDSPEED, 0, (&mut speed as *mut u32).cast(), 0)
    } != 0;
    if succeeded {
        u16::try_from(speed).ok()
    } else {
        None
    }
}

pub(super) fn oem_to_ansi(
    ansi_codec: GuestTextCodec,
    source: &[u8],
    guest_oem_page: u32,
) -> Result<Vec<u8>, RuntimeError> {
    let oem_codec = GuestTextCodec::new(guest_oem_page)?;
    let wide = oem_codec.to_wide(source)?;
    // Windows' documented default-character replacement is retained by the
    // codec when a Unicode character cannot be represented in the guest ANSI
    // page; no host ACP is consulted.
    Ok(ansi_codec.from_wide(&wide)?.bytes)
}

/// Convert a checked guest ANSI byte sequence to the configured OEM page.
/// Explicit input lengths preserve embedded NULs in buffer-form requests.
pub(super) fn ansi_to_oem(
    ansi_codec: GuestTextCodec,
    source: &[u8],
    guest_oem_page: u32,
) -> Result<Vec<u8>, RuntimeError> {
    let oem_codec = GuestTextCodec::new(guest_oem_page)?;
    let wide = ansi_codec.to_wide(source)?;
    Ok(oem_codec.from_wide(&wide)?.bytes)
}

/// Ask the configured guest code page whether a byte is a DBCS lead byte.
pub(super) fn is_dbcs_lead_byte(guest_code_page: u32, value: u8) -> bool {
    // SAFETY: This API reads only the scalar arguments.
    unsafe { IsDBCSLeadByteEx(guest_code_page, value) != 0 }
}

/// Map one Win16 OEM byte to the keyboard layout's scan code and shift state.
///
/// OemKeyScan has no W variant and uses the host OEM page. Its documented
/// input domain is OEMASCII 0..=0xff, and its result stores the scan code in
/// the low WORD and shift state in the high WORD. Decode that byte with the
/// fixed guest OEM codec, then use the W layout APIs so a host code page cannot
/// alter the guest character. Reject a DBCS lead byte because this entrypoint
/// describes one OEMASCII character, not a multibyte string.
pub(super) fn oem_key_scan(codec: GuestTextCodec, value: u16) -> Result<u32, RuntimeError> {
    let Ok(byte) = u8::try_from(value) else {
        return Ok(u32::MAX);
    };
    let Some(character) = decode_guest_keyboard_byte(codec, byte)? else {
        return Ok(u32::MAX);
    };

    // SAFETY: `GetKeyboardLayout` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let layout = unsafe { GetKeyboardLayout(0) };
    // SAFETY: The call reads one decoded UTF-16 character and the current
    // thread's layout handle, matching the layout used by the follow-up W map.
    let key_and_shift = unsafe { VkKeyScanExW(character, layout) };
    if key_and_shift == -1 {
        return Ok(u32::MAX);
    }
    let key_and_shift = key_and_shift as u16;
    let shift_state = key_and_shift >> 8;
    // OemKeyScan does not translate characters requiring CTRL+ALT, even when
    // VkKeyScanExW can describe that combination for a layout such as French.
    if shift_state & 0x0006 == 0x0006 {
        return Ok(u32::MAX);
    }

    // MAPVK_VK_TO_VSC matches OemKeyScan's scan-code representation. Keep the
    // high WORD exactly as the keyboard layout's shift-state byte.
    // SAFETY: Both arguments are scalar values and `layout` is a native HKL
    // returned by GetKeyboardLayout on this same worker thread.
    let scan_code =
        unsafe { MapVirtualKeyExW(u32::from(key_and_shift as u8), MAPVK_VK_TO_VSC, layout) };
    if scan_code == 0 {
        return Ok(u32::MAX);
    }
    Ok((u32::from(shift_state) << 16) | (scan_code & 0xffff))
}

/// Decode exactly one guest keyboard byte, distinguishing invalid input from
/// host failures. The round trip rejects Windows replacement decoding and
/// preserves SBCS/DBCS byte identity for both OemKeyScan and VkKeyScan.
fn decode_guest_keyboard_byte(
    codec: GuestTextCodec,
    value: u8,
) -> Result<Option<u16>, RuntimeError> {
    if is_dbcs_lead_byte(codec.code_page(), value) {
        return Ok(None);
    }
    let wide = match codec.to_wide(&[value]) {
        Ok(wide) => wide,
        Err(error) if error.kind() == Kind::HostFailure => return Ok(None),
        Err(error) => return Err(error),
    };
    if wide.len() != 1 || (0xd800..=0xdfff).contains(&wide[0]) {
        return Ok(None);
    }
    let encoded = codec.from_wide(&wide)?;
    if encoded.bytes.as_slice() != [value] || encoded.used_default_char == Some(true) {
        return Ok(None);
    }
    Ok(Some(wide[0]))
}

/// Return the virtual key and modifier state for one guest ANSI character.
pub(super) fn virtual_key_scan(codec: GuestTextCodec, value: u8) -> Result<i16, RuntimeError> {
    let Some(character) = decode_guest_keyboard_byte(codec, value)? else {
        return Ok(-1);
    };
    // SAFETY: The API reads only the decoded Unicode scalar.
    Ok(unsafe { VkKeyScanW(character) })
}

/// Return the host keyboard type, subtype, or function-key count selector.
pub(super) fn keyboard_type(selector: i16) -> i32 {
    // SAFETY: This API reads only the scalar argument.
    unsafe { GetKeyboardType(i32::from(selector)) }
}

/// Apply the W mapping mode and encode character results into guest bytes.
pub(super) fn map_virtual_key(
    codec: GuestTextCodec,
    code: u16,
    map_type: u16,
) -> Result<u32, RuntimeError> {
    // SAFETY: The API reads only the scalar arguments.
    let mapped = unsafe { MapVirtualKeyW(u32::from(code), u32::from(map_type)) };
    if map_type != MAPVK_VK_TO_CHAR as u16 || mapped == 0 {
        return Ok(mapped);
    }
    encode_map_virtual_key_character(codec, mapped)
}

fn encode_map_virtual_key_character(
    codec: GuestTextCodec,
    mapped: u32,
) -> Result<u32, RuntimeError> {
    let encoded = codec.from_wide(&[mapped as u16])?.bytes;
    if encoded.len() > std::mem::size_of::<u32>() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "guest code-page character does not fit MapVirtualKey's DWORD result",
        ));
    }
    let guest_character = encoded
        .iter()
        .enumerate()
        .fold(0_u32, |value, (index, byte)| {
            value | (u32::from(*byte) << (index * 8))
        });
    // The W and A APIs both reserve the top bit to mark dead keys.
    Ok((mapped & 0xffff_0000) | guest_character)
}

/// Translate once through the active Windows keyboard layout, then encode its
/// Unicode output in the fixed guest code page. KEYBOARD.4 returns a 32-bit
/// buffer of two WORD slots, with one guest output byte in each low byte;
/// the copied-byte count and dead-key sign follow the DDK contract. The shared
/// Windows bindings do not model this guest byte/WORD layout, so it is packed
/// explicitly after conversion.
pub(super) fn to_ascii(
    codec: GuestTextCodec,
    virtual_key: u16,
    scan_code: u16,
    key_state: &[u8; 256],
    flags: u16,
) -> Result<(i32, [u16; 2]), RuntimeError> {
    let mut wide = [0_u16; 8];
    // SAFETY: `key_state` owns the complete 256-byte input snapshot and
    // `wide` owns eight writable UTF-16 units for this synchronous call.
    // ToUnicodeEx is called once so Windows updates dead-key state exactly
    // once. Win16 defines only bit 0 as the menu flag; map that bit explicitly
    // because ToUnicodeEx gives bits 1 and 2 different meanings. The current
    // thread's active layout is selected with GetKeyboardLayout(0).
    let native_flags = u32::from(flags & 0x0001);
    let native_count = unsafe {
        ToUnicodeEx(
            u32::from(virtual_key),
            u32::from(scan_code),
            key_state.as_ptr(),
            wide.as_mut_ptr(),
            wide.len() as i32,
            native_flags,
            GetKeyboardLayout(0),
        )
    };
    let units_written = if native_count < 0 {
        usize::try_from(native_count.checked_neg().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Windows ToUnicodeEx returned an invalid negative UTF-16 length",
            )
        })?)
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Windows ToUnicodeEx returned a negative UTF-16 length outside usize",
            )
        })?
    } else {
        usize::try_from(native_count).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Windows ToUnicodeEx returned a UTF-16 length outside usize",
            )
        })?
    };
    if units_written > wide.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows ToUnicodeEx returned a UTF-16 length larger than its output buffer",
        ));
    }

    encode_to_ascii_result(codec, &wide[..units_written], native_count < 0)
}

fn encode_to_ascii_result(
    codec: GuestTextCodec,
    wide: &[u16],
    dead_key: bool,
) -> Result<(i32, [u16; 2]), RuntimeError> {
    // KEYBOARD.4's DDK contract stores one output byte in each WORD. Bound
    // conversion by those two byte slots so DBCS output stays complete and a
    // longer encoding (such as a UTF-8 scalar) is never reported partially.
    let encoded = codec.from_wide_bounded(wide, 2)?;
    let mut words = [0_u16; 2];
    for (slot, byte) in words.iter_mut().zip(&encoded.bytes) {
        *slot = u16::from(*byte);
    }

    let count = if dead_key {
        // The Windows 3.0 DDK returns -1 for a dead key, even though it may
        // also have placed that key's spacing accent in the output state.
        -1
    } else {
        encoded.bytes.len() as i32
    };
    Ok((count, words))
}

/// Call the W key-name service and encode its result into the guest buffer,
/// preserving bytes beyond the written NUL-terminated name.
pub(super) fn key_name_text(
    codec: GuestTextCodec,
    parameter: i32,
    mut output: Vec<u8>,
) -> Result<(Vec<u8>, usize), RuntimeError> {
    let capacity = i32::try_from(output.len()).map_err(|_| {
        RuntimeError::new(
            Kind::InvalidInput,
            "Win16 key-name buffer exceeds the Windows API limit",
        )
    })?;
    if capacity == 0 {
        return Ok((output, 0));
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(output.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 key-name UTF-16 buffer",
            error,
        )
    })?;
    wide.resize(output.len(), 0);
    // SAFETY: The owned vector contains the complete WCHAR capacity.
    let written = unsafe { GetKeyNameTextW(parameter, wide.as_mut_ptr(), capacity) };
    if written < 0 || written as usize >= wide.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows GetKeyNameTextW returned an invalid output length",
        ));
    }
    let guest_written = encode_key_name(codec, &wide[..written as usize], &mut output)?;
    Ok((output, guest_written))
}

fn encode_key_name(
    codec: GuestTextCodec,
    wide: &[u16],
    output: &mut [u8],
) -> Result<usize, RuntimeError> {
    if output.is_empty() {
        return Ok(0);
    }
    let mut written_units = wide.len();
    if written_units > 0 && (0xd800..=0xdbff).contains(&wide[written_units - 1]) {
        written_units -= 1;
    }
    let bounded = codec.from_wide_bounded(&wide[..written_units], output.len() - 1)?;
    let guest_written = bounded.bytes.len();
    output[..guest_written].copy_from_slice(&bounded.bytes);
    output[guest_written] = 0;
    Ok(guest_written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn ansi_oem_conversion_preserves_counted_nuls_with_fixed_pages() {
        let ansi = cp936();
        assert_eq!(ansi_to_oem(ansi, b"A\0B", 437).unwrap(), b"A\0B");
        assert_eq!(oem_to_ansi(ansi, b"A\0B", 437).unwrap(), b"A\0B");
    }

    #[test]
    fn mapped_character_result_preserves_dead_key_flag_and_guest_bytes() {
        assert_eq!(
            encode_map_virtual_key_character(cp936(), 0x8000_4e2d).unwrap(),
            0x8000_d0d6,
        );
    }

    #[test]
    fn key_name_capacity_truncates_only_at_guest_character_boundaries() {
        let codec = cp936();
        let mut output = [0xcc; 3];
        assert_eq!(
            encode_key_name(codec, &[0x4e2d, b'A' as u16], &mut output).unwrap(),
            2
        );
        assert_eq!(output, [0xd6, 0xd0, 0]);

        let mut too_small = [0xcc; 2];
        assert_eq!(
            encode_key_name(codec, &[0x4e2d], &mut too_small).unwrap(),
            0
        );
        assert_eq!(too_small, [0, 0xcc]);
    }

    #[test]
    fn unicode_keyboard_translation_keeps_guest_byte_count_and_dead_key_sign() {
        let codec = cp936();
        let (count, bytes) = encode_to_ascii_result(codec, &[0x4e2d, b'A' as u16], false).unwrap();
        assert_eq!(count, 2);
        assert_eq!(bytes, [0x00d6, 0x00d0]);

        let (sbcs_count, sbcs_words) =
            encode_to_ascii_result(codec, &[b'A' as u16, b'B' as u16], false).unwrap();
        assert_eq!(sbcs_count, 2);
        assert_eq!(sbcs_words, [0x0041, 0x0042]);

        let (dead_count, dead_bytes) = encode_to_ascii_result(codec, &[b'A' as u16], true).unwrap();
        assert_eq!(dead_count, -1);
        assert_eq!(dead_bytes, [0x0041, 0]);

        let utf8 = GuestTextCodec::new(65001).expect("Windows should provide code page 65001");
        let (utf8_count, utf8_bytes) = encode_to_ascii_result(utf8, &[0x4e2d], false).unwrap();
        assert_eq!(utf8_count, 0);
        assert_eq!(utf8_bytes, [0, 0]);
    }

    #[test]
    fn virtual_key_scan_returns_no_mapping_for_invalid_guest_bytes() {
        assert_eq!(virtual_key_scan(cp936(), 0xd6).unwrap(), -1);
        let utf8 = GuestTextCodec::new(65001).expect("Windows should provide code page 65001");
        assert_eq!(virtual_key_scan(utf8, 0xc3).unwrap(), -1);
    }
}
