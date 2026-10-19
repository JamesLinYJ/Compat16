//! Reversible guest names without changing the native registry namespace.
//!
//! A short ASCII token identifies a UTF-16 name, not a native HKEY. Resolution
//! enumerates only the requested parent, so aliases survive close/reopen and
//! never borrow another parent's identity. No registry data stores the mapping.

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    ERROR_DUP_NAME, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_NO_UNICODE_TRANSLATION,
    ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_ENUMERATE_SUB_KEYS, RegCloseKey, RegOpenKeyExW,
};

use super::{GuestTextCodec, TextConversionError, enum_native_name, wide_z};

const PREFIX: &[u16] = &[
    b'~' as u16,
    b'C' as u16,
    b'1' as u16,
    b'6' as u16,
    b'~' as u16,
];
const ALIAS_UNITS: usize = PREFIX.len() + 32;

fn is_alias(name: &[u16]) -> bool {
    name.len() == ALIAS_UNITS
        && name[..PREFIX.len()]
            .iter()
            .zip(PREFIX)
            .all(|(&left, &right)| left == right || (left == b'c' as u16 && right == b'C' as u16))
        && name[PREFIX.len()..]
            .iter()
            .all(|unit| matches!(*unit, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66))
}

fn alias(name: &[u16]) -> Vec<u16> {
    let mut hash = Sha256::new();
    hash.update(b"Compat16.RegistryName.v1\0");
    for unit in name {
        hash.update(unit.to_le_bytes());
    }
    let digest = hash.finalize();
    let mut result = Vec::with_capacity(ALIAS_UNITS);
    result.extend_from_slice(PREFIX);
    for byte in &digest[..16] {
        for nibble in [byte >> 4, byte & 15] {
            result.push(u16::from(b"0123456789ABCDEF"[usize::from(nibble)]));
        }
    }
    result
}

fn same_alias(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(&left, &right)| {
            // Alias tokens contain ASCII only; native names remain untouched.
            left <= 0x7f && right <= 0x7f && (left as u8).eq_ignore_ascii_case(&(right as u8))
        })
}

fn exact_guest_name(
    codec: GuestTextCodec,
    name: &[u16],
) -> Result<Option<Vec<u8>>, TextConversionError> {
    // Reserve only the complete token shape. A real key with that spelling is
    // itself aliased, preventing it from shadowing another Unicode key.
    if is_alias(name) {
        return Ok(None);
    }
    let encoded = match codec.from_wide(name) {
        Ok(encoded) => encoded,
        Err(error) if super::guest_output_conversion_failure(&error) => return Ok(None),
        Err(error) => return Err(TextConversionError::Runtime(error)),
    };
    if encoded.used_default_char == Some(true) {
        return Ok(None);
    }
    match codec.to_wide(&encoded.bytes) {
        Ok(decoded) if decoded == name => Ok(Some(encoded.bytes)),
        Ok(_) => Ok(None),
        Err(error) if super::guest_output_conversion_failure(&error) => Ok(None),
        Err(error) => Err(TextConversionError::Runtime(error)),
    }
}

fn resolve_alias(
    codec: GuestTextCodec,
    parent: HKEY,
    token: &[u16],
) -> Result<Vec<u16>, TextConversionError> {
    super::scan::run(parent, move |parent| resolve_alias_on_scan_thread(codec, parent, token))
}

fn resolve_alias_on_scan_thread(
    codec: GuestTextCodec,
    parent: HKEY,
    token: &[u16],
) -> Result<Vec<u16>, TextConversionError> {
    let mut found = None;
    let mut index = 0_u32;
    loop {
        let name = match enum_native_name(parent, index) {
            Ok(name) => name,
            Err(TextConversionError::GuestStatus(ERROR_NO_MORE_ITEMS)) => break,
            Err(error) => return Err(error),
        };
        if same_alias(&alias(&name), token) && exact_guest_name(codec, &name)?.is_none() {
            if found.as_ref().is_some_and(|previous| previous != &name) {
                // A digest collision must never select an arbitrary key for a
                // query or mutation. Enumeration checks the same ambiguity.
                return Err(TextConversionError::GuestStatus(ERROR_DUP_NAME));
            }
            found = Some(name);
        }
        index = index
            .checked_add(1)
            .ok_or(TextConversionError::GuestStatus(ERROR_NO_MORE_ITEMS))?;
    }
    found.ok_or(TextConversionError::GuestStatus(ERROR_FILE_NOT_FOUND))
}

pub(super) fn guest_name(
    codec: GuestTextCodec,
    parent: HKEY,
    name: &[u16],
) -> Result<Vec<u8>, TextConversionError> {
    if let Some(encoded) = exact_guest_name(codec, name)? {
        return Ok(encoded);
    }
    let token = alias(name);
    // Verify uniqueness against live siblings, including real token-shaped
    // names. Native enumeration order is not stable and is never an identity.
    if resolve_alias(codec, parent, &token)? != name {
        return Err(TextConversionError::GuestStatus(ERROR_FILE_NOT_FOUND));
    }
    let encoded = codec
        .from_wide(&token)
        .map_err(TextConversionError::Runtime)?;
    let decoded = codec
        .to_wide(&encoded.bytes)
        .map_err(TextConversionError::Runtime)?;
    if encoded.used_default_char == Some(true) || decoded != token {
        return Err(TextConversionError::GuestStatus(
            ERROR_NO_UNICODE_TRANSLATION,
        ));
    }
    Ok(encoded.bytes)
}

struct ParentKey(HKEY);
impl Drop for ParentKey {
    fn drop(&mut self) {
        // SAFETY: only a successful RegOpenKeyExW enters this temporary owner.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

pub(super) fn native_path(
    codec: GuestTextCodec,
    root: HKEY,
    bytes: &[u8],
) -> Result<Vec<u16>, TextConversionError> {
    let mut decoded = wide_z(codec, bytes)?;
    decoded.pop();
    // Split after decoding: a DBCS trail byte of 0x5c is not a separator.
    if !decoded.split(|unit| *unit == 0x5c).any(is_alias) {
        decoded.push(0);
        return Ok(decoded);
    }
    let mut result = Vec::with_capacity(decoded.len() + 1);
    for (index, component) in decoded.split(|unit| *unit == 0x5c).enumerate() {
        if index != 0 {
            result.push(0x5c);
        }
        if !is_alias(component) {
            result.extend_from_slice(component);
            continue;
        }
        let mut parent = None;
        if !result.is_empty() {
            // result currently ends with the separator before this component.
            let mut prefix = result[..result.len() - 1].to_vec();
            prefix.push(0);
            let mut opened = std::ptr::null_mut();
            // SAFETY: root is validated by RegistryHandles; prefix is owned
            // UTF-16. Only enumeration rights are needed for reverse lookup.
            let status = unsafe {
                RegOpenKeyExW(
                    root,
                    prefix.as_ptr(),
                    0,
                    KEY_ENUMERATE_SUB_KEYS,
                    &mut opened,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(TextConversionError::GuestStatus(status));
            }
            parent = Some(ParentKey(opened));
        }
        let native = parent.as_ref().map_or(root, |parent| parent.0);
        result.extend_from_slice(&resolve_alias(codec, native, component)?);
    }
    result.push(0);
    Ok(result)
}
