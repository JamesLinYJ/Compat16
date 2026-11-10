//! Native Windows W NLS services behind the OLE2NLS Win16 ABI adapter.

use super::guest_text::GuestTextCodec;
use compat_services::automation::{map_compare_flags16, map_lcmap_flags16};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16NlsHostResult as HostResult,
    Win16NlsOperation, Win16NlsString,
};
use std::ptr;
use windows_sys::Win32::Globalization::{
    CompareStringW, GetLocaleInfoW, GetStringTypeExW, GetSystemDefaultLangID,
    GetSystemDefaultLCID, GetUserDefaultLangID, GetUserDefaultLCID, LCMapStringW,
    LCMAP_SORTKEY, LOCALE_RETURN_NUMBER,
};

const MAX_NLS_BUFFER: usize = 1 << 20;

pub(super) fn execute(
    operation: Win16NlsOperation,
    codec: GuestTextCodec,
) -> Result<HostResult, RuntimeError> {
    match operation {
        Win16NlsOperation::GetUserDefaultLcid => {
            // SAFETY: GetUserDefaultLCID takes no pointer or handle. It returns
            // the user-default locale identifier and retains nothing. No guest
            // address is involved.
            Ok(HostResult::Scalar(unsafe { GetUserDefaultLCID() }))
        }
        Win16NlsOperation::GetSystemDefaultLcid => {
            // SAFETY: GetSystemDefaultLCID takes no pointer or handle. It
            // returns the system-default locale identifier and retains nothing.
            // No guest address is involved.
            Ok(HostResult::Scalar(unsafe { GetSystemDefaultLCID() }))
        }
        Win16NlsOperation::GetUserDefaultLangId => {
            // SAFETY: GetUserDefaultLangID takes no pointer or handle. It
            // returns the user-default language identifier and retains nothing.
            // No guest address is involved.
            Ok(HostResult::Scalar(u32::from(unsafe { GetUserDefaultLangID() })))
        }
        Win16NlsOperation::GetSystemDefaultLangId => {
            // SAFETY: GetSystemDefaultLangID takes no pointer or handle. It
            // returns the system-default language identifier and retains
            // nothing. No guest address is involved.
            Ok(HostResult::Scalar(u32::from(unsafe { GetSystemDefaultLangID() })))
        }
        Win16NlsOperation::GetLocaleInfoA { lcid, info_type, capacity } => {
            get_locale_info(codec, lcid, info_type, capacity)
        }
        Win16NlsOperation::LcMapStringA {
            lcid, flags, source, destination_capacity,
        } => lc_map_string(codec, lcid, flags, &source, destination_capacity),
        Win16NlsOperation::GetStringTypeA { lcid, info_type, source } => {
            get_string_type(codec, lcid, info_type, &source)
        }
        Win16NlsOperation::CompareStringA { lcid, flags, left, right } => {
            let flags = map_compare_flags16(flags).map_err(|_| RuntimeError::new(
                Kind::InternalInvariant, "Win16 CompareStringA flag translation failed"))?;
            let left = NlsWideInput::new(codec, &left)?;
            let right = NlsWideInput::new(codec, &right)?;
            let left_units = left.pointer();
            let left_count = left.count();
            let right_units = right.pointer();
            let right_count = right.count();
            // SAFETY: `left_units` is null or points at the owned UTF-16 copy
            // in `left`, which stays live for this call. `left_count` is that
            // copy's declared count, including -1 for a null-terminated
            // string. `right_units` is null or points at the owned UTF-16 copy
            // in `right`, which stays live. `right_count` is that copy's
            // declared count. CompareStringW compares the strings and returns
            // the order, or zero. It retains no pointer. No pointer is a guest
            // address.
            let result = unsafe {
                CompareStringW(lcid, flags, left_units, left_count, right_units, right_count)
            };
            Ok(HostResult::Scalar(result as u32))
        }
    }
}

fn get_locale_info(
    codec: GuestTextCodec,
    lcid: u32,
    info_type: u32,
    byte_capacity: u16,
) -> Result<HostResult, RuntimeError> {
    if info_type & LOCALE_RETURN_NUMBER != 0 {
        return get_locale_number(lcid, info_type, byte_capacity);
    }

    // Query W character capacity first; the guest API reports encoded bytes.
    let output = ptr::null_mut();
    // SAFETY: `output` is null and the character count is zero, so
    // GetLocaleInfoW does not write through it. It returns the required
    // UTF-16 unit count, including the terminator, or zero. It retains no
    // pointer. No guest address is passed.
    let required = unsafe { GetLocaleInfoW(lcid, info_type, output, 0) };
    if required <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let mut wide = zeroed_wide(required as usize, "allocate locale-information output")?;
    let output = wide.as_mut_ptr();
    // SAFETY: `output` addresses `required` initialized UTF-16 units in
    // `wide`, and that buffer stays live for this call. GetLocaleInfoW writes
    // the locale string there and returns the unit count, or zero. It retains
    // no pointer. No pointer is a guest address.
    let written = unsafe { GetLocaleInfoW(lcid, info_type, output, required) };
    if written <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let count = checked_count(written, wide.len(), "GetLocaleInfoW")?;
    let bytes = codec.from_wide(&wide[..count])?.bytes;
    if byte_capacity == 0 {
        return Ok(HostResult::Buffer {
            result: checked_i32(bytes.len(), "size guest locale-information output")?,
            bytes: Vec::new(),
        });
    }
    if bytes.len() > usize::from(byte_capacity) {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let result = checked_i32(bytes.len(), "count guest locale-information output")?;
    Ok(HostResult::Buffer { result, bytes })
}

fn get_locale_number(
    lcid: u32,
    info_type: u32,
    byte_capacity: u16,
) -> Result<HostResult, RuntimeError> {
    if byte_capacity == 0 {
        // W reports two WCHARs for a DWORD result; Win16 returns four bytes.
        let output = ptr::null_mut();
        // SAFETY: `output` is null and the character count is zero, so
        // GetLocaleInfoW does not write through it. It returns the required
        // unit count, or zero. It retains no pointer. No guest address is
        // passed.
        let result = unsafe { GetLocaleInfoW(lcid, info_type, output, 0) };
        return Ok(HostResult::Buffer {
            result: if result > 0 { 4 } else { 0 },
            bytes: Vec::new(),
        });
    }
    if byte_capacity < 4 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let mut value = 0_u32;
    // LOCALE_RETURN_NUMBER writes a DWORD while cchData is measured in WCHARs.
    let output: *mut u16 = (&mut value as *mut u32).cast();
    // SAFETY: `output` addresses the aligned local DWORD `value`, which stays
    // live for this call. The character count is 2, the WCHAR width of that
    // DWORD. GetLocaleInfoW writes the numeric locale value there and returns
    // the unit count, or zero. It retains no pointer. No pointer is a guest
    // address.
    let result = unsafe { GetLocaleInfoW(lcid, info_type, output, 2) };
    if result <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    Ok(HostResult::Buffer { result: 4, bytes: value.to_le_bytes().to_vec() })
}

fn lc_map_string(
    codec: GuestTextCodec,
    lcid: u32,
    flags: u32,
    source: &Win16NlsString,
    byte_capacity: u16,
) -> Result<HostResult, RuntimeError> {
    let flags = map_lcmap_flags16(flags).map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "Win16 LCMapStringA flag translation failed"))?;
    let input = NlsWideInput::new(codec, source)?;
    if input.is_null() {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    if flags & LCMAP_SORTKEY != 0 {
        return lc_map_sort_key(lcid, flags, &input, byte_capacity);
    }

    // W uses UTF-16 units for transformed text; encode the completed result
    // before enforcing the guest's byte capacity.
    let source = input.pointer();
    let source_count = input.count();
    let destination = ptr::null_mut();
    // SAFETY: `source` points at the owned UTF-16 copy in `input`, which stays
    // live for this call. `source_count` is that copy's declared count.
    // `destination` is null and the destination count is zero, so LCMapStringW
    // does not write. It returns the required UTF-16 unit count, or zero. It
    // retains no pointer. No pointer is a guest address.
    let required = unsafe { LCMapStringW(lcid, flags, source, source_count, destination, 0) };
    if required <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let mut wide = zeroed_wide(required as usize, "allocate locale-mapped output")?;
    let destination = wide.as_mut_ptr();
    // SAFETY: `source` points at the owned UTF-16 copy in `input`, which stays
    // live for this call. `source_count` is that copy's declared count.
    // `destination` addresses `required` initialized UTF-16 units in `wide`,
    // and that buffer stays live. LCMapStringW writes the mapped string there
    // and returns the unit count, or zero. It retains no pointer. No pointer
    // is a guest address.
    let written = unsafe {
        LCMapStringW(lcid, flags, source, source_count, destination, required)
    };
    if written <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let count = checked_count(written, wide.len(), "LCMapStringW")?;
    let bytes = codec.from_wide(&wide[..count])?.bytes;
    if byte_capacity == 0 {
        return Ok(HostResult::Buffer {
            result: checked_i32(bytes.len(), "size guest LCMapString output")?,
            bytes: Vec::new(),
        });
    }
    if bytes.len() > usize::from(byte_capacity) {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let result = checked_i32(bytes.len(), "count guest LCMapString output")?;
    Ok(HostResult::Buffer { result, bytes })
}

fn lc_map_sort_key(
    lcid: u32,
    flags: u32,
    input: &NlsWideInput,
    byte_capacity: u16,
) -> Result<HostResult, RuntimeError> {
    // Sort keys are opaque bytes; LCMapStringW returns their byte count even
    // though the W binding types its output pointer as PWSTR.
    let source = input.pointer();
    let source_count = input.count();
    let destination = ptr::null_mut();
    // SAFETY: `source` points at the owned UTF-16 copy in `input`, which stays
    // live for this call. `source_count` is that copy's declared count.
    // `destination` is null and the destination count is zero, so LCMapStringW
    // does not write. It returns the sort-key byte count, or zero. It retains
    // no pointer. No pointer is a guest address.
    let required = unsafe { LCMapStringW(lcid, flags, source, source_count, destination, 0) };
    if required <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let required = usize::try_from(required).map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "LCMapStringW returned an invalid sort-key byte count"))?;
    if byte_capacity == 0 {
        return Ok(HostResult::Buffer {
            result: checked_i32(required, "size locale sort key")?,
            bytes: Vec::new(),
        });
    }
    let capacity = usize::from(byte_capacity);
    if required > capacity {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let units = capacity.checked_add(1).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "locale sort-key buffer size overflow"))? / 2;
    let mut storage = zeroed_wide(units, "allocate locale sort-key bytes")?;
    let destination = storage.as_mut_ptr();
    let destination_bytes = i32::from(byte_capacity);
    // SAFETY: `source` points at the owned UTF-16 copy in `input`, which stays
    // live for this call. `source_count` is that copy's declared count.
    // `destination` addresses the aligned UTF-16 storage in `storage`, which
    // has at least `byte_capacity` writable bytes and stays live.
    // `destination_bytes` is that byte capacity. LCMapStringW with
    // LCMAP_SORTKEY writes the opaque sort key there and returns its byte
    // count, or zero. It retains no pointer. No pointer is a guest address.
    let written = unsafe {
        LCMapStringW(lcid, flags, source, source_count, destination, destination_bytes)
    };
    if written <= 0 {
        return Ok(HostResult::Buffer { result: 0, bytes: Vec::new() });
    }
    let written = usize::try_from(written).map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "LCMapStringW returned an invalid sort-key byte count"))?;
    if written > capacity || written > units.saturating_mul(2) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "LCMapStringW exceeded its aligned sort-key buffer"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(written).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy locale sort-key bytes", error))?;
    for unit in storage {
        bytes.extend_from_slice(&unit.to_le_bytes());
        if bytes.len() >= written { break; }
    }
    bytes.truncate(written);
    Ok(HostResult::Buffer { result: written as i32, bytes })
}

fn get_string_type(
    codec: GuestTextCodec,
    lcid: u32,
    info_type: u32,
    source: &Win16NlsString,
) -> Result<HostResult, RuntimeError> {
    let input = NlsWideInput::new(codec, source)?;
    let count = input.output_units();
    if count > MAX_NLS_BUFFER / std::mem::size_of::<u16>() {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "OLE NLS character-type output exceeds its checked limit"));
    }
    let mut values = zeroed_wide(count, "allocate OLE NLS character-type output")?;
    let source_units = input.pointer();
    let source_count = input.count();
    let output = if values.is_empty() {
        ptr::null_mut()
    } else {
        values.as_mut_ptr()
    };
    // SAFETY: `source_units` is null or points at the owned UTF-16 copy in
    // `input`, which stays live for this call. `source_count` is that copy's
    // declared count, including -1 for a null-terminated string. `output` is
    // null when `values` is empty; otherwise it addresses one initialized WORD
    // in `values` for each UTF-16 input unit, including a NUL when the count
    // is -1, and that buffer stays live. GetStringTypeExW writes those
    // character types and returns nonzero on success. It retains no pointer.
    // No pointer is a guest address.
    let result = unsafe {
        GetStringTypeExW(lcid, info_type, source_units, source_count, output)
    };
    if result == 0 {
        values.clear();
    }
    Ok(HostResult::StringTypes { result: i32::from(result != 0), values })
}

struct NlsWideInput {
    wide: Vec<u16>,
    is_null: bool,
    count: i32,
    output_units: usize,
}

impl NlsWideInput {
    fn new(codec: GuestTextCodec, source: &Win16NlsString) -> Result<Self, RuntimeError> {
        if source.is_null {
            return Ok(Self {
                wide: Vec::new(),
                is_null: true,
                count: i32::from(source.declared_count),
                output_units: 0,
            });
        }
        let mut wide = if source.declared_count < 0 {
            let end = source.bytes.iter().position(|byte| *byte == 0)
                .unwrap_or(source.bytes.len());
            codec.to_wide(&source.bytes[..end])?
        } else {
            codec.to_wide(&source.bytes)?
        };
        let count = if source.declared_count < 0 {
            wide.push(0);
            i32::from(source.declared_count)
        } else {
            checked_i32(wide.len(), "count converted OLE NLS source units")?
        };
        let output_units = if source.declared_count == 0 { 0 } else { wide.len() };
        // W ignores the pointer for a zero source count; retain a valid
        // address without changing the guest's declared count.
        if wide.is_empty() {
            wide.push(0);
        }
        Ok(Self { wide, is_null: false, count, output_units })
    }

    fn pointer(&self) -> *const u16 {
        if self.is_null { ptr::null() } else { self.wide.as_ptr() }
    }

    fn count(&self) -> i32 { self.count }
    fn output_units(&self) -> usize { self.output_units }
    fn is_null(&self) -> bool { self.is_null }
}

fn zeroed_wide(units: usize, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    if units > MAX_NLS_BUFFER / std::mem::size_of::<u16>() {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "OLE NLS UTF-16 buffer exceeds its checked limit"));
    }
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(units).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, operation, error))?;
    buffer.resize(units, 0);
    Ok(buffer)
}

fn checked_count(value: i32, capacity: usize, operation: &'static str)
    -> Result<usize, RuntimeError> {
    let count = usize::try_from(value).map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, format!("{operation} returned an invalid count")))?;
    if count > capacity {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            format!("{operation} exceeded its queried buffer")));
    }
    Ok(count)
}

fn checked_i32(value: usize, operation: &'static str) -> Result<i32, RuntimeError> {
    i32::try_from(value).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, operation, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Globalization::{
        CSTR_LESS_THAN, LCMAP_SORTKEY, LCMAP_UPPERCASE, LOCALE_IMEASURE,
        LOCALE_RETURN_NUMBER, LOCALE_SDECIMAL,
    };

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    fn text(bytes: &[u8], count: i16) -> Win16NlsString {
        Win16NlsString { bytes: bytes.to_vec(), declared_count: count, is_null: false }
    }

    fn nls_execute(codec: GuestTextCodec, operation: Win16NlsOperation)
        -> Result<HostResult, RuntimeError> {
        execute(operation, codec)
    }

    #[test]
    fn locale_text_and_numeric_queries_report_guest_byte_counts() {
        let codec = cp936();
        let query = |capacity| nls_execute(codec, Win16NlsOperation::GetLocaleInfoA {
            lcid: 0x0409,
            info_type: LOCALE_SDECIMAL,
            capacity,
        }).unwrap();
        assert_eq!(query(0), HostResult::Buffer { result: 2, bytes: Vec::new() });
        assert_eq!(query(1), HostResult::Buffer { result: 0, bytes: Vec::new() });
        assert_eq!(query(2), HostResult::Buffer {
            result: 2,
            bytes: vec![b'.', 0],
        });

        match nls_execute(codec, Win16NlsOperation::GetLocaleInfoA {
            lcid: 0x0409,
            info_type: LOCALE_IMEASURE | LOCALE_RETURN_NUMBER,
            capacity: 4,
        }).unwrap() {
            HostResult::Buffer { result: 4, bytes } => assert_eq!(bytes.len(), 4),
            other => panic!("unexpected numeric locale result: {other:?}"),
        }
    }

    #[test]
    fn locale_mapping_and_character_types_keep_wide_and_guest_counts_separate() {
        let codec = cp936();
        assert_eq!(
            nls_execute(codec, Win16NlsOperation::LcMapStringA {
                lcid: 0x0409,
                flags: LCMAP_UPPERCASE,
                source: text(b"a", 1),
                destination_capacity: 1,
            }).unwrap(),
            HostResult::Buffer { result: 1, bytes: b"A".to_vec() },
        );

        let types = nls_execute(codec, Win16NlsOperation::GetStringTypeA {
            lcid: 0x0409,
            info_type: 1,
            source: text(b"A", -1),
        }).unwrap();
        match types {
            HostResult::StringTypes { result: 1, values } => assert_eq!(values.len(), 2),
            other => panic!("unexpected GetStringTypeA result: {other:?}"),
        }
    }

    #[test]
    fn sort_key_stays_opaque_bytes_and_compare_returns_win32_order() {
        let codec = cp936();
        let query = nls_execute(codec, Win16NlsOperation::LcMapStringA {
            lcid: 0x0409,
            flags: LCMAP_SORTKEY,
            source: text(b"A", 1),
            destination_capacity: 0,
        }).unwrap();
        let HostResult::Buffer { result: required, bytes } = query else {
            panic!("unexpected sort-key size result: {query:?}");
        };
        assert!(required > 0);
        assert!(bytes.is_empty());
        let output = nls_execute(codec, Win16NlsOperation::LcMapStringA {
            lcid: 0x0409,
            flags: LCMAP_SORTKEY,
            source: text(b"A", 1),
            destination_capacity: 64,
        }).unwrap();
        let HostResult::Buffer { result, bytes } = output else {
            panic!("unexpected sort-key output: {output:?}");
        };
        assert_eq!(result, bytes.len() as i32);
        assert_eq!(result, required);

        assert_eq!(
            nls_execute(codec, Win16NlsOperation::CompareStringA {
                lcid: 0x0409,
                flags: 0,
                left: text(b"A", 1),
                right: text(b"B", 1),
            }).unwrap(),
            HostResult::Scalar(CSTR_LESS_THAN as u32),
        );
    }
}
