use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win32HostEnvironmentCall as C,
    Win32HostImportResult, Win32HostImportValue as V, Win32ImportString as S};
use windows_sys::Win32::Foundation::SetLastError;
use windows_sys::Win32::System::Environment::{ExpandEnvironmentStringsW,
    GetEnvironmentVariableW, SetEnvironmentVariableW};

use super::super::{api_error, result, text};
use super::super::super::guest_text::GuestTextCodec;

pub(super) fn execute(call: C, codec: GuestTextCodec) -> Result<Win32HostImportResult, RuntimeError> {
    match call {
        C::Get { name, capacity, output_present } => get(name, capacity, output_present, codec),
        C::Set { name, value } => set(name, value, codec),
        C::Expand { source, capacity, output_present } => expand(source, capacity, output_present, codec),
    }
}

fn get(name: S, capacity: u32, output_present: bool, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> {
    let ansi = matches!(name, S::Ansi(_));
    let name = text::to_wide_z(codec, name, "environment variable name contains embedded NUL")?;
    if !ansi {
        let mut buffer = wide(capacity, output_present)?;
        unsafe { SetLastError(0); }
        // SAFETY: the owned name is terminated and the optional output buffer
        // has the exact UTF-16 capacity supplied by the guest W entrypoint.
        let returned = unsafe { GetEnvironmentVariableW(name.as_ptr(),
            if output_present { buffer.as_mut_ptr() } else { ptr::null_mut() }, capacity) };
        let native_error = (returned == 0).then(api_error);
        let empty_value = returned == 0 && native_error == Some(0);
        let valid = output_present && ((returned != 0 && returned < capacity)
            || (empty_value && capacity != 0));
        let value = if returned != 0 && valid { prefix_wide(&buffer, returned)? } else { Vec::new() };
        // Keep zero for a present empty value: callers distinguish it from a
        // missing variable by observing ERROR_SUCCESS after this zero return.
        let error = native_error;
        return Ok(result(V::Text { result: returned, output_valid: valid,
            text: S::Wide(value), file_part_offset: None }, error));
    }

    const MAX_ENVIRONMENT_VALUE: usize = 32_768;
    let native_capacity = u32::try_from(MAX_ENVIRONMENT_VALUE)
        .map_err(|_| exhausted("environment value buffer"))?;
    let mut buffer = wide(native_capacity, true)?;
    unsafe { SetLastError(0); }
    // SAFETY: Windows documents user-defined environment values at up to
    // 32,767 characters, so this owned buffer includes the terminating unit.
    let returned = unsafe { GetEnvironmentVariableW(name.as_ptr(), buffer.as_mut_ptr(), native_capacity) };
    if returned == 0 {
        let native_error = api_error();
        let empty_value = native_error == 0 && buffer.first() == Some(&0);
        let capacity = usize::try_from(capacity).map_err(|_| exhausted("ANSI environment capacity"))?;
        let valid = empty_value && output_present && capacity != 0;
        return Ok(result(V::Text { result: 0, output_valid: valid,
            text: S::Ansi(Vec::new()), file_part_offset: None }, Some(native_error)));
    }
    if returned >= native_capacity {
        return Err(contract("GetEnvironmentVariableW exceeded the documented maximum"));
    }
    let wide_value = prefix_wide(&buffer, returned)?;
    let value = text::from_wide(codec, &wide_value)?;
    let (result_count, valid) = ansi_get_count(value.len(), capacity, output_present)?;
    Ok(result(V::Text { result: result_count, output_valid: valid,
        text: S::Ansi(if valid { value } else { Vec::new() }), file_part_offset: None }, None))
}

fn set(name: S, value: Option<S>, codec: GuestTextCodec) -> Result<Win32HostImportResult, RuntimeError> {
    if value.as_ref().is_some_and(|value| value.encoding() != name.encoding()) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "environment name and value encodings differ"));
    }
    let name = text::to_wide_z(codec, name, "environment variable name contains embedded NUL")?;
    let value = value.map(|value| text::to_wide_z(codec, value,
        "environment variable value contains embedded NUL")).transpose()?;
    // SAFETY: both UTF-16 inputs are owned and terminated; NULL retains the
    // API's delete-variable operation.
    let success = unsafe { SetEnvironmentVariableW(name.as_ptr(),
        value.as_ref().map_or(ptr::null(), Vec::as_ptr)) != 0 };
    Ok(result(V::Bool(success), (!success).then(api_error)))
}

fn expand(source: S, capacity: u32, output_present: bool, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> {
    let ansi = matches!(source, S::Ansi(_));
    let source = text::to_wide_z(codec, source,
        "environment expansion source contains embedded NUL")?;
    if !ansi {
        let mut buffer = wide(capacity, output_present)?;
        unsafe { SetLastError(0); }
        // SAFETY: the source is owned/terminated and output uses guest W units.
        let returned = unsafe { ExpandEnvironmentStringsW(source.as_ptr(),
            if output_present { buffer.as_mut_ptr() } else { ptr::null_mut() }, capacity) };
        let error = (returned == 0).then(api_error);
        let valid = returned != 0 && returned <= capacity && output_present;
        let value = if valid { prefix_wide(&buffer, returned - 1)? } else { Vec::new() };
        return Ok(result(V::Text { result: returned, output_valid: valid,
            text: S::Wide(value), file_part_offset: None }, error));
    }

    let (value, error) = complete_expansion_w(&source)?;
    let Some(value) = value else {
        return Ok(result(V::Text { result: 0, output_valid: false,
            text: S::Ansi(Vec::new()), file_part_offset: None }, error));
    };
    let encoded = text::from_wide(codec, &value)?;
    let result_count = ansi_expansion_count(encoded.len())?;
    let required = usize::try_from(result_count).map_err(|_| exhausted("ANSI expansion result"))?;
    let capacity = usize::try_from(capacity).map_err(|_| exhausted("ANSI expansion capacity"))?;
    let valid = output_present && capacity >= required;
    Ok(result(V::Text { result: result_count, output_valid: valid,
        text: S::Ansi(if valid { encoded } else { Vec::new() }), file_part_offset: None }, None))
}

fn complete_expansion_w(source: &[u16])
    -> Result<(Option<Vec<u16>>, Option<u32>), RuntimeError> {
    unsafe { SetLastError(0); }
    // SAFETY: NULL/zero requests the W API's required character count; source
    // is an owned, terminated UTF-16 string and remains live for the call.
    let required = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), ptr::null_mut(), 0) };
    if required == 0 { return Ok((None, Some(api_error()))); }
    let mut capacity = required;
    loop {
        let mut buffer = wide(capacity, true)?;
        unsafe { SetLastError(0); }
        // SAFETY: the destination has the supplied number of UTF-16 units and
        // is separate from the owned source string.
        let returned = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), buffer.as_mut_ptr(), capacity) };
        if returned == 0 { return Ok((None, Some(api_error()))); }
        if returned <= capacity {
            let value_length = returned - 1;
            let value = prefix_wide(&buffer, value_length)?;
            return Ok((Some(value), None));
        }
        capacity = returned;
    }
}

fn wide(capacity: u32, present: bool) -> Result<Vec<u16>, RuntimeError> {
    reserve_zeroed::<u16>(capacity, present)
}

fn reserve_zeroed<T: Copy + Default>(capacity: u32, present: bool)
    -> Result<Vec<T>, RuntimeError> {
    if !present && capacity != 0 {
        return Err(RuntimeError::new(Kind::GuestFault,
            "NULL environment output buffer has nonzero capacity"));
    }
    let count = usize::try_from(capacity).map_err(|_| exhausted("environment output"))?;
    let count = count.max(usize::from(present && count == 0));
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve environment output", error))?;
    buffer.resize(count, T::default());
    Ok(buffer)
}

fn prefix_wide(buffer: &[u16], length: u32) -> Result<Vec<u16>, RuntimeError> {
    let length = usize::try_from(length).map_err(|_| exhausted("environment text"))?;
    if length >= buffer.len() || buffer[length] != 0 {
        return Err(contract("native environment API returned an unbounded UTF-16 string"));
    }
    let mut text = Vec::new();
    text.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy environment text", error))?;
    text.extend_from_slice(&buffer[..length]);
    Ok(text)
}

/// GetEnvironmentVariableA returns guest bytes excluding NUL on success and
/// includes one byte in the required size when the guest buffer is too small.
fn ansi_get_count(byte_length: usize, capacity: u32, output_present: bool)
    -> Result<(u32, bool), RuntimeError> {
    let required = byte_length.checked_add(1).ok_or_else(|| exhausted("ANSI environment value"))?;
    let capacity = usize::try_from(capacity).map_err(|_| exhausted("ANSI environment capacity"))?;
    let valid = output_present && capacity >= required;
    let count = if valid { byte_length } else { required };
    Ok((u32::try_from(count).map_err(|_| exhausted("ANSI environment value"))?, valid))
}

/// ExpandEnvironmentStringsA always counts the final NUL, including when
/// returning the required capacity for an undersized guest buffer.
fn ansi_expansion_count(byte_length: usize) -> Result<u32, RuntimeError> {
    let count = byte_length.checked_add(1).ok_or_else(|| exhausted("ANSI expansion result"))?;
    u32::try_from(count).map_err(|_| exhausted("ANSI expansion result"))
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

fn contract(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::HostFailure, message) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct DeleteVariable(Vec<u16>);

    impl Drop for DeleteVariable {
        fn drop(&mut self) {
            // SAFETY: this test owns a terminated variable name; NULL deletes it.
            unsafe {
                windows_sys::Win32::System::Environment::SetEnvironmentVariableW(
                    self.0.as_ptr(), std::ptr::null(),
                );
            }
        }
    }

    #[test]
    fn get_environment_variable_ansi_counts_guest_bytes_and_required_nul() {
        assert_eq!(ansi_get_count(2, 3, true).unwrap(), (2, true));
        assert_eq!(ansi_get_count(2, 2, true).unwrap(), (3, false));
        assert_eq!(ansi_get_count(2, 0, false).unwrap(), (3, false));
        assert_eq!(ansi_get_count(0, 1, true).unwrap(), (0, true));
    }

    #[test]
    fn expand_environment_strings_ansi_always_counts_the_final_nul() {
        assert_eq!(ansi_expansion_count(2).unwrap(), 3);
        assert_eq!(ansi_expansion_count(0).unwrap(), 1);
    }

    #[test]
    fn present_empty_environment_values_return_zero_and_error_success() {
        static NEXT_TEST_KEY: AtomicU32 = AtomicU32::new(1);
        let codec = GuestTextCodec::new(936).expect("Windows should provide code page 936");
        let key = format!("WIN32_TEST_EMPTY_{}_{}", std::process::id(),
            NEXT_TEST_KEY.fetch_add(1, Ordering::Relaxed));
        let wide_key = key.encode_utf16().collect::<Vec<_>>();
        let _cleanup = DeleteVariable(text::to_wide_z(codec,
            S::Wide(wide_key.clone()), "test environment variable name").unwrap());
        let set = set(S::Wide(wide_key.clone()), Some(S::Wide(Vec::new())), codec).unwrap();
        assert_eq!(set.value, V::Bool(true));

        let wide = get(S::Wide(wide_key.clone()), 1, true, codec).unwrap();
        let ansi = get(S::Ansi(codec.from_wide(&wide_key).unwrap().bytes), 1, true, codec).unwrap();
        let wide_sizing = get(S::Wide(wide_key.clone()), 0, false, codec).unwrap();
        let ansi_sizing = get(S::Ansi(codec.from_wide(&wide_key).unwrap().bytes), 0, false, codec).unwrap();

        assert_eq!(wide.last_error, Some(0));
        assert_eq!(wide.value, V::Text { result: 0, output_valid: true,
            text: S::Wide(Vec::new()), file_part_offset: None });
        assert_eq!(ansi.last_error, Some(0));
        assert_eq!(ansi.value, V::Text { result: 0, output_valid: true,
            text: S::Ansi(Vec::new()), file_part_offset: None });
        assert_eq!(wide_sizing.last_error, Some(0));
        assert_eq!(wide_sizing.value, V::Text { result: 0, output_valid: false,
            text: S::Wide(Vec::new()), file_part_offset: None });
        assert_eq!(ansi_sizing.last_error, Some(0));
        assert_eq!(ansi_sizing.value, V::Text { result: 0, output_valid: false,
            text: S::Ansi(Vec::new()), file_part_offset: None });
    }
}
