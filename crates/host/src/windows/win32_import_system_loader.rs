//! Module-name queries for host-owned native System32 references.

use runtime::{DiagnosticKind as Kind, RuntimeError, Win32HostImportResult,
    Win32HostImportValue as V, Win32HostLoaderCall as C, Win32ImportString as S,
    Win32ImportTextEncoding as E};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, ERROR_INSUFFICIENT_BUFFER},
    System::LibraryLoader::GetModuleFileNameW,
};

use super::super::guest_text::GuestTextCodec;
use super::{Win32ImportSystem, result, text};

/// Classify the runtime's copied guest-code-page path without loading or
/// executing it. System-directory comparison uses host-owned UTF-16 paths.
pub(super) fn is_system_directory_path(path: S, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> {
    let S::Ansi(path) = path else {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "module search path provenance requires the guest ANSI path"));
    };
    if path.is_empty() || path.contains(&0) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "module search path is empty or contains NUL"));
    }
    let path = text::to_wide_z(codec, S::Ansi(path),
        "module search path contains embedded NUL")?;
    let path = &path[..path.len() - 1];
    let directory = super::system_directory()?;
    Ok(result(V::Bool(is_direct_child_path(path, &directory)), None))
}

fn is_direct_child_path(path: &[u16], directory: &[u16]) -> bool {
    if path.len() <= directory.len() + 1
        || !path.get(..directory.len()).is_some_and(|prefix| wide_path_eq(prefix, directory))
        || !path.get(directory.len()).is_some_and(|unit| matches!(*unit, 0x2f | 0x5c))
    { return false; }
    !path[directory.len() + 1..].iter().any(|unit| matches!(*unit, 0x2f | 0x5c))
}

fn wide_path_eq(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| {
        let normalize = |unit: u16| {
            let unit = if unit == 0x2f { 0x5c } else { unit };
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) { unit + 0x20 } else { unit }
        };
        normalize(*left) == normalize(*right)
    })
}

pub(super) fn execute(
    system: &mut Win32ImportSystem, call: C,
) -> Result<Win32HostImportResult, RuntimeError> {
    match call {
        C::LoadSystemModule { basename, owner } => system.load_system_module(basename, owner),
        C::FreeSystemModule { module, owner } => system.free_system_module(module, owner),
        C::GetModuleHandle { expected, name } => {
            let owner = system.modules.iter().find(|entry| entry.id == expected.host_id())
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "GetModuleHandle received a stale system-module token"))?;
            let name = text::to_wide_z(system.codec, name,
                "GetModuleHandle module name contains embedded NUL")?;
            // SAFETY: the expected HMODULE remains owned by the host table;
            // this terminated UTF-16 lookup does not acquire another reference.
            unsafe { SetLastError(0); }
            let raw = unsafe { windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(name.as_ptr()) };
            let same = raw == owner.raw;
            let error = (!same).then(|| unsafe { GetLastError() });
            Ok(result(V::Bool(same), error))
        }
        C::GetModuleFileName { module, encoding, capacity } => {
            let owner = system.modules.iter().find(|entry| entry.id == module.host_id())
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "GetModuleFileName received a stale system-module token"))?;
            module_file_name(owner.raw, encoding, capacity, system.codec)
        }
    }
}

fn module_file_name(module: windows_sys::Win32::Foundation::HMODULE,
    encoding: E, capacity: u32, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> {
    match encoding {
        E::Wide => module_file_name_wide(module, capacity),
        E::Ansi => module_file_name_ansi(module, capacity, codec),
    }
}

fn module_file_name_wide(module: windows_sys::Win32::Foundation::HMODULE, capacity: u32)
    -> Result<Win32HostImportResult, RuntimeError> {
    let capacity_usize = usize::try_from(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "PE32 module-name capacity does not fit host indexing", error))?;
    let allocation = capacity_usize.max(1);
    let mut output = Vec::new();
    output.try_reserve_exact(allocation).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve GetModuleFileNameW host buffer", error))?;
    output.resize(allocation, 0xFFFF_u16);
    unsafe { SetLastError(0); }
    // SAFETY: module is table-owned. Output is host-owned for at least one
    // unit; the native API still receives the guest's original capacity.
    let written = unsafe { GetModuleFileNameW(module, output.as_mut_ptr(), capacity) };
    let native_error = unsafe { GetLastError() };
    let length = if capacity == 0 { 0 } else {
        output[..capacity_usize].iter().position(|unit| *unit == 0)
            .map_or_else(|| usize::try_from(written).unwrap_or(capacity_usize).min(capacity_usize),
                |index| index + 1)
    };
    let terminated = length != 0 && output[length - 1] == 0;
    output.truncate(length);
    let error = (written == 0 || written == capacity).then_some(native_error);
    Ok(result(V::ModuleFileName { result: written,
        output_valid: capacity != 0 && written != 0, output: S::Wide(output), terminated }, error))
}

fn module_file_name_ansi(module: windows_sys::Win32::Foundation::HMODULE,
    capacity: u32, codec: GuestTextCodec) -> Result<Win32HostImportResult, RuntimeError> {
    let path = super::module_path(module)?;
    let capacity_usize = usize::try_from(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "PE32 ANSI module-name capacity does not fit host indexing", error))?;
    if capacity_usize == 0 {
        return Ok(result(V::ModuleFileName { result: 0, output_valid: false,
            output: S::Ansi(Vec::new()), terminated: false }, Some(ERROR_INSUFFICIENT_BUFFER)));
    }
    let encoded = text::from_wide(codec, &path)?;
    let required = encoded.len().checked_add(1)
        .ok_or_else(|| exhausted("ANSI module path"))?;
    if required <= capacity_usize {
        let length = u32::try_from(encoded.len()).map_err(|_| exhausted("ANSI module path"))?;
        let output = append_nul(encoded)?;
        return Ok(result(V::ModuleFileName { result: length, output_valid: true,
            output: S::Ansi(output), terminated: true }, None));
    }

    // GetModuleFileNameA counts bytes. Leave one byte for the guest NUL and
    // let the shared codec stop at a complete guest-code-page character.
    let bounded = codec.from_wide_bounded(&path, capacity_usize - 1)?;
    let output = append_nul(bounded.bytes)?;
    Ok(result(V::ModuleFileName { result: capacity, output_valid: true,
        output: S::Ansi(output), terminated: true }, Some(ERROR_INSUFFICIENT_BUFFER)))
}

fn append_nul(mut bytes: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
    bytes.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "terminate guest ANSI module path", error))?;
    bytes.push(0);
    Ok(bytes)
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn ansi_module_path_uses_fixed_codec_and_retains_native_module_path() {
        let codec = cp936();
        // SAFETY: NULL asks Windows for the current process image module.
        let module = unsafe { GetModuleHandleW(std::ptr::null()) };
        assert!(!module.is_null());
        let native_path = super::super::module_path(module).unwrap();
        let expected = text::from_wide(codec, &native_path).unwrap();
        let capacity = u32::try_from(expected.len() + 1).unwrap();

        let result = module_file_name_ansi(module, capacity, codec).unwrap();
        let runtime::Win32HostImportValue::ModuleFileName { result, output_valid,
            output: S::Ansi(output), terminated } = result.value else {
            panic!("ANSI module query must return its typed module-path DTO");
        };
        assert!(output_valid);
        assert!(terminated);
        assert_eq!(result as usize, expected.len());
        assert_eq!(output, [expected, vec![0]].concat());
    }
}
