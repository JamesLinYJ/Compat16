//! KERNEL32 directory/path services with byte-vs-WCHAR capacity translation.

use guest_core::memory::Memory;

use crate::{RuntimeError, RuntimeHost, Win32HostImportValue as V, Win32HostPathCall as C,
    Win32HostServiceOperation as O, Win32ImportString as S, Win32ImportTextEncoding as E,
    Win32PathQuery as Q, Win32PathTransform as T};
use crate::win32_import_catalog::Win32ImportService as A;
use crate::win32_import_state::{Win32ImportState, Win32ServiceGate};

use super::{Win32GuestReturn, expect_bool, guest_fault, invariant, invoke};
use super::memory::{self, GuestOutput};

pub(super) fn dispatch(
    state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32],
) -> Result<Win32GuestReturn, RuntimeError> {
    match gate.service {
        A::SetCurrentDirectoryA | A::SetCurrentDirectoryW => {
            let path = memory::read_string(memory, a[0], gate.service == A::SetCurrentDirectoryW)?;
            let success = expect_bool(invoke(state, gate, host,
                O::Path(C::SetCurrentDirectory { path }))?)?;
            Ok(ret(u32::from(success)))
        }
        A::GetFullPathNameA | A::GetFullPathNameW |
        A::GetLongPathNameA | A::GetLongPathNameW |
        A::GetShortPathNameA | A::GetShortPathNameW => transform(state, gate, memory, host, a),
        A::GetCurrentDirectoryA | A::GetCurrentDirectoryW | A::GetSystemDirectoryA
        | A::GetSystemDirectoryW | A::GetWindowsDirectoryA | A::GetWindowsDirectoryW
        | A::GetTempPathA | A::GetTempPathW => query(state, gate, memory, host, a),
        _ => Err(invariant("path dispatcher received a non-path service")),
    }
}

fn query(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let (kind, capacity, pointer, wide) = match gate.service {
        A::GetCurrentDirectoryA => (Q::CurrentDirectory, a[0], a[1], false),
        A::GetCurrentDirectoryW => (Q::CurrentDirectory, a[0], a[1], true),
        A::GetSystemDirectoryA => (Q::SystemDirectory, a[1], a[0], false),
        A::GetSystemDirectoryW => (Q::SystemDirectory, a[1], a[0], true),
        A::GetWindowsDirectoryA => (Q::WindowsDirectory, a[1], a[0], false),
        A::GetWindowsDirectoryW => (Q::WindowsDirectory, a[1], a[0], true),
        A::GetTempPathA => (Q::TempPath, a[0], a[1], false),
        A::GetTempPathW => (Q::TempPath, a[0], a[1], true),
        _ => return Err(invariant("invalid directory-query service")),
    };
    let output = output(memory, pointer, capacity, wide)?;
    let value = invoke(state, gate, host, O::Path(C::Query { kind,
        encoding: if wide { E::Wide } else { E::Ansi }, capacity,
        output_present: pointer != 0 }))?;
    let V::Text { result, output_valid, text, .. } = value else {
        return Err(invariant("directory query returned a non-text DTO"));
    };
    if output_valid {
        let mut output = output.ok_or_else(|| invariant("native path output lacks guest storage"))?;
        set_text(&mut output, text, wide, true)?;
        memory::commit(memory, std::slice::from_mut(&mut output))?;
    }
    Ok(ret(result))
}

fn transform(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = matches!(gate.service, A::GetFullPathNameW | A::GetLongPathNameW | A::GetShortPathNameW);
    let (kind, path, capacity, pointer, part_pointer) = match gate.service {
        A::GetFullPathNameA | A::GetFullPathNameW =>
            (T::Full, memory::read_string(memory, a[0], wide)?, a[1], a[2], Some(a[3])),
        A::GetLongPathNameA | A::GetLongPathNameW =>
            (T::Long, memory::read_string(memory, a[0], wide)?, a[2], a[1], None),
        A::GetShortPathNameA | A::GetShortPathNameW =>
            (T::Short, memory::read_string(memory, a[0], wide)?, a[2], a[1], None),
        _ => return Err(invariant("invalid path transform service")),
    };
    let output = output(memory, pointer, capacity, wide)?;
    let file_part = if let Some(pointer) = part_pointer.filter(|value| *value != 0) {
        Some(GuestOutput::new(memory, pointer, 4)?)
    } else { None };
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
        crate::DiagnosticKind::ResourceExhausted, "reserve path output transaction", error))?;
    let output_index = output.map(|output| { outputs.push(output); outputs.len() - 1 });
    let file_part_index = file_part.map(|output| { outputs.push(output); outputs.len() - 1 });
    let value = invoke(state, gate, host, O::Path(C::Transform {
        kind, path, capacity, output_present: pointer != 0,
        request_file_part: part_pointer.is_some_and(|value| value != 0),
    }))?;
    let V::Text { result, output_valid, text, file_part_offset } = value else {
        return Err(invariant("path transform returned a non-text DTO"));
    };
    if output_valid {
        let output_buffer = output_index.and_then(|index| outputs.get_mut(index))
            .ok_or_else(|| invariant("path output lacks guest storage"))?;
        set_text(output_buffer, text, wide, true)?;
        if let Some(index) = file_part_index {
            let out = outputs.get_mut(index).ok_or_else(|| invariant("file-part output disappeared"))?;
            let offset = file_part_offset.unwrap_or(u32::MAX);
            let unit = if wide { 2 } else { 1 };
            let address = if offset == u32::MAX { 0 } else {
                pointer.checked_add(offset.checked_mul(unit).ok_or_else(||
                    super::exhausted("GetFullPathName file-part pointer"))?)
                    .ok_or_else(|| guest_fault("GetFullPathName file-part pointer wraps"))?
            };
            out.set(&address.to_le_bytes())?;
        }
        memory::commit(memory, &mut outputs)?;
    }
    Ok(ret(result))
}

fn output(memory: &mut Memory, pointer: u32, capacity: u32, wide: bool)
    -> Result<Option<GuestOutput>, RuntimeError> {
    if pointer == 0 {
        return if capacity == 0 { Ok(None) }
            else { Err(guest_fault("NULL path output has nonzero capacity")) };
    }
    let bytes = usize::try_from(capacity).ok().and_then(|units| units.checked_mul(if wide { 2 } else { 1 }))
        .ok_or_else(|| super::exhausted("PE32 path output capacity"))?;
    GuestOutput::new(memory, pointer, bytes).map(Some)
}

fn set_text(output: &mut GuestOutput, text: S, wide: bool, terminate: bool)
    -> Result<(), RuntimeError> {
    match (text, wide) {
        (S::Ansi(text), false) => output.set_ansi(&text, terminate),
        (S::Wide(text), true) => output.set_wide(&text, terminate),
        _ => Err(invariant("native path output encoding differs from guest API")),
    }
}

fn ret(eax: u32) -> Win32GuestReturn { Win32GuestReturn { eax: Some(eax), edx: None } }
