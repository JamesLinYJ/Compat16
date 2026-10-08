//! File API argument codecs and owned guest-handle publication.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win32HostFileCall as C,
    Win32HostImportValue as V, Win32HostServiceOperation as O, Win32ImportString as S};
use crate::win32_import_catalog::Win32ImportService as A;
use crate::win32_import_state::{Win32ImportState, Win32ServiceGate};

use super::{Win32GuestReturn, expect_bool, expect_dword, guest_fault, invariant, invoke};
use super::memory::{self, GuestOutput};

#[path = "files_search.rs"]
mod search;

pub(super) fn dispatch(
    state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32],
) -> Result<Win32GuestReturn, RuntimeError> {
    let result = match gate.service {
        A::CreateFileA | A::CreateFileW => create_file(state, gate, memory, host, a)?,
        A::ReadFile => read_file(state, gate, memory, host, a)?,
        A::WriteFile => write_file(state, gate, memory, host, a)?,
        A::CloseHandle => close_handle(state, gate, host, a[0])?,
        A::FindFirstFileA | A::FindFirstFileW | A::FindFirstFileExA | A::FindFirstFileExW =>
            search::first(state, gate, memory, host, a)?,
        A::FindNextFileA | A::FindNextFileW => search::next(state, gate, memory, host, a)?,
        A::FindClose => search::close(state, gate, host, a[0])?,
        A::DeleteFileA | A::DeleteFileW => bool_call(state, gate, host,
            C::Delete { path: string(memory, a[0], gate.service == A::DeleteFileW)? })?,
        A::MoveFileA | A::MoveFileW => bool_call(state, gate, host, C::Move {
            from: string(memory, a[0], gate.service == A::MoveFileW)?,
            to: string(memory, a[1], gate.service == A::MoveFileW)?,
        })?,
        A::CopyFileA | A::CopyFileW => bool_call(state, gate, host, C::Copy {
            from: string(memory, a[0], gate.service == A::CopyFileW)?,
            to: string(memory, a[1], gate.service == A::CopyFileW)?, fail_if_exists: a[2] != 0,
        })?,
        A::CreateDirectoryA | A::CreateDirectoryW => {
            if a[1] != 0 { return Err(gap("CreateDirectory security attributes are not translated")); }
            bool_call(state, gate, host, C::CreateDirectory {
                path: string(memory, a[0], gate.service == A::CreateDirectoryW)?,
            })?
        }
        A::RemoveDirectoryA | A::RemoveDirectoryW => bool_call(state, gate, host,
            C::RemoveDirectory { path: string(memory, a[0], gate.service == A::RemoveDirectoryW)? })?,
        A::GetFileAttributesA | A::GetFileAttributesW => dword_call(state, gate, host,
            C::GetAttributes { path: string(memory, a[0], gate.service == A::GetFileAttributesW)? })?,
        A::SetFileAttributesA | A::SetFileAttributesW => bool_call(state, gate, host,
            C::SetAttributes { path: string(memory, a[0], gate.service == A::SetFileAttributesW)?,
                attributes: a[1] })?,
        A::GetFileType => file_type(state, gate, host, a[0])?,
        A::GetFileSize => file_size(state, gate, memory, host, a[0], a[1])?,
        A::GetFileSizeEx => file_size_ex(state, gate, memory, host, a[0], a[1])?,
        A::SetFilePointer => file_pointer(state, gate, memory, host, a)?,
        A::SetEndOfFile | A::FlushFileBuffers => unary_handle(state, gate, host, a[0])?,
        _ => return Err(gap("unimplemented PE32 file service")),
    };
    Ok(result)
}

fn create_file(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    if a[3] != 0 { return Err(gap("CreateFile security attributes are not translated")); }
    const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    if a[5] & (FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED) != 0 {
        return Err(gap("CreateFile no-buffering and overlapped I/O need aligned/pending buffer ownership"));
    }
    let path = string(memory, a[0], gate.service == A::CreateFileW)?;
    let template = if a[6] == 0 { None } else { state.native_handle(a[6]) };
    if a[6] != 0 && template.is_none() {
        state.set_last_error(6);
        return Ok(ret(u32::MAX));
    }
    let reservation = state.reserve_guest_handle()?;
    let value = match invoke(state, gate, host, O::File(C::Create { path,
        desired_access: a[1], share_mode: a[2], creation_disposition: a[4],
        flags_and_attributes: a[5], template })) {
        Ok(value) => value,
        Err(primary) => {
            let cleanup = state.cancel_guest_handle(reservation).err();
            return Err(match cleanup { Some(cleanup) => combine(primary, cleanup), None => primary });
        }
    };
    match value {
        V::FileHandle(Some(handle)) => Ok(ret(state.publish_guest_handle(reservation, handle)?)),
        V::FileHandle(None) => { state.cancel_guest_handle(reservation)?; Ok(ret(u32::MAX)) }
        _ => { state.cancel_guest_handle(reservation)?; Err(invariant("CreateFile returned a non-handle DTO")) }
    }
}

fn read_file(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    if a[4] != 0 { return Err(gap("asynchronous ReadFile OVERLAPPED is unsupported")); }
    let capacity = usize::try_from(a[2]).map_err(|_| exhausted("ReadFile buffer"))?;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve ReadFile output transaction", error))?;
    if capacity != 0 { outputs.push(GuestOutput::new(memory, a[1], capacity)?); }
    let count_out = GuestOutput::new(memory, a[3], 4)?;
    outputs.push(count_out);
    let count_index = outputs.len() - 1;
    let Some(handle) = state.native_handle(a[0]) else {
        outputs[count_index].set(&0_u32.to_le_bytes())?;
        memory::commit(memory, &mut outputs)?;
        state.set_last_error(6);
        return Ok(ret(0));
    };
    let value = invoke(state, gate, host, O::File(C::Read { handle, capacity: a[2] }))?;
    let V::Transfer { success, bytes, count } = value else {
        return Err(invariant("ReadFile returned a non-transfer DTO"));
    };
    if usize::try_from(count).map_or(true, |value| value > capacity) || bytes.len() != count as usize {
        return Err(invariant("ReadFile returned a byte span inconsistent with its native count"));
    }
    if capacity != 0 { outputs[0].set(&bytes)?; }
    outputs[count_index].set(&count.to_le_bytes())?;
    memory::commit(memory, &mut outputs)?;
    Ok(ret(u32::from(success)))
}

fn write_file(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    if a[4] != 0 { return Err(gap("asynchronous WriteFile OVERLAPPED is unsupported")); }
    let mut written = GuestOutput::new(memory, a[3], 4)?;
    let Some(handle) = state.native_handle(a[0]) else {
        written.set(&0_u32.to_le_bytes())?;
        memory::commit(memory, std::slice::from_mut(&mut written))?;
        state.set_last_error(6);
        return Ok(ret(0));
    };
    let length = usize::try_from(a[2]).map_err(|_| exhausted("WriteFile input"))?;
    if length != 0 && a[1] == 0 { return Err(guest_fault("WriteFile input buffer is NULL with nonzero length")); }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy WriteFile input", error))?;
    bytes.resize(length, 0);
    if length != 0 { memory::read_exact(memory, a[1], &mut bytes)?; }
    let value = invoke(state, gate, host, O::File(C::Write { handle, bytes }))?;
    let V::Transfer { success, count, bytes, .. } = value else {
        return Err(invariant("WriteFile returned a non-transfer DTO"));
    };
    if !bytes.is_empty() || count > a[2] { return Err(invariant("WriteFile returned invalid output")); }
    written.set(&count.to_le_bytes())?;
    memory::commit(memory, std::slice::from_mut(&mut written))?;
    Ok(ret(u32::from(success)))
}

fn close_handle(state: &mut Win32ImportState, gate: Win32ServiceGate, host: &mut impl RuntimeHost,
    value: u32) -> Result<Win32GuestReturn, RuntimeError> {
    let handle = match state.begin_close_handle(value) {
        Ok(handle) => handle,
        Err(error) if error.kind() == Kind::GuestFault => { state.set_last_error(6); return Ok(ret(0)); }
        Err(error) => return Err(error),
    };
    let result = invoke(state, gate, host, O::File(C::Close { handle }));
    match result {
        Ok(V::Bool(closed)) => { state.finish_close_handle(value, closed)?; Ok(ret(u32::from(closed))) }
        Ok(_) => { state.finish_close_handle(value, false)?; Err(invariant("CloseHandle returned a non-BOOL DTO")) }
        Err(primary) => { let cleanup = state.finish_close_handle(value, false).err();
            Err(match cleanup { Some(cleanup) => combine(primary, cleanup), None => primary }) }
    }
}

fn file_type(state: &mut Win32ImportState, gate: Win32ServiceGate, host: &mut impl RuntimeHost,
    value: u32) -> Result<Win32GuestReturn, RuntimeError> {
    let Some(handle) = state.native_handle(value) else { state.set_last_error(6); return Ok(ret(0)); };
    dword_call(state, gate, host, C::GetType { handle })
}

fn file_size(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, value: u32, high: u32) -> Result<Win32GuestReturn, RuntimeError> {
    let Some(handle) = state.native_handle(value) else { state.set_last_error(6); return Ok(ret(u32::MAX)); };
    let mut out = if high == 0 { None } else { Some(GuestOutput::new(memory, high, 4)?) };
    let value = invoke(state, gate, host, O::File(C::GetSize { handle, high_output: high != 0 }))?;
    let V::FileSize { success, low, high: high_value } = value else {
        return Err(invariant("GetFileSize returned a non-size DTO"));
    };
    if let Some(out) = out.as_mut() {
        let high_value = high_value.ok_or_else(|| invariant("GetFileSize omitted requested high DWORD"))?;
        out.set(&high_value.to_le_bytes())?;
        memory::commit(memory, std::slice::from_mut(out))?;
    }
    if !success && low != u32::MAX { return Err(invariant("failed GetFileSize returned a non-error low DWORD")); }
    Ok(ret(low))
}

fn file_size_ex(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, value: u32, pointer: u32) -> Result<Win32GuestReturn, RuntimeError> {
    let Some(handle) = state.native_handle(value) else { state.set_last_error(6); return Ok(ret(0)); };
    let mut out = GuestOutput::new(memory, pointer, 8)?;
    let result = invoke(state, gate, host, O::File(C::GetSizeEx { handle }))?;
    let V::FileSize { success, low, high: Some(high) } = result else {
        return Err(invariant("GetFileSizeEx returned an incomplete size DTO"));
    };
    if success { let mut bytes = [0; 8]; bytes[..4].copy_from_slice(&low.to_le_bytes());
        bytes[4..].copy_from_slice(&high.to_le_bytes()); out.set(&bytes)?; }
    memory::commit(memory, std::slice::from_mut(&mut out))?;
    Ok(ret(u32::from(success)))
}

fn file_pointer(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let Some(handle) = state.native_handle(a[0]) else { state.set_last_error(6); return Ok(ret(u32::MAX)); };
    let mut high = if a[2] == 0 { None } else { Some(GuestOutput::new(memory, a[2], 4)?) };
    let initial_high = if a[2] == 0 { None } else { Some(memory::read_u32(memory, a[2])? as i32) };
    let value = invoke(state, gate, host, O::File(C::SetPointer { handle,
        low: a[1] as i32, high: initial_high, method: a[3] }))?;
    let V::FilePosition { success, low, high: high_value } = value else {
        return Err(invariant("SetFilePointer returned a non-position DTO"));
    };
    if let Some(out) = high.as_mut() {
        let high_value = high_value.ok_or_else(|| invariant("SetFilePointer omitted requested high DWORD"))?;
        out.set(&high_value.to_le_bytes())?;
        memory::commit(memory, std::slice::from_mut(out))?;
    }
    if !success && low != u32::MAX { return Err(invariant("failed SetFilePointer returned a valid low DWORD")); }
    Ok(ret(low))
}

fn unary_handle(state: &mut Win32ImportState, gate: Win32ServiceGate,
    host: &mut impl RuntimeHost, value: u32) -> Result<Win32GuestReturn, RuntimeError> {
    let Some(handle) = state.native_handle(value) else { state.set_last_error(6); return Ok(ret(0)); };
    let call = if gate.service == A::SetEndOfFile { C::SetEndOfFile { handle } }
        else { C::Flush { handle } };
    bool_call(state, gate, host, call)
}

fn bool_call(state: &mut Win32ImportState, gate: Win32ServiceGate, host: &mut impl RuntimeHost,
    call: C) -> Result<Win32GuestReturn, RuntimeError> {
    Ok(ret(u32::from(expect_bool(invoke(state, gate, host, O::File(call))?)?)))
}

fn dword_call(state: &mut Win32ImportState, gate: Win32ServiceGate, host: &mut impl RuntimeHost,
    call: C) -> Result<Win32GuestReturn, RuntimeError> {
    Ok(ret(expect_dword(invoke(state, gate, host, O::File(call))?)?))
}

fn string(memory: &mut Memory, value: u32, wide: bool) -> Result<S, RuntimeError> {
    memory::read_string(memory, value, wide)
}
fn ret(eax: u32) -> Win32GuestReturn { Win32GuestReturn { eax: Some(eax), edx: None } }
fn gap(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::CompatibilityGap, message) }
fn exhausted(message: &'static str) -> RuntimeError { super::exhausted(message) }
fn combine(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    primary.with_cleanup("PE32 file-service cleanup failed", cleanup)
}
