//! Volume and environment APIs; nullable outputs are kept distinct from scalars.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win32HostEnvironmentCall as EC,
    Win32HostImportValue as V, Win32HostServiceOperation as O, Win32HostVolumeCall as VC,
    Win32ImportString as S};
use crate::win32_import_catalog::Win32ImportService as A;
use crate::win32_import_state::{Win32ImportState, Win32ServiceGate};

use super::{Win32GuestReturn, expect_bool, expect_dword, invariant, invoke};
use super::memory::{self, GuestOutput};

pub(super) fn dispatch(state: &mut Win32ImportState, gate: Win32ServiceGate,
    memory: &mut Memory, host: &mut impl RuntimeHost, a: &[u32])
    -> Result<Win32GuestReturn, RuntimeError> {
    match gate.service {
        A::GetLogicalDrives | A::GetDriveTypeA | A::GetDriveTypeW =>
            volume_dword(state, gate, memory, host, a),
        A::GetDiskFreeSpaceA | A::GetDiskFreeSpaceW =>
            disk_space(state, gate, memory, host, a),
        A::GetDiskFreeSpaceExA | A::GetDiskFreeSpaceExW =>
            disk_space_ex(state, gate, memory, host, a),
        A::GetVolumeInformationA | A::GetVolumeInformationW =>
            volume_information(state, gate, memory, host, a),
        A::GetEnvironmentVariableA | A::GetEnvironmentVariableW =>
            environment_get(state, gate, memory, host, a),
        A::SetEnvironmentVariableA | A::SetEnvironmentVariableW =>
            environment_set(state, gate, memory, host, a),
        A::ExpandEnvironmentStringsA | A::ExpandEnvironmentStringsW =>
            environment_expand(state, gate, memory, host, a),
        _ => Err(invariant("query dispatcher received a non-query service")),
    }
}

fn volume_dword(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let call = match gate.service {
        A::GetLogicalDrives => VC::LogicalDrives,
        A::GetDriveTypeA => VC::DriveType { root: optional_root(memory, a[0], false)?, wide: false },
        A::GetDriveTypeW => VC::DriveType { root: optional_root(memory, a[0], true)?, wide: true },
        _ => return Err(invariant("invalid volume DWORD service")),
    };
    Ok(ret(expect_dword(invoke(state, gate, host, O::Volume(call))?)?))
}

fn disk_space(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::GetDiskFreeSpaceW;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(4).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve disk-space output transaction", error))?;
    for pointer in &a[1..5] { outputs.push(GuestOutput::new(memory, *pointer, 4)?); }
    let root = optional_root(memory, a[0], wide)?;
    let value = invoke(state, gate, host, O::Volume(VC::DiskFreeSpace { root, wide }))?;
    let V::DiskFreeSpace { success, sectors_per_cluster, bytes_per_sector,
        free_clusters, total_clusters } = value else {
        return Err(invariant("GetDiskFreeSpace returned a non-space DTO"));
    };
    if success {
        for (output, value) in outputs.iter_mut().zip([
            sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters,
        ]) { output.set(&value.to_le_bytes())?; }
        memory::commit(memory, &mut outputs)?;
    }
    Ok(ret(u32::from(success)))
}

fn disk_space_ex(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::GetDiskFreeSpaceExW;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(3).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve extended disk-space outputs", error))?;
    let mut indices = [None; 3];
    for index in 0..3 {
        if a[index + 1] != 0 {
            indices[index] = Some(outputs.len());
            outputs.push(GuestOutput::new(memory, a[index + 1], 8)?);
        }
    }
    let root = optional_root(memory, a[0], wide)?;
    let value = invoke(state, gate, host, O::Volume(VC::DiskFreeSpaceEx {
        root, wide, available_present: indices[0].is_some(), total_present: indices[1].is_some(),
        free_present: indices[2].is_some(),
    }))?;
    let V::DiskFreeSpaceEx { success, available, total, free } = value else {
        return Err(invariant("GetDiskFreeSpaceEx returned a non-space DTO"));
    };
    if success {
        for (index, value) in indices.into_iter().zip([available, total, free]) {
            if let Some(index) = index { outputs[index].set(&value.to_le_bytes())?; }
        }
        memory::commit(memory, &mut outputs)?;
    }
    Ok(ret(u32::from(success)))
}

fn volume_information(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::GetVolumeInformationW;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(5).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve volume-information outputs", error))?;
    let mut indices = [None; 5];
    if a[1] != 0 { indices[0] = Some(outputs.len());
        outputs.push(optional_text_output(memory, a[1], a[2], wide)?.ok_or_else(||
            super::guest_fault("volume-name output buffer is NULL"))?); }
    for (slot, pointer) in [(1, a[3]), (2, a[4]), (3, a[5])] {
        if pointer != 0 { indices[slot] = Some(outputs.len()); outputs.push(GuestOutput::new(memory, pointer, 4)?); }
    }
    if a[6] != 0 { indices[4] = Some(outputs.len());
        outputs.push(optional_text_output(memory, a[6], a[7], wide)?.ok_or_else(||
            super::guest_fault("filesystem-name output buffer is NULL"))?); }
    let root = optional_root(memory, a[0], wide)?;
    let value = invoke(state, gate, host, O::Volume(VC::VolumeInformation {
        root, wide, volume_name_capacity: a[2], filesystem_name_capacity: a[7],
        volume_name_buffer_present: indices[0].is_some(), filesystem_name_buffer_present: indices[4].is_some(),
        want_serial: indices[1].is_some(), want_maximum_component: indices[2].is_some(),
        want_flags: indices[3].is_some(),
    }))?;
    let V::VolumeInformation { success, volume_name, filesystem_name, serial,
        maximum_component, flags } = value else {
        return Err(invariant("GetVolumeInformation returned an invalid DTO"));
    };
    if success {
        if let Some(index) = indices[0] { set_text(&mut outputs[index], volume_name, wide)?; }
        if let Some(index) = indices[4] { set_text(&mut outputs[index], filesystem_name, wide)?; }
        for (slot, value) in [(1, serial), (2, maximum_component), (3, flags)] {
            if let Some(index) = indices[slot] {
                outputs[index].set(&value.ok_or_else(|| invariant("native volume query omitted requested DWORD"))?.to_le_bytes())?;
            }
        }
        memory::commit(memory, &mut outputs)?;
    }
    Ok(ret(u32::from(success)))
}

fn environment_get(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::GetEnvironmentVariableW;
    let name = memory::read_string(memory, a[0], wide)?;
    let out = optional_text_output(memory, a[1], a[2], wide)?;
    let value = invoke(state, gate, host, O::Environment(EC::Get {
        name, capacity: a[2], output_present: a[1] != 0,
    }))?;
    let V::Text { result, output_valid, text, .. } = value else {
        return Err(invariant("GetEnvironmentVariable returned a non-text DTO"));
    };
    if output_valid {
        let mut out = out.ok_or_else(|| invariant("environment output lacks preflighted storage"))?;
        set_text(&mut out, text, wide)?;
        memory::commit(memory, std::slice::from_mut(&mut out))?;
    }
    Ok(ret(result))
}

fn environment_set(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::SetEnvironmentVariableW;
    let name = memory::read_string(memory, a[0], wide)?;
    let value = if a[1] == 0 { None } else { Some(memory::read_string(memory, a[1], wide)?) };
    Ok(ret(u32::from(expect_bool(invoke(state, gate, host,
        O::Environment(EC::Set { name, value }))?)?)))
}

fn environment_expand(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, a: &[u32]) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::ExpandEnvironmentStringsW;
    let source = memory::read_string(memory, a[0], wide)?;
    let mut out = optional_text_output(memory, a[1], a[2], wide)?;
    let value = invoke(state, gate, host, O::Environment(EC::Expand {
        source, capacity: a[2], output_present: a[1] != 0,
    }))?;
    let V::Text { result, output_valid, text, .. } = value else {
        return Err(invariant("ExpandEnvironmentStrings returned a non-text DTO"));
    };
    if output_valid {
        let output = out.as_mut().ok_or_else(|| invariant(
            "expanded environment output lacks preflighted storage"))?;
        set_text(output, text, wide)?;
        memory::commit(memory, std::slice::from_mut(output))?;
    }
    Ok(ret(result))
}

fn optional_text_output(memory: &mut Memory, pointer: u32, capacity: u32, wide: bool)
    -> Result<Option<GuestOutput>, RuntimeError> {
    if pointer == 0 {
        return if capacity == 0 { Ok(None) }
            else { Err(super::guest_fault("NULL text output has nonzero capacity")) };
    }
    let capacity = usize::try_from(capacity).ok().and_then(|value| value.checked_mul(if wide { 2 } else { 1 }))
        .ok_or_else(|| super::exhausted("PE32 text output capacity"))?;
    GuestOutput::new(memory, pointer, capacity).map(Some)
}

fn optional_root(memory: &mut Memory, pointer: u32, wide: bool)
    -> Result<Option<S>, RuntimeError> {
    if pointer == 0 { Ok(None) } else { memory::read_string(memory, pointer, wide).map(Some) }
}

fn set_text(out: &mut GuestOutput, value: S, wide: bool) -> Result<(), RuntimeError> {
    match (value, wide) {
        (S::Ansi(text), false) => out.set_ansi(&text, true),
        (S::Wide(text), true) => out.set_wide(&text, true),
        _ => Err(invariant("native query output encoding differs from API")),
    }
}

fn ret(eax: u32) -> Win32GuestReturn { Win32GuestReturn { eax: Some(eax), edx: None } }
