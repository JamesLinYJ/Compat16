//! Task LastError and system-query structure codecs for PE32 services.

use guest_core::{memory::Memory, GuestMemory};
use x86_cpu::Cpu;
use zerocopy::IntoBytes;
use zerocopy::byteorder::{U16, U32};

#[path = "system_wire.rs"]
mod wire;
use wire::{
    PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_INTEL_486, PROCESSOR_INTEL_PENTIUM, SystemInfo32,
};

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win32HostImportValue as V,
    Win32HostServiceOperation as O, Win32HostSystemCall as C, Win32ImportTextEncoding as E};
use crate::win32_import_catalog::Win32ImportService as A;
use crate::win32_import_state::{Win32ImportState, Win32ServiceGate};

use super::{Win32GuestReturn, expect_dword, invariant, invoke};
use super::memory::{self, GuestOutput};

pub(super) fn runtime_service(state: &mut Win32ImportState, service: A, a: &[u32])
    -> Result<Win32GuestReturn, RuntimeError> {
    match service {
        A::GetLastError => Ok(ret(state.last_error())),
        A::SetLastError => { state.set_last_error(a[0]); Ok(Win32GuestReturn { eax: None, edx: None }) }
        _ => Err(invariant("runtime dispatcher received a non-runtime service")),
    }
}

pub(super) fn dispatch(state: &mut Win32ImportState, gate: Win32ServiceGate, cpu: &Cpu,
    memory: &mut Memory, host: &mut impl RuntimeHost, a: &[u32])
    -> Result<Win32GuestReturn, RuntimeError> {
    match gate.service {
        A::GetVersion | A::GetTickCount | A::GetCurrentProcessId | A::GetCurrentThreadId => {
            let call = match gate.service {
                A::GetVersion => C::Version,
                A::GetTickCount => C::TickCount,
                A::GetCurrentProcessId => C::ProcessId,
                A::GetCurrentThreadId => C::ThreadId,
                _ => return Err(invariant("invalid scalar system service")),
            };
            Ok(ret(expect_dword(invoke(state, gate, host, O::System(call))?)?))
        }
        A::GetVersionExA | A::GetVersionExW => version_info(state, gate, memory, host, a[0]),
        A::GetSystemTime | A::GetLocalTime => {
            // SYSTEMTIME is eight little-endian WORDs in PE32; a host struct
            // copy would depend on native alignment instead of guest offsets.
            let mut output = GuestOutput::new(memory, a[0], 16)?;
            let local = gate.service == A::GetLocalTime;
            let value = invoke(state, gate, host, O::System(C::SystemTime { local }))?;
            let V::SystemTime(fields) = value else { return Err(invariant("system time DTO mismatch")); };
            let mut bytes = [0_u8; 16];
            for (index, field) in fields.into_iter().enumerate() {
                bytes[index * 2..index * 2 + 2].copy_from_slice(&field.to_le_bytes());
            }
            output.set(&bytes)?;
            memory::commit(memory, std::slice::from_mut(&mut output))?;
            Ok(Win32GuestReturn { eax: None, edx: None })
        }
        A::GetSystemTimeAsFileTime => {
            let mut output = GuestOutput::new(memory, a[0], 8)?;
            let value = invoke(state, gate, host, O::System(C::SystemTimeAsFileTime))?;
            let V::FileTime(value) = value else { return Err(invariant("FILETIME DTO mismatch")); };
            output.set(&value.to_le_bytes())?;
            memory::commit(memory, std::slice::from_mut(&mut output))?;
            Ok(Win32GuestReturn { eax: None, edx: None })
        }
        A::QueryPerformanceCounter | A::QueryPerformanceFrequency => {
            let mut output = GuestOutput::new(memory, a[0], 8)?;
            let frequency = gate.service == A::QueryPerformanceFrequency;
            let value = invoke(state, gate, host, O::System(C::QueryPerformance { frequency }))?;
            let V::ScalarQuery { success, value } = value else {
                return Err(invariant("performance query DTO mismatch"));
            };
            if success { output.set(&value.to_le_bytes())?; }
            memory::commit(memory, std::slice::from_mut(&mut output))?;
            Ok(ret(u32::from(success)))
        }
        A::GetSystemInfo | A::GetNativeSystemInfo => system_info(state, gate, cpu, memory, host, a[0]),
        _ => Err(invariant("system dispatcher received a non-system service")),
    }
}

fn version_info(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, pointer: u32) -> Result<Win32GuestReturn, RuntimeError> {
    // These fixed PE32 records are encoded field-by-field because the host
    // windows-sys structs use native pointer width/alignment; the guest wire
    // contract is little-endian with 32-bit fields and guest-owned extents.
    let mut header = [0_u8; 4];
    memory::read_exact(memory, pointer, &mut header)?;
    let size = u32::from_le_bytes(header);
    let wide = gate.service == A::GetVersionExW;
    let base_size = if wide { 276 } else { 148 };
    let extended_size = base_size + 8;
    if size != base_size && size != extended_size {
        state.set_last_error(87);
        return Ok(ret(0));
    }
    let length = usize::try_from(size).map_err(|_| super::exhausted("OSVERSIONINFO"))?;
    let mut output = GuestOutput::new(memory, pointer, length)?;
    let value = invoke(state, gate, host, O::System(C::VersionInfo {
        encoding: if wide { E::Wide } else { E::Ansi }, extended: size == extended_size,
    }))?;
    let V::VersionInfo { success, major, minor, build, platform, service_pack,
        service_pack_major, service_pack_minor, suite_mask, product_type } = value else {
        return Err(invariant("GetVersionEx returned an incompatible DTO"));
    };
    if success {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "stage guest OSVERSIONINFO", error))?;
        bytes.resize(length, 0);
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        bytes[4..8].copy_from_slice(&major.to_le_bytes());
        bytes[8..12].copy_from_slice(&minor.to_le_bytes());
        bytes[12..16].copy_from_slice(&build.to_le_bytes());
        bytes[16..20].copy_from_slice(&platform.to_le_bytes());
        match (service_pack, wide) {
            (crate::Win32ImportString::Ansi(text), false) => {
                if text.len() >= 128 { return Err(invariant("native service-pack string exceeds guest field")); }
                bytes[20..20 + text.len()].copy_from_slice(&text);
            }
            (crate::Win32ImportString::Wide(text), true) => {
                if text.len() >= 128 { return Err(invariant("native service-pack string exceeds guest field")); }
                for (index, unit) in text.into_iter().enumerate() {
                    bytes[20 + index * 2..22 + index * 2].copy_from_slice(&unit.to_le_bytes());
                }
            }
            _ => return Err(invariant("GetVersionEx text encoding changed")),
        }
        if size == extended_size {
            bytes[base_size as usize..base_size as usize + 2].copy_from_slice(&service_pack_major.to_le_bytes());
            bytes[base_size as usize + 2..base_size as usize + 4].copy_from_slice(&service_pack_minor.to_le_bytes());
            bytes[base_size as usize + 4..base_size as usize + 6].copy_from_slice(&suite_mask.to_le_bytes());
            bytes[base_size as usize + 6] = product_type;
        }
        output.set(&bytes)?;
        memory::commit(memory, std::slice::from_mut(&mut output))?;
    }
    Ok(ret(u32::from(success)))
}

fn system_info(state: &mut Win32ImportState, gate: Win32ServiceGate, cpu: &Cpu,
    memory: &mut Memory, host: &mut impl RuntimeHost, pointer: u32)
    -> Result<Win32GuestReturn, RuntimeError> {
    // Native SYSTEM_INFO has host-width pointers. Project owned scalar data
    // into the fixed little-endian PE32 wire; never copy the native layout.
    let mut output = GuestOutput::new(memory, pointer, SystemInfo32::BYTE_LEN)?;
    let native = gate.service == A::GetNativeSystemInfo;
    let wire = if native {
        let value = invoke(state, gate, host, O::System(C::SystemInfo { native: true }))?;
        let V::SystemInfo { architecture, page_size, minimum_address, maximum_address,
            active_processor_mask, processor_count, processor_type, allocation_granularity,
            processor_level, processor_revision } = value else {
                return Err(invariant("GetNativeSystemInfo returned an incompatible DTO"));
            };
        if minimum_address > u64::from(u32::MAX) || maximum_address > u64::from(u32::MAX)
            || active_processor_mask > u64::from(u32::MAX) {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "native SYSTEM_INFO contains values not representable by PE32 pointers"));
        }
        SystemInfo32 {
            architecture: U16::new(architecture),
            reserved: U16::new(0),
            page_size: U32::new(page_size),
            minimum_address: U32::new(minimum_address as u32),
            maximum_address: U32::new(maximum_address as u32),
            active_processor_mask: U32::new(active_processor_mask as u32),
            processor_count: U32::new(processor_count),
            processor_type: U32::new(processor_type),
            allocation_granularity: U32::new(allocation_granularity),
            processor_level: U16::new(processor_level),
            processor_revision: U16::new(processor_revision),
        }
    } else {
        // Report the configured guest model; GetSystemInfo must not identify the host CPU.
        let processor_level = cpu.model().architecture_family();
        let processor_type = match processor_level {
            4 => PROCESSOR_INTEL_486,
            5 | 6 => PROCESSOR_INTEL_PENTIUM,
            _ => return Err(invariant("unsupported guest CPU family for SYSTEM_INFO")),
        };
        let end = memory.len().checked_sub(1).ok_or_else(|| invariant("guest RAM is empty"))?;
        SystemInfo32 {
            architecture: U16::new(PROCESSOR_ARCHITECTURE_INTEL),
            reserved: U16::new(0),
            page_size: U32::new(0x1000),
            minimum_address: U32::new(0),
            maximum_address: U32::new(end),
            active_processor_mask: U32::new(1),
            processor_count: U32::new(1),
            processor_type: U32::new(processor_type),
            allocation_granularity: U32::new(0x10000),
            processor_level: U16::new(u16::from(processor_level)),
            processor_revision: U16::new(0),
        }
    };
    output.set(wire.as_bytes())?;
    memory::commit(memory, std::slice::from_mut(&mut output))?;
    Ok(Win32GuestReturn { eax: None, edx: None })
}

fn ret(eax: u32) -> Win32GuestReturn { Win32GuestReturn { eax: Some(eax), edx: None } }
