use std::mem::size_of;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win32HostImportResult,
    Win32HostImportValue as V, Win32HostSystemCall as C, Win32ImportString as S,
    Win32ImportTextEncoding as E};
use windows_sys::Win32::{
    Foundation::{FILETIME, SYSTEMTIME},
    System::{SystemInformation::{GetLocalTime, GetNativeSystemInfo, GetSystemInfo,
        GetSystemTime, GetSystemTimeAsFileTime, GetTickCount, GetVersion, GetVersionExW,
        OSVERSIONINFOEXW, OSVERSIONINFOW, SYSTEM_INFO}, Performance::{QueryPerformanceCounter,
        QueryPerformanceFrequency}, Threading::{GetCurrentProcessId, GetCurrentThreadId}},
};

use super::super::{api_error, result, text};
use super::super::super::guest_text::GuestTextCodec;

pub(super) fn execute(call: C, codec: GuestTextCodec) -> Result<Win32HostImportResult, RuntimeError> {
    match call {
        C::Version => Ok(result(V::Dword(unsafe { GetVersion() }), None)),
        C::VersionInfo { encoding, extended } => version_info(encoding, extended, codec),
        C::TickCount => Ok(result(V::Dword(unsafe { GetTickCount() }), None)),
        C::ProcessId => Ok(result(V::Dword(unsafe { GetCurrentProcessId() }), None)),
        C::ThreadId => Ok(result(V::Dword(unsafe { GetCurrentThreadId() }), None)),
        C::SystemTime { local } => {
            let mut time = SYSTEMTIME::default();
            unsafe { if local { GetLocalTime(&mut time) } else { GetSystemTime(&mut time) } };
            Ok(result(V::SystemTime([time.wYear, time.wMonth, time.wDayOfWeek,
                time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds]), None))
        }
        C::SystemTimeAsFileTime => {
            let mut time = FILETIME::default();
            unsafe { GetSystemTimeAsFileTime(&mut time) };
            Ok(result(V::FileTime((u64::from(time.dwHighDateTime) << 32)
                | u64::from(time.dwLowDateTime)), None))
        }
        C::QueryPerformance { frequency } => query_performance(frequency),
        C::SystemInfo { native } => system_info(native),
    }
}

fn version_info(encoding: E, extended: bool, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> {
    if extended {
        let mut info = OSVERSIONINFOEXW::default();
        info.dwOSVersionInfoSize = u32::try_from(size_of::<OSVERSIONINFOEXW>())
            .map_err(|_| invariant("OSVERSIONINFOEXW host size overflowed"))?;
        let success = unsafe { GetVersionExW((&mut info as *mut OSVERSIONINFOEXW).cast()) } != 0;
        let error = (!success).then(api_error);
        let service_pack = version_text(encoding, codec, &info.szCSDVersion)?;
        Ok(result(V::VersionInfo { success, major: info.dwMajorVersion,
            minor: info.dwMinorVersion, build: info.dwBuildNumber, platform: info.dwPlatformId,
            service_pack, service_pack_major: info.wServicePackMajor,
            service_pack_minor: info.wServicePackMinor, suite_mask: info.wSuiteMask,
            product_type: info.wProductType }, error))
    } else {
        let mut info = OSVERSIONINFOW::default();
        info.dwOSVersionInfoSize = u32::try_from(size_of::<OSVERSIONINFOW>())
            .map_err(|_| invariant("OSVERSIONINFOW host size overflowed"))?;
        let success = unsafe { GetVersionExW(&mut info) } != 0;
        let error = (!success).then(api_error);
        let service_pack = version_text(encoding, codec, &info.szCSDVersion)?;
        Ok(result(V::VersionInfo { success, major: info.dwMajorVersion,
            minor: info.dwMinorVersion, build: info.dwBuildNumber, platform: info.dwPlatformId,
            service_pack, service_pack_major: 0, service_pack_minor: 0,
            suite_mask: 0, product_type: 0 }, error))
    }
}

fn system_info(native: bool) -> Result<Win32HostImportResult, RuntimeError> {
    let mut info = SYSTEM_INFO::default();
    unsafe { if native { GetNativeSystemInfo(&mut info) } else { GetSystemInfo(&mut info) } };
    // SYSTEM_INFO contains host-width pointers and processor masks. Preserve
    // them as data; the PE32 guest adapter applies its own address-space and
    // CPU contract and never treats this host result as decoder capability.
    let architecture = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture };
    Ok(result(V::SystemInfo { architecture, page_size: info.dwPageSize,
        minimum_address: info.lpMinimumApplicationAddress as usize as u64,
        maximum_address: info.lpMaximumApplicationAddress as usize as u64,
        active_processor_mask: info.dwActiveProcessorMask as u64,
        processor_count: info.dwNumberOfProcessors, processor_type: info.dwProcessorType,
        allocation_granularity: info.dwAllocationGranularity,
        processor_level: info.wProcessorLevel, processor_revision: info.wProcessorRevision }, None))
}

fn query_performance(frequency: bool) -> Result<Win32HostImportResult, RuntimeError> {
    let mut value = 0i64;
    let success = unsafe { if frequency { QueryPerformanceFrequency(&mut value) }
        else { QueryPerformanceCounter(&mut value) } } != 0;
    let error = (!success).then(api_error);
    let value = if success { u64::try_from(value).map_err(|_| RuntimeError::new(
        Kind::HostFailure, "Windows returned a negative performance-counter value"))? } else { 0 };
    Ok(result(V::ScalarQuery { success, value }, error))
}

fn version_text(encoding: E, codec: GuestTextCodec, buffer: &[u16])
    -> Result<S, RuntimeError> {
    if encoding == E::Ansi {
        let encoded = text::from_wide_z(codec, buffer,
            "GetVersionExW returned unterminated service-pack text")?;
        if encoded.len() < 128 { return Ok(S::Ansi(encoded)); }
        let end = buffer.iter().position(|unit| *unit == 0)
            .ok_or_else(|| invariant("GetVersionExW returned unterminated service-pack text"))?;
        let bounded = codec.from_wide_bounded(&buffer[..end], 127)?;
        return Ok(S::Ansi(bounded.bytes));
    }
    let end = buffer.iter().position(|unit| *unit == 0)
        .ok_or_else(|| invariant("GetVersionExW returned unterminated service-pack text"))?;
    let mut output = Vec::new();
    output.try_reserve_exact(end).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy OS service-pack text", error))?;
    output.extend_from_slice(&buffer[..end]);
    Ok(S::Wide(output))
}

fn invariant(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::InternalInvariant, message) }
