//! Formal signatures for the Win32 imports dispatched by the PE32 bridge.
//!
//! A catalog match is valid only after the host loader established an exact
//! Windows system-module provider. Export names remain case-sensitive; module
//! basenames follow the Windows loader's case-insensitive comparison.

use crate::pe32::Pe32TypedHostServiceId;
use super::win32_import_host::Win32HostImportFamily as F;

#[path = "win32_import_catalog_signatures.rs"]
mod signatures;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u16)]
pub(crate) enum Win32ImportService {
    GetLastError = 1, SetLastError,
    CreateFileA, CreateFileW, ReadFile, WriteFile, CloseHandle,
    DeleteFileA, DeleteFileW, MoveFileA, MoveFileW, CopyFileA, CopyFileW,
    CreateDirectoryA, CreateDirectoryW, RemoveDirectoryA, RemoveDirectoryW,
    GetFileAttributesA, GetFileAttributesW, SetFileAttributesA, SetFileAttributesW,
    GetFileType, GetFileSize, GetFileSizeEx, SetFilePointer, SetEndOfFile, FlushFileBuffers,
    GetCurrentDirectoryA, GetCurrentDirectoryW, SetCurrentDirectoryA, SetCurrentDirectoryW,
    GetSystemDirectoryA, GetSystemDirectoryW, GetWindowsDirectoryA, GetWindowsDirectoryW,
    GetTempPathA, GetTempPathW, GetFullPathNameA, GetFullPathNameW,
    GetLongPathNameA, GetLongPathNameW, GetShortPathNameA, GetShortPathNameW,
    GetLogicalDrives, GetDriveTypeA, GetDriveTypeW, GetDiskFreeSpaceA, GetDiskFreeSpaceW,
    GetDiskFreeSpaceExA, GetDiskFreeSpaceExW, GetVolumeInformationA, GetVolumeInformationW,
    GetEnvironmentVariableA, GetEnvironmentVariableW, SetEnvironmentVariableA,
    SetEnvironmentVariableW, ExpandEnvironmentStringsA, ExpandEnvironmentStringsW,
    GetVersion, GetVersionExA, GetVersionExW, GetTickCount, GetCurrentProcessId,
    GetCurrentThreadId, GetSystemTime, GetLocalTime, GetSystemTimeAsFileTime,
    QueryPerformanceCounter, QueryPerformanceFrequency, GetSystemInfo, GetNativeSystemInfo,
    LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW, FreeLibrary,
    GetModuleHandleA, GetModuleHandleW, GetProcAddress, GetModuleFileNameA, GetModuleFileNameW,
    FindFirstFileA, FindFirstFileW, FindFirstFileExA, FindFirstFileExW,
    FindNextFileA, FindNextFileW, FindClose,
}

impl Win32ImportService {
    pub(crate) const fn id(self) -> Pe32TypedHostServiceId {
        Pe32TypedHostServiceId::from_typed_catalog(self as u16)
    }

    pub(crate) const fn family(self) -> F {
        use Win32ImportService as S;
        match self {
            S::GetLastError | S::SetLastError => F::Runtime,
            S::LoadLibraryA | S::LoadLibraryW | S::LoadLibraryExA | S::LoadLibraryExW
                | S::FreeLibrary | S::GetModuleHandleA | S::GetModuleHandleW
                | S::GetProcAddress | S::GetModuleFileNameA | S::GetModuleFileNameW => F::Loader,
            S::CreateFileA | S::CreateFileW | S::ReadFile | S::WriteFile | S::CloseHandle
                | S::DeleteFileA | S::DeleteFileW | S::MoveFileA | S::MoveFileW
                | S::CopyFileA | S::CopyFileW | S::CreateDirectoryA | S::CreateDirectoryW
                | S::RemoveDirectoryA | S::RemoveDirectoryW | S::GetFileAttributesA
                | S::GetFileAttributesW | S::SetFileAttributesA | S::SetFileAttributesW
                | S::GetFileType | S::GetFileSize | S::GetFileSizeEx | S::SetFilePointer
                | S::SetEndOfFile | S::FlushFileBuffers | S::FindFirstFileA | S::FindFirstFileW
                | S::FindFirstFileExA | S::FindFirstFileExW | S::FindNextFileA | S::FindNextFileW
                | S::FindClose => F::File,
            S::GetCurrentDirectoryA | S::GetCurrentDirectoryW | S::SetCurrentDirectoryA
                | S::SetCurrentDirectoryW | S::GetSystemDirectoryA | S::GetSystemDirectoryW
                | S::GetWindowsDirectoryA | S::GetWindowsDirectoryW | S::GetTempPathA
                | S::GetTempPathW | S::GetFullPathNameA | S::GetFullPathNameW
                | S::GetLongPathNameA | S::GetLongPathNameW | S::GetShortPathNameA
                | S::GetShortPathNameW => F::Path,
            S::GetLogicalDrives | S::GetDriveTypeA | S::GetDriveTypeW | S::GetDiskFreeSpaceA
                | S::GetDiskFreeSpaceW | S::GetDiskFreeSpaceExA | S::GetDiskFreeSpaceExW
                | S::GetVolumeInformationA | S::GetVolumeInformationW => F::Volume,
            S::GetEnvironmentVariableA | S::GetEnvironmentVariableW
                | S::SetEnvironmentVariableA | S::SetEnvironmentVariableW
                | S::ExpandEnvironmentStringsA | S::ExpandEnvironmentStringsW => F::Environment,
            S::GetVersion | S::GetVersionExA | S::GetVersionExW | S::GetTickCount
                | S::GetCurrentProcessId | S::GetCurrentThreadId | S::GetSystemTime
                | S::GetLocalTime | S::GetSystemTimeAsFileTime | S::QueryPerformanceCounter
                | S::QueryPerformanceFrequency | S::GetSystemInfo | S::GetNativeSystemInfo => F::System,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win32ImportParam {
    Dword, SignedLong, Boolean, Handle, OptionalHandle,
    AnsiString, WideString, OptionalAnsiString, OptionalWideString, ProcedureNameOrOrdinal,
    InputBytes, OutputBytes, OutputDword, OptionalOutputDword, OutputQword,
    OptionalOutputBytes, OptionalOutputQword, OptionalOutputLong, OptionalSecurityAttributes32,
    OptionalOverlapped32, FilePartOutput, VersionInfoA, VersionInfoW,
    SystemTimeOutput, FileTimeOutput, SystemInfoOutput, SearchHandle,
    FindDataAOutput, FindDataWOutput, FindInfoLevel, FindSearchOperation, RequiredNullPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win32ImportReturn { Void, Boolean, Dword, Handle, Pointer, QwordEaxEdx }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win32ImportEffect { ReadOnly, MutateProcess, CreateResource, ReleaseResource }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win32ImportDescriptor {
    pub(crate) service: Win32ImportService,
    pub(crate) export: &'static [u8],
    pub(crate) parameters: &'static [Win32ImportParam],
    pub(crate) result: Win32ImportReturn,
    pub(crate) effect: Win32ImportEffect,
    pub(crate) sets_last_error_on_failure: bool,
}

pub(crate) fn lookup(symbol: &[u8]) -> Option<&'static Win32ImportDescriptor> {
    signatures::BY_NAME.iter().find(|entry| entry.export == symbol)
}

/// Ordinal lookup is intentionally explicit. No KERNEL32 ordinal is assigned
/// from an observed DLL layout; undocumented ordinals stay unresolved.
pub(crate) fn lookup_ordinal(ordinal: u16) -> Option<&'static Win32ImportDescriptor> {
    signatures::BY_ORDINAL.iter().find(|entry| entry.0 == ordinal).map(|entry| &entry.1)
}

pub(crate) fn descriptor_for_service(service: Win32ImportService) -> &'static Win32ImportDescriptor {
    signatures::BY_NAME.iter().find(|entry| entry.service == service)
        .expect("every service enum value has one signature descriptor")
}
