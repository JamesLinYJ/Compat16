//! Win32 KERNEL32-family declarations with explicit PE32 stack shapes.

use super::{Win32ImportDescriptor as D, Win32ImportEffect as E, Win32ImportParam as P,
    Win32ImportReturn as R, Win32ImportService as S};

const fn d(service: S, export: &'static [u8], parameters: &'static [P], result: R,
    effect: E, sets_last_error_on_failure: bool) -> D {
    D { service, export, parameters, result, effect, sets_last_error_on_failure }
}

const A_PATH: &[P] = &[P::AnsiString];
const W_PATH: &[P] = &[P::WideString];
const A_PAIR: &[P] = &[P::AnsiString, P::AnsiString];
const W_PAIR: &[P] = &[P::WideString, P::WideString];
const A_COPY: &[P] = &[P::AnsiString, P::AnsiString, P::Boolean];
const W_COPY: &[P] = &[P::WideString, P::WideString, P::Boolean];
const CREATE_FILE_A: &[P] = &[P::AnsiString, P::Dword, P::Dword,
    P::OptionalSecurityAttributes32, P::Dword, P::Dword, P::OptionalHandle];
const CREATE_FILE_W: &[P] = &[P::WideString, P::Dword, P::Dword,
    P::OptionalSecurityAttributes32, P::Dword, P::Dword, P::OptionalHandle];
const READ_FILE: &[P] = &[P::Handle, P::OutputBytes, P::Dword, P::OutputDword,
    P::OptionalOverlapped32];
const WRITE_FILE: &[P] = &[P::Handle, P::InputBytes, P::Dword, P::OutputDword,
    P::OptionalOverlapped32];
const GET_BUFFER: &[P] = &[P::Dword, P::OutputBytes];
const SYSTEM_DIR_BUFFER: &[P] = &[P::OutputBytes, P::Dword];
const SET_POINTER: &[P] = &[P::Handle, P::SignedLong, P::OptionalOutputLong, P::Dword];
const GET_DISK_SPACE: &[P] = &[P::OptionalAnsiString, P::OutputDword, P::OutputDword,
    P::OutputDword, P::OutputDword];
const GET_DISK_SPACE_W: &[P] = &[P::OptionalWideString, P::OutputDword, P::OutputDword,
    P::OutputDword, P::OutputDword];
const GET_DISK_SPACE_EX_A: &[P] = &[P::OptionalAnsiString, P::OptionalOutputQword,
    P::OptionalOutputQword, P::OptionalOutputQword];
const GET_DISK_SPACE_EX_W: &[P] = &[P::OptionalWideString, P::OptionalOutputQword,
    P::OptionalOutputQword, P::OptionalOutputQword];
const GET_VOLUME_A: &[P] = &[P::OptionalAnsiString, P::OptionalOutputBytes, P::Dword, P::OptionalOutputDword,
    P::OptionalOutputDword, P::OptionalOutputDword, P::OptionalOutputBytes, P::Dword];
const GET_VOLUME_W: &[P] = &[P::OptionalWideString, P::OptionalOutputBytes, P::Dword, P::OptionalOutputDword,
    P::OptionalOutputDword, P::OptionalOutputDword, P::OptionalOutputBytes, P::Dword];
const GET_ENV_A: &[P] = &[P::AnsiString, P::OutputBytes, P::Dword];
const GET_ENV_W: &[P] = &[P::WideString, P::OutputBytes, P::Dword];
const SET_ENV_A: &[P] = &[P::AnsiString, P::OptionalAnsiString];
const SET_ENV_W: &[P] = &[P::WideString, P::OptionalWideString];
const EXPAND_ENV_A: &[P] = &[P::AnsiString, P::OutputBytes, P::Dword];
const EXPAND_ENV_W: &[P] = &[P::WideString, P::OutputBytes, P::Dword];
const VERSION_INFO_A: &[P] = &[P::VersionInfoA];
const VERSION_INFO_W: &[P] = &[P::VersionInfoW];
const GET_SYSTEM_TIME: &[P] = &[P::SystemTimeOutput];
const GET_FILE_TIME: &[P] = &[P::FileTimeOutput];
const QUERY_COUNTER: &[P] = &[P::OutputQword];
const GET_SYSTEM_INFO: &[P] = &[P::SystemInfoOutput];
const TRANSFORM_A: &[P] = &[P::AnsiString, P::Dword, P::OutputBytes, P::FilePartOutput];
const TRANSFORM_W: &[P] = &[P::WideString, P::Dword, P::OutputBytes, P::FilePartOutput];
const LONG_SHORT_A: &[P] = &[P::AnsiString, P::OutputBytes, P::Dword];
const LONG_SHORT_W: &[P] = &[P::WideString, P::OutputBytes, P::Dword];
const MODULE_FILE_A: &[P] = &[P::OptionalHandle, P::OutputBytes, P::Dword];
const MODULE_FILE_W: &[P] = &[P::OptionalHandle, P::OutputBytes, P::Dword];
const LOAD_EX_A: &[P] = &[P::AnsiString, P::OptionalHandle, P::Dword];
const LOAD_EX_W: &[P] = &[P::WideString, P::OptionalHandle, P::Dword];
const GET_MODULE_A: &[P] = &[P::OptionalAnsiString];
const GET_MODULE_W: &[P] = &[P::OptionalWideString];
const GET_PROC: &[P] = &[P::Handle, P::ProcedureNameOrOrdinal];
const FIND_FIRST_A: &[P] = &[P::AnsiString, P::FindDataAOutput];
const FIND_FIRST_W: &[P] = &[P::WideString, P::FindDataWOutput];
const FIND_FIRST_EX_A: &[P] = &[P::AnsiString, P::FindInfoLevel, P::FindDataAOutput,
    P::FindSearchOperation, P::RequiredNullPointer, P::Dword];
const FIND_FIRST_EX_W: &[P] = &[P::WideString, P::FindInfoLevel, P::FindDataWOutput,
    P::FindSearchOperation, P::RequiredNullPointer, P::Dword];
const FIND_NEXT_A: &[P] = &[P::SearchHandle, P::FindDataAOutput];
const FIND_NEXT_W: &[P] = &[P::SearchHandle, P::FindDataWOutput];

pub(super) static BY_NAME: &[D] = &[
    d(S::GetLastError, b"GetLastError", &[], R::Dword, E::ReadOnly, false),
    d(S::SetLastError, b"SetLastError", &[P::Dword], R::Void, E::MutateProcess, false),
    d(S::CreateFileA, b"CreateFileA", CREATE_FILE_A, R::Handle, E::CreateResource, true),
    d(S::CreateFileW, b"CreateFileW", CREATE_FILE_W, R::Handle, E::CreateResource, true),
    d(S::ReadFile, b"ReadFile", READ_FILE, R::Boolean, E::MutateProcess, true),
    d(S::WriteFile, b"WriteFile", WRITE_FILE, R::Boolean, E::MutateProcess, true),
    d(S::CloseHandle, b"CloseHandle", &[P::Handle], R::Boolean, E::ReleaseResource, true),
    d(S::DeleteFileA, b"DeleteFileA", A_PATH, R::Boolean, E::MutateProcess, true),
    d(S::DeleteFileW, b"DeleteFileW", W_PATH, R::Boolean, E::MutateProcess, true),
    d(S::MoveFileA, b"MoveFileA", A_PAIR, R::Boolean, E::MutateProcess, true),
    d(S::MoveFileW, b"MoveFileW", W_PAIR, R::Boolean, E::MutateProcess, true),
    d(S::CopyFileA, b"CopyFileA", A_COPY, R::Boolean, E::MutateProcess, true),
    d(S::CopyFileW, b"CopyFileW", W_COPY, R::Boolean, E::MutateProcess, true),
    d(S::CreateDirectoryA, b"CreateDirectoryA", &[P::AnsiString, P::OptionalSecurityAttributes32], R::Boolean, E::MutateProcess, true),
    d(S::CreateDirectoryW, b"CreateDirectoryW", &[P::WideString, P::OptionalSecurityAttributes32], R::Boolean, E::MutateProcess, true),
    d(S::RemoveDirectoryA, b"RemoveDirectoryA", A_PATH, R::Boolean, E::MutateProcess, true),
    d(S::RemoveDirectoryW, b"RemoveDirectoryW", W_PATH, R::Boolean, E::MutateProcess, true),
    d(S::GetFileAttributesA, b"GetFileAttributesA", A_PATH, R::Dword, E::ReadOnly, true),
    d(S::GetFileAttributesW, b"GetFileAttributesW", W_PATH, R::Dword, E::ReadOnly, true),
    d(S::SetFileAttributesA, b"SetFileAttributesA", &[P::AnsiString, P::Dword], R::Boolean, E::MutateProcess, true),
    d(S::SetFileAttributesW, b"SetFileAttributesW", &[P::WideString, P::Dword], R::Boolean, E::MutateProcess, true),
    d(S::GetFileType, b"GetFileType", &[P::Handle], R::Dword, E::ReadOnly, true),
    d(S::GetFileSize, b"GetFileSize", &[P::Handle, P::OptionalOutputDword], R::Dword, E::ReadOnly, true),
    d(S::GetFileSizeEx, b"GetFileSizeEx", &[P::Handle, P::OutputQword], R::Boolean, E::ReadOnly, true),
    d(S::SetFilePointer, b"SetFilePointer", SET_POINTER, R::Dword, E::MutateProcess, true),
    d(S::SetEndOfFile, b"SetEndOfFile", &[P::Handle], R::Boolean, E::MutateProcess, true),
    d(S::FlushFileBuffers, b"FlushFileBuffers", &[P::Handle], R::Boolean, E::MutateProcess, true),
    d(S::GetCurrentDirectoryA, b"GetCurrentDirectoryA", GET_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetCurrentDirectoryW, b"GetCurrentDirectoryW", GET_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::SetCurrentDirectoryA, b"SetCurrentDirectoryA", A_PATH, R::Boolean, E::MutateProcess, true),
    d(S::SetCurrentDirectoryW, b"SetCurrentDirectoryW", W_PATH, R::Boolean, E::MutateProcess, true),
    d(S::GetSystemDirectoryA, b"GetSystemDirectoryA", SYSTEM_DIR_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetSystemDirectoryW, b"GetSystemDirectoryW", SYSTEM_DIR_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetWindowsDirectoryA, b"GetWindowsDirectoryA", SYSTEM_DIR_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetWindowsDirectoryW, b"GetWindowsDirectoryW", SYSTEM_DIR_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetTempPathA, b"GetTempPathA", GET_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetTempPathW, b"GetTempPathW", GET_BUFFER, R::Dword, E::ReadOnly, true),
    d(S::GetFullPathNameA, b"GetFullPathNameA", TRANSFORM_A, R::Dword, E::ReadOnly, true),
    d(S::GetFullPathNameW, b"GetFullPathNameW", TRANSFORM_W, R::Dword, E::ReadOnly, true),
    d(S::GetLongPathNameA, b"GetLongPathNameA", LONG_SHORT_A, R::Dword, E::ReadOnly, true),
    d(S::GetLongPathNameW, b"GetLongPathNameW", LONG_SHORT_W, R::Dword, E::ReadOnly, true),
    d(S::GetShortPathNameA, b"GetShortPathNameA", LONG_SHORT_A, R::Dword, E::ReadOnly, true),
    d(S::GetShortPathNameW, b"GetShortPathNameW", LONG_SHORT_W, R::Dword, E::ReadOnly, true),
    d(S::GetLogicalDrives, b"GetLogicalDrives", &[], R::Dword, E::ReadOnly, true),
    d(S::GetDriveTypeA, b"GetDriveTypeA", &[P::OptionalAnsiString], R::Dword, E::ReadOnly, false),
    d(S::GetDriveTypeW, b"GetDriveTypeW", &[P::OptionalWideString], R::Dword, E::ReadOnly, false),
    d(S::GetDiskFreeSpaceA, b"GetDiskFreeSpaceA", GET_DISK_SPACE, R::Boolean, E::ReadOnly, true),
    d(S::GetDiskFreeSpaceW, b"GetDiskFreeSpaceW", GET_DISK_SPACE_W, R::Boolean, E::ReadOnly, true),
    d(S::GetDiskFreeSpaceExA, b"GetDiskFreeSpaceExA", GET_DISK_SPACE_EX_A, R::Boolean, E::ReadOnly, true),
    d(S::GetDiskFreeSpaceExW, b"GetDiskFreeSpaceExW", GET_DISK_SPACE_EX_W, R::Boolean, E::ReadOnly, true),
    d(S::GetVolumeInformationA, b"GetVolumeInformationA", GET_VOLUME_A, R::Boolean, E::ReadOnly, true),
    d(S::GetVolumeInformationW, b"GetVolumeInformationW", GET_VOLUME_W, R::Boolean, E::ReadOnly, true),
    d(S::GetEnvironmentVariableA, b"GetEnvironmentVariableA", GET_ENV_A, R::Dword, E::ReadOnly, true),
    d(S::GetEnvironmentVariableW, b"GetEnvironmentVariableW", GET_ENV_W, R::Dword, E::ReadOnly, true),
    d(S::SetEnvironmentVariableA, b"SetEnvironmentVariableA", SET_ENV_A, R::Boolean, E::MutateProcess, true),
    d(S::SetEnvironmentVariableW, b"SetEnvironmentVariableW", SET_ENV_W, R::Boolean, E::MutateProcess, true),
    d(S::ExpandEnvironmentStringsA, b"ExpandEnvironmentStringsA", EXPAND_ENV_A, R::Dword, E::ReadOnly, true),
    d(S::ExpandEnvironmentStringsW, b"ExpandEnvironmentStringsW", EXPAND_ENV_W, R::Dword, E::ReadOnly, true),
    d(S::GetVersion, b"GetVersion", &[], R::Dword, E::ReadOnly, false),
    d(S::GetVersionExA, b"GetVersionExA", VERSION_INFO_A, R::Boolean, E::ReadOnly, true),
    d(S::GetVersionExW, b"GetVersionExW", VERSION_INFO_W, R::Boolean, E::ReadOnly, true),
    d(S::GetTickCount, b"GetTickCount", &[], R::Dword, E::ReadOnly, false),
    d(S::GetCurrentProcessId, b"GetCurrentProcessId", &[], R::Dword, E::ReadOnly, false),
    d(S::GetCurrentThreadId, b"GetCurrentThreadId", &[], R::Dword, E::ReadOnly, false),
    d(S::GetSystemTime, b"GetSystemTime", GET_SYSTEM_TIME, R::Void, E::ReadOnly, false),
    d(S::GetLocalTime, b"GetLocalTime", GET_SYSTEM_TIME, R::Void, E::ReadOnly, false),
    d(S::GetSystemTimeAsFileTime, b"GetSystemTimeAsFileTime", GET_FILE_TIME, R::Void, E::ReadOnly, false),
    d(S::QueryPerformanceCounter, b"QueryPerformanceCounter", QUERY_COUNTER, R::Boolean, E::ReadOnly, true),
    d(S::QueryPerformanceFrequency, b"QueryPerformanceFrequency", QUERY_COUNTER, R::Boolean, E::ReadOnly, true),
    d(S::GetSystemInfo, b"GetSystemInfo", GET_SYSTEM_INFO, R::Void, E::ReadOnly, false),
    d(S::GetNativeSystemInfo, b"GetNativeSystemInfo", GET_SYSTEM_INFO, R::Void, E::ReadOnly, false),
    d(S::LoadLibraryA, b"LoadLibraryA", A_PATH, R::Handle, E::CreateResource, true),
    d(S::LoadLibraryW, b"LoadLibraryW", W_PATH, R::Handle, E::CreateResource, true),
    d(S::LoadLibraryExA, b"LoadLibraryExA", LOAD_EX_A, R::Handle, E::CreateResource, true),
    d(S::LoadLibraryExW, b"LoadLibraryExW", LOAD_EX_W, R::Handle, E::CreateResource, true),
    d(S::FreeLibrary, b"FreeLibrary", &[P::Handle], R::Boolean, E::ReleaseResource, true),
    d(S::GetModuleHandleA, b"GetModuleHandleA", GET_MODULE_A, R::Handle, E::ReadOnly, true),
    d(S::GetModuleHandleW, b"GetModuleHandleW", GET_MODULE_W, R::Handle, E::ReadOnly, true),
    d(S::GetProcAddress, b"GetProcAddress", GET_PROC, R::Pointer, E::ReadOnly, true),
    d(S::GetModuleFileNameA, b"GetModuleFileNameA", MODULE_FILE_A, R::Dword, E::ReadOnly, true),
    d(S::GetModuleFileNameW, b"GetModuleFileNameW", MODULE_FILE_W, R::Dword, E::ReadOnly, true),
    d(S::FindFirstFileA, b"FindFirstFileA", FIND_FIRST_A, R::Handle, E::CreateResource, true),
    d(S::FindFirstFileW, b"FindFirstFileW", FIND_FIRST_W, R::Handle, E::CreateResource, true),
    d(S::FindFirstFileExA, b"FindFirstFileExA", FIND_FIRST_EX_A, R::Handle, E::CreateResource, true),
    d(S::FindFirstFileExW, b"FindFirstFileExW", FIND_FIRST_EX_W, R::Handle, E::CreateResource, true),
    d(S::FindNextFileA, b"FindNextFileA", FIND_NEXT_A, R::Boolean, E::MutateProcess, true),
    d(S::FindNextFileW, b"FindNextFileW", FIND_NEXT_W, R::Boolean, E::MutateProcess, true),
    d(S::FindClose, b"FindClose", &[P::SearchHandle], R::Boolean, E::ReleaseResource, true),
];

pub(super) static BY_ORDINAL: &[(u16, D)] = &[];
