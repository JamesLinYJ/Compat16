//! Export decoder arms owned by the Kernel API module group.

use super::*;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    let request = match descriptor.id {
        Win16ExportId::KernelCatch => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Catch { buffer: dword_argument(arguments, 0)? }),
        Win16ExportId::KernelThrow => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Throw { buffer: dword_argument(arguments, 0)?,
                value: word_argument(arguments, 1)? }),
        Win16ExportId::KernelInitAtomTable
        | Win16ExportId::KernelFindAtom
        | Win16ExportId::KernelAddAtom
        | Win16ExportId::KernelDeleteAtom
        | Win16ExportId::KernelGetAtomName
        | Win16ExportId::KernelGetAtomHandle => {
            kernel_atom_calls::decode(descriptor.id, arguments, selectors, memory)?
        }
        Win16ExportId::KernelGetInstanceData
        | Win16ExportId::KernelGetCodeHandle
        | Win16ExportId::KernelGetCodeInfo => {
            super::super::call_kernel_instance::decode(descriptor.id, arguments)?
        }
        Win16ExportId::KernelOutputDebugString
        | Win16ExportId::KernelFatalAppExit
        | Win16ExportId::KernelFatalExit
        | Win16ExportId::KernelDebugBreak => {
            let request = super::super::call_kernel_diagnostics::decode(
                descriptor.id, arguments, selectors, memory,
            )?.ok_or(Win16Error::InvalidRange)?;
            Win16ApiRequest::KernelDiagnostics(request)
        }
        Win16ExportId::KernelGetWindowsDirectory
        | Win16ExportId::KernelGetSystemDirectory
        | Win16ExportId::KernelGetTempDrive
        | Win16ExportId::KernelGetTempFileName => {
            let request = super::super::call_kernel_path_info::decode(
                descriptor.id,
                arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?;
            Win16ApiRequest::KernelPathInfo(request)
        }
        Win16ExportId::KernelFileCdr
        | Win16ExportId::KernelCreateDirectory
        | Win16ExportId::KernelRemoveDirectory
        | Win16ExportId::KernelDeleteFile
        | Win16ExportId::KernelGetCurrentDirectory
        | Win16ExportId::KernelSetCurrentDirectory
        | Win16ExportId::KernelFindFirstFile
        | Win16ExportId::KernelFindNextFile
        | Win16ExportId::KernelFindClose
        | Win16ExportId::KernelGetFileAttributes
        | Win16ExportId::KernelSetFileAttributes
        | Win16ExportId::KernelGetDiskFreeSpace => {
            let request = super::super::call_kernel_file_system::decode(
                descriptor.id,
                arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?;
            Win16ApiRequest::KernelFileSystem(request)
        }
        Win16ExportId::KernelIsDbcsLeadByte => {
            kernel_locale::decode(descriptor.id, arguments)?.ok_or(Win16Error::InvalidRange)?
        }
        Win16ExportId::KernelWinExec => Win16ApiRequest::ShellExecution(
            super::Win16ShellExecutionRequest::WinExec {
                command_line: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                show: word_argument(arguments, 1)?,
            },
        ),
        Win16ExportId::KernelWritePrivateProfileSection
        | Win16ExportId::KernelWriteProfileSection
        | Win16ExportId::KernelGetPrivateProfileSection
        | Win16ExportId::KernelGetProfileSection => {
            let request = super::super::call_kernel_profile_sections::decode(
                descriptor, arguments, selectors, memory,
            )?
            .ok_or(Win16Error::InvalidRange)?;
            Win16ApiRequest::KernelProfileSection(request)
        }
        Win16ExportId::KernelYield
        | Win16ExportId::KernelGetVersion
        | Win16ExportId::KernelGetCurrentTask
        | Win16ExportId::KernelGetDriveType
        | Win16ExportId::KernelSetErrorMode
        | Win16ExportId::KernelWaitEvent
        | Win16ExportId::KernelPostEvent
        | Win16ExportId::KernelMakeProcInstance
        | Win16ExportId::KernelFreeProcInstance
        | Win16ExportId::KernelExitProcess => {
            kernel_runtime_calls::decode(descriptor.id, &arguments)?
        }
        Win16ExportId::KernelLstrlen => {
            let far = dword_argument(arguments, 0)?;
            let byte_count = if far == 0 { 0 } else {
                u16::try_from(crate::strings::count_ansi_z(
                    selectors, memory, far, super::super::MAX_WIN16_STRING_BYTES,
                )?).map_err(|_| Win16Error::InvalidRange)?
            };
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Strings(
                super::Win16KernelStringsRequest::StringLength { byte_count },
            ))
        }
        Win16ExportId::KernelLstrcpy => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Strings(super::Win16KernelStringsRequest::StringCopy {
                destination: dword_argument(&arguments, 0)?,
                source: read_nullable_far_string(
                    dword_argument(&arguments, 1)?,
                    selectors,
                    memory,
                )?,
            }),
        ),
        Win16ExportId::KernelLstrcat => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Strings(super::Win16KernelStringsRequest::StringConcat {
                destination: dword_argument(&arguments, 0)?,
                source: read_far_string(dword_argument(&arguments, 1)?, selectors, memory)?,
            }),
        ),
        Win16ExportId::KernelGetModuleFileName
        | Win16ExportId::KernelGetModuleHandle
        | Win16ExportId::KernelGetModuleUsage
        | Win16ExportId::KernelGetProcAddress
        | Win16ExportId::KernelLoadLibrary
        | Win16ExportId::KernelFreeLibrary
        | Win16ExportId::KernelLoadModule
        | Win16ExportId::KernelFreeModule => {
            kernel_module_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::KernelFindResource
        | Win16ExportId::KernelLoadResource
        | Win16ExportId::KernelLockResource
        | Win16ExportId::KernelFreeResource
        | Win16ExportId::KernelAccessResource
        | Win16ExportId::KernelSizeofResource
        | Win16ExportId::KernelAllocResource
        | Win16ExportId::KernelSetResourceHandler
        | Win16ExportId::KernelDefResourceHandler => {
            resource_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::KernelAllocSelector
        | Win16ExportId::KernelAllocCStoDSAlias
        | Win16ExportId::KernelAllocDStoCSAlias
        | Win16ExportId::KernelAllocAlias
        | Win16ExportId::KernelFreeSelector
        | Win16ExportId::KernelPrestoChangoSelector
        | Win16ExportId::KernelGetSelectorBase
        | Win16ExportId::KernelSetSelectorBase
        | Win16ExportId::KernelGetSelectorLimit
        | Win16ExportId::KernelSetSelectorLimit
        | Win16ExportId::KernelSelectorAccessRights
        | Win16ExportId::KernelAllocSelectorArray
        | Win16ExportId::KernelLongPtrAdd
        | Win16ExportId::KernelIsSharedSelector
        | Win16ExportId::KernelMapSL
        | Win16ExportId::KernelMapLS
        | Win16ExportId::KernelUnMapLS => {
            kernel_selector_calls::decode(descriptor.id, &arguments)?
        }
        Win16ExportId::KernelGetWinFlags => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::GetWinFlags),
        ),
        Win16ExportId::KernelInitTask | Win16ExportId::KernelSwitchStackBack =>
            return Err(Win16Error::UnsupportedRegisterContextExport),
        Win16ExportId::KernelSwitchStackTo => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::SwitchStackTo {
                stack_selector: word_argument(arguments, 0)?,
                stack_pointer: word_argument(arguments, 1)?,
                stack_top: word_argument(arguments, 2)?,
            },
        ),
        Win16ExportId::KernelGlobalAlloc
        | Win16ExportId::KernelGlobalFree
        | Win16ExportId::KernelGlobalLock
        | Win16ExportId::KernelGlobalUnlock
        | Win16ExportId::KernelGlobalSize
        | Win16ExportId::KernelGlobalHandle
        | Win16ExportId::KernelLocalInit
        | Win16ExportId::KernelLocalAlloc
        | Win16ExportId::KernelLocalReAlloc
        | Win16ExportId::KernelLocalFree
        | Win16ExportId::KernelLocalLock
        | Win16ExportId::KernelLocalUnlock
        | Win16ExportId::KernelLocalSize
        | Win16ExportId::KernelLocalHandle
        | Win16ExportId::KernelLocalFlags
        | Win16ExportId::KernelLocalCompact
        | Win16ExportId::KernelLocalShrink
        | Win16ExportId::KernelLocalHandleDelta
        | Win16ExportId::KernelLocalCountFree
        | Win16ExportId::KernelLocalHeapSize => {
            kernel_heap_calls::decode(descriptor.id, &arguments)?
        }
        Win16ExportId::KernelLclose
        | Win16ExportId::KernelLopen
        | Win16ExportId::KernelOpenFile
        | Win16ExportId::KernelLlseek
        | Win16ExportId::KernelLcreat
        | Win16ExportId::KernelSetHandleCount => {
            file_control_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::KernelGetPrivateProfileInt
        | Win16ExportId::KernelGetPrivateProfileString
        | Win16ExportId::KernelGetProfileString
        | Win16ExportId::KernelWritePrivateProfileString
        | Win16ExportId::KernelGetProfileInt => {
            profile_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::KernelLread
        | Win16ExportId::KernelLwrite
        | Win16ExportId::KernelHmemcpy
        | Win16ExportId::KernelHread
        | Win16ExportId::KernelHwrite => file_io_calls::decode(descriptor.id, &arguments)?,
        Win16ExportId::KernelLoadLibraryEx32W
        | Win16ExportId::KernelFreeLibrary32W
        | Win16ExportId::KernelGetProcAddress32W
        | Win16ExportId::KernelGetVDMPointer32W => {
            return Err(Win16Error::GenericThunkRequiresSpecialDecoder);
        }
        Win16ExportId::KernelCallProc32W | Win16ExportId::KernelCallProcEx32W => {
            return Err(Win16Error::VariableStackRequiresSpecialDecoder);
        }
        Win16ExportId::KernelGetModuleName
        | Win16ExportId::KernelGetCurrentPdb
        | Win16ExportId::KernelGetDosEnvironment
        | Win16ExportId::KernelReserved1
        | Win16ExportId::KernelReserved2
        | Win16ExportId::KernelReserved3
        | Win16ExportId::KernelReserved4
        | Win16ExportId::KernelGetExeVersion
        | Win16ExportId::KernelGetExePtr
        | Win16ExportId::KernelGetNumTasks
        | Win16ExportId::KernelGetTaskDs
        | Win16ExportId::KernelGetExpWinVer
        | Win16ExportId::KernelIsTask
        | Win16ExportId::KernelSetPriority
        | Win16ExportId::KernelLockCurrentTask
        | Win16ExportId::KernelSetTaskQueue
        | Win16ExportId::KernelGetTaskQueue
        | Win16ExportId::KernelOldYield
        | Win16ExportId::KernelGetTaskQueueDs
        | Win16ExportId::KernelGetTaskQueueEs
        | Win16ExportId::KernelIsTaskLocked
        | Win16ExportId::KernelSetLastError
        | Win16ExportId::KernelGetLastError
        | Win16ExportId::KernelGetVersionEx
        | Win16ExportId::KernelDirectedYield
        | Win16ExportId::KernelIsBadReadPtr
        | Win16ExportId::KernelIsBadWritePtr
        | Win16ExportId::KernelIsBadCodePtr
        | Win16ExportId::KernelIsBadStringPtr
        | Win16ExportId::KernelIsBadHugeReadPtr
        | Win16ExportId::KernelIsBadHugeWritePtr
        | Win16ExportId::KernelLstrcatn
        | Win16ExportId::KernelLstrcpyn
        | Win16ExportId::KernelGlobalFreeAll
        | Win16ExportId::KernelGlobalHandleNoRip
        | Win16ExportId::KernelWriteProfileString
        | Win16ExportId::KernelGetProfileSectionNames
        | Win16ExportId::KernelGetPrivateProfileSectionNames => {
            kernel_service_calls::decode(descriptor.id, &arguments, selectors, memory)?
                .ok_or(Win16Error::InvalidRange)?
        }
        Win16ExportId::KernelReserved5 => Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::Strings(super::Win16LibraryStringsRequest::StringCompare {
                left: read_far_string(dword_argument(&arguments, 0)?, selectors, memory)?,
                right: read_far_string(dword_argument(&arguments, 1)?, selectors, memory)?,
                comparison: match descriptor.id {
                    Win16ExportId::KernelReserved5 => Win16StringComparison::Binary,
                    Win16ExportId::UserLstrcmp => Win16StringComparison::Linguistic,
                    Win16ExportId::UserLstrcmpi => Win16StringComparison::LinguisticIgnoreCase,
                    _ => unreachable!("string comparison arm contains only comparison exports"),
                },
            }),
        ),
        Win16ExportId::KernelGlobalReAlloc
        | Win16ExportId::KernelGlobalFlags
        | Win16ExportId::KernelGlobalCompact
        | Win16ExportId::KernelGlobalFix
        | Win16ExportId::KernelGlobalWire
        | Win16ExportId::KernelGlobalUnWire
        | Win16ExportId::KernelGlobalUnfix
        | Win16ExportId::KernelGlobalPageLock
        | Win16ExportId::KernelGlobalPageUnlock
        | Win16ExportId::KernelGlobalSmartPageLock
        | Win16ExportId::KernelGlobalSmartPageUnlock
        | Win16ExportId::KernelGlobalLruOldest
        | Win16ExportId::KernelGlobalLruNewest
        | Win16ExportId::KernelGlobalDosAlloc
        | Win16ExportId::KernelGlobalDosFree
        | Win16ExportId::KernelGlobalMasterHandle
        | Win16ExportId::KernelGlobalChangeLockCount
        | Win16ExportId::KernelFarSetOwner
        | Win16ExportId::KernelFarGetOwner
        | Win16ExportId::KernelLockSegment
        | Win16ExportId::KernelUnlockSegment
        | Win16ExportId::KernelGetFreeSpace => {
            win16_service_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        _ => return Ok(None),
    };
    Ok(Some(request))
}

#[cfg(test)]
#[path = "call_lstrlen_tests.rs"]
mod lstrlen_tests;
