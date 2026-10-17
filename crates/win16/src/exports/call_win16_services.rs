//! Decoding for the USER system queries, KERNEL global heap, and compatibility DLL batch.

use super::{
    Win16ApiRequest, Win16ExportId, dword_argument, read_far_bytes, read_far_string,
    word_argument,
};
use crate::exports::request::{
    Win16KernelGlobalHeapRequest, Win16LzExpandRequest, Win16ShellRequest,
    Win16UserSystemRequest, Win16VerRequest,
};
use crate::{SelectorTable, Win16Argument, Win16Error, Win16ResourceName};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::UserSetDoubleClickTime => Win16ApiRequest::UserSystem(
            Win16UserSystemRequest::SetDoubleClickTime { milliseconds: word_argument(arguments, 0)? },
        ),
        Win16ExportId::UserGetDoubleClickTime => {
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::GetDoubleClickTime)
        }
        Win16ExportId::UserSetCaretBlinkTime => Win16ApiRequest::UserSystem(
            Win16UserSystemRequest::SetCaretBlinkTime { milliseconds: word_argument(arguments, 0)? },
        ),
        Win16ExportId::UserGetCaretBlinkTime => {
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::GetCaretBlinkTime)
        }
        Win16ExportId::UserGetSysColor => Win16ApiRequest::UserSystem(
            Win16UserSystemRequest::GetSysColor { index: word_argument(arguments, 0)? },
        ),
        Win16ExportId::UserSetSysColors => {
            let signed_count = word_argument(arguments, 0)? as i16;
            if signed_count < 0 {
                return Err(Win16Error::InvalidRange);
            }
            let count = usize::try_from(signed_count).map_err(|_| Win16Error::InvalidRange)?;
            let index_data = read_far_bytes(
                dword_argument(arguments, 1)?,
                count.checked_mul(2).ok_or(Win16Error::InvalidRange)?,
                selectors,
                memory,
            )?;
            let color_data = read_far_bytes(
                dword_argument(arguments, 2)?,
                count.checked_mul(4).ok_or(Win16Error::InvalidRange)?,
                selectors,
                memory,
            )?;
            let mut indices = Vec::new();
            indices.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;
            indices.extend(index_data.chunks_exact(2).map(|pair| {
                i32::from(i16::from_le_bytes([pair[0], pair[1]]))
            }));
            let mut colors = Vec::new();
            colors.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;
            colors.extend(color_data.chunks_exact(4).map(|quad| {
                u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
            }));
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetSysColors {
                indices,
                colors,
            })
        }
        Win16ExportId::UserSwapMouseButton => {
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::SwapMouseButton {
                swap: word_argument(arguments, 0)? != 0,
            })
        }
        Win16ExportId::UserAnyPopup => {
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::AnyPopup)
        }
        Win16ExportId::UserGetDialogBaseUnits => {
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::GetDialogBaseUnits)
        }
        Win16ExportId::UserIconSize => Win16ApiRequest::UserSystem(Win16UserSystemRequest::IconSize),
        Win16ExportId::UserDragObject => Win16ApiRequest::UserSystem(Win16UserSystemRequest::DragObject {
            parent: word_argument(arguments, 0)?,
            source: word_argument(arguments, 1)?,
            format: word_argument(arguments, 2)?,
            data: dword_argument(arguments, 3)?,
            cursor: word_argument(arguments, 4)?,
        }),
        Win16ExportId::UserDragDetect => {
            let point = dword_argument(arguments, 1)?;
            Win16ApiRequest::UserSystem(Win16UserSystemRequest::DragDetect {
                window: word_argument(arguments, 0)?,
                x: point as u16 as i16,
                y: (point >> 16) as u16 as i16,
            })
        }
        Win16ExportId::KernelGlobalReAlloc => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalReAlloc {
                handle: word_argument(arguments, 0)?,
                size: dword_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            },
        ),
        Win16ExportId::KernelGlobalFlags => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalFlags { handle: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelGlobalCompact => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalCompact { minimum_free: dword_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelGlobalFix => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalFix { handle: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelGlobalUnfix => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalUnfix { handle: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelGlobalPageLock | Win16ExportId::KernelGlobalSmartPageLock => {
            Win16ApiRequest::KernelGlobalHeap(Win16KernelGlobalHeapRequest::GlobalPageLock {
                handle: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::KernelGlobalPageUnlock | Win16ExportId::KernelGlobalSmartPageUnlock => {
            Win16ApiRequest::KernelGlobalHeap(Win16KernelGlobalHeapRequest::GlobalPageUnlock {
                handle: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::KernelFarSetOwner => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::FarSetOwner {
                handle: word_argument(arguments, 0)?,
                owner: word_argument(arguments, 1)?,
            },
        ),
        Win16ExportId::KernelFarGetOwner => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::FarGetOwner {
                handle: word_argument(arguments, 0)?,
            },
        ),
        Win16ExportId::KernelGlobalLruOldest => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalLruOldest {
                handle: word_argument(arguments, 0)?,
            },
        ),
        Win16ExportId::KernelGlobalLruNewest => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalLruNewest {
                handle: word_argument(arguments, 0)?,
            },
        ),
        Win16ExportId::KernelGlobalDosAlloc => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalDosAlloc {
                size: dword_argument(arguments, 0)?,
            },
        ),
        Win16ExportId::KernelGlobalDosFree => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalDosFree {
                selector: word_argument(arguments, 0)?,
            },
        ),
        Win16ExportId::KernelGlobalMasterHandle => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalMasterHandle,
        ),
        Win16ExportId::KernelGlobalChangeLockCount => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalChangeLockCount {
                handle: word_argument(arguments, 0)?,
                delta: word_argument(arguments, 1)? as i16,
            },
        ),
        Win16ExportId::KernelGlobalWire => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalWire { handle: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelGlobalUnWire => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GlobalUnWire { handle: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelLockSegment => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::LockSegment { segment: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelUnlockSegment => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::UnlockSegment { segment: word_argument(arguments, 0)? },
        ),
        Win16ExportId::KernelGetFreeSpace => Win16ApiRequest::KernelGlobalHeap(
            Win16KernelGlobalHeapRequest::GetFreeSpace { flags: word_argument(arguments, 0)? },
        ),
        Win16ExportId::VerGetFileResourceSize => Win16ApiRequest::Ver(
            Win16VerRequest::VerGetFileResourceSize {
                path: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                resource_type: resource_name(dword_argument(arguments, 1)?, selectors, memory)?,
                resource_name: resource_name(dword_argument(arguments, 2)?, selectors, memory)?,
                size_output: dword_argument(arguments, 3)?,
            },
        ),
        Win16ExportId::VerGetFileResource => Win16ApiRequest::Ver(
            Win16VerRequest::VerGetFileResource {
                path: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                resource_type: resource_name(dword_argument(arguments, 1)?, selectors, memory)?,
                resource_name: resource_name(dword_argument(arguments, 2)?, selectors, memory)?,
                offset: dword_argument(arguments, 3)? as i32,
                count: dword_argument(arguments, 4)? as i32,
                output: dword_argument(arguments, 5)?,
            },
        ),
        Win16ExportId::VerGetFileVersionInfoSize => Win16ApiRequest::Ver(
            Win16VerRequest::VerGetFileVersionInfoSize {
                path: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                handle_output: dword_argument(arguments, 1)?,
            },
        ),
        Win16ExportId::VerGetFileVersionInfo => Win16ApiRequest::Ver(
            Win16VerRequest::VerGetFileVersionInfo {
                path: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                handle: dword_argument(arguments, 1)?,
                capacity: dword_argument(arguments, 2)?,
                output: dword_argument(arguments, 3)?,
            },
        ),
        Win16ExportId::VerFindFile => Win16ApiRequest::Ver(Win16VerRequest::VerFindFile {
            flags: word_argument(arguments, 0)?,
            file: read_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            windows_dir: read_far_string(dword_argument(arguments, 2)?, selectors, memory)?,
            app_dir: read_far_string(dword_argument(arguments, 3)?, selectors, memory)?,
            dir_output: dword_argument(arguments, 4)?,
            dir_capacity_output: dword_argument(arguments, 5)?,
            file_output: dword_argument(arguments, 6)?,
            file_capacity_output: dword_argument(arguments, 7)?,
        }),
        Win16ExportId::VerInstallFile => Win16ApiRequest::Ver(Win16VerRequest::VerInstallFile {
            flags: word_argument(arguments, 0)?,
            source: read_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            destination: read_far_string(dword_argument(arguments, 2)?, selectors, memory)?,
            source_dir: read_far_string(dword_argument(arguments, 3)?, selectors, memory)?,
            destination_dir: read_far_string(dword_argument(arguments, 4)?, selectors, memory)?,
            current_dir: read_far_string(dword_argument(arguments, 5)?, selectors, memory)?,
            scratch_output: dword_argument(arguments, 6)?,
            scratch_capacity_output: dword_argument(arguments, 7)?,
        }),
        Win16ExportId::VerLanguageName => Win16ApiRequest::Ver(Win16VerRequest::VerLanguageName {
            language: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
            capacity: word_argument(arguments, 2)?,
        }),
        Win16ExportId::VerQueryValue => Win16ApiRequest::Ver(Win16VerRequest::VerQueryValue {
            block: dword_argument(arguments, 0)?,
            sub_block: read_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            value_output: dword_argument(arguments, 2)?,
            length_output: dword_argument(arguments, 3)?,
        }),
        Win16ExportId::LzexpandLzCopy => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzCopy {
            source: word_argument(arguments, 0)? as i16,
            destination: word_argument(arguments, 1)? as i16,
        }),
        Win16ExportId::LzexpandLzOpenFile => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzOpenFile {
            path: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            ofstruct: dword_argument(arguments, 1)?,
            style: word_argument(arguments, 2)?,
        }),
        Win16ExportId::LzexpandLzInit => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzInit {
            file: word_argument(arguments, 0)? as i16,
        }),
        Win16ExportId::LzexpandLzSeek => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzSeek {
            file: word_argument(arguments, 0)? as i16,
            offset: dword_argument(arguments, 1)? as i32,
            origin: word_argument(arguments, 2)?,
        }),
        Win16ExportId::LzexpandLzRead => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzRead {
            file: word_argument(arguments, 0)? as i16,
            output: dword_argument(arguments, 1)?,
            count: word_argument(arguments, 2)?,
        }),
        Win16ExportId::LzexpandLzClose => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzClose {
            file: word_argument(arguments, 0)? as i16,
        }),
        Win16ExportId::LzexpandLzStart => {
            Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzStart)
        }
        Win16ExportId::LzexpandCopyLzFile => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzCopyFile {
            source: word_argument(arguments, 0)? as i16,
            destination: word_argument(arguments, 1)? as i16,
        }),
        Win16ExportId::LzexpandLzDone => Win16ApiRequest::LzExpand(Win16LzExpandRequest::LzDone),
        Win16ExportId::LzexpandGetExpandedName => Win16ApiRequest::LzExpand(
            Win16LzExpandRequest::LzGetExpandedName {
                source: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                output: dword_argument(arguments, 1)?,
            },
        ),
        Win16ExportId::ShellDoEnvironmentSubst => Win16ApiRequest::Shell(
            Win16ShellRequest::DoEnvironmentSubst {
                buffer: dword_argument(arguments, 0)?,
                capacity: word_argument(arguments, 1)?,
            },
        ),
        Win16ExportId::ShellFindEnvironmentString => Win16ApiRequest::Shell(
            Win16ShellRequest::FindEnvironmentString {
                query: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            },
        ),
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn resource_name(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ResourceName, Win16Error> {
    if raw >> 16 == 0 {
        Ok(Win16ResourceName::Id(raw as u16))
    } else {
        read_far_string(raw, selectors, memory).map(Win16ResourceName::Name)
    }
}

#[cfg(test)]
#[path = "call_any_popup_tests.rs"]
mod any_popup_tests;
#[cfg(test)]
#[path = "call_set_sys_colors_tests.rs"]
mod set_sys_colors_tests;
#[cfg(test)]
#[path = "call_swap_mouse_button_tests.rs"]
mod swap_mouse_button_tests;
#[cfg(test)]
#[path = "call_drag_tests.rs"]
mod drag_tests;
