use crate::{FormatError, NeEntryKind, NeModule};
use guest_core::Selector;

const WINDOWS_TARGET: u8 = 2;
const MODULE_MULTIPLE_DATA: u16 = 0x0002;
const SEGMENT_DATA: u16 = 0x0001;
const ENTRY_EXPORTED: u8 = 0x01;
const ENTRY_SINGLE_DATA: u8 = 0x02;

// Microsoft Windows 3.1 Programmer's Reference, Vol. 1, sections 21.1.1-
// 21.1.3 describe the three-byte Windows prolog and its AX/DS contract:
// https://www.bitsavers.org/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28915-0492_Programmers_Reference_Volume_1_199204.pdf
// Entry flag meanings are documented in the MS-DOS Encyclopedia, Appendix K:
// https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/appendix-k/
pub(super) fn patch_windows_prologs(
    module: &NeModule,
    selectors: &[Selector],
    images: &mut [Vec<u8>],
) -> Result<(), FormatError> {
    if module.header.target_os != WINDOWS_TARGET || module.header.automatic_data_segment == 0 {
        return Ok(());
    }
    for entry in &module.entries {
        let single_data = entry.flags & ENTRY_SINGLE_DATA != 0;
        let instance_callback = module.header.flags & MODULE_MULTIPLE_DATA != 0
            && entry.flags & ENTRY_EXPORTED != 0;
        if !single_data && !instance_callback {
            continue;
        }
        let (segment, offset) = match entry.kind {
            NeEntryKind::Fixed { segment, offset } | NeEntryKind::Movable { segment, offset } => {
                (segment, offset)
            }
            NeEntryKind::Unused | NeEntryKind::Constant(_) => continue,
        };
        let index = usize::from(segment.checked_sub(1).ok_or(FormatError::InvalidNeLoad(
            "Windows prolog references segment zero",
        ))?);
        let metadata = module.segments.get(index).ok_or(FormatError::InvalidNeLoad(
            "Windows prolog references a missing segment",
        ))?;
        if metadata.flags & SEGMENT_DATA != 0 {
            continue;
        }
        let image = images.get_mut(index).ok_or(FormatError::InvalidNeLoad(
            "Windows prolog has no staged segment image",
        ))?;
        let start = usize::from(offset);
        // Short entries and arbitrary assembly exports are valid. Only these
        // complete, documented instruction sequences reserve patchable bytes.
        let Some(prefix) = image.get_mut(start..start + 3) else { continue; };
        if prefix != [0x1e, 0x58, 0x90] && prefix != [0x8c, 0xd8, 0x90] {
            continue;
        }
        let replacement = if single_data {
            let data_index = usize::from(module.header.automatic_data_segment - 1);
            let selector = selectors.get(data_index).ok_or(FormatError::InvalidNeLoad(
                "Windows prolog references a missing automatic data segment",
            ))?;
            let [low, high] = selector.0.to_le_bytes();
            [0xb8, low, high] // MOV AX, DGROUP
        } else {
            // Preserve the instance selector supplied in AX by the caller or
            // MakeProcInstance rather than overwriting it with the caller's DS.
            [0x90; 3]
        };
        prefix.copy_from_slice(&replacement);
    }
    Ok(())
}
