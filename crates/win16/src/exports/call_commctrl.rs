//! Typed stack decoding for the known-signature Win16 common-control exports.

use super::{
    lookup_export_metadata, ExportArchitecture, ExportArgumentType, ExportEntryKind,
    ExportLookupTarget, ExportSignatureKind, Win16ExportDescriptor,
};
use super::request::{Win16ApiRequest, Win16CommctrlRequest};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = decode_commctrl_export(
        descriptor.module().as_bytes(),
        ExportLookupTarget::Ordinal(descriptor.ordinal()),
        arguments,
        selectors,
        memory,
    )?
    .ok_or(Win16Error::InvalidRange)?;
    Ok(Win16ApiRequest::Commctrl(request))
}

pub fn decode_commctrl_export(
    module: &[u8],
    target: ExportLookupTarget<'_>,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16CommctrlRequest>, Win16Error> {
    let Some(declaration) = lookup_export_metadata(module, target) else { return Ok(None); };
    if declaration.architecture != ExportArchitecture::Win16
        || declaration.kind != ExportEntryKind::Function
        || !declaration.module.eq_ignore_ascii_case("COMMCTRL")
    { return Ok(None); }
    let Some(abi) = declaration.abi else { return Ok(None); };
    if abi.signature != ExportSignatureKind::Known || abi.arguments.len() != arguments.len() {
        return Ok(None);
    }
    if !signature_matches(abi.arguments, arguments) { return Ok(None); }
    let ordinal = declaration.ordinal;
    let word = |index: usize| -> Result<u16, Win16Error> {
        match arguments.get(index).copied() { Some(Win16Argument::Word(value)) => Ok(value), _ => Err(Win16Error::InvalidRange) }
    };
    let dword = |index: usize| -> Result<u32, Win16Error> {
        match arguments.get(index).copied() { Some(Win16Argument::Dword(value)) => Ok(value), _ => Err(Win16Error::InvalidRange) }
    };
    let string = |index: usize| -> Result<Vec<u8>, Win16Error> {
        crate::strings::read_ansi_z(selectors, memory, dword(index)?, super::MAX_WIN16_STRING_BYTES)
    };
    let optional_string = |index: usize| -> Result<Option<Vec<u8>>, Win16Error> {
        let far = dword(index)?;
        if far == 0 { return Ok(None); }
        crate::strings::read_ansi_z(selectors, memory, far, super::MAX_WIN16_STRING_BYTES)
            .map(Some)
    };
    let request = match ordinal {
        2 => Win16CommctrlRequest::MenuHelp {
            message: word(0)?, w_param: word(1)?, l_param: dword(2)?,
            menu: word(3)?, instance: word(4)?, status_bar: word(5)?,
            help_id_table: dword(6)?,
        },
        4 => Win16CommctrlRequest::GetEffectiveClientRect {
            window: word(0)?, rect: dword(1)?, control_ids: dword(2)?,
        },
        6 => Win16CommctrlRequest::CreateStatusWindow {
            style: dword(0)?, text: string(1)?, parent: word(2)?, control_id: word(3)?,
        },
        7 => Win16CommctrlRequest::CreateToolbar {
            parent: word(0)?, style: dword(1)?, control_id: word(2)?,
            bitmap_count: word(3)?, bitmap_instance: word(4)?,
            bitmap_resource: word(5)?, buttons: dword(6)?, button_count: word(7)?,
            button_width: None, button_height: None, bitmap_width: None,
            bitmap_height: None, button_struct_size: None,
        },
        8 => Win16CommctrlRequest::CreateMappedBitmap {
            instance: word(0)?, bitmap_resource: word(1)?, flags: word(2)?,
            color_map: dword(3)?, color_map_count: word(4)?,
        },
        9 => Win16CommctrlRequest::CreateHeaderWindow {
            style: dword(0)?, text: string(1)?, parent: word(2)?, control_id: word(3)?,
        },
        10 => Win16CommctrlRequest::WritePrivateProfileStruct {
            section: optional_string(0)?, key: optional_string(1)?, data: dword(2)?,
            data_size: word(3)?, file_name: optional_string(4)?,
        },
        11 => Win16CommctrlRequest::GetPrivateProfileStruct {
            section: string(0)?, key: string(1)?, output: dword(2)?,
            capacity: word(3)?, file_name: string(4)?,
        },
        13 => Win16CommctrlRequest::MakeDragList { list_box: word(0)? },
        17 => Win16CommctrlRequest::InitCommonControls,
        20 => Win16CommctrlRequest::CreateToolbarEx {
            parent: word(0)?, style: dword(1)?, control_id: word(2)?,
            bitmap_count: word(3)?, bitmap_instance: word(4)?,
            bitmap_resource: word(5)?, buttons: dword(6)?, button_count: word(7)?,
            button_width: word(8)?, button_height: word(9)?, bitmap_width: word(10)?,
            bitmap_height: word(11)?, button_struct_size: word(12)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn signature_matches(declared: &[ExportArgumentType], arguments: &[Win16Argument]) -> bool {
    declared.iter().copied().zip(arguments.iter().copied()).all(|(kind, value)| {
        match (kind, value) {
            (ExportArgumentType::Word | ExportArgumentType::SignedWord, Win16Argument::Word(_)) => true,
            (ExportArgumentType::Long | ExportArgumentType::Pointer
                | ExportArgumentType::SegmentedPointer | ExportArgumentType::String,
                Win16Argument::Dword(_)) => true,
            _ => false,
        }
    })
}
