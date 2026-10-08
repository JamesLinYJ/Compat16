//! Decoding for the known Win16 CTL3D and CTL3DV2 exports.

use super::Win16ExportDescriptor;
use super::request::{
    Win16ApiRequest, Win16Ctl3dArgument, Win16Ctl3dModule, Win16Ctl3dRequest,
};
use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy)]
enum SlotWidth {
    Word,
    Dword,
}

const W: SlotWidth = SlotWidth::Word;
const D: SlotWidth = SlotWidth::Dword;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    let module = match descriptor.module() {
        "CTL3D" => Win16Ctl3dModule::Ctl3d,
        "CTL3DV2" => Win16Ctl3dModule::Ctl3dV2,
        _ => return Err(Win16Error::InvalidRange),
    };
    let request = decode_ctl3d_arguments(module, descriptor.ordinal(), arguments)?
        .ok_or(Win16Error::InvalidRange)?;
    Ok(Win16ApiRequest::Ctl3d(request))
}

/// The family decoder consumes the scalar slots already decoded by the
/// catalog call path. It does not look up or reinterpret the source spec.
pub(super) fn decode_ctl3d_arguments(
    module: Win16Ctl3dModule,
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16Ctl3dRequest>, Win16Error> {
    let Some((name, widths)) = signature(ordinal) else {
        return Ok(None);
    };
    if widths.len() != arguments.len() {
        return Ok(None);
    }

    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(arguments.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    for (width, argument) in widths.iter().zip(arguments.iter()) {
        let value = match (*width, *argument) {
            (SlotWidth::Word, Win16Argument::Word(value)) => {
                Win16Ctl3dArgument::Word(value)
            }
            (SlotWidth::Dword, Win16Argument::Dword(value)) => {
                Win16Ctl3dArgument::Dword(value)
            }
            _ => return Ok(None),
        };
        decoded.push(value);
    }

    Ok(Some(Win16Ctl3dRequest {
        module,
        ordinal,
        name: Some(name),
        arguments: decoded,
    }))
}

fn signature(ordinal: u16) -> Option<(&'static str, &'static [SlotWidth])> {
    Some(match ordinal {
        1 => ("Ctl3dGetVer", &[]),
        2 => ("Ctl3dSubclassDlg", &[W, W]),
        3 => ("Ctl3dSubclassCtl", &[W]),
        4 => ("Ctl3dCtlColor", &[W, D]),
        5 => ("Ctl3dEnabled", &[]),
        6 => ("Ctl3dColorChange", &[]),
        12 => ("Ctl3dRegister", &[W]),
        13 => ("Ctl3dUnregister", &[W]),
        16 => ("Ctl3dAutoSubclass", &[W]),
        18 => ("Ctl3dCtlColorEx", &[W, W, D]),
        // Ordinal 19 has no Microsoft prototype in the available target SDK;
        // it stays out of the formal catalog until its return contract is known.
        20 => ("Ctl3dDlgFramePaint", &[W, W, W, D]),
        21 => ("Ctl3dSubclassDlgEx", &[W, D]),
        22 => ("Ctl3dWinIniChange", &[]),
        23 => ("Ctl3dIsAutoSubclass", &[]),
        24 => ("Ctl3dUnAutoSubclass", &[]),
        25 => ("Ctl3dSubclassCtlEx", &[W, W]),
        26 => ("Ctl3dUnsubclassCtl", &[W]),
        27 => ("Ctl3dAutoSubclassEx", &[W, D]),
        _ => return None,
    })
}
