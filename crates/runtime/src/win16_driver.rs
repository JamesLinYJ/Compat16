//! Runtime results for driver and deferred-device exports.
//!
//! Guest far addresses stay in the decoded slots. This module does not turn
//! those bits into host pointers and does not write a guest buffer.

use std::collections::BTreeSet;

use win16_abi::Win16DriverCall;

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

/// `REC_NOTABLET` from the Windows for Pen Computing recognition codes.
const REC_NOTABLET: u32 = 0xFFFA;
/// `MMSYSERR_NODRIVER`.
const MMSYSERR_NODRIVER: u32 = 6;
/// `ICERR_UNSUPPORTED` (`-1`).
const ICERR_UNSUPPORTED: u32 = 0xFFFF_FFFF;
/// `ICERR_BADHANDLE` (`-8`).
const ICERR_BADHANDLE: u32 = 0xFFFF_FFF8;
/// `AVIERR_UNSUPPORTED` (`MAKE_AVIERR(101)`).
const AVIERR_UNSUPPORTED: u32 = 0x8004_4065;
/// `CLASS_E_CLASSNOTAVAILABLE`.
const CLASS_E_CLASSNOTAVAILABLE: u32 = 0x8004_0111;
/// `DISPDIB.H` `DISPLAYDIB_NOTSUPPORTED`.
const DISPLAYDIB_NOT_SUPPORTED: u32 = 1;
/// `GGRC_PARAMERROR` and `SGRC_PARAMERROR`.
const PEN_PARAM_ERROR: u32 = 2;

#[derive(Clone, Debug, Default)]
pub(super) struct DriverGaps {
    reported: BTreeSet<u32>,
}

struct Answer {
    value: u32,
    detail: Option<&'static str>,
}

impl Win16State {
    pub(super) fn driver_call(
        &mut self,
        _call: Win16DriverCall,
        module: &str,
        ordinal: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let answer = answer(module, ordinal)?;
        if let Some(detail) = answer.detail {
            self.note_driver_gap(module, ordinal, detail, host);
        }
        Ok(answer.value)
    }

    fn note_driver_gap(
        &mut self,
        module: &str,
        ordinal: u16,
        detail: &'static str,
        host: &mut impl RuntimeHost,
    ) {
        let key = gap_key(module, ordinal);
        if self.driver_gaps.reported.insert(key) {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("{module} ordinal {ordinal} {detail}"),
            ));
        }
    }
}

fn answer(module: &str, ordinal: u16) -> Result<Answer, RuntimeError> {
    if module.eq_ignore_ascii_case("SYSTEM") && ordinal == 20 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 SYSTEM A20_Proc is not installed",
        ));
    }
    if module.eq_ignore_ascii_case("STRESS") && ordinal == 8 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 STRESS GetFreeFileHandles is not queried",
        ));
    }
    if module.eq_ignore_ascii_case("AVIFILE") && matches!(ordinal, 140 | 160) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 AVI AddRef is not installed",
        ));
    }
    Ok(Answer {
        value: value(module, ordinal),
        detail: detail(module, ordinal),
    })
}

fn value(module: &str, ordinal: u16) -> u32 {
    if module.eq_ignore_ascii_case("DISPDIB") && ordinal == 1 {
        return DISPLAYDIB_NOT_SUPPORTED;
    }
    if module.eq_ignore_ascii_case("MSVIDEO") {
        return msvideo_value(ordinal);
    }
    if module.eq_ignore_ascii_case("AVIFILE") {
        return avifile_value(ordinal);
    }
    if module.eq_ignore_ascii_case("WINSPOOL") && ordinal == 90 {
        return ICERR_UNSUPPORTED;
    }
    if module.eq_ignore_ascii_case("PENWIN") {
        return pen_value(ordinal);
    }
    0
}

fn msvideo_value(ordinal: u16) -> u32 {
    match ordinal {
        // Builtin MSVIDEO is already loaded. This does not open a capture device.
        3 => 1,
        21 | 28 | 29 | 30 | 31 | 32 | 33 | 34 | 35 | 40 | 41 | 42 | 43 | 44 | 46 | 47 | 49 | 50
        | 51 | 52 | 53 | 60 => MMSYSERR_NODRIVER,
        204 => ICERR_BADHANDLE,
        205 | 207 | 224 | 230 | 232 | 234 => ICERR_UNSUPPORTED,
        _ => 0,
    }
}

fn avifile_value(ordinal: u16) -> u32 {
    match ordinal {
        2 => CLASS_E_CLASSNOTAVAILABLE,
        102 | 103 | 104 | 123 | 142 | 143 | 144 | 146 | 147 | 148 | 162 | 164 | 165 | 166 | 167
        | 168 | 169 => AVIERR_UNSUPPORTED,
        // Unknown stream positions are not sample 0.
        130 | 131 | 132 | 133 | 163 => ICERR_UNSUPPORTED,
        _ => 0,
    }
}

fn pen_value(ordinal: u16) -> u32 {
    match ordinal {
        11 | 12 | 138 | 139 | 170 => REC_NOTABLET,
        150 | 151 => PEN_PARAM_ERROR,
        _ => 0,
    }
}

fn detail(module: &str, ordinal: u16) -> Option<&'static str> {
    if module.eq_ignore_ascii_case("MSVIDEO") && ordinal == 3 {
        return None;
    }
    if module.eq_ignore_ascii_case("AVIFILE") && matches!(ordinal, 100 | 101) {
        return None;
    }
    if module.eq_ignore_ascii_case("MSVIDEO") && matches!(ordinal, 2 | 20) {
        return Some("returns zero; no Video for Windows capture device is published");
    }
    Some(if module.eq_ignore_ascii_case("COMM") {
        "returns zero; COMM.DRV is not a host serial port"
    } else if module.eq_ignore_ascii_case("DISPLAY") {
        "returns zero; there is no 16-bit display driver"
    } else if module.eq_ignore_ascii_case("KEYBOARD") {
        "returns zero; the keyboard driver entry is not installed"
    } else if module.eq_ignore_ascii_case("MOUSE") {
        "returns zero; the mouse driver entry is not installed"
    } else if module.eq_ignore_ascii_case("SOUND") {
        "returns zero; this SOUND.DRV stub is not playback"
    } else if module.eq_ignore_ascii_case("SYSTEM") {
        "returns zero; no system timer or coprocessor save area is installed"
    } else if module.eq_ignore_ascii_case("TIMER") {
        "returns zero; timer.drv does not load"
    } else if module.eq_ignore_ascii_case("WINSPOOL") {
        "returns the printer-driver failure and writes no DEVMODE"
    } else if module.eq_ignore_ascii_case("PENWIN") {
        "returns the pen failure; no recognizer or tablet is installed"
    } else if module.eq_ignore_ascii_case("STRESS") {
        "returns zero; stress allocation is not performed"
    } else if module.eq_ignore_ascii_case("MSVIDEO") {
        "returns the video or codec failure and writes no buffer"
    } else if module.eq_ignore_ascii_case("DISPDIB") {
        "returns DISPLAYDIB_NOTSUPPORTED"
    } else if module.eq_ignore_ascii_case("AVIFILE") {
        "returns the AVI failure and writes no buffer"
    } else {
        "returns zero"
    })
}

fn gap_key(module: &str, ordinal: u16) -> u32 {
    let index = match module {
        "COMM" => 1,
        "DISPLAY" => 2,
        "KEYBOARD" => 3,
        "MOUSE" => 4,
        "SOUND" => 5,
        "SYSTEM" => 6,
        "TIMER" => 7,
        "WINSPOOL" => 8,
        "PENWIN" => 9,
        "STRESS" => 10,
        "MSVIDEO" => 11,
        "DISPDIB" => 12,
        "AVIFILE" => 13,
        _ => 0,
    };
    (index << 16) | u32::from(ordinal)
}
