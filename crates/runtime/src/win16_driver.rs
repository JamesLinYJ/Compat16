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
    if module.eq_ignore_ascii_case("COMM") {
        return comm_value(ordinal);
    }
    if module.eq_ignore_ascii_case("DISPLAY") || module.eq_ignore_ascii_case("WINSPOOL") {
        return graphics_value(ordinal);
    }
    if module.eq_ignore_ascii_case("KEYBOARD") && ordinal == 11 {
        // `VkKeyScanEx` returns -1 when the character has no translation.
        return 0xFFFF;
    }
    if module.eq_ignore_ascii_case("MOUSE") && ordinal == 4 {
        // `MouseGetIntVect` returns -1 when no mouse interrupt vector exists.
        return 0xFFFF;
    }
    if module.eq_ignore_ascii_case("PENWIN") {
        return pen_value(ordinal);
    }
    0
}

fn comm_value(ordinal: u16) -> u32 {
    // Windows 3.1 `WINDOWS.H` defines `IE_HARDWARE` as -10.
    const IE_HARDWARE: i16 = -10;
    match ordinal {
        // Success for these entries is zero. A missing UART returns
        // `IE_HARDWARE` in AX.
        1 | 2 | 3 | 5 | 6 | 7 => u32::from(IE_HARDWARE as u16),
        // `reccom`, `csetbrk`, and `cclrbrk` document -1 as the error.
        4 | 13 | 14 => 0xFFFF,
        // `stacom` and `cflush` return the most recent error. `CE_MODE` means
        // the requested mode is not supported.
        8 | 10 => 0x8000,
        // `cextfcn` returns a negative long. The same error is sign-extended.
        9 => i32::from(IE_HARDWARE) as u32,
        // `WEP` returns 1 so the already-loaded builtin may be released.
        101 => 1,
        _ => 0,
    }
}

fn graphics_value(ordinal: u16) -> u32 {
    match ordinal {
        // `EnumDFonts` and `EnumObj` return 1 when no object of that kind exists.
        // The callback is not called.
        6 | 7 => 1,
        // `Pixel` returns `0x80000000` when the pixel cannot be read or set.
        9 => 0x8000_0000,
        // `ScanLR` returns -1 when no qualifying pixel is found.
        12 => 0xFFFF,
        _ => 0,
    }
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
        102 | 103 | 104 | 105 | 106 | 107 | 120 | 121 | 123 | 142 | 143 | 144 | 146 | 147 | 148
        | 162 | 164 | 165 | 166 | 167 | 168 | 169 | 180 | 181 | 182 | 184 | 185 | 187 | 188
        | 190 | 191 | 192 | 200 | 201 => AVIERR_UNSUPPORTED,
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
    if module.eq_ignore_ascii_case("COMM") && ordinal == 101 {
        return None;
    }
    if module.eq_ignore_ascii_case("AVIFILE") && matches!(ordinal, 100 | 101) {
        return None;
    }
    if module.eq_ignore_ascii_case("MSVIDEO") && matches!(ordinal, 2 | 20) {
        return Some("returns zero; no Video for Windows capture device is published");
    }
    if module.eq_ignore_ascii_case("MSVIDEO") && ordinal == 115 {
        return Some("does not stretch the bitmap and writes no destination");
    }
    if module.eq_ignore_ascii_case("DISPLAY") && ordinal == 31 {
        return Some("returns FALSE and does not rewrite PDEVICE or GDIINFO");
    }
    Some(if module.eq_ignore_ascii_case("COMM") {
        "returns the communications failure and writes no DCB, queue, or status"
    } else if module.eq_ignore_ascii_case("DISPLAY") {
        "returns the display-driver failure or empty result and writes no surface"
    } else if module.eq_ignore_ascii_case("KEYBOARD") {
        "returns the keyboard-driver failure and writes no translation"
    } else if module.eq_ignore_ascii_case("MOUSE") {
        "returns the mouse-driver failure"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_contract_avi_constructors_fail_without_publishing_an_object() {
        for ordinal in [102, 103, 104, 105, 106, 107] {
            let result = answer("AVIFILE", ordinal).unwrap();
            assert_eq!(result.value, 0x8004_4065);
            assert_ne!(result.value & 0x8000_0000, 0, "HRESULT must fail");
            assert!(result.detail.is_some());
        }
        assert_eq!(value("COMM", 1), 0xFFF6);
        assert_eq!(value("COMM", 4), 0xFFFF);
        assert_eq!(value("COMM", 9), 0xFFFF_FFF6);
        assert_eq!(value("COMM", 101), 1);
        assert!(answer("COMM", 101).unwrap().detail.is_none());
        assert_eq!(value("DISPLAY", 6), 1);
        assert_eq!(value("DISPLAY", 9), 0x8000_0000);
        assert_eq!(value("DISPLAY", 12), 0xFFFF);
        assert_eq!(value("DISPLAY", 31), 0);
        assert_eq!(value("WINSPOOL", 9), 0x8000_0000);
        assert_eq!(value("KEYBOARD", 11), 0xFFFF);
        assert_eq!(value("MOUSE", 4), 0xFFFF);
        assert_eq!(value("AVIFILE", 120), AVIERR_UNSUPPORTED);
        assert_eq!(value("AVIFILE", 122), 0);
        assert_eq!(value("AVIFILE", 188), AVIERR_UNSUPPORTED);
    }
}
