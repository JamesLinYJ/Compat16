//! Runtime marshalling for the USER SystemParametersInfo family.
//!
//! Win16 pointers are preflighted and copied here. The host payload contains
//! only typed values and owned bytes; no guest address crosses the worker.

use guest_core::memory::Memory;
use win16_abi::{
    SegmentedPointer, SelectorTable, user_service_abi::{LogFont16, MouseParameters16},
    Win16SystemParametersInfoRequest,
};

use super::Win16State;
use super::guest_ranges::GuestOutputRange;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostLogFont,
    Win16HostSystemParametersResult, Win16SystemParametersRequest as HostRequest,
    Win16SystemParametersValue as HostValue,
};

#[derive(Clone, Copy, Debug)]
enum OutputKind { Bool, Word, Mouse, LanguageDriver, LogFont }

#[derive(Clone, Debug)]
pub(super) struct Win16SpiContinuation {
    output: Option<GuestOutputRange>,
    capacity: u16,
    kind: Option<OutputKind>,
}

impl Win16SpiContinuation {
    pub(super) fn project_output(
        &self,
        result: &Win16HostSystemParametersResult,
    ) -> Result<(u32, Option<Vec<u8>>), RuntimeError> {
        let Some(kind) = self.kind else {
            if result.value != HostValue::None {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 SPI setter returned a value for a no-output request"));
            }
            return Ok((u32::from(result.succeeded), None));
        };
        let range = self.output.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "SystemParametersInfo output kind lost its entry-captured range",
        ))?;
        let bytes = match (kind, &result.value) {
            (OutputKind::Bool, HostValue::Bool(value)) => {
                if !result.succeeded { return Ok((0, None)); }
                let encoded = (if *value { 1_u16 } else { 0 }).to_le_bytes();
                copy_output_bytes(&encoded)?
            }
            (OutputKind::Word, HostValue::Word(value)) => {
                if !result.succeeded { return Ok((0, None)); }
                copy_output_bytes(&value.to_le_bytes())?
            }
            (OutputKind::Mouse, HostValue::Mouse(values)) => {
                if !result.succeeded { return Ok((0, None)); }
                copy_output_bytes(&MouseParameters16(*values).encode())?
            }
            (OutputKind::LanguageDriver, HostValue::LanguageDriver(bytes)) => {
                if !result.succeeded { return Ok((0, None)); }
                if bytes.len() > usize::from(self.capacity) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 SPI language-driver result exceeds its checked buffer"));
                }
                copy_output_bytes(bytes)?
            }
            (OutputKind::LogFont, HostValue::LogFont(font)) => {
                if !result.succeeded { return Ok((0, None)); }
                copy_output_bytes(&logfont_from_host(font.clone()).encode())?
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 SPI host result does not match its action")),
        };
        if bytes.len() > range.length() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 SPI output exceeds its entry-captured guest range"));
        }
        Ok((1, Some(bytes)))
    }

    pub(super) fn commit_output(
        &self,
        selectors: &SelectorTable,
        memory: &mut Memory,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        let range = self.output.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "SystemParametersInfo output commit lost its captured range",
        ))?;
        super::guest_ranges::commit_guest_output_with_selectors(
            selectors, memory, range, bytes,
        )
    }
}

pub(super) enum Win16SpiPreparation {
    Immediate(u32),
    Host {
        request: HostRequest,
        continuation: Win16SpiContinuation,
    },
}

impl Win16State {
    fn capture_spi_fixed_output(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
        length: usize,
    ) -> Result<GuestOutputRange, RuntimeError> {
        self.selectors.translate(pointer, win16_abi::Access::Write, length, memory)
            .map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, length)
    }

    /// Convert known Windows 3.x SPI actions to explicit host request shapes.
    /// Unrecognized actions take the documented FALSE path instead of being
    /// forwarded through an assumed data layout.
    pub(super) fn prepare_system_parameters_info(
        &self,
        request: Win16SystemParametersInfoRequest,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16SpiPreparation, RuntimeError> {
        use Win16SpiPreparation as Prepared;

        let mut continuation = Win16SpiContinuation {
            output: None,
            capacity: request.param,
            kind: None,
        };
        let prepared = match request.action {
            SPI_GETBEEP | SPI_GETSCREENSAVEACTIVE | SPI_GETICONTITLEWRAP
            | SPI_GETMENUDROPALIGNMENT => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                continuation.output = Some(self.capture_spi_fixed_output(memory, pointer, 2)?);
                continuation.kind = Some(OutputKind::Bool);
                HostRequest::GetBool(request.action)
            }
            SPI_SETBEEP | SPI_SETSCREENSAVEACTIVE | SPI_SETICONTITLEWRAP
            | SPI_SETMENUDROPALIGNMENT => HostRequest::SetBool {
                action: request.action,
                value: request.param != 0,
                flags: request.flags,
            },
            SPI_GETBORDER | SPI_GETKEYBOARDSPEED | SPI_GETSCREENSAVETIMEOUT
            | SPI_GETGRIDGRANULARITY | SPI_GETKEYBOARDDELAY => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                continuation.output = Some(self.capture_spi_fixed_output(memory, pointer, 2)?);
                continuation.kind = Some(OutputKind::Word);
                HostRequest::GetWord(request.action)
            }
            SPI_SETBORDER | SPI_SETKEYBOARDSPEED | SPI_SETSCREENSAVETIMEOUT
            | SPI_SETGRIDGRANULARITY | SPI_SETKEYBOARDDELAY => HostRequest::SetWord {
                action: request.action,
                value: request.param,
                flags: request.flags,
            },
            SPI_ICONHORIZONTALSPACING | SPI_ICONVERTICALSPACING => {
                if request.param != 0 {
                    HostRequest::SetWord {
                        action: request.action,
                        value: request.param,
                        flags: request.flags,
                    }
                } else if let Some(pointer) = self.spi_data_pointer(request.data)? {
                    continuation.output = Some(self.capture_spi_fixed_output(memory, pointer, 2)?);
                    continuation.kind = Some(OutputKind::Word);
                    HostRequest::GetWord(request.action)
                } else {
                    return Ok(Prepared::Immediate(0));
                }
            }
            SPI_GETMOUSE => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                continuation.output = Some(self.capture_spi_fixed_output(
                    memory, pointer, MouseParameters16::SIZE,
                )?);
                continuation.kind = Some(OutputKind::Mouse);
                HostRequest::GetMouse
            }
            SPI_SETMOUSE => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                let bytes = self.read_text_bytes(memory, pointer, MouseParameters16::SIZE)?;
                let encoded: [u8; MouseParameters16::SIZE] = bytes.try_into().map_err(|_| {
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 SPI mouse input has an invalid byte count")
                })?;
                HostRequest::SetMouse {
                    values: MouseParameters16::decode(&encoded).0,
                    flags: request.flags,
                }
            }
            SPI_LANGDRIVER => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                continuation.output = Some(GuestOutputRange::capture(
                    self, memory, pointer, usize::from(request.param),
                )?);
                continuation.capacity = request.param;
                continuation.kind = Some(OutputKind::LanguageDriver);
                HostRequest::GetLanguageDriver { capacity: request.param }
            }
            SPI_SETDESKWALLPAPER => {
                if request.data == 0 { return Ok(Prepared::Immediate(0)); }
                let path = win16_abi::strings::read_ansi_z(
                    &self.selectors, memory, request.data,
                    win16_abi::exports::MAX_WIN16_STRING_BYTES,
                ).map_err(crate::runtime_error)?;
                HostRequest::SetDesktopWallpaper { path, flags: request.flags }
            }
            SPI_SETDESKPATTERN => HostRequest::SetDesktopPattern { flags: request.flags },
            SPI_GETICONTITLELOGFONT => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                continuation.output = Some(self.capture_spi_fixed_output(
                    memory, pointer, LogFont16::SIZE,
                )?);
                continuation.kind = Some(OutputKind::LogFont);
                HostRequest::GetIconTitleLogFont
            }
            SPI_SETICONTITLELOGFONT => {
                let Some(pointer) = self.spi_data_pointer(request.data)? else {
                    return Ok(Prepared::Immediate(0));
                };
                let bytes = self.read_text_bytes(memory, pointer, LogFont16::SIZE)?;
                let encoded: [u8; LogFont16::SIZE] = bytes.try_into().map_err(|_| {
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 SPI LOGFONT input has an invalid byte count")
                })?;
                let font = logfont_to_host(LogFont16::decode(&encoded));
                HostRequest::SetIconTitleLogFont { font, flags: request.flags }
            }
            action => {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!("SystemParametersInfo action 0x{action:04X} is not implemented"),
                ));
                return Ok(Prepared::Immediate(0));
            }
        };
        Ok(Prepared::Host { request: prepared, continuation })
    }

    /// Decode `pvParam` only after the selected action requires it. Ignored
    /// pointers and unknown actions are ordinary API outcomes, not guest
    /// memory faults.
    fn spi_data_pointer(&self, far: u32) -> Result<Option<SegmentedPointer>, RuntimeError> {
        if far == 0 {
            Ok(None)
        } else {
            self.selectors.pointer_from_far(far)
                .map(Some)
                .map_err(crate::runtime_error)
        }
    }

    pub(super) fn finish_system_parameters_info(
        &self,
        continuation: Win16SpiContinuation,
        result: Win16HostSystemParametersResult,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let (value, bytes) = continuation.project_output(&result)?;
        if let Some(bytes) = bytes {
            continuation.commit_output(&self.selectors, memory, &bytes)?;
        }
        Ok(value)
    }
}

fn copy_output_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "retain Win16 SPI output bytes", error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn logfont_to_host(font: LogFont16) -> Win16HostLogFont {
    Win16HostLogFont {
        height: font.height,
        width: font.width,
        escapement: font.escapement,
        orientation: font.orientation,
        weight: font.weight,
        italic: font.italic,
        underline: font.underline,
        strikeout: font.strike_out,
        char_set: font.char_set,
        out_precision: font.out_precision,
        clip_precision: font.clip_precision,
        quality: font.quality,
        pitch_and_family: font.pitch_and_family,
        face_name: font.face_name,
    }
}

fn logfont_from_host(font: Win16HostLogFont) -> LogFont16 {
    LogFont16 {
        height: font.height,
        width: font.width,
        escapement: font.escapement,
        orientation: font.orientation,
        weight: font.weight,
        italic: font.italic,
        underline: font.underline,
        strike_out: font.strikeout,
        char_set: font.char_set,
        out_precision: font.out_precision,
        clip_precision: font.clip_precision,
        quality: font.quality,
        pitch_and_family: font.pitch_and_family,
        face_name: font.face_name,
    }
}

// Win3.x SystemParametersInfo action values shared with the documented
// Windows API. Newer-only actions are intentionally not guessed here.
const SPI_GETBEEP: u16 = 1;
const SPI_SETBEEP: u16 = 2;
const SPI_GETMOUSE: u16 = 3;
const SPI_SETMOUSE: u16 = 4;
const SPI_GETBORDER: u16 = 5;
const SPI_SETBORDER: u16 = 6;
const SPI_GETKEYBOARDSPEED: u16 = 10;
const SPI_SETKEYBOARDSPEED: u16 = 11;
const SPI_LANGDRIVER: u16 = 12;
const SPI_ICONHORIZONTALSPACING: u16 = 13;
const SPI_GETSCREENSAVETIMEOUT: u16 = 14;
const SPI_SETSCREENSAVETIMEOUT: u16 = 15;
const SPI_GETSCREENSAVEACTIVE: u16 = 16;
const SPI_SETSCREENSAVEACTIVE: u16 = 17;
const SPI_GETGRIDGRANULARITY: u16 = 18;
const SPI_SETGRIDGRANULARITY: u16 = 19;
const SPI_SETDESKWALLPAPER: u16 = 20;
const SPI_SETDESKPATTERN: u16 = 21;
const SPI_GETKEYBOARDDELAY: u16 = 22;
const SPI_SETKEYBOARDDELAY: u16 = 23;
const SPI_ICONVERTICALSPACING: u16 = 24;
const SPI_GETICONTITLEWRAP: u16 = 25;
const SPI_SETICONTITLEWRAP: u16 = 26;
const SPI_GETMENUDROPALIGNMENT: u16 = 27;
const SPI_SETMENUDROPALIGNMENT: u16 = 28;
const SPI_GETICONTITLELOGFONT: u16 = 31;
const SPI_SETICONTITLELOGFONT: u16 = 34;
