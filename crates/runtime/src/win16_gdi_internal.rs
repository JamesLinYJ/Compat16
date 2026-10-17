//! Runtime for GDI ordinals that had no call binding.
//!
//! Guest handles and far addresses stay guest values. Host drawing goes through
//! the existing GDI adapter. An ordinal this host cannot perform returns that
//! ordinal's failure value and does not report success.

use guest_core::memory::Memory;
use win16_abi::gdi_abi::{ETO_PDY, ETO_RECT_FLAGS};
use win16_abi::{Win16GdiInternalArg as Arg, Win16GdiInternalRequest as Request};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingRect, Win16DrawingResult as HostResult,
};

const ABSOLUTE: u16 = 1;
const DEFAULT_CHARSET: u32 = 1;
const GCP_ERROR: u32 = 0x8000;
const SCAN_NOT_FOUND: u32 = 0xFFFF;

impl Win16State {
    pub(super) fn execute_gdi_internal(
        &mut self,
        request: Request,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let args = &request.arguments;
        match request.ordinal {
            5 => self.gdi_set_rel_abs(word(args, 0)?, word(args, 1)?),
            86 => Ok(self.gdi_get_rel_abs(word(args, 0)?)),
            179 => Ok(self.gdi_dc_state(word(args, 0)?)),
            180 => self.gdi_set_dc_state(word(args, 0)?, word(args, 1)?),
            195 => self.select_object(word(args, 0)?, word(args, 1)?, host).map(u32::from),
            250 => self.gdi_copy(memory, far(args, 0)?, far(args, 1)?, word(args, 2)?),
            407 => self.create_bitmap(
                memory,
                word(args, 0)? as i16,
                word(args, 1)? as i16,
                word(args, 2)?,
                word(args, 3)?,
                far(args, 4)?,
                host,
            ).map(u32::from),
            409 => self.create_discardable_bitmap(
                word(args, 0)?,
                word(args, 1)? as i16,
                word(args, 2)? as i16,
                host,
            ),
            410 => self.gdi_is_valid_metafile(word(args, 0)?, memory),
            530 => self.gdi_raw_text_out(
                memory,
                host,
                word(args, 0)?,
                word(args, 1)? as i16,
                word(args, 2)? as i16,
                far(args, 3)?,
                word(args, 4)?,
            ),
            531 => self.gdi_raw_ext_text_out(memory, host, args),
            532 => self.gdi_raw_text_extent(memory, host, word(args, 0)?, far(args, 1)?, word(args, 2)?),
            572 | 612 => Ok(DEFAULT_CHARSET),
            588 => self.gdi_set_text_code_page(word(args, 0)?, word(args, 1)?),
            589 => Ok(u32::from(self.guest_gdi.session_text_code_page())),
            605 => self.delete_object(word(args, 0)?, memory, host).map(u32::from),
            616 => Ok(self.gdi_font_language_info(word(args, 0)?)),
            1000 => self.gdi_set_layout(word(args, 0)?, dword(args, 1)?),
            135 => Ok(SCAN_NOT_FOUND),
            403 | 405 | 5000 => Ok(1),
            _ => Ok(0),
        }
    }

    fn gdi_set_rel_abs(&mut self, dc: u16, mode: u16) -> Result<u32, RuntimeError> {
        if self.guest_gdi.dc(dc).is_none() {
            return Ok(0);
        }
        let previous = self.guest_gdi.rel_abs(dc).unwrap_or(ABSOLUTE);
        self.guest_gdi.set_rel_abs(dc, mode);
        Ok(u32::from(previous))
    }

    fn gdi_get_rel_abs(&self, dc: u16) -> u32 {
        if self.guest_gdi.dc(dc).is_none() {
            0
        } else {
            u32::from(self.guest_gdi.rel_abs(dc).unwrap_or(ABSOLUTE))
        }
    }

    fn gdi_dc_state(&self, dc: u16) -> u32 {
        if self.guest_gdi.dc(dc).is_none() {
            0
        } else {
            u32::from(self.guest_gdi.dc_state(dc).unwrap_or(0))
        }
    }

    fn gdi_set_dc_state(&mut self, dc: u16, state: u16) -> Result<u32, RuntimeError> {
        if self.guest_gdi.dc(dc).is_none() {
            return Ok(0);
        }
        let previous = self.guest_gdi.dc_state(dc).unwrap_or(0);
        self.guest_gdi.set_dc_state(dc, state);
        Ok(u32::from(previous))
    }

    fn gdi_set_text_code_page(&mut self, dc: u16, page: u16) -> Result<u32, RuntimeError> {
        if self.guest_gdi.dc(dc).is_none() {
            return Ok(0);
        }
        let previous = self.guest_gdi.dc_code_page(dc).unwrap_or(0);
        self.guest_gdi.set_dc_code_page(dc, page);
        self.guest_gdi.set_session_text_code_page(page);
        Ok(u32::from(previous))
    }

    fn gdi_set_layout(&mut self, dc: u16, layout: u32) -> Result<u32, RuntimeError> {
        if self.guest_gdi.dc(dc).is_none() {
            return Ok(0);
        }
        let previous = self.guest_gdi.dc_layout(dc).unwrap_or(0);
        self.guest_gdi.set_dc_layout(dc, layout);
        Ok(previous as u16 as u32)
    }

    fn gdi_font_language_info(&self, dc: u16) -> u32 {
        if self.guest_gdi.dc(dc).is_none() {
            GCP_ERROR
        } else {
            0
        }
    }

    fn gdi_copy(
        &self,
        memory: &mut Memory,
        destination: u32,
        source: u32,
        count: u16,
    ) -> Result<u32, RuntimeError> {
        if count == 0 {
            return Ok(0);
        }
        let length = usize::from(count);
        let source_pointer = self
            .selectors
            .pointer_from_far(source)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, source_pointer, length)?;
        let destination_pointer = self
            .selectors
            .pointer_from_far(destination)
            .map_err(crate::runtime_error)?;
        self.write_text_bytes(memory, destination_pointer, &bytes)?;
        Ok(u32::from(count))
    }

    fn gdi_is_valid_metafile(
        &mut self,
        handle: u16,
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(bytes) = self.copy_global_bytes(handle, memory)? else {
            return Ok(0);
        };
        Ok(u32::from(u16::from(windows_metafile_header(&bytes))))
    }

    fn gdi_raw_text_out(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        dc: u16,
        x: i16,
        y: i16,
        text: u32,
        count: u16,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        let text = self.read_counted_guest(memory, text, count)?;
        match host.win16_gdi(Operation::TextOut {
            dc,
            x: i32::from(x),
            y: i32::from(y),
            text,
        })? {
            HostResult::Bool(result) => Ok(u32::from(u16::from(result))),
            _ => Err(wrong_result("RawTextOut")),
        }
    }

    fn gdi_raw_text_extent(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        dc: u16,
        text: u32,
        count: u16,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        let text = self.read_counted_guest(memory, text, count)?;
        match host.win16_gdi(Operation::GetTextExtent { dc, text })? {
            HostResult::Size { width, height } => Ok(pack_words(width, height)),
            _ => Err(wrong_result("RawGetTextExtent")),
        }
    }

    fn gdi_raw_ext_text_out(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        args: &[Arg],
    ) -> Result<u32, RuntimeError> {
        let dc_handle = word(args, 0)?;
        let Some(dc) = self.guest_gdi.dc(dc_handle) else {
            return Ok(0);
        };
        let options = word(args, 3)?;
        let count = word(args, 6)?;
        let text = self.read_counted_guest(memory, far(args, 5)?, count)?;
        let rect = if options & ETO_RECT_FLAGS != 0 {
            self.read_guest_rect(memory, far(args, 4)?)?
        } else {
            None
        };
        let spacing = self.read_guest_spacing(memory, far(args, 7)?, count, options)?;
        match host.win16_gdi(Operation::ExtTextOut {
            dc,
            x: i32::from(word(args, 1)? as i16),
            y: i32::from(word(args, 2)? as i16),
            options: u32::from(options),
            rect,
            text,
            spacing,
        })? {
            HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
            _ => Err(wrong_result("RawExtTextOut")),
        }
    }

    fn read_counted_guest(
        &self,
        memory: &Memory,
        far: u32,
        count: u16,
    ) -> Result<Vec<u8>, RuntimeError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.read_text_bytes(memory, pointer, usize::from(count))
    }

    fn read_guest_rect(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<Option<Win16DrawingRect>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, 8)?;
        let word = |offset: usize| i16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        Ok(Some(Win16DrawingRect {
            left: i32::from(word(0)),
            top: i32::from(word(2)),
            right: i32::from(word(4)),
            bottom: i32::from(word(6)),
        }))
    }

    fn read_guest_spacing(
        &self,
        memory: &Memory,
        far: u32,
        count: u16,
        options: u16,
    ) -> Result<Option<Vec<i32>>, RuntimeError> {
        if count == 0 || far == 0 {
            return Ok(None);
        }
        let values_per_character = if options & ETO_PDY != 0 { 2 } else { 1 };
        let values = usize::from(count)
            .checked_mul(values_per_character)
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "RawExtTextOut spacing"))?;
        let byte_count = values
            .checked_mul(2)
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "RawExtTextOut spacing"))?;
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, byte_count)?;
        let mut spacing = Vec::new();
        spacing
            .try_reserve_exact(values)
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, "RawExtTextOut spacing", error))?;
        for pair in bytes.chunks_exact(2) {
            spacing.push(i32::from(i16::from_le_bytes([pair[0], pair[1]])));
        }
        Ok(Some(spacing))
    }
}

fn windows_metafile_header(bytes: &[u8]) -> bool {
    if bytes.len() < 18 {
        return false;
    }
    let kind = u16::from_le_bytes([bytes[0], bytes[1]]);
    let header = u16::from_le_bytes([bytes[2], bytes[3]]);
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    matches!(kind, 1 | 2) && header == 9 && matches!(version, 0x0100 | 0x0300)
}

fn pack_words(low: i32, high: i32) -> u32 {
    u32::from(low as u16) | (u32::from(high as u16) << 16)
}

fn word(args: &[Arg], index: usize) -> Result<u16, RuntimeError> {
    match args.get(index) {
        Some(Arg::Word(value)) => Ok(*value),
        _ => Err(slot("word")),
    }
}

fn dword(args: &[Arg], index: usize) -> Result<u32, RuntimeError> {
    match args.get(index) {
        Some(Arg::Dword(value)) => Ok(*value),
        _ => Err(slot("dword")),
    }
}

fn far(args: &[Arg], index: usize) -> Result<u32, RuntimeError> {
    match args.get(index) {
        Some(Arg::Far(value)) => Ok(*value),
        _ => Err(slot("far")),
    }
}

fn slot(kind: &str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("GDI internal call is missing a {kind} argument"),
    )
}

fn wrong_result(name: &str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("Win16 {name} returned a different GDI result"),
    )
}
