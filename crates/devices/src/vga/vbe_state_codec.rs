//! VBE 4F04 save/restore using a bounded, versioned byte format.
//!
//! The VBE function defines four independently selectable state groups and
//! excludes framebuffer memory. This adapter stores only explicit register,
//! BIOS-data, DAC, and VBE mode fields; it never serializes Rust layouts,
//! framebuffer bytes, or host pointers. Its private buffer format is not a
//! claim that this device implements VBE 2.0.

use super::super::{VgaDevice, VgaState, modes, svga::{self, SvgaState}};
use crate::{bios::BDA_BASE, DeviceError};
use guest_core::{GuestMemory, PhysAddr, real_address};

pub(super) const STATE_HARDWARE: u16 = 1 << 0;
pub(super) const STATE_BIOS_DATA: u16 = 1 << 1;
pub(super) const STATE_DAC: u16 = 1 << 2;
pub(super) const STATE_SVGA: u16 = 1 << 3;
pub(super) const SUPPORTED_STATE_MASK: u16 = STATE_HARDWARE | STATE_BIOS_DATA | STATE_DAC | STATE_SVGA;

pub(super) const HEADER_BYTES: usize = 24;
const HARDWARE_BYTES: usize = 75;
const BIOS_BYTES: usize = 31;
const DAC_BYTES: usize = 773;
const SVGA_BYTES: usize = 12;
const STATE_BLOCK_BYTES: usize = 64;

const FORMAT_MAGIC: [u8; 4] = *b"NTVB";
pub(super) const FORMAT_VERSION: u8 = 1;

pub(super) const BDA_MODE: usize = 0x49;
pub(super) const BDA_COLUMNS: usize = 0x4a;
pub(super) const BDA_PAGE_BYTES: usize = 0x4c;
pub(super) const BDA_DISPLAY_START: usize = 0x4e;
pub(super) const BDA_CURSOR_POSITIONS: usize = 0x50;
pub(super) const BDA_CURSOR_SHAPE: usize = 0x60;
pub(super) const BDA_ACTIVE_PAGE: usize = 0x62;
pub(super) const BDA_CRTC_BASE: usize = 0x63;
pub(super) const BDA_ROWS: usize = 0x84;
pub(super) const BDA_CHAR_HEIGHT: usize = 0x85;

pub(super) fn block_count(mask: u16) -> Option<u16> {
    if mask & !SUPPORTED_STATE_MASK != 0 { return None; }
    if mask == 0 {
        return Some(0);
    }
    let bytes = HEADER_BYTES.checked_add(payload_bytes(mask)?)?;
    let blocks = bytes.checked_add(STATE_BLOCK_BYTES - 1)? / STATE_BLOCK_BYTES;
    u16::try_from(blocks).ok()
}

fn payload_bytes(mask: u16) -> Option<usize> {
    if mask & !SUPPORTED_STATE_MASK != 0 {
        return None;
    }
    let mut bytes = 0usize;
    for (bit, length) in [
        (STATE_HARDWARE, HARDWARE_BYTES),
        (STATE_BIOS_DATA, BIOS_BYTES),
        (STATE_DAC, DAC_BYTES),
        (STATE_SVGA, SVGA_BYTES),
    ] {
        if mask & bit != 0 {
            bytes = bytes.checked_add(length)?;
        }
    }
    Some(bytes)
}

pub(super) fn encode_state(
    state: &VgaState,
    mask: u16,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, DeviceError> {
    if !current_mode_is_valid(state) {
        return Ok(None);
    }

    let bios = if mask & STATE_BIOS_DATA != 0 {
        let Some(bios) = read_bios_state(state.bios_mode, memory)? else {
            return Ok(None);
        };
        Some(bios)
    } else {
        None
    };
    let svga = if mask & STATE_SVGA != 0 { Some(state.svga.clone()) } else { None };
    let payload_size = payload_bytes(mask).ok_or_else(invalid_state_error)?;
    let blocks = block_count(mask).ok_or_else(invalid_state_error)? as usize;
    let total_size = blocks.checked_mul(STATE_BLOCK_BYTES).ok_or_else(invalid_state_error)?;
    let mut bytes = vec![0; total_size];
    let mut payload = Vec::with_capacity(payload_size);

    if mask & STATE_HARDWARE != 0 {
        HardwareState::capture(state).encode(&mut payload);
    }
    if let Some(bios) = bios {
        bios.encode(&mut payload);
    }
    if mask & STATE_DAC != 0 {
        DacState::capture(state).encode(&mut payload);
    }
    if let Some(svga) = svga {
        encode_svga(&svga, &mut payload);
    }

    if payload.len() != payload_size {
        return Err(invalid_state_error());
    }

    bytes[0..4].copy_from_slice(&FORMAT_MAGIC);
    bytes[4] = FORMAT_VERSION;
    bytes[5] = HEADER_BYTES as u8;
    bytes[6..8].copy_from_slice(&mask.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total_size as u32).to_le_bytes());
    bytes[16] = state.bios_mode;
    if let Some(svga) = state.svga.as_ref() {
        bytes[17] = 1;
        bytes[18..20].copy_from_slice(&svga.mode.to_le_bytes());
    }
    bytes[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(&payload);
    Ok(Some(bytes))
}

fn current_mode_is_valid(state: &VgaState) -> bool {
    match (state.bios_mode, state.svga.as_ref()) {
        (0xff, Some(svga)) => svga.is_valid(),
        (mode, None) => modes::mode_info(mode).is_some(),
        _ => false,
    }
}

fn invalid_state_error() -> DeviceError {
    DeviceError::InvalidRequest {
        interrupt: 0x10,
        function: 0x4f04,
        detail: "internal VBE save-state format length is inconsistent",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HardwareState {
    sequencer: [u8; 5],
    graphics: [u8; 9],
    crtc: [u8; 25],
    attribute: [u8; 21],
    misc_output: u8,
    sequencer_index: u8,
    graphics_index: u8,
    crtc_index: u8,
    attribute_index: u8,
    attribute_data_phase: bool,
    attribute_palette_enabled: bool,
    feature_control: u8,
    video_subsystem_enable: u8,
    cga_mode_control: u8,
    cga_color_control: u8,
    latches: [u8; 4],
}

impl HardwareState {
    fn capture(state: &VgaState) -> Self {
        Self {
            sequencer: state.sequencer,
            graphics: state.graphics,
            crtc: state.crtc,
            attribute: state.attribute,
            misc_output: state.misc_output,
            sequencer_index: state.sequencer_index,
            graphics_index: state.graphics_index,
            crtc_index: state.crtc_index,
            attribute_index: state.attribute_index,
            attribute_data_phase: state.attribute_data_phase,
            attribute_palette_enabled: state.attribute_palette_enabled,
            feature_control: state.feature_control,
            video_subsystem_enable: state.video_subsystem_enable,
            cga_mode_control: state.cga_mode_control,
            cga_color_control: state.cga_color_control,
            latches: state.latches,
        }
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.sequencer);
        output.extend_from_slice(&self.graphics);
        output.extend_from_slice(&self.crtc);
        output.extend_from_slice(&self.attribute);
        output.push(self.misc_output);
        output.extend_from_slice(&[
            self.sequencer_index,
            self.graphics_index,
            self.crtc_index,
            self.attribute_index,
            u8::from(self.attribute_data_phase),
            u8::from(self.attribute_palette_enabled),
            self.feature_control,
            self.video_subsystem_enable,
            self.cga_mode_control,
            self.cga_color_control,
        ]);
        output.extend_from_slice(&self.latches);
    }

    fn decode(cursor: &mut Cursor<'_>) -> Option<Self> {
        let value = Self {
            sequencer: cursor.take()?,
            graphics: cursor.take()?,
            crtc: cursor.take()?,
            attribute: cursor.take()?,
            misc_output: cursor.u8()?,
            sequencer_index: cursor.u8()?,
            graphics_index: cursor.u8()?,
            crtc_index: cursor.u8()?,
            attribute_index: cursor.u8()?,
            attribute_data_phase: decode_bool(cursor.u8()?)?,
            attribute_palette_enabled: decode_bool(cursor.u8()?)?,
            feature_control: cursor.u8()?,
            video_subsystem_enable: cursor.u8()?,
            cga_mode_control: cursor.u8()?,
            cga_color_control: cursor.u8()?,
            latches: cursor.take()?,
        };
        Some(value)
    }

    fn apply(&self, state: &mut VgaState) {
        state.sequencer = self.sequencer;
        state.graphics = self.graphics;
        state.crtc = self.crtc;
        state.attribute = self.attribute;
        state.misc_output = self.misc_output;
        state.sequencer_index = self.sequencer_index;
        state.graphics_index = self.graphics_index;
        state.crtc_index = self.crtc_index;
        state.attribute_index = self.attribute_index;
        state.attribute_data_phase = self.attribute_data_phase;
        state.attribute_palette_enabled = self.attribute_palette_enabled;
        state.feature_control = self.feature_control;
        state.video_subsystem_enable = self.video_subsystem_enable;
        state.cga_mode_control = self.cga_mode_control;
        state.cga_color_control = self.cga_color_control;
        state.latches = self.latches;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BiosState {
    bios_mode: u8,
    bda_mode: u8,
    columns: u16,
    page_bytes: u16,
    display_start: u16,
    cursor_positions: [u8; 16],
    cursor_shape: u16,
    active_page: u8,
    crtc_base: u16,
    rows: u8,
    char_height: u8,
}

impl BiosState {
    fn from_bda(bios_mode: u8, bda: &[u8; crate::bios::BDA_SIZE]) -> Option<Self> {
        let value = Self {
            bios_mode,
            bda_mode: bda[BDA_MODE],
            columns: read_word(bda, BDA_COLUMNS)?,
            page_bytes: read_word(bda, BDA_PAGE_BYTES)?,
            display_start: read_word(bda, BDA_DISPLAY_START)?,
            cursor_positions: bda.get(BDA_CURSOR_POSITIONS..BDA_CURSOR_POSITIONS + 16)?.try_into().ok()?,
            cursor_shape: read_word(bda, BDA_CURSOR_SHAPE)?,
            active_page: bda[BDA_ACTIVE_PAGE],
            crtc_base: read_word(bda, BDA_CRTC_BASE)?,
            rows: bda[BDA_ROWS],
            char_height: bda[BDA_CHAR_HEIGHT],
        };
        (value.bios_mode == value.bda_mode && valid_bios_mode(value.bios_mode)).then_some(value)
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.push(self.bios_mode);
        output.push(self.bda_mode);
        output.extend_from_slice(&self.columns.to_le_bytes());
        output.extend_from_slice(&self.page_bytes.to_le_bytes());
        output.extend_from_slice(&self.display_start.to_le_bytes());
        output.extend_from_slice(&self.cursor_positions);
        output.extend_from_slice(&self.cursor_shape.to_le_bytes());
        output.push(self.active_page);
        output.extend_from_slice(&self.crtc_base.to_le_bytes());
        output.push(self.rows);
        output.push(self.char_height);
    }

    fn decode(cursor: &mut Cursor<'_>, header_mode: u8) -> Option<Self> {
        let value = Self {
            bios_mode: cursor.u8()?,
            bda_mode: cursor.u8()?,
            columns: cursor.u16()?,
            page_bytes: cursor.u16()?,
            display_start: cursor.u16()?,
            cursor_positions: cursor.take()?,
            cursor_shape: cursor.u16()?,
            active_page: cursor.u8()?,
            crtc_base: cursor.u16()?,
            rows: cursor.u8()?,
            char_height: cursor.u8()?,
        };
        (value.bios_mode == value.bda_mode
            && value.bios_mode == header_mode
            && valid_bios_mode(value.bios_mode))
        .then_some(value)
    }

    fn write_into_bda(&self, bda: &mut [u8; crate::bios::BDA_SIZE]) {
        bda[BDA_MODE] = self.bda_mode;
        write_word(bda, BDA_COLUMNS, self.columns);
        write_word(bda, BDA_PAGE_BYTES, self.page_bytes);
        write_word(bda, BDA_DISPLAY_START, self.display_start);
        bda[BDA_CURSOR_POSITIONS..BDA_CURSOR_POSITIONS + 16]
            .copy_from_slice(&self.cursor_positions);
        write_word(bda, BDA_CURSOR_SHAPE, self.cursor_shape);
        bda[BDA_ACTIVE_PAGE] = self.active_page;
        write_word(bda, BDA_CRTC_BASE, self.crtc_base);
        bda[BDA_ROWS] = self.rows;
        bda[BDA_CHAR_HEIGHT] = self.char_height;
    }
}

fn valid_bios_mode(mode: u8) -> bool {
    mode == 0xff || modes::mode_info(mode).is_some()
}

fn read_bios_state(bios_mode: u8, memory: &impl GuestMemory) -> Result<Option<BiosState>, DeviceError> {
    let mut bda = [0; crate::bios::BDA_SIZE];
    memory.read(PhysAddr(BDA_BASE), &mut bda)?;
    Ok(BiosState::from_bda(bios_mode, &bda))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DacState {
    palette: [[u8; 3]; 256],
    pel_mask: u8,
    read_index: u8,
    write_index: u8,
    component: u8,
    read_mode: bool,
}

impl DacState {
    fn capture(state: &VgaState) -> Self {
        Self {
            palette: state.palette,
            pel_mask: state.pel_mask,
            read_index: state.dac_read_index,
            write_index: state.dac_write_index,
            component: state.dac_component,
            read_mode: state.dac_read_mode,
        }
    }

    fn encode(&self, output: &mut Vec<u8>) {
        for color in self.palette {
            output.extend_from_slice(&color);
        }
        output.extend_from_slice(&[
            self.pel_mask,
            self.read_index,
            self.write_index,
            self.component,
            u8::from(self.read_mode),
        ]);
    }

    fn decode(cursor: &mut Cursor<'_>) -> Option<Self> {
        let mut palette = [[0; 3]; 256];
        for color in &mut palette {
            *color = cursor.take()?;
            if color.iter().any(|component| *component > 0x3f) {
                return None;
            }
        }
        let value = Self {
            palette,
            pel_mask: cursor.u8()?,
            read_index: cursor.u8()?,
            write_index: cursor.u8()?,
            component: cursor.u8()?,
            read_mode: decode_bool(cursor.u8()?)?,
        };
        (value.component < 3).then_some(value)
    }

    fn apply(&self, state: &mut VgaState) {
        state.palette = self.palette;
        state.pel_mask = self.pel_mask;
        state.dac_read_index = self.read_index;
        state.dac_write_index = self.write_index;
        state.dac_component = self.component;
        state.dac_read_mode = self.read_mode;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateHeader {
    mask: u16,
    total_bytes: usize,
    bios_mode: u8,
    svga_mode: Option<u16>,
}

impl StateHeader {
    fn decode(bytes: &[u8; HEADER_BYTES]) -> Option<Self> {
        if bytes[0..4] != FORMAT_MAGIC
            || bytes[4] != FORMAT_VERSION
            || usize::from(bytes[5]) != HEADER_BYTES
        {
            return None;
        }
        let mask = u16::from_le_bytes([bytes[6], bytes[7]]);
        if mask == 0 || mask & !SUPPORTED_STATE_MASK != 0 {
            return None;
        }
        let total_bytes = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
        if usize::from(block_count(mask)?).checked_mul(STATE_BLOCK_BYTES)? != total_bytes {
            return None;
        }
        let bios_mode = bytes[16];
        let svga_present = decode_bool(bytes[17])?;
        let svga_mode = u16::from_le_bytes([bytes[18], bytes[19]]);
        let svga_mode = if svga_present { Some(svga_mode) } else if svga_mode == 0 { None } else { return None };
        if !valid_mode_pair(bios_mode, svga_mode) {
            return None;
        }
        Some(Self { mask, total_bytes, bios_mode, svga_mode })
    }

}

fn valid_mode_pair(bios_mode: u8, svga_mode: Option<u16>) -> bool {
    match (bios_mode, svga_mode) {
        (0xff, Some(mode)) => svga::mode_info(mode).is_some(),
        (mode, None) => modes::mode_info(mode).is_some(),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DecodedState {
    header: StateHeader,
    hardware: Option<HardwareState>,
    bios: Option<BiosState>,
    dac: Option<DacState>,
    svga: Option<Option<SvgaState>>,
}

pub(super) fn read_and_decode_state(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    requested: u16,
) -> Result<Option<DecodedState>, DeviceError> {
    let mut header_bytes = [0; HEADER_BYTES];
    read_far_buffer(memory, segment, offset, &mut header_bytes)?;
    let Some(header) = StateHeader::decode(&header_bytes) else {
        return Ok(None);
    };
    if requested & !header.mask != 0 {
        return Ok(None);
    }

    let mut bytes = vec![0; header.total_bytes];
    read_far_buffer(memory, segment, offset, &mut bytes)?;
    let Some(full_header) = bytes.get(..HEADER_BYTES)
        .and_then(|bytes| <&[u8; HEADER_BYTES]>::try_from(bytes).ok())
        .and_then(StateHeader::decode)
    else {
        return Ok(None);
    };
    if full_header != header {
        return Ok(None);
    }
    Ok(decode_state(&bytes, header, requested))
}

fn decode_state(bytes: &[u8], header: StateHeader, requested: u16) -> Option<DecodedState> {
    if bytes.len() != header.total_bytes || bytes.len() < HEADER_BYTES {
        return None;
    }
    let payload_len = payload_bytes(header.mask)?;
    let payload_end = HEADER_BYTES.checked_add(payload_len)?;
    if payload_end > bytes.len() {
        return None;
    }

    let mut cursor = Cursor::new(&bytes[HEADER_BYTES..payload_end]);
    let hardware = if header.mask & STATE_HARDWARE != 0 {
        Some(HardwareState::decode(&mut cursor)?)
    } else {
        None
    };
    let bios = if header.mask & STATE_BIOS_DATA != 0 {
        Some(BiosState::decode(&mut cursor, header.bios_mode)?)
    } else {
        None
    };
    let dac = if header.mask & STATE_DAC != 0 {
        Some(DacState::decode(&mut cursor)?)
    } else {
        None
    };
    let svga = if header.mask & STATE_SVGA != 0 {
        let present = decode_bool(cursor.u8()?)?;
        let mode = cursor.u16()?;
        let stride = cursor.u16()?;
        let bank = cursor.u16()?;
        let display_x = cursor.u16()?;
        let display_y = cursor.u16()?;
        let preserve_memory = decode_bool(cursor.u8()?)?;
        let state = if present {
            Some(SvgaState { mode, stride, bank, display_x, display_y, preserve_memory })
        } else {
            if [mode, stride, bank, display_x, display_y].iter().any(|field| *field != 0)
                || preserve_memory
            {
                return None;
            }
            None
        };
        if state.as_ref().is_some_and(|state| !state.is_valid())
            || state.as_ref().map(|state| state.mode) != header.svga_mode
        {
            return None;
        }
        Some(state)
    } else {
        None
    };
    if cursor.position != cursor.bytes.len() {
        return None;
    }

    let decoded = DecodedState { header, hardware, bios, dac, svga };
    decoded.contains(requested).then_some(decoded)
}

impl DecodedState {
    fn contains(&self, requested: u16) -> bool {
        requested & !self.header.mask == 0
            && ((requested & STATE_HARDWARE == 0) || self.hardware.is_some())
            && ((requested & STATE_BIOS_DATA == 0) || self.bios.is_some())
            && ((requested & STATE_DAC == 0) || self.dac.is_some())
            && ((requested & STATE_SVGA == 0) || self.svga.is_some())
    }
}

pub(super) fn apply_state(
    vga: &VgaDevice,
    memory: &mut impl GuestMemory,
    requested: u16,
    snapshot: DecodedState,
) -> Result<(), DeviceError> {
    let bios = if requested & STATE_BIOS_DATA != 0 {
        let Some(bios) = snapshot.bios.as_ref() else {
            return Err(invalid_state_error());
        };
        Some(bios)
    } else {
        None
    };
    if let Some(bios) = bios {
        restore_bios_data(memory, bios)?;
    }

    let mut state = vga.borrow_mut();
    let mut changed = false;
    if let Some(hardware) = snapshot.hardware.filter(|_| requested & STATE_HARDWARE != 0) {
        let previous = HardwareState::capture(&state);
        if previous != hardware {
            hardware.apply(&mut state);
            changed = true;
        }
    }
    if let Some(bios) = snapshot.bios.filter(|_| requested & STATE_BIOS_DATA != 0) {
        if state.bios_mode != bios.bios_mode {
            state.bios_mode = bios.bios_mode;
            changed = true;
        }
    }
    if let Some(dac) = snapshot.dac.filter(|_| requested & STATE_DAC != 0) {
        if DacState::capture(&state) != dac {
            dac.apply(&mut state);
            changed = true;
        }
    }
    if let Some(svga) = snapshot.svga.filter(|_| requested & STATE_SVGA != 0) {
        if state.svga != svga {
            state.svga = svga;
            changed = true;
        }
    }
    if changed {
        state.mark_changed();
    }
    Ok(())
}

fn restore_bios_data(memory: &mut impl GuestMemory, bios: &BiosState) -> Result<(), DeviceError> {
    let mut bda = [0; crate::bios::BDA_SIZE];
    memory.read(PhysAddr(BDA_BASE), &mut bda)?;
    bios.write_into_bda(&mut bda);
    memory.validate_write(PhysAddr(BDA_BASE), bda.len())?;
    memory.write(PhysAddr(BDA_BASE), &bda)?;
    Ok(())
}

fn encode_svga(state: &Option<SvgaState>, output: &mut Vec<u8>) {
    if let Some(state) = state {
        output.push(1);
        output.extend_from_slice(&state.mode.to_le_bytes());
        output.extend_from_slice(&state.stride.to_le_bytes());
        output.extend_from_slice(&state.bank.to_le_bytes());
        output.extend_from_slice(&state.display_x.to_le_bytes());
        output.extend_from_slice(&state.display_y.to_le_bytes());
        output.push(u8::from(state.preserve_memory));
    } else {
        output.extend_from_slice(&[0; SVGA_BYTES]);
    }
}

fn decode_bool(value: u8) -> Option<bool> {
    match value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn read_word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn write_word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, position: 0 } }

    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.position.checked_add(N)?;
        let value = self.bytes.get(self.position..end)?.try_into().ok()?;
        self.position = end;
        Some(value)
    }

    fn u8(&mut self) -> Option<u8> { Some(self.take::<1>()?[0]) }
    fn u16(&mut self) -> Option<u16> { Some(u16::from_le_bytes(self.take()?)) }
}

fn read_far_buffer(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    output: &mut [u8],
) -> Result<(), DeviceError> {
    let chunks = far_chunks(segment, offset, output.len());
    for (address, _, length) in &chunks {
        memory.validate_read(*address, *length)?;
    }
    let mut output_offset = 0usize;
    for (address, _, length) in chunks {
        memory.read(address, &mut output[output_offset..output_offset + length])?;
        output_offset += length;
    }
    Ok(())
}

pub(super) fn write_far_buffer(
    memory: &mut impl GuestMemory,
    segment: u16,
    offset: u16,
    bytes: &[u8],
) -> Result<(), DeviceError> {
    let chunks = far_chunks(segment, offset, bytes.len());
    for (address, _, length) in &chunks {
        memory.validate_write(*address, *length)?;
    }
    for (address, data_offset, length) in chunks {
        memory.write(address, &bytes[data_offset..data_offset + length])?;
    }
    Ok(())
}

fn far_chunks(segment: u16, start: u16, length: usize) -> Vec<(PhysAddr, usize, usize)> {
    let mut chunks = Vec::new();
    let mut remaining = length;
    let mut data_offset = 0usize;
    let mut current_offset = start;
    while remaining != 0 {
        let until_wrap = 0x1_0000 - usize::from(current_offset);
        let chunk_length = remaining.min(until_wrap);
        chunks.push((real_address(segment, current_offset), data_offset, chunk_length));
        remaining -= chunk_length;
        data_offset += chunk_length;
        current_offset = 0;
    }
    chunks
}
