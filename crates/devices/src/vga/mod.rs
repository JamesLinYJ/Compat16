//! Shared VGA adapter state for BIOS calls, I/O ports, guest memory, and scanout.
//!
//! The guest-facing adapter is backed by ordinary process-owned memory. The
//! `VgaDevice` handle is deliberately cloneable so the BIOS, port bus, and
//! memory bus all observe the same registers and VRAM.

pub mod bios;
mod memory;
pub mod modes;
pub(crate) mod palette;
pub mod ports;
pub mod frame;
pub mod vbe;
pub(crate) mod svga;
mod vbe_state;

#[cfg(test)]
mod ports_tests;

#[cfg(test)]
#[path = "svga_tests.rs"]
mod svga_tests;

pub use frame::VgaFrame;
pub use modes::{ModeInfo, ModeKind};

use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;
use guest_core::memory::MemoryMappedDevice;
use guest_core::MemoryError;

pub const VGA_VRAM_BYTES: usize = 256 * 1024;
/// Total process-owned framebuffer storage shared by VGA and VBE modes.
pub const VIDEO_MEMORY_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const SVGA_BANK_BYTES: usize = 64 * 1024;
pub const VGA_APERTURE_START: u32 = 0x000a_0000;
pub const VGA_APERTURE_SIZE: u32 = 0x0002_0000;

/// The mutable state of one guest VGA-compatible adapter.
///
/// Register bytes use the VGA/6845 indices. The first 256 KiB of VRAM is
/// interleaved by byte address and plane (`vram[address * 4 + plane]`) for
/// legacy VGA modes; active VBE modes use the shared four MiB allocation as
/// packed pixels. Palette components retain their six-bit DAC values.
#[derive(Clone, Debug)]
pub struct VgaState {
    pub(crate) sequencer: [u8; 5],
    pub(crate) graphics: [u8; 9],
    pub(crate) crtc: [u8; 25],
    pub(crate) attribute: [u8; 21],
    pub(crate) misc_output: u8,
    pub(crate) palette: [[u8; 3]; 256],
    pub(crate) pel_mask: u8,
    pub(crate) vram: Vec<u8>,
    pub(crate) svga: Option<svga::SvgaState>,
    pub(crate) bios_mode: u8,
    pub(crate) generation: u64,
    pub(crate) latches: [u8; 4],

    sequencer_index: u8,
    graphics_index: u8,
    crtc_index: u8,
    attribute_index: u8,
    attribute_data_phase: bool,
    attribute_palette_enabled: bool,
    feature_control: u8,
    video_subsystem_enable: u8,
    pub(crate) cga_mode_control: u8,
    pub(crate) cga_color_control: u8,
    dac_read_index: u8,
    dac_write_index: u8,
    dac_component: u8,
    dac_read_mode: bool,
    clock_ticks: u64,
}

impl VgaState {
    pub fn new() -> Self {
        let mut state = Self {
            sequencer: [0; 5],
            graphics: [0; 9],
            crtc: [0; 25],
            attribute: [0; 21],
            misc_output: 0,
            palette: [[0; 3]; 256],
            pel_mask: 0xff,
            vram: vec![0; VIDEO_MEMORY_BYTES],
            svga: None,
            bios_mode: 0,
            generation: 0,
            latches: [0; 4],
            sequencer_index: 0,
            graphics_index: 0,
            crtc_index: 0,
            attribute_index: 0,
            attribute_data_phase: false,
            attribute_palette_enabled: true,
            feature_control: 0,
            video_subsystem_enable: 1,
            cga_mode_control: 0,
            cga_color_control: 0,
            dac_read_index: 0,
            dac_write_index: 0,
            dac_component: 0,
            dac_read_mode: false,
            clock_ticks: 0,
        };
        state.set_mode(0x03, true);
        state
    }

    pub(crate) fn mark_changed(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

impl Default for VgaState {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable, shared handle to the guest's VGA adapter state.
#[derive(Clone, Debug)]
pub struct VgaDevice {
    inner: Rc<RefCell<VgaState>>,
}

impl VgaDevice {
    pub fn new() -> Self {
        Self { inner: Rc::new(RefCell::new(VgaState::new())) }
    }

    pub fn borrow(&self) -> Ref<'_, VgaState> {
        self.inner.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, VgaState> {
        self.inner.borrow_mut()
    }

    pub fn generation(&self) -> u64 {
        self.borrow().generation
    }

    pub fn set_mode(&self, mode: u8, clear: bool) -> bool {
        self.borrow_mut().set_mode(mode, clear)
    }

    /// Advance deterministic video timing by PIT input-clock ticks.
    pub fn advance_ticks(&self, ticks: u64) {
        let mut state = self.inner.borrow_mut();
        state.clock_ticks = state.clock_ticks.wrapping_add(ticks);
    }
}

impl Default for VgaDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryMappedDevice for VgaDevice {
    fn validate_read(&self, offset: u32, length: u32) -> Result<(), MemoryError> {
        validate_aperture_range(offset, length)
    }

    fn validate_write(&self, offset: u32, length: u32) -> Result<(), MemoryError> {
        validate_aperture_range(offset, length)
    }

    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        let length = u32::try_from(output.len()).map_err(|_| MemoryError::AddressOverflow)?;
        validate_aperture_range(offset, length)?;
        let mut state = self.inner.borrow_mut();
        for (index, byte) in output.iter_mut().enumerate() {
            let index = u32::try_from(index).map_err(|_| MemoryError::AddressOverflow)?;
            *byte = state.aperture_read(offset + index);
        }
        Ok(())
    }

    fn write(&self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        let length = u32::try_from(input.len()).map_err(|_| MemoryError::AddressOverflow)?;
        validate_aperture_range(offset, length)?;
        let mut state = self.inner.borrow_mut();
        for (index, byte) in input.iter().copied().enumerate() {
            let index = u32::try_from(index).map_err(|_| MemoryError::AddressOverflow)?;
            state.aperture_write_byte(offset + index, byte);
        }
        Ok(())
    }
}

fn validate_aperture_range(offset: u32, length: u32) -> Result<(), MemoryError> {
    let address = VGA_APERTURE_START
        .checked_add(offset)
        .ok_or(MemoryError::AddressOverflow)?;
    let end = offset.checked_add(length).ok_or(MemoryError::AddressOverflow)?;
    if offset > VGA_APERTURE_SIZE || end > VGA_APERTURE_SIZE {
        return Err(MemoryError::OutOfBounds {
            address,
            length: usize::try_from(length).map_err(|_| MemoryError::AddressOverflow)?,
        });
    }
    Ok(())
}
