use crate::{
    keyboard::{BiosKeyboard, KeyStroke},
    mouse::{GuestCallbackRequest, MouseDevice, MouseInput},
    rtc::{ClockReading, RtcState},
    video::{ConsoleSnapshot, VideoDevice},
    vga::VgaDevice,
};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

pub const BDA_BASE: u32 = 0x0400;
pub const BDA_SIZE: usize = 0x0100;
pub const VGA_TEXT_MEMORY: u32 = 0xb8000;
pub const CONVENTIONAL_MEMORY_KIB: u16 = 640;

pub(crate) const VIDEO_EQUIPMENT_WORD: u16 = 0x0020;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceError {
    Memory(MemoryError),
    UnsupportedInterrupt { interrupt: u8, function: u16 },
    InvalidRequest { interrupt: u8, function: u16, detail: &'static str },
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(error) => write!(f, "BIOS device memory access failed: {error}"),
            Self::UnsupportedInterrupt { interrupt, function } => write!(
                f,
                "unsupported BIOS interrupt INT {interrupt:02X}h function {function:04X}h"
            ),
            Self::InvalidRequest { interrupt, function, detail } => write!(
                f,
                "invalid BIOS request for INT {interrupt:02X}h function {function:04X}h: {detail}"
            ),
        }
    }
}
impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Memory(error) => Some(error), _ => None }
    }
}
impl From<MemoryError> for DeviceError {
    fn from(value: MemoryError) -> Self { Self::Memory(value) }
}

/// Requests for the runtime or host adapter. Guest callbacks retain guest
/// segment:offset addresses and must be scheduled through the guest CPU.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceAction {
    RenderText(ConsoleSnapshot),
    AwaitKeyboard,
    SetHostMousePosition { x: u16, y: u16 },
    SetA20Gate { enabled: bool },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DispatchOutcome {
    pub actions: Vec<DeviceAction>,
}

#[derive(Clone, Debug)]
pub struct BiosDevices {
    pub video: VideoDevice,
    pub keyboard: BiosKeyboard,
    pub mouse: MouseDevice,
    pub(super) rtc: RtcState,
    pub(super) conventional_memory_kib: u16,
    pub(super) cmos_posted: bool,
    a20_enabled: bool,
}

impl Default for BiosDevices {
    fn default() -> Self { Self::new() }
}

impl BiosDevices {
    pub fn new() -> Self {
        Self::with_vga(VgaDevice::new())
    }

    /// Build BIOS services over the machine's shared VGA device. Clones of
    /// this handle keep the BIOS, guest-memory aperture and renderer on one
    /// emulated VGA state.
    pub fn with_vga(vga: VgaDevice) -> Self {
        Self {
            video: VideoDevice::with_vga(vga),
            keyboard: BiosKeyboard::new(),
            mouse: MouseDevice::new(),
            rtc: RtcState::new(),
            conventional_memory_kib: CONVENTIONAL_MEMORY_KIB,
            cmos_posted: false,
            a20_enabled: true,
        }
    }

    /// The CMOS chip shared with the port bus.
    pub fn cmos(&self) -> crate::cmos::CmosRtc { self.rtc.cmos() }

    pub fn load_cmos_file(&mut self, path: &std::path::Path) {
        self.rtc.cmos().attach_file(path);
    }

    pub fn a20_enabled(&self) -> bool { self.a20_enabled }

    pub fn set_a20_enabled(&mut self, enabled: bool) { self.a20_enabled = enabled; }

    /// Initialize the BIOS data area and the reset VGA text screen. Requires normal PC low memory
    /// and a mapped color-text aperture in the emulated guest RAM.
    pub fn initialize(&mut self, memory: &mut impl GuestMemory) -> Result<(), DeviceError> {
        self.conventional_memory_kib = CONVENTIONAL_MEMORY_KIB;
        // Keep the already-wired Rc<RefCell<VgaState>> intact: guest physical
        // memory and the BIOS must continue to address the same VGA device.
        self.video.reset_text_mode();
        self.keyboard = BiosKeyboard::new();
        self.mouse = MouseDevice::new();
        if !self.rtc.cmos().loaded_from_file() {
            self.rtc.cmos().install_defaults(memory.len());
        }
        self.rtc.reset_tick_state();
        self.conventional_memory_kib = self.rtc.cmos().base_memory_kib();
        let equipment = self.rtc.cmos().equipment_word();

        let (text_base, columns, rows, page_bytes) = self.video.text_layout();
        let text_bytes = u32::try_from(columns * rows * 2).unwrap_or(u32::MAX);
        let required = text_base.saturating_add(text_bytes);
        if memory.len() < required {
            return Err(DeviceError::Memory(MemoryError::OutOfBounds {
                address: text_base,
                length: text_bytes as usize,
            }));
        }

        let mut bda = [0u8; BDA_SIZE];
        write_word(&mut bda, 0x10, equipment);
        write_word(&mut bda, 0x13, self.conventional_memory_kib);
        write_word(&mut bda, 0x1a, 0x001e);
        write_word(&mut bda, 0x1c, 0x001e);
        write_word(&mut bda, 0x4a, columns as u16);
        write_word(&mut bda, 0x4c, page_bytes as u16);
        bda[0x49] = self.video.mode();
        write_word(&mut bda, 0x4e, self.video.display_start_bytes() as u16);
        write_word(&mut bda, 0x60, self.video.cursor_shape());
        bda[0x62] = self.video.active_page();
        write_word(&mut bda, 0x63, self.video.crtc_base());
        write_word(&mut bda, 0x6c, 0);
        write_word(&mut bda, 0x80, 0x001e);
        write_word(&mut bda, 0x82, 0x003e);
        bda[0x84] = rows.saturating_sub(1) as u8;
        bda[0x85] = self.video.char_height();
        for page in 0..8_u8 {
            let (column, row) = self.video.cursor_for_page(page).unwrap_or((0, 0));
            bda[0x50 + usize::from(page) * 2] = column;
            bda[0x51 + usize::from(page) * 2] = row;
        }

        memory.write(PhysAddr(BDA_BASE), &bda)?;
        self.video.sync_to_guest(memory)?;
        self.cmos_posted = true;
        Ok(())
    }

    pub fn push_key(&mut self, key: KeyStroke) -> bool { self.keyboard.push(key) }

    pub fn sync_keyboard_bda(&self, memory: &mut impl GuestMemory) -> Result<(), DeviceError> {
        self.keyboard.sync_bda(memory)?;
        Ok(())
    }

    /// A returned callback request must be scheduled as a guest far call by
    /// the runtime; it is never invoked through a host pointer.
    pub fn push_mouse_input(&mut self, input: MouseInput) -> Option<GuestCallbackRequest> {
        self.mouse.inject(input)
    }

    pub fn video_snapshot(&self) -> ConsoleSnapshot { self.video.snapshot() }

    pub fn refresh_video_from_guest(&mut self, memory: &impl GuestMemory) -> Result<(), DeviceError> {
        self.video.refresh_from_guest(memory)?;
        Ok(())
    }

    /// Refresh guest-written VGA text cells and request a render only on change.
    pub fn refresh_video_action(&mut self, memory: &impl GuestMemory) -> Result<Option<DeviceAction>, DeviceError> {
        let version = self.video.version();
        self.video.refresh_from_guest(memory)?;
        Ok((self.video.is_text() && self.video.version() != version)
            .then(|| DeviceAction::RenderText(self.video.snapshot())))
    }

    pub fn update_clock(&mut self, memory: &mut impl GuestMemory, epoch_seconds: i64) -> Result<ClockReading, DeviceError> {
        self.rtc.update_bda(memory, epoch_seconds).map_err(DeviceError::from)
    }

    /// Dispatch a supported BIOS vector and surface host work as explicit
    /// actions. Optional probes return their guest-defined absence status.
    pub fn dispatch_interrupt(
        &mut self,
        interrupt: u8,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        epoch_seconds: i64,
    ) -> Result<DispatchOutcome, DeviceError> {
        let mut outcome = DispatchOutcome::default();
        match interrupt {
            0x10 => {
                let old_version = self.video.version();
                let restoring_bios_data = regs.ax() == 0x4f04 && regs.dl() == 2 && regs.cx() & 2 != 0;
                self.video.refresh_from_guest(memory)?;
                if regs.ah() == 0x4f {
                    self.video.dispatch_vbe(regs, memory)?;
                } else if !crate::vga::bios::dispatch(self.video.vga(), regs, memory)? {
                    self.video.dispatch_int10(regs, memory)?;
                }
                if !(restoring_bios_data && regs.ax() == 0x004f) {
                    self.sync_video_bda(memory)?;
                }
                if self.video.is_text() && self.video.version() != old_version {
                    outcome.actions.push(DeviceAction::RenderText(self.video.snapshot()));
                }
            }
            0x11 | 0x12 | 0x15 => crate::system_bios::dispatch(self, interrupt, regs, memory, &mut outcome)?,
            0x13 => crate::disk_bios::dispatch(regs, memory)?,
            0x14 => crate::serial_bios::dispatch(regs),
            0x16 => self.keyboard.dispatch_int16(regs, memory, &mut outcome)?,
            0x17 => crate::printer_bios::dispatch(regs),
            0x1a => self.rtc.dispatch_int1a(regs, memory, epoch_seconds)?,
            0x70 => {
                let _ = self.rtc.cmos().acknowledge_interrupt();
            }
            0x33 => self.mouse.dispatch_int33(regs, memory, &mut outcome)?,
            _ => return Err(DeviceError::UnsupportedInterrupt { interrupt, function: u16::from(regs.ah()) }),
        }
        Ok(outcome)
    }

    fn sync_video_bda(&self, memory: &mut impl GuestMemory) -> Result<(), DeviceError> {
        let (columns, rows, page_bytes) = {
            let (_, columns, rows, page_bytes) = self.video.text_layout();
            (columns, rows, page_bytes)
        };
        memory.write_u8(PhysAddr(BDA_BASE + 0x49), self.video.mode())?;
        memory.write_u16(PhysAddr(BDA_BASE + 0x4a), columns as u16)?;
        memory.write_u16(PhysAddr(BDA_BASE + 0x4c), page_bytes as u16)?;
        memory.write_u16(PhysAddr(BDA_BASE + 0x4e), self.video.display_start_bytes() as u16)?;
        memory.write_u8(PhysAddr(BDA_BASE + 0x62), self.video.active_page())?;
        memory.write_u16(PhysAddr(BDA_BASE + 0x63), self.video.crtc_base())?;
        for page in 0..8_u8 {
            let (column, row) = self.video.cursor_for_page(page).unwrap_or((0, 0));
            memory.write_u8(PhysAddr(BDA_BASE + 0x50 + u32::from(page) * 2), column)?;
            memory.write_u8(PhysAddr(BDA_BASE + 0x51 + u32::from(page) * 2), row)?;
        }
        memory.write_u16(PhysAddr(BDA_BASE + 0x60), self.video.cursor_shape())?;
        memory.write_u8(PhysAddr(BDA_BASE + 0x84), rows.saturating_sub(1) as u8)?;
        memory.write_u8(PhysAddr(BDA_BASE + 0x85), self.video.char_height())?;
        Ok(())
    }
}

pub(crate) fn high_byte(value: u32) -> u8 { (value >> 8) as u8 }
pub(crate) fn low_byte(value: u32) -> u8 { value as u8 }
pub(crate) fn set_high_byte(value: &mut u32, byte: u8) { *value = (*value & !0xff00) | (u32::from(byte) << 8); }
pub(crate) fn set_low_byte(value: &mut u32, byte: u8) { *value = (*value & !0xff) | u32::from(byte); }

fn write_word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
