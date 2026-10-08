//! Native display for the guest-owned VGA framebuffer.
//!
//! This adapter owns one private window namespace. Its handle never enters the
//! guest USER model and does not identify an arbitrary guest HWND.

use std::error::Error;
use std::fmt;
use dos_kernel::DosHostError;
use devices::keyboard::KeyStroke;
use devices::vga::VgaFrame;
use graphics::{
    Color, GraphicsError, HostAction, HostEvent, Rect, Surface, WindowHandle,
    MAX_SURFACE_PIXELS,
};

use crate::windowing::{Windowing, WindowingError};

const VGA_WINDOW_HANDLE: WindowHandle = match WindowHandle::from_raw(1) {
    Some(handle) => handle,
    None => unreachable!(),
};
const WINDOW_LEFT: i32 = 64;
const WINDOW_TOP: i32 = 64;

#[derive(Debug)]
pub(super) enum VgaWindowError {
    Closed,
    InvalidDimensions,
    PixelCount { expected: usize, actual: usize },
    InvalidRgbPixel { index: usize, value: u32 },
    InvalidUtf16(std::string::FromUtf16Error),
    AllocationFailed,
    Graphics(GraphicsError),
    Windowing(WindowingError),
    Encoding(DosHostError),
}

impl fmt::Display for VgaWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the VGA display window was closed"),
            Self::InvalidDimensions => {
                f.write_str("the VGA framebuffer has zero or unrepresentable dimensions")
            }
            Self::PixelCount { expected, actual } => write!(
                f,
                "the VGA framebuffer has {actual} pixels, but its dimensions require {expected}"
            ),
            Self::InvalidRgbPixel { index, value } => write!(
                f,
                "VGA framebuffer pixel {index} is {value:#010x}; expected packed 0x00RRGGBB"
            ),
            Self::InvalidUtf16(error) => write!(f, "invalid UTF-16 VGA key character: {error}"),
            Self::AllocationFailed => f.write_str("allocating VGA display storage failed"),
            Self::Graphics(error) => write!(f, "building the VGA software surface failed: {error}"),
            Self::Windowing(error) => write!(f, "native VGA window operation failed: {error}"),
            Self::Encoding(error) => write!(f, "encoding VGA keyboard input failed: {error}"),
        }
    }
}

impl Error for VgaWindowError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Graphics(error) => Some(error),
            Self::Windowing(error) => Some(error),
            Self::Encoding(error) => Some(error),
            Self::InvalidUtf16(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WindowingError> for VgaWindowError {
    fn from(error: WindowingError) -> Self {
        Self::Windowing(error)
    }
}

/// Lazily creates and updates one visible window using the existing USER/GDI
/// host adapter. The OS window and all frame storage remain host-owned.
pub(super) struct VgaWindow {
    windowing: Option<Windowing>,
    last_frame: Option<(u16, u16, u64)>,
    closed: bool,
    visible: bool,
    code_page: u32,
}

impl VgaWindow {
    pub(super) const fn new(code_page: u32) -> Self {
        Self {
            windowing: None,
            last_frame: None,
            closed: false,
            visible: false,
            code_page,
        }
    }

    pub(super) fn is_active(&self) -> bool {
        self.visible && self.windowing.is_some() && !self.closed
    }

    /// Hide the VGA window while the guest is using text mode. The window is
    /// retained so a later graphics frame can restore it without re-registering.
    pub(super) fn hide(&mut self) -> Result<(), VgaWindowError> {
        self.ensure_open()?;
        if self.visible {
            if let Some(windowing) = &mut self.windowing {
                windowing.apply_action(HostAction::SetWindowVisible {
                    handle: VGA_WINDOW_HANDLE,
                    visible: false,
                })?;
            }
            self.visible = false;
        }
        Ok(())
    }

    /// Installs the latest image, creating the visible window on the first
    /// frame, then pumps native messages and returns BIOS-compatible keydowns.
    pub(super) fn render(&mut self, frame: &VgaFrame) -> Result<Vec<KeyStroke>, VgaWindowError> {
        self.ensure_open()?;
        let frame_id = (frame.width, frame.height, frame.generation);
        let changed = self.last_frame != Some(frame_id);
        let surface = changed.then(|| surface_from_frame(frame)).transpose()?;
        self.ensure_window(frame.width, frame.height)?;
        self.show()?;

        if changed {
            let windowing = self.windowing.as_mut().ok_or(VgaWindowError::Closed)?;
            if self
                .last_frame
                .is_some_and(|(width, height, _)| width != frame.width || height != frame.height)
            {
                windowing.apply_action(HostAction::MoveWindow {
                    handle: VGA_WINDOW_HANDLE,
                    rect: window_rect(frame.width, frame.height),
                })?;
            }
            windowing.update_surface(
                VGA_WINDOW_HANDLE,
                surface.as_ref().ok_or(VgaWindowError::Closed)?,
            )?;
            self.last_frame = Some(frame_id);
        }

        self.pump_events()
    }

    /// Delivers pending window events without requiring a new framebuffer
    /// generation. Runtime calls this periodically and while BIOS input waits.
    pub(super) fn pump_events(&mut self) -> Result<Vec<KeyStroke>, VgaWindowError> {
        self.ensure_open()?;
        let code_page = self.code_page;
        let Some(windowing) = self.windowing.as_mut() else {
            return Ok(Vec::new());
        };

        let events = windowing.poll_events()?;
        if windowing.take_quit_code().is_some() {
            self.closed = true;
            return Err(VgaWindowError::Closed);
        }

        let mut keys = Vec::new();
        for event in events {
            match event {
                HostEvent::Close { window } if window == VGA_WINDOW_HANDLE => {
                    self.closed = true;
                    self.visible = false;
                    return Err(VgaWindowError::Closed);
                }
                HostEvent::Character {
                    window,
                    character,
                    scan,
                    repeat_count,
                } if window == VGA_WINDOW_HANDLE => {
                    let strokes = character_strokes(character, scan, repeat_count, code_page)?;
                    keys.try_reserve(strokes.len())
                        .map_err(|_| VgaWindowError::AllocationFailed)?;
                    keys.extend(strokes);
                }
                HostEvent::KeyDown {
                    window,
                    key,
                    repeat_count,
                } if window == VGA_WINDOW_HANDLE => {
                    let Some(stroke) = bios_special_key(key) else {
                        continue;
                    };
                    let repetitions = usize::from(repeat_count.max(1));
                    keys.try_reserve(repetitions)
                        .map_err(|_| VgaWindowError::AllocationFailed)?;
                    keys.resize(keys.len() + repetitions, stroke);
                }
                _ => {}
            }
        }
        Ok(keys)
    }

    fn ensure_open(&self) -> Result<(), VgaWindowError> {
        if self.closed {
            Err(VgaWindowError::Closed)
        } else {
            Ok(())
        }
    }

    fn ensure_window(&mut self, width: u16, height: u16) -> Result<(), VgaWindowError> {
        if self.windowing.is_some() {
            return Ok(());
        }

        let mut windowing = Windowing::new()?;
        windowing.apply_action(HostAction::CreateWindow {
            handle: VGA_WINDOW_HANDLE,
            class_name: "Private VGA display".to_owned(),
            title: "DOS Graphics".to_owned(),
            parent: None,
            rect: window_rect(width, height),
        })?;
        windowing.apply_action(HostAction::SetWindowVisible {
            handle: VGA_WINDOW_HANDLE,
            visible: true,
        })?;
        self.windowing = Some(windowing);
        self.visible = true;
        Ok(())
    }

    fn show(&mut self) -> Result<(), VgaWindowError> {
        if self.visible {
            return Ok(());
        }
        let windowing = self.windowing.as_mut().ok_or(VgaWindowError::Closed)?;
        windowing.apply_action(HostAction::SetWindowVisible {
            handle: VGA_WINDOW_HANDLE,
            visible: true,
        })?;
        self.visible = true;
        Ok(())
    }
}

fn window_rect(width: u16, height: u16) -> Rect {
    Rect::new(
        WINDOW_LEFT,
        WINDOW_TOP,
        WINDOW_LEFT + i32::from(width),
        WINDOW_TOP + i32::from(height),
    )
}

fn surface_from_frame(frame: &VgaFrame) -> Result<Surface, VgaWindowError> {
    if frame.width == 0 || frame.height == 0 {
        return Err(VgaWindowError::InvalidDimensions);
    }
    let count = u64::from(frame.width) * u64::from(frame.height);
    if count > MAX_SURFACE_PIXELS {
        return Err(VgaWindowError::Graphics(GraphicsError::SurfaceTooLarge));
    }
    let expected = usize::try_from(count).map_err(|_| VgaWindowError::InvalidDimensions)?;
    if frame.pixels.len() != expected {
        return Err(VgaWindowError::PixelCount {
            expected,
            actual: frame.pixels.len(),
        });
    }

    let mut colors = Vec::new();
    colors
        .try_reserve_exact(expected)
        .map_err(|_| VgaWindowError::AllocationFailed)?;
    for (index, &rgb) in frame.pixels.iter().enumerate() {
        if rgb & 0xff00_0000 != 0 {
            return Err(VgaWindowError::InvalidRgbPixel { index, value: rgb });
        }
        colors.push(Color::rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8));
    }
    Surface::from_pixels(u32::from(frame.width), u32::from(frame.height), colors)
        .map_err(VgaWindowError::Graphics)
}

/// Translate virtual keys with stable BIOS set-1 scan codes. Shift-dependent
/// punctuation and modifiers are omitted because the shared event model does
/// not carry character or modifier state.
fn character_strokes(
    character: u16,
    scan: u8,
    repeat_count: u16,
    code_page: u32,
) -> Result<Vec<KeyStroke>, VgaWindowError> {
    let text = String::from_utf16(&[character]).map_err(VgaWindowError::InvalidUtf16)?;
    let bytes = super::encode(&text, code_page).map_err(VgaWindowError::Encoding)?;
    let repeats = usize::from(repeat_count.max(1));
    let count = bytes
        .len()
        .checked_mul(repeats)
        .ok_or(VgaWindowError::AllocationFailed)?;
    let mut keys = Vec::new();
    keys.try_reserve_exact(count)
        .map_err(|_| VgaWindowError::AllocationFailed)?;
    for _ in 0..repeats {
        keys.extend(bytes.iter().copied().map(|ascii| KeyStroke { ascii, scan }));
    }
    Ok(keys)
}

/// Navigation and function keys do not generate `WM_CHAR`. Text keys are
/// delivered only through the translated character event above.
fn bios_special_key(virtual_key: u16) -> Option<KeyStroke> {
    let scan = match virtual_key {
        0x70..=0x79 => 0x3b + (virtual_key - 0x70) as u8,
        0x7a => 0x57,
        0x7b => 0x58,
        0x24 => 0x47, // Home
        0x26 => 0x48, // Up
        0x21 => 0x49, // Page Up
        0x25 => 0x4b, // Left
        0x27 => 0x4d, // Right
        0x23 => 0x4f, // End
        0x28 => 0x50, // Down
        0x22 => 0x51, // Page Down
        0x2d => 0x52, // Insert
        0x2e => 0x53, // Delete
        _ => return None,
    };
    Some(KeyStroke { ascii: 0, scan })
}

#[cfg(test)]
mod tests {
    use super::{bios_special_key, character_strokes, surface_from_frame, VgaWindowError};
    use devices::vga::VgaFrame;
    use graphics::Color;

    #[test]
    fn converts_packed_rgb_into_top_left_surface_colors() {
        let frame = VgaFrame {
            width: 2,
            height: 1,
            pixels: vec![0x0011_2233, 0x00aa_bbcc],
            generation: 1,
        };
        let surface = surface_from_frame(&frame).unwrap();
        assert_eq!(surface.pixel(0, 0), Some(Color::rgb(0x11, 0x22, 0x33)));
        assert_eq!(surface.pixel(1, 0), Some(Color::rgb(0xaa, 0xbb, 0xcc)));
    }

    #[test]
    fn rejects_frames_with_an_alpha_byte_or_wrong_pixel_count() {
        let alpha = VgaFrame {
            width: 1,
            height: 1,
            pixels: vec![0xff00_0000],
            generation: 1,
        };
        assert!(matches!(
            surface_from_frame(&alpha),
            Err(VgaWindowError::InvalidRgbPixel { index: 0, .. })
        ));

        let short = VgaFrame {
            width: 2,
            height: 1,
            pixels: vec![0],
            generation: 1,
        };
        assert!(matches!(
            surface_from_frame(&short),
            Err(VgaWindowError::PixelCount { expected: 2, actual: 1 })
        ));
    }

    #[test]
    fn encodes_character_events_with_the_configured_oem_page() {
        let strokes = character_strokes(0x4e2d, 0x32, 2, 936).unwrap();
        assert_eq!(
            strokes.iter().map(|stroke| (stroke.ascii, stroke.scan)).collect::<Vec<_>>(),
            [(0xd6, 0x32), (0xd0, 0x32), (0xd6, 0x32), (0xd0, 0x32)],
        );
    }

    #[test]
    fn maps_only_navigation_and_function_virtual_keys_separately() {
        assert_eq!(bios_special_key(0x26).unwrap().bios_word(), 0x4800);
        assert_eq!(bios_special_key(0x70).unwrap().bios_word(), 0x3b00);
        assert_eq!(bios_special_key(0x41), None);
        assert_eq!(bios_special_key(0x0d), None);
    }
}
