//! BIOS and PC input-device emulation over the shared guest-memory buffer.
#![forbid(unsafe_code)]

pub mod vga;

mod bios;
mod system_bios;
mod printer_bios;
pub mod disk_bios;

pub mod keyboard;
pub mod mouse;
pub mod ports;
pub mod rtc;
pub mod video;

pub use bios::{BiosDevices, DeviceAction, DeviceError, DispatchOutcome};
pub use bios::{BDA_BASE, BDA_SIZE, CONVENTIONAL_MEMORY_KIB, VGA_TEXT_MEMORY};

#[cfg(test)]
mod tests;
