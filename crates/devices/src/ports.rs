//! Emulated PC I/O ports backed only by process-owned device state.

mod pic;
mod pit;

use guest_core::io::{PortError, PortIo, PortWidth};
use crate::vga::VgaDevice;

pub use pic::Pic8259Pair;
pub use pit::Pit8254;

/// Configured guest PC port bus: PIT, cascaded master/slave PICs, and VGA.
///
/// Other port addresses are unconnected in this virtual machine. They return
/// all-one data on reads and ignore writes. Accesses that overlap a connected
/// device must be supported as a complete transaction; an unsupported width
/// or transaction crossing the VGA decode range remains an error.
#[derive(Clone, Debug)]
pub struct MachinePorts {
    pit: Pit8254,
    pic: Pic8259Pair,
    vga: VgaDevice,
    cmos: crate::cmos::CmosRtc,
}

impl Default for MachinePorts {
    fn default() -> Self {
        Self::new()
    }
}

impl MachinePorts {
    pub fn new() -> Self {
        Self::with_vga(VgaDevice::new())
    }

    /// Construct the port bus around a VGA handle shared with BIOS and guest
    /// memory, so port writes affect the same adapter state those paths see.
    pub fn with_vga(vga: VgaDevice) -> Self {
        Self::with_vga_and_cmos(vga, crate::cmos::CmosRtc::new())
    }

    pub fn with_vga_and_cmos(vga: VgaDevice, cmos: crate::cmos::CmosRtc) -> Self {
        Self { pit: Pit8254::new(), pic: Pic8259Pair::new(), vga, cmos }
    }

    /// Use the BIOS chip so port 70h/71h and INT 1Ah address the same RAM.
    pub fn share_cmos(&mut self, cmos: crate::cmos::CmosRtc) {
        self.cmos = cmos;
    }

    pub fn take_cmos_waits(&self) -> Vec<(u16, u16)> {
        self.cmos.take_completed_waits()
    }

    /// Advance the deterministic guest PIT clock and route channel 0 rising
    /// edges to the master PIC's IRQ0 input.
    pub fn advance_ticks(&mut self, ticks: u64) {
        self.vga.advance_ticks(ticks);
        if self.pit.advance_ticks(ticks) {
            self.pic.request_irq(0).expect("IRQ0 is in range");
        }
        if self.cmos.advance_pit_ticks(ticks) {
            self.pic.request_irq(8).expect("IRQ8 is in range");
        }
    }

    pub fn set_pit_gate(&mut self, channel: u8, high: bool) -> Result<(), PortError> {
        let output_rise = self.pit.set_gate(channel, high)?;
        if channel == 0 && output_rise {
            self.pic.request_irq(0)?;
        }
        Ok(())
    }

    pub fn request_irq(&mut self, irq: u8) -> Result<(), PortError> {
        self.pic.request_irq(irq)
    }

    /// Set or clear a level-sensitive guest IRQ input.
    pub fn set_irq_level(&mut self, irq: u8, high: bool) -> Result<(), PortError> {
        self.pic.set_irq_level(irq, high)
    }

    /// Resolve and acknowledge the highest-priority eligible interrupt,
    /// returning its programmed 8086-mode vector.
    pub fn acknowledge_interrupt(&mut self) -> Option<u8> {
        self.pic.acknowledge()
    }

    pub fn interrupt_pending(&self) -> bool {
        self.pic.interrupt_pending()
    }

    pub fn pit(&self) -> &Pit8254 {
        &self.pit
    }

    pub fn pic(&self) -> &Pic8259Pair {
        &self.pic
    }

    pub fn vga(&self) -> &VgaDevice {
        &self.vga
    }
}

impl PortIo for MachinePorts {
    fn read(&mut self, port: u16, width: PortWidth) -> Result<u32, PortError> {
        if transaction_end(port, width).is_none() {
            return Err(PortError::Unsupported { port, width, write: false });
        }
        if is_vga_transaction(port, width) {
            let mut value = 0;
            for byte_offset in 0..width.bytes() {
                let byte = self.vga.read_port(port + u16::from(byte_offset))?;
                value |= u32::from(byte) << (u32::from(byte_offset) * 8);
            }
            return Ok(value);
        }
        if transaction_overlaps_vga(port, width)
            || (width != PortWidth::Byte && transaction_overlaps_legacy_pc_device(port, width))
        {
            return Err(PortError::Unsupported { port, width, write: false });
        }
        match port {
            0x40..=0x42 => self.pit.read_counter((port - 0x40) as u8).map(u32::from),
            0x20 | 0x21 | 0xa0 | 0xa1 => self.pic.read_port(port).map(u32::from),
            0x70 => Ok(u32::from(self.cmos.read_index())),
            0x71 => Ok(u32::from(self.cmos.read_data())),
            _ => Ok(width.mask()),
        }
    }

    fn write(&mut self, port: u16, width: PortWidth, value: u32) -> Result<(), PortError> {
        if transaction_end(port, width).is_none() {
            return Err(PortError::Unsupported { port, width, write: true });
        }
        if is_vga_transaction(port, width) {
            for byte_offset in 0..width.bytes() {
                self.vga.write_port(
                    port + u16::from(byte_offset),
                    (value >> (u32::from(byte_offset) * 8)) as u8,
                )?;
            }
            return Ok(());
        }
        if transaction_overlaps_vga(port, width)
            || (width != PortWidth::Byte && transaction_overlaps_legacy_pc_device(port, width))
        {
            return Err(PortError::Unsupported { port, width, write: true });
        }
        let value = value as u8;
        match port {
            0x40..=0x42 => self.pit.write_counter((port - 0x40) as u8, value),
            0x43 => self.pit.write_control(value),
            0x20 | 0x21 | 0xa0 | 0xa1 => self.pic.write_port(port, value),
            0x70 => {
                self.cmos.write_index(value);
                Ok(())
            }
            0x71 => {
                self.cmos.write_data(value);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn is_vga_transaction(port: u16, width: PortWidth) -> bool {
    const FIRST_VGA_PORT: u16 = 0x03b0;
    const LAST_VGA_PORT: u16 = 0x03df;
    port >= FIRST_VGA_PORT
        && transaction_end(port, width).is_some_and(|last| last <= LAST_VGA_PORT)
}

fn transaction_overlaps_vga(port: u16, width: PortWidth) -> bool {
    const FIRST_VGA_PORT: u16 = 0x03b0;
    const LAST_VGA_PORT: u16 = 0x03df;
    transaction_end(port, width)
        .is_some_and(|last| port <= LAST_VGA_PORT && last >= FIRST_VGA_PORT)
}

fn transaction_overlaps_legacy_pc_device(port: u16, width: PortWidth) -> bool {
    const LEGACY_DEVICE_RANGES: [(u16, u16); 4] = [
        (0x0020, 0x0021), // master PIC
        (0x0040, 0x0043), // PIT counters and control
        (0x0070, 0x0071), // CMOS address and data
        (0x00a0, 0x00a1), // slave PIC
    ];
    transaction_end(port, width).is_some_and(|last| {
        LEGACY_DEVICE_RANGES
            .iter()
            .any(|(first, end)| port <= *end && last >= *first)
    })
}

fn transaction_end(port: u16, width: PortWidth) -> Option<u16> {
    port.checked_add(u16::from(width.bytes() - 1))
}

#[cfg(test)]
#[path = "ports/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "vga/ports_tests.rs"]
mod vga_ports_tests;
