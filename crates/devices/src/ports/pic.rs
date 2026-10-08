//! Cascaded 8259A-compatible interrupt controllers.
//!
//! Initialization, register reads, and priority/EOI behavior follow Intel
//! datasheet 231468-003 (https://www.pcjs.org/documents/datasheets/intel/INTEL_8259A_PIC.pdf).

use guest_core::io::{PortError, PortWidth};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitStep {
    None,
    Icw2,
    Icw3,
    Icw4,
}

#[derive(Clone, Debug)]
struct Controller {
    vector_base: u8,
    icw3: u8,
    imr: u8,
    irr: u8,
    isr: u8,
    level_inputs: u8,
    level_triggered: bool,
    auto_eoi: bool,
    rotate_auto_eoi: bool,
    special_mask: bool,
    priority_base: u8,
    read_isr: bool,
    single: bool,
    needs_icw4: bool,
    init_step: InitStep,
}

impl Controller {
    fn new(vector_base: u8, icw3: u8) -> Self {
        Self {
            vector_base,
            icw3,
            imr: 0xff,
            irr: 0,
            isr: 0,
            level_inputs: 0,
            level_triggered: false,
            auto_eoi: false,
            rotate_auto_eoi: false,
            special_mask: false,
            priority_base: 0,
            read_isr: false,
            single: false,
            needs_icw4: true,
            init_step: InitStep::None,
        }
    }

    fn begin_initialization(&mut self, value: u8) {
        self.irr = 0;
        self.isr = 0;
        self.imr = 0;
        self.level_triggered = value & 0x08 != 0;
        self.single = value & 0x02 != 0;
        self.needs_icw4 = value & 0x01 != 0;
        self.auto_eoi = false;
        self.rotate_auto_eoi = false;
        self.special_mask = false;
        self.priority_base = 0;
        self.read_isr = false;
        self.init_step = InitStep::Icw2;
    }

    fn write_data(&mut self, value: u8, port: u16) -> Result<(), PortError> {
        match self.init_step {
            InitStep::Icw2 => {
                self.vector_base = value & 0xf8;
                self.init_step = if self.single {
                    if self.needs_icw4 { InitStep::Icw4 } else { InitStep::None }
                } else {
                    InitStep::Icw3
                };
            }
            InitStep::Icw3 => {
                self.icw3 = value;
                self.init_step = if self.needs_icw4 { InitStep::Icw4 } else { InitStep::None };
            }
            InitStep::Icw4 => {
                if value & 0x01 == 0 {
                    return Err(PortError::Unsupported { port, width: PortWidth::Byte, write: true });
                }
                if value & 0x1c != 0 {
                    return Err(PortError::Unsupported { port, width: PortWidth::Byte, write: true });
                }
                if value & 0xe0 != 0 {
                    return Err(PortError::InvalidState { port, detail: "8259 ICW4 reserved bits must be zero" });
                }
                self.auto_eoi = value & 0x02 != 0;
                self.init_step = InitStep::None;
            }
            InitStep::None => self.imr = value,
        }
        Ok(())
    }

    fn write_command(&mut self, value: u8, port: u16) -> Result<(), PortError> {
        if value & 0x10 != 0 {
            if value & 0x01 == 0 {
                return Err(PortError::Unsupported { port, width: PortWidth::Byte, write: true });
            }
            self.begin_initialization(value);
            return Ok(());
        }
        if value & 0x08 != 0 {
            if value & 0x04 != 0 {
                return Err(PortError::Unsupported { port, width: PortWidth::Byte, write: true });
            }
            if value & 0x40 != 0 {
                self.special_mask = value & 0x20 != 0;
            }
            if value & 0x02 != 0 {
                self.read_isr = value & 0x01 != 0;
            }
            return Ok(());
        }

        let rotate = value & 0x80 != 0;
        let specific = value & 0x40 != 0;
        let eoi = value & 0x20 != 0;
        let level = value & 7;
        match (rotate, specific, eoi) {
            (false, false, false) => self.rotate_auto_eoi = false,
            (false, false, true) => self.end_of_interrupt(None, false),
            (false, true, false) => {}
            (false, true, true) => self.end_of_interrupt(Some(level), false),
            (true, false, false) => self.rotate_auto_eoi = true,
            (true, false, true) => self.end_of_interrupt(None, true),
            (true, true, false) => self.priority_base = (level + 1) & 7,
            (true, true, true) => self.end_of_interrupt(Some(level), true),
        }
        Ok(())
    }

    fn set_input_level(&mut self, line: u8, high: bool) {
        let mask = 1u8 << line;
        let was_high = self.level_inputs & mask != 0;
        if high {
            self.level_inputs |= mask;
            if !self.level_triggered && !was_high {
                self.irr |= mask;
            }
        } else {
            self.level_inputs &= !mask;
        }
    }

    fn request(&mut self, line: u8) {
        self.irr |= 1u8 << line;
    }

    fn requests(&self) -> u8 {
        if self.level_triggered { self.irr | self.level_inputs } else { self.irr }
    }

    fn highest_pending(&self, irr_override: Option<u8>) -> Option<u8> {
        let requests = irr_override.unwrap_or_else(|| self.requests());
        let active_isr = if self.special_mask { self.isr & !self.imr } else { self.isr };
        let active = self.highest_set_priority(active_isr);
        let candidate = (0..8)
            .map(|offset| (self.priority_base + offset) & 7)
            .find(|line| requests & (1 << line) != 0 && self.imr & (1 << line) == 0)?;
        match active {
            Some(in_service) if self.priority_rank(candidate) >= self.priority_rank(in_service) => None,
            _ => Some(candidate),
        }
    }

    fn highest_set_priority(&self, bits: u8) -> Option<u8> {
        (0..8)
            .map(|offset| (self.priority_base + offset) & 7)
            .find(|line| bits & (1 << line) != 0)
    }

    fn priority_rank(&self, line: u8) -> u8 {
        line.wrapping_add(8).wrapping_sub(self.priority_base) & 7
    }

    fn acknowledge(&mut self, line: u8) {
        let bit = 1u8 << line;
        self.irr &= !bit;
        if !self.auto_eoi {
            self.isr |= bit;
        } else if self.rotate_auto_eoi {
            self.priority_base = (line + 1) & 7;
        }
    }

    fn end_of_interrupt(&mut self, requested: Option<u8>, rotate: bool) {
        let non_specific_candidates = if self.special_mask { self.isr & !self.imr } else { self.isr };
        let line = requested.or_else(|| self.highest_set_priority(non_specific_candidates));
        if let Some(line) = line {
            self.isr &= !(1 << line);
            if rotate {
                self.priority_base = (line + 1) & 7;
            }
        }
    }

    fn read_status(&self, irr_override: Option<u8>) -> u8 {
        if self.read_isr { self.isr } else { irr_override.unwrap_or_else(|| self.requests()) }
    }
}

/// A standard AT-style master/slave pair with the slave connected to master
/// IRQ2 (slave cascade identifier 2). Vector bases are the legacy BIOS values
/// until guest software programs ICW2.
#[derive(Clone, Debug)]
pub struct Pic8259Pair {
    master: Controller,
    slave: Controller,
}

impl Default for Pic8259Pair {
    fn default() -> Self {
        Self::new()
    }
}

impl Pic8259Pair {
    pub fn new() -> Self {
        Self { master: Controller::new(0x08, 0x04), slave: Controller::new(0x70, 0x02) }
    }

    pub fn request_irq(&mut self, irq: u8) -> Result<(), PortError> {
        let Some((controller, line)) = self.controller_for(irq) else {
            return Err(PortError::InternalInvariant { port: 0x20, detail: "8259 IRQ index is outside 0 through 15" });
        };
        controller.request(line);
        Ok(())
    }

    pub fn set_irq_level(&mut self, irq: u8, high: bool) -> Result<(), PortError> {
        let Some((controller, line)) = self.controller_for(irq) else {
            return Err(PortError::InternalInvariant { port: 0x20, detail: "8259 IRQ index is outside 0 through 15" });
        };
        controller.set_input_level(line, high);
        Ok(())
    }

    pub fn interrupt_pending(&self) -> bool {
        self.best_master_pending().is_some()
    }

    /// Acknowledge one eligible request and return its programmed vector.
    pub fn acknowledge(&mut self) -> Option<u8> {
        let slave_line = self.best_slave_pending();
        let cascade = self.cascade_connected().then_some(slave_line).flatten();
        let master_requests = cascade.map_or_else(|| self.master.requests(), |_| self.master.requests() | (1 << 2));
        let master_line = self.master.highest_pending(Some(master_requests))?;
        self.master.acknowledge(master_line);
        if master_line == 2 {
            if let Some(slave_line) = cascade {
                self.slave.acknowledge(slave_line);
                return Some(self.slave.vector_base | slave_line);
            }
        }
        Some(self.master.vector_base | master_line)
    }

    pub fn master_irr(&self) -> u8 {
        self.master_requests()
    }

    pub fn master_isr(&self) -> u8 {
        self.master.isr
    }

    pub fn master_mask(&self) -> u8 {
        self.master.imr
    }

    pub fn slave_irr(&self) -> u8 {
        self.slave.requests()
    }

    pub fn slave_isr(&self) -> u8 {
        self.slave.isr
    }

    pub fn slave_mask(&self) -> u8 {
        self.slave.imr
    }

    pub(super) fn read_port(&mut self, port: u16) -> Result<u8, PortError> {
        let data_port = port == 0x21 || port == 0xa1;
        if port == 0x20 || port == 0x21 {
            Ok(if data_port { self.master.imr } else { self.master.read_status(Some(self.master_requests())) })
        } else {
            Ok(if data_port { self.slave.imr } else { self.slave.read_status(None) })
        }
    }

    pub(super) fn write_port(&mut self, port: u16, value: u8) -> Result<(), PortError> {
        let controller = if port == 0x20 || port == 0x21 { &mut self.master } else { &mut self.slave };
        if port == 0x21 || port == 0xa1 {
            controller.write_data(value, port)
        } else {
            controller.write_command(value, port)
        }
    }

    fn controller_for(&mut self, irq: u8) -> Option<(&mut Controller, u8)> {
        match irq {
            0..=7 => Some((&mut self.master, irq)),
            8..=15 => Some((&mut self.slave, irq - 8)),
            _ => None,
        }
    }

    fn cascade_connected(&self) -> bool {
        !self.master.single && self.master.icw3 & (1 << 2) != 0 && !self.slave.single && self.slave.icw3 & 7 == 2
    }

    fn best_slave_pending(&self) -> Option<u8> {
        self.cascade_connected().then(|| self.slave.highest_pending(None)).flatten()
    }

    fn master_requests(&self) -> u8 {
        let mut requests = self.master.requests();
        if self.best_slave_pending().is_some() {
            requests |= 1 << 2;
        }
        requests
    }

    fn best_master_pending(&self) -> Option<u8> {
        self.master.highest_pending(Some(self.master_requests()))
    }
}
