//! Real-mode timer interrupt wiring over the process-owned PIT/PIC state.

use devices::ports::MachinePorts;
use guest_core::{GuestMemory, PhysAddr, real_address};
use guest_core::io::{PortIo, PortWidth};
use guest_core::memory::Memory;

use crate::{RuntimeError, runtime_error};

const TIMER_VECTOR: u8 = 0x08;
const TIMER_SEGMENT: u16 = 0xf000;
const TIMER_OFFSET: u16 = 0x0200;

pub(crate) fn initialize(memory: &mut Memory, ports: &mut MachinePorts) -> Result<(), RuntimeError> {
    // The default BIOS handler invokes the replaceable INT 1Ch tick hook and
    // acknowledges IRQ0. Preserve AX and the interrupted FLAGS/CS/IP frame.
    // The runtime maintains the BDA wall clock separately from hook delivery.
    let timer_handler = [
        0x50,             // PUSH AX
        0xcd, 0x1c,       // INT 1Ch
        0xb0, 0x20,       // MOV AL, non-specific EOI
        0xe6, 0x20,       // OUT master PIC command port, AL
        0x58,             // POP AX
        0xcf,             // IRET
    ];
    memory.initialize_rom(real_address(TIMER_SEGMENT, TIMER_OFFSET), &timer_handler)
        .map_err(runtime_error)?;
    let mut vector = [0; 4];
    vector[..2].copy_from_slice(&TIMER_OFFSET.to_le_bytes());
    vector[2..].copy_from_slice(&TIMER_SEGMENT.to_le_bytes());
    memory.write(PhysAddr(u32::from(TIMER_VECTOR) * 4), &vector).map_err(runtime_error)?;

    // IBM PC timer convention: channel 0, binary mode 3, divisor 65536
    // (encoded as two zero bytes), approximately 18.2 interrupts/second.
    ports.write(0x43, PortWidth::Byte, 0x36).map_err(runtime_error)?;
    ports.write(0x40, PortWidth::Byte, 0).map_err(runtime_error)?;
    ports.write(0x40, PortWidth::Byte, 0).map_err(runtime_error)?;
    install_rtc_handler(memory)?;
    // IRQ0 and the IRQ2 cascade stay unmasked. The slave leaves IRQ8
    // unmasked and holds every other slave line.
    ports.write(0x21, PortWidth::Byte, 0xfa).map_err(runtime_error)?;
    ports.write(0xa1, PortWidth::Byte, 0xfe).map_err(runtime_error)?;
    Ok(())
}

fn install_rtc_handler(memory: &mut Memory) -> Result<(), RuntimeError> {
    // Default INT 70h: read CMOS register C (which clears the flags) and
    // send end-of-interrupt to the slave and the master.
    const RTC_VECTOR: u8 = 0x70;
    const RTC_SEGMENT: u16 = 0xf000;
    const RTC_OFFSET: u16 = 0x0280;
    let handler = [
        0x50,       // PUSH AX
        0xb0, 0x0c, // MOV AL, 0Ch
        0xe6, 0x70, // OUT 70h, AL
        0xe4, 0x71, // IN AL, 71h
        0xb0, 0x20, // MOV AL, 20h
        0xe6, 0xa0, // OUT A0h, AL
        0xe6, 0x20, // OUT 20h, AL
        0x58,       // POP AX
        0xcf,       // IRET
    ];
    memory.initialize_rom(real_address(RTC_SEGMENT, RTC_OFFSET), &handler)
        .map_err(runtime_error)?;
    let mut vector = [0; 4];
    vector[..2].copy_from_slice(&RTC_OFFSET.to_le_bytes());
    vector[2..].copy_from_slice(&RTC_SEGMENT.to_le_bytes());
    memory.write(PhysAddr(u32::from(RTC_VECTOR) * 4), &vector).map_err(runtime_error)
}
