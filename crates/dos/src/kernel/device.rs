use crate::{
    DosError, DosErrorCode, DosHost, DosHostError, DosIoctlObjectInfo, DosIoctlStream,
};
use guest_core::{real_address, GuestMemory, Registers};

use super::system::{CON_HEADER_OFFSET, SYSTEM_SEGMENT};
use super::DosKernel;

const NUL_HEADER: u16 = 0x003a;
const NUL_STRATEGY: u16 = 0x0100;
const NUL_INTERRUPT: u16 = 0x0110;
const CON_STRATEGY: u16 = 0x0120;
const CON_INTERRUPT: u16 = 0x0130;

const HEADER_LEN: usize = 13;
// The common header ends at byte 12. Character I/O additionally uses media
// byte 13, transfer pointer 14..17, and count 18..19; the start field at
// 20..21 is for block devices and is not read by the FreeDOS CON handlers.
const IO_PACKET_LEN: usize = 20;
// Non-destructive input uses only the common header and byte 13.
const SAFE_INPUT_PACKET_LEN: usize = 14;
const STATUS_OFFSET: u16 = 3;
const STATUS_PREFIX_LEN: usize = STATUS_OFFSET as usize + 2;
const IO_BUFFER_OFFSET: u16 = 14;
const IO_COUNT_OFFSET: u16 = 18;
const SAFE_INPUT_DATA_OFFSET: u16 = 13;

const CMD_INPUT: u8 = 4;
const CMD_SAFE_INPUT: u8 = 5;
const CMD_INPUT_STATUS: u8 = 6;
const CMD_INPUT_FLUSH: u8 = 7;
const CMD_OUTPUT: u8 = 8;
const CMD_SAFE_OUTPUT: u8 = 9;
const CMD_OUTPUT_STATUS: u8 = 10;
const CMD_OUTPUT_FLUSH: u8 = 11;

const STATUS_DONE: u16 = 0x0100;
const STATUS_BUSY: u16 = 0x0200;
const STATUS_ERROR: u16 = 0x8000;
// Device status errors are not DOS INT 21h error codes. See the MS-DOS
// device-driver request contract (write-protect, unknown unit, not ready,
// unknown command, bad packet length, write/read fault, general failure).
const DEVICE_ERROR_WRITE_PROTECTED: u8 = 0;
const DEVICE_ERROR_UNKNOWN_UNIT: u8 = 1;
const DEVICE_ERROR_NOT_READY: u8 = 2;
const DEVICE_ERROR_UNKNOWN_COMMAND: u8 = 3;
const DEVICE_ERROR_BAD_LENGTH: u8 = 5;
const DEVICE_ERROR_WRITE_FAULT: u8 = 10;
const DEVICE_ERROR_READ_FAULT: u8 = 11;
const DEVICE_ERROR_GENERAL: u8 = 12;

#[derive(Clone, Copy)]
enum Device {
    Nul,
    Con,
}

impl Device {
    fn request_slot(self) -> usize {
        match self {
            Self::Nul => 0,
            Self::Con => 1,
        }
    }
}

#[derive(Clone, Copy)]
enum Entry {
    Strategy(Device),
    Interrupt(Device),
}

#[derive(Clone, Copy)]
enum HostDirection {
    Read,
    Write,
    General,
}

fn entry(offset: u16) -> Option<Entry> {
    match offset {
        NUL_STRATEGY => Some(Entry::Strategy(Device::Nul)),
        NUL_INTERRUPT => Some(Entry::Interrupt(Device::Nul)),
        CON_STRATEGY => Some(Entry::Strategy(Device::Con)),
        CON_INTERRUPT => Some(Entry::Interrupt(Device::Con)),
        _ => None,
    }
}

fn device_header(
    next_offset: u16,
    next_segment: u16,
    attributes: u16,
    strategy: u16,
    interrupt: u16,
    name: &[u8; 8],
) -> [u8; 18] {
    let mut bytes = [0; 18];
    bytes[0..2].copy_from_slice(&next_offset.to_le_bytes());
    bytes[2..4].copy_from_slice(&next_segment.to_le_bytes());
    bytes[4..6].copy_from_slice(&attributes.to_le_bytes());
    bytes[6..8].copy_from_slice(&strategy.to_le_bytes());
    bytes[8..10].copy_from_slice(&interrupt.to_le_bytes());
    bytes[10..18].copy_from_slice(name);
    bytes
}

// DOS uses 16-bit offsets for request packets and the far-return stack. Keep
// those accesses segmented, including the architecturally wrapping SS:SP case.
fn validate_segmented(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    length: usize,
    write: bool,
) -> Result<(), DosError> {
    let first = length.min(0x1_0000usize - usize::from(offset));
    let first_address = real_address(segment, offset);
    if write {
        memory.validate_write(first_address, first)?;
    } else {
        memory.validate_read(first_address, first)?;
    }
    let remaining = length - first;
    if remaining != 0 {
        let wrapped_address = real_address(segment, 0);
        if write {
            memory.validate_write(wrapped_address, remaining)?;
        } else {
            memory.validate_read(wrapped_address, remaining)?;
        }
    }
    Ok(())
}

fn read_segmented(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    output: &mut [u8],
) -> Result<(), DosError> {
    validate_segmented(memory, segment, offset, output.len(), false)?;
    let first = output.len().min(0x1_0000usize - usize::from(offset));
    memory.read(real_address(segment, offset), &mut output[..first])?;
    if first < output.len() {
        memory.read(real_address(segment, 0), &mut output[first..])?;
    }
    Ok(())
}

fn write_segmented(
    memory: &mut impl GuestMemory,
    segment: u16,
    offset: u16,
    input: &[u8],
) -> Result<(), DosError> {
    validate_segmented(memory, segment, offset, input.len(), true)?;
    let first = input.len().min(0x1_0000usize - usize::from(offset));
    memory.write(real_address(segment, offset), &input[..first])?;
    if first < input.len() {
        memory.write(real_address(segment, 0), &input[first..])?;
    }
    Ok(())
}

fn packet_offset(base: u16, field: u16) -> u16 {
    base.wrapping_add(field)
}

fn read_packet_word(
    memory: &impl GuestMemory,
    segment: u16,
    base: u16,
    field: u16,
) -> Result<u16, DosError> {
    let mut bytes = [0; 2];
    read_segmented(memory, segment, packet_offset(base, field), &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn write_packet_word(
    memory: &mut impl GuestMemory,
    segment: u16,
    base: u16,
    field: u16,
    value: u16,
) -> Result<(), DosError> {
    write_segmented(
        memory,
        segment,
        packet_offset(base, field),
        &value.to_le_bytes(),
    )
}

fn validate_packet_field(
    memory: &impl GuestMemory,
    segment: u16,
    base: u16,
    field: u16,
    size: usize,
    write: bool,
) -> Result<(), DosError> {
    validate_segmented(memory, segment, packet_offset(base, field), size, write)
}

fn status_for_error(error: &DosHostError, direction: HostDirection) -> u16 {
    let device_code = match error.code {
        DosErrorCode::WriteProtected => DEVICE_ERROR_WRITE_PROTECTED,
        DosErrorCode::UnknownUnit => DEVICE_ERROR_UNKNOWN_UNIT,
        DosErrorCode::DriveNotReady => DEVICE_ERROR_NOT_READY,
        DosErrorCode::GeneralFailure => DEVICE_ERROR_GENERAL,
        _ => match direction {
            HostDirection::Read => DEVICE_ERROR_READ_FAULT,
            HostDirection::Write => DEVICE_ERROR_WRITE_FAULT,
            HostDirection::General => DEVICE_ERROR_GENERAL,
        },
    };
    status_with_device_error(device_code)
}

fn status_for_unsupported_command() -> u16 {
    status_with_device_error(DEVICE_ERROR_UNKNOWN_COMMAND)
}

fn status_for_bad_length() -> u16 {
    status_with_device_error(DEVICE_ERROR_BAD_LENGTH)
}

fn console_stream_status(
    host: &impl DosHost,
    stream: DosIoctlStream,
    direction: HostDirection,
) -> Result<(), u16> {
    let info = host
        .standard_ioctl_info(stream)
        .map_err(|error| status_for_error(&error, direction))?;
    let is_expected_console = match (stream, direction, info) {
        (
            DosIoctlStream::Input,
            HostDirection::Read,
            DosIoctlObjectInfo::CharacterDevice {
                standard_input: true,
                ..
            },
        ) => true,
        (
            DosIoctlStream::Output,
            HostDirection::Write,
            DosIoctlObjectInfo::CharacterDevice {
                standard_output: true,
                ..
            },
        ) => true,
        _ => false,
    };
    if is_expected_console {
        Ok(())
    } else {
        Err(status_with_device_error(DEVICE_ERROR_NOT_READY))
    }
}

fn status_with_device_error(error: u8) -> u16 {
    STATUS_DONE | STATUS_ERROR | u16::from(error)
}

fn validate_transfer_buffer(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    length: usize,
    write: bool,
) -> Result<(), DosError> {
    if length == 0 {
        return Ok(());
    }
    if usize::from(offset) + length > 0x1_0000 {
        return Err(DosError::MalformedGuestInput(
            "DOS device transfer buffer wraps its segment",
        ));
    }
    let address = real_address(segment, offset);
    if write {
        memory.validate_write(address, length)?;
    } else {
        memory.validate_read(address, length)?;
    }
    Ok(())
}

impl DosKernel {
    /// Install the two resident character-device headers and real-mode RETF
    /// entry stubs in the guest DOS system segment.
    pub fn initialize_character_devices(
        &mut self,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DosError> {
        const ATTR_NUL: u16 = 0x8000 | 0x0004;
        // Do not advertise FASTCON or either IOCTL capability: this runtime
        // does not install INT 29h or implement those request commands.
        const ATTR_CON: u16 = 0x8000 | 0x0001 | 0x0002;

        let nul = device_header(
            CON_HEADER_OFFSET,
            SYSTEM_SEGMENT,
            ATTR_NUL,
            NUL_STRATEGY,
            NUL_INTERRUPT,
            b"NUL     ",
        );
        let con = device_header(
            u16::MAX,
            u16::MAX,
            ATTR_CON,
            CON_STRATEGY,
            CON_INTERRUPT,
            b"CON     ",
        );
        let headers = [(NUL_HEADER, nul), (CON_HEADER_OFFSET, con)];
        let entries = [NUL_STRATEGY, NUL_INTERRUPT, CON_STRATEGY, CON_INTERRUPT];

        // Preflight every guest write before publishing any header or entry.
        for (offset, bytes) in &headers {
            memory.validate_write(real_address(SYSTEM_SEGMENT, *offset), bytes.len())?;
        }
        for offset in entries {
            memory.validate_write(real_address(SYSTEM_SEGMENT, offset), 1)?;
        }

        for (offset, bytes) in &headers {
            memory.write(real_address(SYSTEM_SEGMENT, *offset), bytes)?;
        }
        for offset in entries {
            memory.write(real_address(SYSTEM_SEGMENT, offset), &[0xcb])?;
        }
        self.device_requests = [None; 2];
        Ok(())
    }

    /// Service one DOS character-device strategy or interrupt entry. The
    /// runtime executes the guest RETF byte after this method returns.
    pub fn character_device_service(
        &mut self,
        offset: u16,
        regs: &Registers,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<bool, DosError> {
        let Some(entry) = entry(offset) else {
            return Ok(false);
        };
        if memory.read_u8(real_address(SYSTEM_SEGMENT, offset))? != 0xcb {
            return Err(DosError::MalformedGuestInput(
                "DOS device entry was overwritten",
            ));
        }
        validate_segmented(memory, regs.ss, regs.sp(), 4, false)?;

        match entry {
            Entry::Strategy(device) => {
                let pointer = (regs.es, regs.bx());
                let mut prefix = [0; STATUS_PREFIX_LEN];
                read_segmented(memory, pointer.0, pointer.1, &mut prefix)?;
                let length = usize::from(prefix[0]);
                if length < prefix.len() {
                    return Err(DosError::MalformedGuestInput(
                        "DOS device request is too short to return status",
                    ));
                }
                validate_segmented(memory, pointer.0, pointer.1, length, false)?;
                // A short request still has an addressable status word. Let
                // the interrupt entry return the DOS bad-length status.
                validate_packet_field(memory, pointer.0, pointer.1, STATUS_OFFSET, 2, true)?;
                self.device_requests[device.request_slot()] = Some(pointer);
            }
            Entry::Interrupt(device) => {
                let Some((segment, packet)) = self.device_requests[device.request_slot()].take() else {
                    return Err(DosError::MalformedGuestInput(
                        "DOS device interrupt entry has no strategy request",
                    ));
                };
                self.service_interrupt(device, segment, packet, memory, host)?;
            }
        }
        Ok(true)
    }

    fn service_interrupt(
        &mut self,
        device: Device,
        segment: u16,
        packet: u16,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        let mut prefix = [0; STATUS_PREFIX_LEN];
        read_segmented(memory, segment, packet, &mut prefix)?;
        let declared_length = usize::from(prefix[0]);
        if declared_length < prefix.len() {
            return Err(DosError::MalformedGuestInput(
                "DOS device request is too short to return status",
            ));
        }
        validate_segmented(memory, segment, packet, declared_length, false)?;

        validate_packet_field(memory, segment, packet, STATUS_OFFSET, 2, true)?;
        if declared_length < HEADER_LEN {
            write_packet_word(
                memory,
                segment,
                packet,
                STATUS_OFFSET,
                status_for_bad_length(),
            )?;
            return Ok(());
        }
        let mut header = [0; HEADER_LEN];
        read_segmented(memory, segment, packet, &mut header)?;
        let command = header[2];
        let required_length = match command {
            CMD_INPUT | CMD_OUTPUT | CMD_SAFE_OUTPUT => IO_PACKET_LEN,
            CMD_SAFE_INPUT => SAFE_INPUT_PACKET_LEN,
            _ => HEADER_LEN,
        };
        if declared_length < required_length {
            write_packet_word(
                memory,
                segment,
                packet,
                STATUS_OFFSET,
                status_for_bad_length(),
            )?;
            return Ok(());
        }

        match (device, command) {
            (Device::Nul, CMD_INPUT) => {
                validate_packet_field(memory, segment, packet, IO_COUNT_OFFSET, 2, true)?;
                write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, 0)?;
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            (Device::Nul, CMD_SAFE_INPUT) => {
                write_packet_word(
                    memory,
                    segment,
                    packet,
                    STATUS_OFFSET,
                    STATUS_DONE | STATUS_BUSY,
                )?;
            }
            (Device::Nul, CMD_INPUT_STATUS) => {
                write_packet_word(
                    memory,
                    segment,
                    packet,
                    STATUS_OFFSET,
                    STATUS_DONE | STATUS_BUSY,
                )?;
            }
            (Device::Nul, CMD_INPUT_FLUSH | CMD_OUTPUT_FLUSH) => {
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            (Device::Nul, CMD_OUTPUT | CMD_SAFE_OUTPUT) => {
                let count = read_packet_word(memory, segment, packet, IO_COUNT_OFFSET)?;
                validate_packet_field(memory, segment, packet, IO_COUNT_OFFSET, 2, true)?;
                // NUL consumes all requested bytes without reading their data.
                write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, count)?;
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            (Device::Nul, CMD_OUTPUT_STATUS) => {
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            (Device::Con, CMD_INPUT) => {
                self.console_input_request(segment, packet, memory, host)?;
            }
            (Device::Con, CMD_SAFE_INPUT) => {
                self.console_safe_input_request(segment, packet, memory, host)?;
            }
            (Device::Con, CMD_INPUT_STATUS) => {
                self.console_status_request(segment, packet, true, memory, host)?;
            }
            (Device::Con, CMD_OUTPUT_STATUS) => {
                let status = console_stream_status(
                    host,
                    DosIoctlStream::Output,
                    HostDirection::Write,
                )
                .map_or_else(|error| error, |_| STATUS_DONE);
                write_packet_word(memory, segment, packet, STATUS_OFFSET, status)?;
            }
            (Device::Con, CMD_INPUT_FLUSH) => {
                if let Err(status) = console_stream_status(
                    host,
                    DosIoctlStream::Input,
                    HostDirection::Read,
                ) {
                    write_packet_word(memory, segment, packet, STATUS_OFFSET, status)?;
                    return Ok(());
                }
                match host.flush_stdin() {
                    Ok(()) => {
                        self.pending_input = None;
                        write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
                    }
                    Err(error) => write_packet_word(
                        memory,
                        segment,
                        packet,
                        STATUS_OFFSET,
                        status_for_error(&error, HostDirection::General),
                    )?,
                }
            }
            (Device::Con, CMD_OUTPUT | CMD_SAFE_OUTPUT) => {
                self.console_output_request(segment, packet, memory, host)?;
            }
            _ => {
                // Unknown or unsupported commands are errors, never a false DONE.
                write_packet_word(
                    memory,
                    segment,
                    packet,
                    STATUS_OFFSET,
                    status_for_unsupported_command(),
                )?;
            }
        }
        Ok(())
    }

    fn console_input_request(
        &mut self,
        segment: u16,
        packet: u16,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        let count = usize::from(read_packet_word(memory, segment, packet, IO_COUNT_OFFSET)?);
        let mut address_bytes = [0; 4];
        read_segmented(
            memory,
            segment,
            packet_offset(packet, IO_BUFFER_OFFSET),
            &mut address_bytes,
        )?;
        let buffer_offset = u16::from_le_bytes([address_bytes[0], address_bytes[1]]);
        let buffer_segment = u16::from_le_bytes([address_bytes[2], address_bytes[3]]);

        // Preflight every guest destination before consuming host input.
        validate_packet_field(memory, segment, packet, IO_COUNT_OFFSET, 2, true)?;
        validate_packet_field(memory, segment, packet, STATUS_OFFSET, 2, true)?;
        validate_transfer_buffer(memory, buffer_segment, buffer_offset, count, true)?;
        if let Err(status) = console_stream_status(
            host,
            DosIoctlStream::Input,
            HostDirection::Read,
        ) {
            write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, 0)?;
            write_packet_word(memory, segment, packet, STATUS_OFFSET, status)?;
            return Ok(());
        }
        let mut input = vec![0; count];
        let read = if count == 0 {
            Ok(0)
        } else {
            self.read_stdin_bytes(host, &mut input)
        };
        match read {
            Ok(0) if count != 0 => {
                return Err(DosError::HostContractViolation(
                    "blocking console device input returned no byte",
                ));
            }
            Ok(read) if read <= count => {
                if read != 0 {
                    write_segmented(
                        memory,
                        buffer_segment,
                        buffer_offset,
                        &input[..read],
                    )?;
                }
                write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, read as u16)?;
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            Ok(_) => return Err(DosError::HostContractViolation("console device read exceeded its request")),
            Err(error) => {
                write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, 0)?;
                write_packet_word(
                    memory,
                        segment,
                        packet,
                        STATUS_OFFSET,
                        status_for_error(&error, HostDirection::Read),
                )?;
            }
        }
        Ok(())
    }

    fn console_safe_input_request(
        &mut self,
        segment: u16,
        packet: u16,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        validate_packet_field(memory, segment, packet, SAFE_INPUT_DATA_OFFSET, 1, true)?;
        validate_packet_field(memory, segment, packet, STATUS_OFFSET, 2, true)?;
        if let Err(status) = console_stream_status(
            host,
            DosIoctlStream::Input,
            HostDirection::Read,
        ) {
            write_packet_word(memory, segment, packet, STATUS_OFFSET, status)?;
            return Ok(());
        }
        match self.poll_console_byte(host) {
            Ok(Some(byte)) => {
                write_segmented(
                    memory,
                    segment,
                    packet_offset(packet, SAFE_INPUT_DATA_OFFSET),
                    &[byte],
                )?;
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            Ok(None) => write_packet_word(
                memory,
                segment,
                packet,
                STATUS_OFFSET,
                STATUS_DONE | STATUS_BUSY,
            )?,
            Err(error) => write_packet_word(
                memory,
                segment,
                packet,
                STATUS_OFFSET,
                status_for_error(&error, HostDirection::Read),
            )?,
        }
        Ok(())
    }

    fn console_status_request(
        &mut self,
        segment: u16,
        packet: u16,
        input: bool,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        validate_packet_field(memory, segment, packet, STATUS_OFFSET, 2, true)?;
        if !input {
            let status = console_stream_status(
                host,
                DosIoctlStream::Output,
                HostDirection::Write,
            )
            .map_or_else(|error| error, |_| STATUS_DONE);
            return write_packet_word(memory, segment, packet, STATUS_OFFSET, status);
        }
        if let Err(status) = console_stream_status(
            host,
            DosIoctlStream::Input,
            HostDirection::Read,
        ) {
            return write_packet_word(memory, segment, packet, STATUS_OFFSET, status);
        }
        let status = match self.poll_console_byte(host) {
            Ok(Some(_)) => STATUS_DONE,
            Ok(None) => STATUS_DONE | STATUS_BUSY,
            Err(error) => status_for_error(&error, HostDirection::Read),
        };
        write_packet_word(memory, segment, packet, STATUS_OFFSET, status)
    }

    fn console_output_request(
        &mut self,
        segment: u16,
        packet: u16,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        let count = usize::from(read_packet_word(memory, segment, packet, IO_COUNT_OFFSET)?);
        let mut address_bytes = [0; 4];
        read_segmented(
            memory,
            segment,
            packet_offset(packet, IO_BUFFER_OFFSET),
            &mut address_bytes,
        )?;
        let buffer_offset = u16::from_le_bytes([address_bytes[0], address_bytes[1]]);
        let buffer_segment = u16::from_le_bytes([address_bytes[2], address_bytes[3]]);
        validate_packet_field(memory, segment, packet, IO_COUNT_OFFSET, 2, true)?;
        validate_packet_field(memory, segment, packet, STATUS_OFFSET, 2, true)?;
        validate_transfer_buffer(memory, buffer_segment, buffer_offset, count, false)?;
        if let Err(status) = console_stream_status(
            host,
            DosIoctlStream::Output,
            HostDirection::Write,
        ) {
            write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, 0)?;
            write_packet_word(memory, segment, packet, STATUS_OFFSET, status)?;
            return Ok(());
        }
        let mut output = vec![0; count];
        if count != 0 {
            read_segmented(memory, buffer_segment, buffer_offset, &mut output)?;
        }
        match host.write_stdout(&output) {
            Ok(written) if written <= count => {
                write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, written as u16)?;
                write_packet_word(memory, segment, packet, STATUS_OFFSET, STATUS_DONE)?;
            }
            Ok(_) => return Err(DosError::HostContractViolation("console device write exceeded its request")),
            Err(error) => {
                write_packet_word(memory, segment, packet, IO_COUNT_OFFSET, 0)?;
                write_packet_word(
                    memory,
                    segment,
                    packet,
                    STATUS_OFFSET,
                    status_for_error(&error, HostDirection::Write),
                )?;
            }
        }
        Ok(())
    }
}
