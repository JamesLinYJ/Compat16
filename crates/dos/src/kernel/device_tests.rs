use super::tests::{TestHost, TestMemory};
use super::DosKernel;
use crate::{DosError, DosHost, DosSeekOrigin};
use guest_core::{GuestMemory, Registers};

const SYSTEM_SEGMENT: u16 = 0x0800;
const REQUEST_SEGMENT: u16 = 0x0200;
const REQUEST_OFFSET: u16 = 0x0020;
const BUFFER_SEGMENT: u16 = 0x0300;
const BUFFER_OFFSET: u16 = 0x0040;

fn device_regs() -> Registers {
    let mut regs = Registers::default();
    regs.cs = SYSTEM_SEGMENT;
    regs.ss = 0x0100;
    regs.set_sp(0xfffe); // Exercise RETF preflight across the 16-bit wrap.
    regs.es = REQUEST_SEGMENT;
    regs.set_bx(REQUEST_OFFSET);
    regs
}

fn request(length: u8, command: u8) -> Vec<u8> {
    let mut bytes = vec![0; usize::from(length)];
    bytes[0] = length;
    bytes[2] = command;
    bytes
}

fn call_device(
    kernel: &mut DosKernel,
    strategy: u16,
    interrupt: u16,
    regs: &Registers,
    memory: &mut TestMemory,
    host: &mut TestHost,
) {
    assert!(kernel
        .character_device_service(strategy, regs, memory, host)
        .unwrap());
    assert!(kernel
        .character_device_service(interrupt, regs, memory, host)
        .unwrap());
}

fn read_word(memory: &TestMemory, address: u32) -> u16 {
    let mut bytes = [0; 2];
    memory.read(guest_core::PhysAddr(address), &mut bytes).unwrap();
    u16::from_le_bytes(bytes)
}

#[test]
fn initializes_real_chained_device_headers_without_claiming_int29() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    kernel.initialize_character_devices(&mut memory).unwrap();

    let nul = 0x0800u32 * 16 + 0x003a;
    let con = 0x0800u32 * 16 + 0x0080;
    assert_eq!(read_word(&memory, nul), 0x0080);
    assert_eq!(read_word(&memory, nul + 2), SYSTEM_SEGMENT);
    assert_eq!(read_word(&memory, nul + 4), 0x8004);
    assert_eq!(read_word(&memory, nul + 6), 0x0100);
    assert_eq!(read_word(&memory, nul + 8), 0x0110);
    let mut name = [0; 8];
    memory
        .read(guest_core::PhysAddr(nul + 10), &mut name)
        .unwrap();
    assert_eq!(&name, b"NUL     ");

    assert_eq!(read_word(&memory, con), u16::MAX);
    assert_eq!(read_word(&memory, con + 2), u16::MAX);
    assert_eq!(read_word(&memory, con + 4), 0x8003);
    assert_eq!(read_word(&memory, con + 6), 0x0120);
    assert_eq!(read_word(&memory, con + 8), 0x0130);
    memory
        .read(guest_core::PhysAddr(con + 10), &mut name)
        .unwrap();
    assert_eq!(&name, b"CON     ");
    for offset in [0x0100, 0x0110, 0x0120, 0x0130] {
        assert_eq!(memory.read_u8(guest_core::real_address(SYSTEM_SEGMENT, offset)).unwrap(), 0xcb);
    }
}

#[test]
fn nul_input_returns_eof_and_unknown_commands_return_driver_error() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    let regs = device_regs();

    let mut packet = request(20, 4);
    packet[18..20].copy_from_slice(&17u16.to_le_bytes());
    memory.put(0x2020, &packet);
    call_device(&mut kernel, 0x0100, 0x0110, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 18), 0);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x0100);

    let packet = request(13, 0xfe);
    memory.put(0x2020, &packet);
    call_device(&mut kernel, 0x0100, 0x0110, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x8103);
}

#[test]
fn nul_reports_bad_length_in_the_request_status_word() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    let regs = device_regs();

    let packet = request(13, 4);
    memory.put(0x2020, &packet);
    call_device(&mut kernel, 0x0100, 0x0110, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x8105);
}

#[test]
fn requests_shorter_than_the_common_header_return_bad_length_when_status_fits() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    let regs = device_regs();

    let packet = request(5, 4);
    memory.put(0x2020, &packet);
    call_device(&mut kernel, 0x0100, 0x0110, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x8105);

    let packet = request(4, 4);
    memory.put(0x2020, &packet);
    assert!(matches!(
        kernel.character_device_service(0x0100, &regs, &mut memory, &mut host),
        Err(DosError::MalformedGuestInput(
            "DOS device request is too short to return status"
        ))
    ));
}

#[test]
fn console_output_flush_is_unsupported_and_redirected_streams_are_not_con() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    let regs = device_regs();

    let packet = request(13, 11);
    memory.put(0x2020, &packet);
    call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x8103);

    host.redirect_standard_streams();
    kernel.pending_input = Some(b'Q');
    let mut input = request(20, 4);
    input[14..16].copy_from_slice(&BUFFER_OFFSET.to_le_bytes());
    input[16..18].copy_from_slice(&BUFFER_SEGMENT.to_le_bytes());
    input[18..20].copy_from_slice(&1u16.to_le_bytes());
    memory.put(0x2020, &input);
    call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 18), 0);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x810b);
    assert_eq!(kernel.pending_input, Some(b'Q'));

    let mut output = request(20, 8);
    output[14..16].copy_from_slice(&BUFFER_OFFSET.to_le_bytes());
    output[16..18].copy_from_slice(&BUFFER_SEGMENT.to_le_bytes());
    output[18..20].copy_from_slice(&1u16.to_le_bytes());
    memory.put(0x2020, &output);
    call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 18), 0);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x810a);
}

#[test]
fn console_safe_input_peeks_then_input_consumes_the_cached_byte_once() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    kernel.pending_input = Some(b'R');
    let regs = device_regs();

    let mut safe_packet = request(14, 5);
    safe_packet[13] = 0xee;
    memory.put(0x2020, &safe_packet);
    call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
    assert_eq!(memory.read_u8(guest_core::PhysAddr(0x2020 + 13)).unwrap(), b'R');
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x0100);
    assert_eq!(kernel.pending_input, Some(b'R'));

    let mut input_packet = request(20, 4);
    input_packet[14..16].copy_from_slice(&BUFFER_OFFSET.to_le_bytes());
    input_packet[16..18].copy_from_slice(&BUFFER_SEGMENT.to_le_bytes());
    input_packet[18..20].copy_from_slice(&1u16.to_le_bytes());
    memory.put(0x2020, &input_packet);
    call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
    let buffer = u32::from(BUFFER_SEGMENT) * 16 + u32::from(BUFFER_OFFSET);
    assert_eq!(memory.read_u8(guest_core::PhysAddr(buffer)).unwrap(), b'R');
    assert_eq!(read_word(&memory, 0x2020 + 18), 1);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x0100);
    assert_eq!(kernel.pending_input, None);
}

#[test]
fn explicit_console_status_and_safe_input_ignore_redirected_guest_stdin() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    let file = host.file_create(b"input", 0).unwrap();
    host.file_write(file, b"F").unwrap();
    host.file_seek(file, 0, DosSeekOrigin::Start).unwrap();
    kernel.handles.insert(3, super::state::Handle::File(file));
    assert!(kernel.file_table.register_open(3, 2).is_some());
    let mut redirect = Registers::default();
    redirect.set_ax(0x4600);
    redirect.set_bx(3);
    redirect.set_cx(0);
    kernel.interrupt(0x21, &mut redirect, &mut memory, &mut host).unwrap();
    assert!(!redirect.carry());
    kernel.pending_input = Some(b'C');
    let regs = device_regs();

    for command in [5, 6] {
        memory.put(0x2020, &request(14, command));
        call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
        assert_eq!(read_word(&memory, 0x2020 + 3), 0x0100);
        if command == 5 {
            assert_eq!(memory.read_u8(guest_core::PhysAddr(0x2020 + 13)).unwrap(), b'C');
        }
        assert_eq!(kernel.pending_input, Some(b'C'));
        assert_eq!(host.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 0);
    }
    kernel.pending_input = None;
    memory.put(0x2020, &request(13, 6));
    call_device(&mut kernel, 0x0120, 0x0130, &regs, &mut memory, &mut host);
    assert_eq!(read_word(&memory, 0x2020 + 3), 0x0300);
    assert_eq!(host.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 0);
}

#[test]
fn invalid_console_destination_is_rejected_before_consuming_cached_input() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    kernel.pending_input = Some(b'X');
    let regs = device_regs();

    let mut packet = request(20, 4);
    packet[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    packet[16..18].copy_from_slice(&u16::MAX.to_le_bytes());
    packet[18..20].copy_from_slice(&1u16.to_le_bytes());
    memory.put(0x2020, &packet);
    assert!(kernel
        .character_device_service(0x0120, &regs, &mut memory, &mut host)
        .unwrap());
    let error = kernel.character_device_service(0x0130, &regs, &mut memory, &mut host);
    assert!(matches!(error, Err(DosError::Memory(_))));
    assert_eq!(kernel.pending_input, Some(b'X'));
}

#[test]
fn overwritten_entry_is_not_serviced_by_the_host() {
    let mut kernel = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    kernel.initialize_character_devices(&mut memory).unwrap();
    memory.put(0x8100, &[0x90]);
    let regs = device_regs();
    assert!(matches!(
        kernel.character_device_service(0x0100, &regs, &mut memory, &mut host),
        Err(DosError::MalformedGuestInput("DOS device entry was overwritten"))
    ));
}
