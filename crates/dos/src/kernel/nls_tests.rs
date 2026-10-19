use super::tests::{TestHost, TestMemory};
use super::{DosKernel, collating_table};
use crate::{DosAction, DosError, DosErrorCode};
use guest_core::{GuestMemory, PhysAddr, Registers, real_address};
use text_codec::CodePage;

const TABLE_SEGMENT: u16 = 0x1000;
const TABLE_OFFSET: u16 = 0x0020;
const OUTPUT_SEGMENT: u16 = 0x0800;
const OUTPUT_OFFSET: u16 = 0x0040;

fn install_us_cp437_table(dos: &mut DosKernel, memory: &mut TestMemory) {
    let table = collating_table(CodePage::Cp437).expect("US CP437 table is part of this DOS core");
    memory.put(real_address(TABLE_SEGMENT, TABLE_OFFSET).0, table);
    dos.set_collating_table_address(CodePage::Cp437, TABLE_SEGMENT, TABLE_OFFSET)
        .expect("valid guest ROM pointer");
}

fn call_6506(
    dos: &mut DosKernel,
    regs: &mut Registers,
    memory: &mut TestMemory,
    host: &mut TestHost,
) -> Result<DosAction, DosError> {
    dos.interrupt(0x21, regs, memory, host)
}

fn output_bytes(memory: &TestMemory) -> [u8; 5] {
    let mut descriptor = [0; 5];
    memory
        .read(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET), &mut descriptor)
        .expect("output descriptor is in guest memory");
    descriptor
}

fn request_default() -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(0x6506);
    regs.set_bx(u16::MAX);
    regs.set_cx(u16::MAX);
    regs.set_dx(u16::MAX);
    regs.es = OUTPUT_SEGMENT;
    regs.set_di(OUTPUT_OFFSET);
    regs
}

#[test]
fn us_cp437_table_matches_microsoft_dos4_weights_and_format() {
    let table = collating_table(CodePage::Cp437).expect("CP437 table exists");
    assert_eq!(&table[..2], &[0x00, 0x01]);

    for byte in 0..32 {
        assert_eq!(table[byte + 2], byte as u8, "control byte {byte:02x}");
    }
    assert_eq!(table[b'a' as usize + 2], b'A');
    assert_eq!(table[b'z' as usize + 2], b'Z');
    assert_eq!(table[0x80 + 2], b'C');
    assert_eq!(table[0x81 + 2], b'U');
    assert_eq!(table[0x82 + 2], b'E');
    assert_eq!(table[0x84 + 2], b'A');
    assert_eq!(table[0x9e + 2], b'$');
    assert_eq!(table[0xa0 + 2], b'A');
    assert_eq!(table[0xb0 + 2], 0xb0);
    assert_eq!(table[0xe1 + 2], b'S');
    assert_eq!(table[0xff + 2], 0xff);

    assert_eq!(collating_table(CodePage::Cp936).unwrap()[0x82 + 2], 0x82);
}

#[test]
fn get_collating_table_returns_guest_far_pointer_descriptor() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_us_cp437_table(&mut dos, &mut memory);
    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 5]);
    let mut regs = request_default();
    regs.ecx = 0xabcd_ffff;
    regs.eflags = 0x202;

    assert_eq!(call_6506(&mut dos, &mut regs, &mut memory, &mut host).unwrap(), DosAction::Continue);
    assert_eq!(output_bytes(&memory), [0x06, 0x20, 0x00, 0x00, 0x10]);
    assert_eq!(regs.cx(), 5);
    assert_eq!(regs.ecx, 0xabcd_0005);
    assert_eq!(regs.ax(), 437);
    assert_eq!(regs.eflags, 0x202);
}

#[test]
fn get_collating_table_accepts_explicit_us_country_and_cp437() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_us_cp437_table(&mut dos, &mut memory);
    let mut regs = request_default();
    regs.set_bx(437);
    regs.set_dx(1);

    call_6506(&mut dos, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(output_bytes(&memory), [0x06, 0x20, 0x00, 0x00, 0x10]);
    assert!(!regs.carry());
}

#[test]
fn unsupported_subfunction_and_short_buffer_return_invalid_function_without_writes() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_us_cp437_table(&mut dos, &mut memory);
    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 5]);

    let mut unsupported = request_default();
    unsupported.set_al(0x03);
    call_6506(&mut dos, &mut unsupported, &mut memory, &mut host).unwrap();
    assert_eq!(unsupported.ax(), DosErrorCode::InvalidFunction as u16);
    assert!(unsupported.carry());
    assert_eq!(output_bytes(&memory), [0xcc; 5]);

    let mut short = request_default();
    short.set_cx(4);
    call_6506(&mut dos, &mut short, &mut memory, &mut host).unwrap();
    assert_eq!(short.ax(), DosErrorCode::InvalidFunction as u16);
    assert!(short.carry());
    assert_eq!(output_bytes(&memory), [0xcc; 5]);
}

#[test]
fn unknown_country_or_unsupported_code_page_returns_file_not_found() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_us_cp437_table(&mut dos, &mut memory);
    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 5]);

    let mut unknown_country = request_default();
    unknown_country.set_dx(2);
    call_6506(&mut dos, &mut unknown_country, &mut memory, &mut host).unwrap();
    assert_eq!(unknown_country.ax(), DosErrorCode::FileNotFound as u16);
    assert!(unknown_country.carry());
    assert_eq!(output_bytes(&memory), [0xcc; 5]);

    let mut cp936 = request_default();
    cp936.set_bx(936);
    cp936.set_dx(1);
    call_6506(&mut dos, &mut cp936, &mut memory, &mut host).unwrap();
    assert_eq!(cp936.ax(), DosErrorCode::FileNotFound as u16);
    assert!(cp936.carry());
    assert_eq!(output_bytes(&memory), [0xcc; 5]);
}

#[test]
fn missing_or_invalid_guest_rom_is_a_host_contract_error_without_output_mutation() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 5]);
    let mut regs = request_default();

    assert!(matches!(
        call_6506(&mut dos, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    assert_eq!(output_bytes(&memory), [0xcc; 5]);

    dos.set_collating_table_address(CodePage::Cp437, TABLE_SEGMENT, TABLE_OFFSET)
        .unwrap();
    regs = request_default();
    assert!(matches!(
        call_6506(&mut dos, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    assert_eq!(output_bytes(&memory), [0xcc; 5]);
}

#[test]
fn table_registration_rejects_a_segment_crossing_pointer() {
    let mut dos = DosKernel::new(0x1000);
    assert!(matches!(
        dos.set_collating_table_address(CodePage::Cp437, TABLE_SEGMENT, 0xff00),
        Err(DosError::HostContractViolation(_))
    ));
}

#[test]
fn bad_guest_output_pointer_faults_without_partial_memory_or_register_mutation() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_us_cp437_table(&mut dos, &mut memory);
    let mut regs = request_default();
    regs.es = u16::MAX;
    regs.set_di(u16::MAX);
    regs.ecx = 0x1234_ffff;
    regs.eflags = 0x203;
    let before_ax = regs.ax();
    let before_ecx = regs.ecx;
    let before_eflags = regs.eflags;

    assert!(matches!(
        call_6506(&mut dos, &mut regs, &mut memory, &mut host),
        Err(DosError::Memory(_))
    ));
    assert_eq!(regs.ax(), before_ax);
    assert_eq!(regs.ecx, before_ecx);
    assert_eq!(regs.eflags, before_eflags);
}

#[test]
fn installed_guest_table_contains_the_exported_weights() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    install_us_cp437_table(&mut dos, &mut memory);
    let mut installed = [0; 258];
    memory.read(PhysAddr(real_address(TABLE_SEGMENT, TABLE_OFFSET).0), &mut installed).unwrap();
    assert_eq!(&installed, collating_table(CodePage::Cp437).unwrap());
}
