use super::tests::{TestHost, TestMemory};
use super::{DosKernel, upper_case_table};
use crate::{DosAction, DosError, DosErrorCode};
use guest_core::{GuestMemory, Registers, real_address};
use text_codec::CodePage;

const TABLE_SEGMENT: u16 = 0x1000;
const UPPERCASE_OFFSET: u16 = 0x0100;
const CASE_MAP_OFFSET: u16 = 0x0040;
const OUTPUT_SEGMENT: u16 = 0x0800;
const OUTPUT_OFFSET: u16 = 0x0040;

fn install_case_map(dos: &mut DosKernel, memory: &mut TestMemory) {
    // The DOS service only stores and returns this guest far pointer. Runtime
    // installs the real executable callback; this byte is sufficient to model
    // its readable entry point in DOS-only service tests.
    memory.put(real_address(TABLE_SEGMENT, CASE_MAP_OFFSET).0, &[0x90]);
    dos.set_case_map_address(CodePage::Cp437, TABLE_SEGMENT, CASE_MAP_OFFSET)
        .expect("valid guest case-map pointer");
}

fn install_uppercase_table(dos: &mut DosKernel, memory: &mut TestMemory) {
    let table = upper_case_table(CodePage::Cp437).expect("US CP437 uppercase table exists");
    memory.put(real_address(TABLE_SEGMENT, UPPERCASE_OFFSET).0, table);
    dos.set_uppercase_table_address(CodePage::Cp437, TABLE_SEGMENT, UPPERCASE_OFFSET)
        .expect("valid guest uppercase pointer");
}

fn call_21(dos: &mut DosKernel, regs: &mut Registers, memory: &mut TestMemory, host: &mut TestHost)
    -> Result<DosAction, DosError>
{
    dos.interrupt(0x21, regs, memory, host)
}

fn read(memory: &TestMemory, segment: u16, offset: u16, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    memory.read(real_address(segment, offset), &mut bytes).expect("test memory range is valid");
    bytes
}

fn country_request(function: u8, length: u16) -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(0x6500 | u16::from(function));
    regs.set_bx(u16::MAX);
    regs.set_cx(length);
    regs.set_dx(u16::MAX);
    regs.es = OUTPUT_SEGMENT;
    regs.set_di(OUTPUT_OFFSET);
    regs.eflags = 0x0202;
    regs
}

#[test]
fn microsoft_us437_uppercase_table_has_the_documented_length_and_source_values() {
    let table = upper_case_table(CodePage::Cp437).expect("US CP437 uppercase table exists");
    assert_eq!(&table[..2], &[0x80, 0x00]);
    assert_eq!(
        &table[2..50],
        &[
            128, 154, 69, 65, 142, 65, 143, 128,
            69, 69, 69, 73, 73, 73, 142, 143,
            144, 146, 146, 79, 153, 79, 85, 85,
            89, 153, 154, 155, 156, 157, 158, 159,
            65, 73, 79, 85, 165, 165, 166, 167,
            168, 169, 170, 171, 172, 173, 174, 175,
        ]
    );
    for byte in 0xb0_u8..=0xff {
        assert_eq!(table[usize::from(byte - 0x80) + 2], byte);
    }
    assert_eq!(upper_case_table(CodePage::Cp936).unwrap()[2..], (128..=255).collect::<Vec<u8>>());
}

#[test]
fn ah6501_returns_full_us437_record_and_truncates_the_declared_size() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_case_map(&mut dos, &mut memory);
    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 41]);

    let mut regs = country_request(0x01, u16::MAX);
    call_21(&mut dos, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.ax(), 437);
    assert_eq!(regs.cx(), 41);
    assert!(!regs.carry());
    assert_eq!(regs.eflags, 0x0202);

    let mut expected = [0; 41];
    expected[0] = 1;
    expected[1..3].copy_from_slice(&38u16.to_le_bytes());
    expected[3..5].copy_from_slice(&1u16.to_le_bytes());
    expected[5..7].copy_from_slice(&437u16.to_le_bytes());
    expected[9] = b'$';
    expected[14] = b',';
    expected[16] = b'.';
    expected[18] = b'-';
    expected[20] = b':';
    expected[23] = 2;
    expected[25..29].copy_from_slice(&[
        CASE_MAP_OFFSET as u8,
        (CASE_MAP_OFFSET >> 8) as u8,
        TABLE_SEGMENT as u8,
        (TABLE_SEGMENT >> 8) as u8,
    ]);
    expected[29] = b',';
    assert_eq!(read(&memory, OUTPUT_SEGMENT, OUTPUT_OFFSET, 41).as_slice(), &expected);

    let mut short = country_request(0x01, 5);
    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 41]);
    call_21(&mut dos, &mut short, &mut memory, &mut host).unwrap();
    assert_eq!(short.ax(), 437);
    assert_eq!(short.cx(), 5);
    assert!(!short.carry());
    assert_eq!(
        read(&memory, OUTPUT_SEGMENT, OUTPUT_OFFSET, 5).as_slice(),
        &[0x01, 0x02, 0x00, 0x01, 0x00],
    );

    memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 41]);
    let mut too_short = country_request(0x01, 4);
    let before_flags = too_short.eflags;
    call_21(&mut dos, &mut too_short, &mut memory, &mut host).unwrap();
    assert_eq!(too_short.ax(), DosErrorCode::InvalidFunction as u16);
    assert_eq!(too_short.cx(), 4);
    assert!(too_short.carry());
    assert_eq!(too_short.eflags & !1, before_flags & !1);
    assert_eq!(read(&memory, OUTPUT_SEGMENT, OUTPUT_OFFSET, 41).as_slice(), &[0xcc; 41]);

    let mut unsupported_page = country_request(0x01, 41);
    unsupported_page.set_bx(936);
    call_21(&mut dos, &mut unsupported_page, &mut memory, &mut host).unwrap();
    assert_eq!(unsupported_page.ax(), DosErrorCode::FileNotFound as u16);
    assert!(unsupported_page.carry());
    assert_eq!(read(&memory, OUTPUT_SEGMENT, OUTPUT_OFFSET, 41).as_slice(), &[0xcc; 41]);
}

#[test]
fn ah6502_and_6504_return_the_installed_uppercase_table_pointer() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_uppercase_table(&mut dos, &mut memory);

    for function in [0x02, 0x04] {
        memory.put(real_address(OUTPUT_SEGMENT, OUTPUT_OFFSET).0, &[0xcc; 5]);
        let mut regs = country_request(function, 32);
        call_21(&mut dos, &mut regs, &mut memory, &mut host).unwrap();
        assert_eq!(regs.ax(), 437);
        assert_eq!(regs.cx(), 5);
        assert!(!regs.carry());
        assert_eq!(
            read(&memory, OUTPUT_SEGMENT, OUTPUT_OFFSET, 5).as_slice(),
            &[function, 0x00, 0x01, 0x00, 0x10],
        );
    }
}

#[test]
fn ah38_get_country_returns_microsoft_old_country_size_and_leaves_tail_untouched() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_case_map(&mut dos, &mut memory);
    const BUFFER_SEGMENT: u16 = 0x0900;
    const BUFFER_OFFSET: u16 = 0x0020;
    memory.put(real_address(BUFFER_SEGMENT, BUFFER_OFFSET).0, &[0xcc; 32]);

    let mut regs = Registers::default();
    regs.set_ax(0x3800); // Current country.
    regs.set_cx(0x1234);
    regs.ds = BUFFER_SEGMENT;
    regs.set_dx(BUFFER_OFFSET);
    regs.eflags = 0x0202;
    call_21(&mut dos, &mut regs, &mut memory, &mut host).unwrap();

    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bx(), 1);
    assert_eq!(regs.cx(), 0x1234);
    assert!(!regs.carry());
    assert_eq!(regs.eflags, 0x0202);
    assert_eq!(
        read(&memory, BUFFER_SEGMENT, BUFFER_OFFSET, 32).as_slice(),
        &[
            0x00, 0x00, b'$', 0, 0, 0, 0, b',', 0, b'.', 0, b'-', 0, b':', 0,
            0, 2, 0, CASE_MAP_OFFSET as u8, (CASE_MAP_OFFSET >> 8) as u8,
            TABLE_SEGMENT as u8, (TABLE_SEGMENT >> 8) as u8, b',', 0,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        ],
    );
}

#[test]
fn ah38_explicit_get_works_and_set_or_unknown_country_returns_ax2_without_writes() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_case_map(&mut dos, &mut memory);
    const BUFFER_SEGMENT: u16 = 0x0900;
    const BUFFER_OFFSET: u16 = 0x0020;

    let mut explicit = Registers::default();
    explicit.set_ax(0x3801); // Country ID 1 (US).
    explicit.ds = BUFFER_SEGMENT;
    explicit.set_dx(BUFFER_OFFSET);
    call_21(&mut dos, &mut explicit, &mut memory, &mut host).unwrap();
    assert_eq!((explicit.ax(), explicit.bx()), (1, 1));
    assert!(!explicit.carry());

    memory.put(real_address(BUFFER_SEGMENT, BUFFER_OFFSET).0, &[0xcc; 32]);
    let mut set = Registers::default();
    set.set_ax(0x3801);
    set.ds = BUFFER_SEGMENT;
    set.set_dx(u16::MAX);
    call_21(&mut dos, &mut set, &mut memory, &mut host).unwrap();
    assert_eq!(set.ax(), DosErrorCode::FileNotFound as u16);
    assert!(set.carry());
    assert_eq!(read(&memory, BUFFER_SEGMENT, BUFFER_OFFSET, 32).as_slice(), &[0xcc; 32]);

    let mut unknown = Registers::default();
    unknown.set_ax(0x3802);
    unknown.ds = BUFFER_SEGMENT;
    unknown.set_dx(BUFFER_OFFSET);
    call_21(&mut dos, &mut unknown, &mut memory, &mut host).unwrap();
    assert_eq!(unknown.ax(), DosErrorCode::FileNotFound as u16);
    assert!(unknown.carry());
    assert_eq!(read(&memory, BUFFER_SEGMENT, BUFFER_OFFSET, 32).as_slice(), &[0xcc; 32]);
}

#[test]
fn country_queries_report_guest_memory_faults_without_register_or_memory_mutation() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_case_map(&mut dos, &mut memory);
    install_uppercase_table(&mut dos, &mut memory);

    let mut extended = country_request(0x01, 41);
    extended.es = u16::MAX;
    extended.set_di(u16::MAX);
    let before_ax = extended.ax();
    let before_cx = extended.cx();
    let before_flags = extended.eflags;
    assert!(matches!(
        call_21(&mut dos, &mut extended, &mut memory, &mut host),
        Err(DosError::Memory(_))
    ));
    assert_eq!((extended.ax(), extended.cx(), extended.eflags), (before_ax, before_cx, before_flags));

    let mut legacy = Registers::default();
    legacy.set_ax(0x3800);
    legacy.ds = u16::MAX;
    legacy.set_dx(0xffe0);
    legacy.set_cx(0x1234);
    let before_ax = legacy.ax();
    let before_bx = legacy.bx();
    let before_dx = legacy.dx();
    let before_flags = legacy.eflags;
    assert!(matches!(
        call_21(&mut dos, &mut legacy, &mut memory, &mut host),
        Err(DosError::Memory(_))
    ));
    assert_eq!(legacy.ax(), before_ax);
    assert_eq!(legacy.bx(), before_bx);
    assert_eq!(legacy.dx(), before_dx);
    assert_eq!(legacy.eflags, before_flags);
}

#[test]
fn guest_output_pointers_wrap_the_16_bit_offset_after_preflighting_both_chunks() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_case_map(&mut dos, &mut memory);
    let mut regs = country_request(0x01, 41);
    regs.es = 0x1000;
    regs.set_di(0xfff0);

    call_21(&mut dos, &mut regs, &mut memory, &mut host).unwrap();
    let first = read(&memory, 0x1000, 0xfff0, 16);
    let second = read(&memory, 0x1000, 0, 25);
    assert_eq!(first[0], 1);
    assert_eq!(u16::from_le_bytes([first[1], first[2]]), 38);
    // The wrapped part starts at response byte 16 (decimal separator),
    // not at the beginning of the country record.
    assert_eq!(&second[..2], &[b'.', 0]);
    assert_eq!(&second[9..13], &[0x40, 0x00, 0x00, 0x10]);
    assert_eq!(&second[15..], &[0; 10]);
    assert_eq!(regs.cx(), 41);
}
