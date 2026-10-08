use super::system::{
    CON_HEADER_OFFSET, LOL_OFFSET, SFT_OFFSET, SYSTEM_BYTES, SYSTEM_SEGMENT,
    CDS_OFFSET,
};
use super::tests::{TestHost, TestMemory};
use crate::{DosAction, DosError, DosFileAccess, DosHost, DosKernel};
use guest_core::{GuestMemory, Registers, real_address};

fn far_pointer(memory: &impl GuestMemory, offset: u16) -> (u16, u16) {
    let address = real_address(SYSTEM_SEGMENT, offset);
    (memory.read_u16(address).unwrap(), memory.read_u16(real_address(SYSTEM_SEGMENT, offset + 2)).unwrap())
}

fn install_default_jft(memory: &mut TestMemory, psp: u16) {
    let mut header = [0; 6];
    header[..2].copy_from_slice(&20u16.to_le_bytes());
    header[2..4].copy_from_slice(&0x18u16.to_le_bytes());
    header[4..6].copy_from_slice(&psp.to_le_bytes());
    memory.put(real_address(psp, 0x32).0, &header);

    let mut entries = [0xff; 20];
    entries[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(real_address(psp, 0x18).0, &entries);
}

#[test]
fn initialization_publishes_only_real_guest_pointers() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    dos.initialize_system_tables(&mut memory).unwrap();

    let first_mcb = memory.read_u16(real_address(SYSTEM_SEGMENT, LOL_OFFSET - 2)).unwrap();
    assert_eq!(first_mcb, 0x0fff);
    assert_eq!(far_pointer(&memory, LOL_OFFSET), (u16::MAX, u16::MAX)); // empty DPB chain
    assert_eq!(far_pointer(&memory, LOL_OFFSET + 4), (SFT_OFFSET, SYSTEM_SEGMENT));
    assert_eq!(far_pointer(&memory, LOL_OFFSET + 8), (0, 0)); // no clock device
    assert_eq!(far_pointer(&memory, LOL_OFFSET + 0x0c), (CON_HEADER_OFFSET, SYSTEM_SEGMENT));
    assert_eq!(far_pointer(&memory, LOL_OFFSET + 0x16), (0, 0)); // no published CDS provider
    assert_eq!(far_pointer(&memory, LOL_OFFSET + 0x1a), (0, 0)); // no FCB table

    let start = real_address(SYSTEM_SEGMENT, 0);
    let mut reserved = vec![0; SYSTEM_BYTES];
    memory.read(start, &mut reserved).unwrap();
    assert_eq!(reserved[usize::from(CDS_OFFSET)], 0);
}

#[test]
fn initialization_is_idempotent_after_device_installation() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    dos.initialize_system_tables(&mut memory).unwrap();

    let con_address = real_address(SYSTEM_SEGMENT, CON_HEADER_OFFSET);
    memory.put(con_address.0, b"port-owned-header");
    dos.initialize_system_tables(&mut memory).unwrap();

    let mut header = [0; 17];
    memory.read(con_address, &mut header).unwrap();
    assert_eq!(&header, b"port-owned-header");
}

#[test]
fn ah52_returns_the_list_pointer_and_preserves_other_registers() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    dos.initialize_system_tables(&mut memory).unwrap();

    let mut regs = Registers {
        eax: 0x1234_5678,
        ebx: 0xabcd_ef01,
        ecx: 0x2345_6789,
        edx: 0x3456_789a,
        esp: 0x4567_89ab,
        ebp: 0x5678_9abc,
        esi: 0x6789_abcd,
        edi: 0x789a_bcde,
        eip: 0x89ab_cdef,
        eflags: 0x0000_0ad7,
        cs: 0x1111,
        ds: 0x2222,
        es: 0x3333,
        ss: 0x4444,
        fs: 0x5555,
        gs: 0x6666,
    };
    let mut expected = regs.clone();
    expected.es = SYSTEM_SEGMENT;
    expected.set_bx(LOL_OFFSET);

    assert_eq!(dos.list_of_lists(&mut regs, &mut memory, &mut host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
    assert_eq!(far_pointer(&memory, LOL_OFFSET + 4), (SFT_OFFSET, SYSTEM_SEGMENT));
}

#[test]
fn corrupted_mcb_is_rejected_before_file_create_side_effect() {
    let psp = 0x1000;
    let mut dos = DosKernel::new(psp);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_default_jft(&mut memory, psp);
    dos.initialize_system_tables(&mut memory).unwrap();

    memory.put(real_address(psp, 0x0200).0, b"NEWFILE.TMP\0");
    // The initial MCB is at PSP-1. Catch guest corruption before file creation,
    // rather than during the post-call system-table refresh.
    memory.put(real_address(psp - 1, 0).0, b"X");

    let mut regs = Registers::default();
    regs.eax = 0x0000_3c00;
    regs.ds = psp;
    regs.set_dx(0x0200);
    let before = regs.clone();
    let result = dos.interrupt(0x21, &mut regs, &mut memory, &mut host);

    let Err(DosError::InvalidMcbSignature {
        segment,
        chain_head,
        psp_segment,
        previous,
        header,
    }) = result else {
        panic!("expected a typed MCB signature diagnostic");
    };
    assert_eq!(segment, psp - 1);
    assert_eq!(chain_head, psp - 1);
    assert_eq!(psp_segment, psp);
    assert_eq!(previous, None);
    assert_eq!(header[0], b'X');
    assert_eq!(header[1..5], [0, 0, 0, 0]);
    assert_eq!(regs, before);
    let lookup = host.file_open(b"NEWFILE.TMP", DosFileAccess::ReadOnly);
    assert_eq!(lookup.unwrap_err().code, crate::DosErrorCode::FileNotFound);
}
