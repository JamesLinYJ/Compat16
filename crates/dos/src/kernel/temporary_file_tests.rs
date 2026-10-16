use super::*;
use super::super::temporary_file::TEMPORARY_CREATE_ATTEMPTS;

const BUFFER: u32 = 0x10100;

fn fixture() -> (DosKernel, TestHost, TestMemory) {
    let host = TestHost {
        local_time: Some(crate::DosLocalDateTime {
            year: 1991, month: 6, day: 3, weekday: 1,
            hour: 12, minute: 34, second: 56, hundredth: 78,
        }),
        ..Default::default()
    };
    (DosKernel::new(0x1000), host, TestMemory::new())
}

fn registers(attributes: u16) -> Registers {
    Registers {
        eax: 0xaaaa_5a99, ebx: 0xbbbb_1234, ecx: 0xcccc_0000 | u32::from(attributes),
        edx: 0xdddd_0100, esi: 0xeeee_5678, edi: 0xffff_9abc,
        eflags: 0xad7, ds: 0x1000, es: 0x4321, ..Default::default()
    }
}

fn create(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory,
    directory: &[u8], attributes: u16,
) -> Registers {
    memory.put(BUFFER, directory);
    memory.put(BUFFER + directory.len() as u32, &[0; 14]);
    let mut regs = registers(attributes);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    regs
}

fn output(memory: &TestMemory) -> &[u8] {
    let buffer = &memory.0[BUFFER as usize..BUFFER as usize + 260];
    &buffer[..buffer.iter().position(|byte| *byte == 0).unwrap()]
}

#[test]
fn temporary_file_appends_eight_hex_bytes_in_place_and_preserves_registers() {
    let (mut dos, mut host, mut memory) = fixture();
    memory.put(BUFFER, b"C:\\SPOOL\\\0");
    memory.put(BUFFER + 10, &[0xa5; 13]);
    let mut regs = registers(0x27);
    let mut expected = regs.clone();
    expected.set_ax(3);
    expected.set_carry(false);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs, expected);
    assert_eq!(output(&memory), b"C:\\SPOOL\\0C22384E");
    assert_eq!(&memory.0[BUFFER as usize + 18..BUFFER as usize + 23], &[0xa5; 5]);
    assert_eq!(host.create_new_paths, [b"C:\\SPOOL\\0C22384E".to_vec()]);
    assert_eq!(host.attributes[output(&memory)], 0x27);
    assert!(dos.file_table.is_handle_inheritable(3));
    let Handle::File(file) = dos.handles[&3] else { panic!("expected file"); };
    assert_eq!(host.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 0);
    host.file_write(file, b"temporary contents").unwrap();
    host.file_seek(file, 0, DosSeekOrigin::Start).unwrap();
    let mut bytes = [0; 18];
    assert_eq!(host.file_read(file, &mut bytes).unwrap(), 18);
    assert_eq!(&bytes, b"temporary contents");
    dos.close_all_handles_checked(&mut host).unwrap();
    assert!(host.handles.is_empty());
    // Closing the process never implicitly deletes a DOS temporary file.
    assert!(host.paths.contains_key(output(&memory)));
}

#[test]
fn temporary_file_normalizes_only_the_missing_separator_in_caller_bytes() {
    for (input, prefix) in [
        (b".\\".as_slice(), b".\\".as_slice()),
        (b"C:\\SPOOL".as_slice(), b"C:\\SPOOL\\".as_slice()),
        (b"C:".as_slice(), b"C:\\".as_slice()),
        (b"".as_slice(), b"\\".as_slice()),
        (b"../".as_slice(), b"../".as_slice()),
    ] {
        let (mut dos, mut host, mut memory) = fixture();
        assert!(!create(&mut dos, &mut host, &mut memory, input, 0).carry());
        assert_eq!(output(&memory), [prefix, b"0C22384E"].concat());
        assert_eq!(host.create_new_paths[0], output(&memory));
    }
}

#[test]
fn temporary_file_keeps_dbcs_trail_backslash_and_adds_real_separator() {
    let (mut dos, mut host, mut memory) = fixture();
    host.code_page = Some(text_codec::CodePage::Cp936);
    assert!(!create(&mut dos, &mut host, &mut memory, b"C:\\\x81\\", 0).carry());
    assert_eq!(output(&memory), b"C:\\\x81\\\\0C22384E");
    let calls = host.create_new_calls;
    let regs = create(&mut dos, &mut host, &mut memory, b"C:\\\x81", 0);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 3);
    assert_eq!(host.create_new_calls, calls);
}

#[test]
fn temporary_file_retries_collisions_without_truncating_or_changing_old_attributes() {
    let (mut dos, mut host, mut memory) = fixture();
    let original = host.file_create_new(b".\\0C22384E", 0x02).unwrap();
    host.file_write(original, b"keep this").unwrap();
    host.directories.insert(b".\\0C22384F".to_vec(), ());
    host.create_new_calls = 0;
    host.create_new_paths.clear();
    let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0x20);
    assert!(!regs.carry());
    assert_eq!(regs.ax(), 3);
    assert_eq!(output(&memory), b".\\0C223850");
    assert_eq!(host.create_new_calls, 3);
    assert_eq!(host.file_for(original).unwrap().bytes, b"keep this");
    assert_eq!(host.file_seek(original, 0, DosSeekOrigin::Current).unwrap(), 9);
    assert_eq!(host.attributes[b".\\0C22384E".as_slice()], 2);
    assert!(host.directories.contains_key(b".\\0C22384F".as_slice()));
    // A second call under an unchanged clock must still propose a new name.
    assert!(!create(&mut dos, &mut host, &mut memory, b".\\", 0).carry());
    assert_eq!(output(&memory), b".\\0C223851");
}

#[test]
fn temporary_file_collision_exhaustion_is_bounded_and_releases_guest_slots() {
    let (mut dos, mut host, mut memory) = fixture();
    host.fail_create_new = Some(DosErrorCode::FileExists);
    let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 5);
    assert_eq!(host.create_new_calls, TEMPORARY_CREATE_ATTEMPTS);
    let unique = host.create_new_paths.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), TEMPORARY_CREATE_ATTEMPTS);
    assert!(host.paths.is_empty());
    assert!(!dos.handles.contains_key(&3));
    assert!(!dos.file_table.is_handle_inheritable(3));
    host.fail_create_new = None;
    let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    assert!(!regs.carry());
    assert_eq!(regs.ax(), 3);
}

#[test]
fn temporary_file_real_host_errors_do_not_retry_and_leave_the_attempted_name() {
    for code in [DosErrorCode::PathNotFound, DosErrorCode::AccessDenied,
        DosErrorCode::DiskFull, DosErrorCode::WriteProtected, DosErrorCode::SharingViolation] {
        let (mut dos, mut host, mut memory) = fixture();
        host.fail_create_new = Some(code);
        let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0);
        assert!(regs.carry());
        assert_eq!(regs.ax(), code as u16);
        assert_eq!(output(&memory), b".\\0C22384E");
        assert_eq!(host.create_new_calls, 1);
        assert!(host.paths.is_empty());
        assert!(!dos.file_table.is_handle_inheritable(3));
    }
}

#[test]
fn temporary_file_rejects_every_reserved_attribute_bit_before_buffer_or_host_mutation() {
    for attributes in [0x08, 0x10, 0x40, 0x80, 0x100, 0x8000, 0xffff] {
        let (mut dos, mut host, mut memory) = fixture();
        let regs = create(&mut dos, &mut host, &mut memory, b".\\", attributes);
        assert!(regs.carry());
        assert_eq!(regs.ax(), 5);
        assert_eq!(output(&memory), b".\\");
        assert_eq!(host.create_new_calls, 0);
    }
}

#[test]
fn temporary_file_handle_and_shared_sft_exhaustion_precede_all_creation() {
    let (mut dos, mut host, mut memory) = fixture();
    for handle in 3..20 {
        assert_eq!(create(&mut dos, &mut host, &mut memory, b".\\", 0).ax(), handle);
    }
    let calls = host.create_new_calls;
    let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 4);
    assert_eq!(host.create_new_calls, calls);
    assert_eq!(output(&memory), b".\\");

    let (mut dos, mut host, mut memory) = fixture();
    let mut other = DosKernel::new(0x2000);
    assert!(other.file_table.inherit_from(&dos.file_table));
    for handle in 3..255 { assert!(other.file_table.register_open(handle, 2).is_some()); }
    let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    assert!(regs.carry());
    assert_eq!(regs.ax(), 4);
    assert_eq!(host.create_new_calls, 0);
    assert_eq!(output(&memory), b".\\");
}

#[test]
fn temporary_file_invalid_unterminated_or_overlong_path_has_no_host_side_effects() {
    let (mut dos, mut host, mut memory) = fixture();
    let mut regs = registers(0);
    regs.ds = 0xffff;
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::Memory(_))));
    assert_eq!(host.create_new_calls, 0);
    for length in [248, 259, 260] {
        memory.put(BUFFER, &[b'X'; 261]);
        memory.put(BUFFER + length, &[0]);
        let mut regs = registers(0);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(regs.carry());
        assert_eq!(regs.ax(), 3);
        assert_eq!(host.create_new_calls, 0);
    }
}

struct CheckedMemory {
    inner: TestMemory,
    denied_from: u32,
    fail_write: bool,
}

impl GuestMemory for CheckedMemory {
    fn len(&self) -> u32 { self.inner.len() }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> { self.inner.read(address, bytes) }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        if address.0 + length as u32 > self.denied_from {
            return Err(MemoryError::ReadOnly { address: address.0, length });
        }
        self.inner.validate_write(address, length)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.fail_write { return Err(MemoryError::InvalidMapping); }
        self.validate_write(address, bytes.len())?;
        self.inner.write(address, bytes)
    }
}

#[test]
fn temporary_file_preflights_all_thirteen_name_bytes_even_when_actual_name_would_fit() {
    for available in [3, 11, 14, 15] {
        let (mut dos, mut host, mut inner) = fixture();
        inner.put(BUFFER, b".\\\0");
        let mut memory = CheckedMemory { inner, denied_from: BUFFER + available, fail_write: false };
        let mut regs = registers(0);
        let result = dos.interrupt(0x21, &mut regs, &mut memory, &mut host);
        if available == 15 {
            result.unwrap();
            assert!(!regs.carry());
            assert_eq!(host.create_new_calls, 1);
        } else {
            assert!(matches!(result, Err(DosError::Memory(MemoryError::ReadOnly { .. }))));
            assert_eq!(host.create_new_calls, 0);
            assert_eq!(output(&memory.inner), b".\\");
            assert!(!dos.file_table.is_handle_inheritable(3));
        }
    }
}

#[test]
fn temporary_file_write_failure_after_preflight_still_precedes_atomic_create() {
    let (mut dos, mut host, mut inner) = fixture();
    inner.put(BUFFER, b".\\\0");
    let mut memory = CheckedMemory { inner, denied_from: u32::MAX, fail_write: true };
    let mut regs = registers(0);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::Memory(_))));
    assert_eq!(host.create_new_calls, 0);
    assert!(host.handles.is_empty());
    assert!(!dos.file_table.is_handle_inheritable(3));
    memory.fail_write = false;
    regs.set_ax(0x5a00);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert_eq!(regs.ax(), 3);
}

#[test]
fn temporary_file_duplicate_and_inheritance_share_cursor_and_close_independently() {
    let (mut dos, mut host, mut memory) = fixture();
    let created = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    let mut regs = registers(0);
    regs.set_ax(0x4500);
    regs.set_bx(created.ax());
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let duplicate = regs.ax();
    let mut child = DosKernel::new(0x2000);
    child.inherit_handles_from(&dos, &mut host).unwrap();
    let Handle::File(original) = dos.handles[&created.ax()] else { panic!("file"); };
    let Handle::File(copy) = dos.handles[&duplicate] else { panic!("file"); };
    let Handle::File(inherited) = child.handles[&created.ax()] else { panic!("file"); };
    assert_ne!(original, copy);
    assert_ne!(original, inherited);
    host.file_write(inherited, b"child").unwrap();
    assert_eq!(host.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 5);
    child.close_all_handles_checked(&mut host).unwrap();
    host.file_write(copy, b" parent").unwrap();
    assert_eq!(host.file_for(original).unwrap().bytes, b"child parent");
    dos.close_all_handles_checked(&mut host).unwrap();
    assert!(host.handles.is_empty());
    assert!(host.paths.contains_key(output(&memory)));
}

#[test]
fn temporary_file_rejects_reused_host_token_without_closing_its_owner() {
    let (mut dos, mut host, mut memory) = fixture();
    let created = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    let Handle::File(file) = dos.handles[&created.ax()] else { panic!("file"); };
    host.create_new_token_override = Some(file);
    memory.put(BUFFER, b".\\\0");
    let mut regs = registers(0);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::HostContractViolation(_))));
    assert!(!dos.file_table.is_handle_inheritable(4));
    assert_eq!(host.handles.len(), 1);
    host.file_write(file, b"still open").unwrap();
}

#[test]
fn temporary_file_is_not_a_protected_scalar_service() {
    let (mut dos, mut host, mut memory) = fixture();
    let mut regs = registers(0);
    assert_eq!(dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host).unwrap(), None);
    assert_eq!(host.create_new_calls, 0);
}

#[test]
fn temporary_file_clock_failure_does_not_modify_caller_buffer_or_reserve_handle() {
    let (mut dos, mut host, mut memory) = fixture();
    host.local_time = None;
    let regs = create(&mut dos, &mut host, &mut memory, b".\\", 0);
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::InvalidFunction as u16);
    assert_eq!(output(&memory), b".\\");
    assert_eq!(host.create_new_calls, 0);
    assert!(!dos.file_table.is_handle_inheritable(3));
}

#[test]
fn temporary_file_corrupt_mcb_preflight_precedes_caller_writeback_and_creation() {
    let (mut dos, mut host, mut memory) = fixture();
    memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
    let mut jft = [0xff; 20];
    jft[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(0x10018, &jft);
    dos.initialize_system_tables(&mut memory).unwrap();
    memory.put(0xfff0, b"X");
    memory.put(BUFFER, b".\\\0");
    let mut regs = registers(0);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::InvalidMcbSignature { .. })));
    assert_eq!(host.create_new_calls, 0);
    assert!(host.paths.is_empty());
    assert_eq!(output(&memory), b".\\");
}
