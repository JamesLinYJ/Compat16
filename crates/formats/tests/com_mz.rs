use formats::{
    load_com, load_executable, load_mz, parse_mz, parse_ne, FormatError, ImageKind,
};
use guest_core::{GuestMemory, MemoryError, PhysAddr};

#[derive(Clone, Debug)]
struct TestMemory(Vec<u8>);

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 {
        u32::try_from(self.0.len()).unwrap_or(u32::MAX)
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let source = self.0.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let target = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        target.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn com_load_copies_bytes_and_returns_dos_registers() {
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    let loaded = load_com(&[0x90, 0xcd, 0x20], 0x1000, &mut memory).expect("COM load");
    assert_eq!(loaded.kind, ImageKind::Com);
    assert_eq!(loaded.load_address, PhysAddr(0x10100));
    assert_eq!(&memory.0[0x10100..0x10103], &[0x90, 0xcd, 0x20]);
    assert_eq!((loaded.registers.cs, loaded.registers.ip()), (0x1000, 0x0100));
    assert_eq!((loaded.registers.ds, loaded.registers.es, loaded.registers.ss), (0x1000, 0x1000, 0x1000));
    assert_eq!(loaded.registers.sp(), 0xfffe);
}

#[test]
fn mz_load_applies_real_relocation_bytes() {
    let bytes = minimal_mz_with_relocation();
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    let loaded = load_mz(&bytes, 0x1000, &mut memory).expect("MZ load");
    assert_eq!(loaded.kind, ImageKind::Mz);
    assert_eq!((loaded.registers.cs, loaded.registers.ip()), (0x1010, 0x0000));
    assert_eq!(&memory.0[0x10100 + 4..0x10100 + 6], &0x2244_u16.to_le_bytes());
}

#[test]
fn mz_initial_cs_and_ss_wrap_as_16_bit_segments() {
    let mut bytes = minimal_mz_with_relocation();
    bytes[0x0e..0x10].copy_from_slice(&0xfff0_u16.to_le_bytes());
    bytes[0x10..0x12].copy_from_slice(&0x0110_u16.to_le_bytes());
    bytes[0x14..0x16].copy_from_slice(&0x0100_u16.to_le_bytes());
    bytes[0x16..0x18].copy_from_slice(&0xfff0_u16.to_le_bytes());
    let mut memory = TestMemory(vec![0; 0x10_0000]);

    let loaded = load_mz(&bytes, 0x1000, &mut memory).expect("MZ load with wrapped segments");

    assert_eq!((loaded.registers.cs, loaded.registers.ip()), (0x1000, 0x0100));
    assert_eq!((loaded.registers.ss, loaded.registers.sp()), (0x1000, 0x0110));
    let expected_image = loaded_bytes_after_relocation();
    assert_eq!(memory.0.get(0x10100..0x10110), Some(expected_image.as_slice()));
}

#[test]
fn mz_rejects_a_relocation_that_would_cross_the_image() {
    let mut bytes = minimal_mz_with_relocation();
    bytes[0x1c..0x1e].copy_from_slice(&15_u16.to_le_bytes());
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    assert!(matches!(load_mz(&bytes, 0x1000, &mut memory), Err(FormatError::InvalidMzHeader("relocation target is outside the loaded image"))));
}

#[test]
fn mz_entry_and_stack_must_fit_the_loaded_image_and_allocation() {
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    let original = memory.0.clone();
    let mut bad_entry = minimal_mz_with_relocation();
    bad_entry[0x14..0x16].copy_from_slice(&16_u16.to_le_bytes());
    assert!(matches!(load_mz(&bad_entry, 0x1000, &mut memory), Err(FormatError::InvalidMzHeader("entry point is outside the loaded image"))));
    assert_eq!(memory.0, original);

    let mut bad_wrapped_entry = minimal_mz_with_relocation();
    bad_wrapped_entry[0x14..0x16].copy_from_slice(&0x00ff_u16.to_le_bytes());
    bad_wrapped_entry[0x16..0x18].copy_from_slice(&0xfff0_u16.to_le_bytes());
    assert!(matches!(load_mz(&bad_wrapped_entry, 0x1000, &mut memory), Err(FormatError::InvalidMzHeader("entry point is outside the loaded image"))));
    assert_eq!(memory.0, original);

    let mut bad_stack = minimal_mz_with_relocation();
    bad_stack[0x0c..0x0e].copy_from_slice(&0_u16.to_le_bytes());
    bad_stack[0x0e..0x10].copy_from_slice(&2_u16.to_le_bytes());
    bad_stack[0x10..0x12].copy_from_slice(&0_u16.to_le_bytes());
    assert!(matches!(load_mz(&bad_stack, 0x1000, &mut memory), Err(FormatError::InvalidMzHeader("initial stack is outside the allocated image"))));
    assert_eq!(memory.0, original);

    let mut bad_wrapped_stack = minimal_mz_with_relocation();
    bad_wrapped_stack[0x0e..0x10].copy_from_slice(&0xfff0_u16.to_le_bytes());
    bad_wrapped_stack[0x10..0x12].copy_from_slice(&0x000f_u16.to_le_bytes());
    assert!(matches!(load_mz(&bad_wrapped_stack, 0x1000, &mut memory), Err(FormatError::InvalidMzHeader("initial stack is outside the allocated image"))));
    assert_eq!(memory.0, original);
}

#[test]
fn truncated_mz_and_ne_inputs_fail_explicitly() {
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    assert!(matches!(load_mz(b"MZ", 0x1000, &mut memory), Err(FormatError::Truncated { .. })));
    assert!(matches!(parse_ne(b"MZ"), Err(FormatError::Truncated { .. })));
}

#[test]
fn old_mz_header_does_not_treat_code_at_3c_as_an_extended_header_pointer() {
    let mut bytes = vec![0_u8; 0x40];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[2..4].copy_from_slice(&0x40_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0x3c..0x3e].copy_from_slice(&0x9090_u16.to_le_bytes());
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    let loaded = load_executable(&bytes, 0x1000, &mut memory).expect("legacy short-header MZ");
    assert_eq!(loaded.kind, ImageKind::Mz);
}

#[test]
fn oversized_com_does_not_write_memory() {
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    let before = memory.0.clone();
    let image = vec![0xaa; 0xff01];
    assert!(matches!(load_com(&image, 0x1000, &mut memory), Err(FormatError::InvalidCom("image exceeds its PSP segment"))));
    assert_eq!(memory.0, before);
}

#[test]
fn mz_parser_keeps_overlay_out_of_the_loaded_image() {
    let mut bytes = vec![0_u8; 80];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[2..4].copy_from_slice(&80_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());
    bytes[64] = 0xc3;
    bytes.extend_from_slice(b"overlay");
    let parsed = parse_mz(&bytes).expect("valid MZ");
    assert_eq!(parsed.image.first(), Some(&0xc3));
    assert_eq!(parsed.image.len(), 16);
    assert_eq!(parsed.declared_file_size, 80);
}

#[test]
fn malformed_relocation_table_is_rejected_before_loading() {
    let mut bytes = vec![0_u8; 80];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[2..4].copy_from_slice(&80_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());
    bytes[0x18..0x1a].copy_from_slice(&62_u16.to_le_bytes());
    assert!(matches!(parse_mz(&bytes), Err(FormatError::InvalidMzHeader("relocation table is outside the MZ header"))));
}

#[test]
fn four_byte_last_page_marker_uses_the_declared_partial_page_size() {
    let mut bytes = vec![0_u8; 516];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[2..4].copy_from_slice(&4_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());
    bytes[512..516].copy_from_slice(&[1, 2, 3, 4]);
    let parsed = parse_mz(&bytes).expect("legacy short last page");
    assert_eq!(parsed.declared_file_size, 516);
    assert_eq!(parsed.image.len(), 452);
    assert_eq!(&parsed.image[448..452], &[1, 2, 3, 4]);
    bytes.pop();
    assert!(matches!(parse_mz(&bytes), Err(FormatError::Truncated { .. })));
}

fn minimal_mz_with_relocation() -> Vec<u8> {
    let mut bytes = vec![0_u8; 80];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[2..4].copy_from_slice(&80_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());
    bytes[0x0c..0x0e].copy_from_slice(&0xffff_u16.to_le_bytes());
    bytes[0x10..0x12].copy_from_slice(&0x0020_u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0x14..0x16].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0x16..0x18].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0x18..0x1a].copy_from_slice(&0x1c_u16.to_le_bytes());
    bytes[0x1c..0x1e].copy_from_slice(&4_u16.to_le_bytes());
    bytes[0x1e..0x20].copy_from_slice(&0_u16.to_le_bytes());
    bytes[64 + 4..64 + 6].copy_from_slice(&0x1234_u16.to_le_bytes());
    bytes
}

fn loaded_bytes_after_relocation() -> Vec<u8> {
    let mut bytes = vec![0_u8; 16];
    bytes[4..6].copy_from_slice(&0x2244_u16.to_le_bytes());
    bytes
}
