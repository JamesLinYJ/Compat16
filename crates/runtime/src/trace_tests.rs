use super::*;

#[test]
fn history_is_bounded_and_reads_a20_gated_guest_bytes_without_modifying_them() {
    let mut memory = Memory::new().unwrap();
    memory.set_a20_enabled(false).unwrap();
    memory.write_u8(real_address(0, 0x47), 0x90).unwrap();
    let registers = Registers { cs: 0xffff, eip: 0x57, ..Default::default() };
    let mut trace = InstructionTrace::new().unwrap();
    for count in 0..100 { trace.record(count, &registers, &mut memory); }
    assert_eq!(trace.entries.len(), CAPACITY);
    assert_eq!(trace.entries.front().unwrap().instruction_count, 36);
    assert_eq!(trace.entries.back().unwrap().bytes[0], 0x90);
    assert_eq!(memory.read_u8(real_address(0, 0x47)).unwrap(), 0x90);
    assert!(trace.format().contains("A20=0 bytes=90"));
}

#[test]
fn instruction_history_is_disabled_until_explicitly_enabled() {
    let mut runtime = crate::Runtime::load(&[0xcd, 0x20], &[], b"C:\\TRACE.COM").unwrap();
    assert!(runtime.format_instruction_trace().is_none());
    runtime.enable_instruction_trace().unwrap();
    assert_eq!(runtime.format_instruction_trace().as_deref(), Some(""));
}
