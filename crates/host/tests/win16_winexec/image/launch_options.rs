use super::Code;

pub fn command_tail_com() -> Vec<u8> {
    let mut code = Code::default();
    let path_operand = code.bytes.len() + 1;
    code.immediate(0xba, 0);
    code.immediate(0xb9, 0);
    code.interrupt(0x3c00); // Create relative to the selected guest directory.
    code.fail_if(0x82);
    code.emit(&[0x89, 0xc3]); // BX = owned DOS file handle.
    code.immediate(0xba, 0x80);
    code.immediate(0xb9, 32);
    code.interrupt(0x4000); // Write the actual PSP command bytes.
    code.fail_if(0x82);
    code.interrupt(0x3e00);
    let mut code = code.finish();
    let path = u16::try_from(0x100 + code.bytes.len()).unwrap();
    code.bytes[path_operand..path_operand + 2].copy_from_slice(&path.to_le_bytes());
    code.bytes.extend_from_slice(b"CHILD.OUT\0");
    code.bytes
}
