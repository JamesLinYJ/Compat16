//! DOS buffered stdin must preserve raw bytes, EOF and real native errors.
use super::Code;

const BUFFER: u16 = 0x2100;
const CAPACITY: u16 = 16;

fn read(code: &mut Code, expected: Result<u16, u16>) {
    code.immediate(0xbb, 0);
    code.immediate(0xb9, CAPACITY);
    code.immediate(0xba, BUFFER);
    code.emit(&[0xf9]);
    code.interrupt(0x3f00);
    code.fail_if(if expected.is_ok() { 0x82 } else { 0x83 });
    code.immediate(0x3d, expected.unwrap_or_else(|error| error));
    code.fail_if(0x85);
}

fn contents(code: &mut Code, expected: &[u8]) {
    for index in 0..CAPACITY {
        code.emit(&[0x80, 0x3e]);
        code.word(BUFFER + index);
        code.emit(&[expected.get(usize::from(index)).copied().unwrap_or(0xa5)]);
        code.fail_if(0x85);
    }
}

pub fn stdin_com(expected: Result<&[u8], u16>) -> Vec<u8> {
    let mut code = Code::default();
    match expected {
        Ok(bytes) => {
            assert!(bytes.len() < usize::from(CAPACITY));
            read(&mut code, Ok(bytes.len() as u16));
            contents(&mut code, bytes);
            // Repeated EOF leaves all previously written and untouched bytes.
            read(&mut code, Ok(0));
            contents(&mut code, bytes);
            read(&mut code, Ok(0));
            contents(&mut code, bytes);
        }
        Err(error) => {
            read(&mut code, Err(error));
            contents(&mut code, &[]);
            read(&mut code, Err(error));
            contents(&mut code, &[]);
        }
    }
    let mut bytes = code.finish().bytes;
    assert!(bytes.len() < usize::from(BUFFER - 0x100));
    bytes.resize(usize::from(BUFFER - 0x100 + CAPACITY), 0xa5);
    bytes
}
