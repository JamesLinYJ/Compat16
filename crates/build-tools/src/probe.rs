use std::fmt;

pub const PROBE_FILE_NAME: &str = "RSPROOF.TXT";
pub const PROBE_FILE_CONTENTS: &[u8] = b"dos-file-probe:v1\r\n";

const START_MESSAGE: &[u8] = b"DOS probe running...\r\n$";
const PASS_MESSAGE: &[u8] = b"PASS: RSPROOF.TXT created and closed.\r\n$";
const CREATE_ERROR: &[u8] = b"FAIL: could not create RSPROOF.TXT.\r\n$";
const WRITE_ERROR: &[u8] = b"FAIL: could not write RSPROOF.TXT.\r\n$";
const CLOSE_ERROR: &[u8] = b"FAIL: could not close RSPROOF.TXT.\r\n$";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFormat {
    Com,
    Mz,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeBuildError {
    message: String,
}

impl fmt::Display for ProbeBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProbeBuildError {}

pub fn probe_file_name() -> &'static str {
    PROBE_FILE_NAME
}

pub fn probe_file_contents() -> &'static [u8] {
    PROBE_FILE_CONTENTS
}

/// Build a minimal DOS COM or MZ acceptance program using only DOS INT 21h
/// services. The file operations are relative to the process current directory.
pub fn dos_probe_bytes(format: ProbeFormat) -> Result<Vec<u8>, ProbeBuildError> {
    match format {
        ProbeFormat::Com => {
            let assembled = assemble_probe(0x100, &[0x0e, 0x1f])?; // push cs / pop ds
            if assembled.bytes.len() > 0xff00 {
                return Err(build_error("COM probe exceeds the DOS COM image limit"));
            }
            Ok(assembled.bytes)
        }
        ProbeFormat::Mz => build_mz_probe(),
    }
}

struct AssembledProbe {
    bytes: Vec<u8>,
}

fn assemble_probe(origin: u16, segment_setup: &[u8]) -> Result<AssembledProbe, ProbeBuildError> {
    let mut code = CodeBuilder::default();
    code.emit(segment_setup);

    emit_print(&mut code, origin, "message_start")?;

    code.emit_address(origin, "file_name")?; // mov dx, file_name
    code.emit(&[0xb9, 0x00, 0x00]); // mov cx, 0 (normal file attributes)
    code.emit(&[0xb4, 0x3c, 0xcd, 0x21]); // create/truncate, INT 21h
    code.branch(0x72, "fail_create"); // jc fail_create
    code.emit(&[0x89, 0xc3]); // mov bx, ax (DOS file handle)

    code.emit_address(origin, "file_contents")?; // mov dx, file_contents
    code.emit(&[0xb9]); // mov cx, expected byte count
    code.emit_word(u16::try_from(PROBE_FILE_CONTENTS.len()).map_err(|_| {
        build_error("proof contents do not fit the DOS write byte count")
    })?);
    code.emit(&[0xb4, 0x40, 0xcd, 0x21]); // write BX/CX bytes from DS:DX
    code.branch(0x72, "fail_write"); // jc fail_write
    code.emit(&[0x3d]); // cmp ax, expected byte count
    code.emit_word(u16::try_from(PROBE_FILE_CONTENTS.len()).map_err(|_| {
        build_error("proof contents do not fit the DOS write byte count")
    })?);
    code.branch(0x75, "fail_write"); // jne fail_write

    code.emit(&[0xb4, 0x3e, 0xcd, 0x21]); // close BX
    code.branch(0x72, "fail_close"); // jc fail_close
    emit_print(&mut code, origin, "message_pass")?;
    emit_exit(&mut code, 0);

    code.mark("fail_create");
    emit_print(&mut code, origin, "message_create_error")?;
    emit_exit(&mut code, 1);

    code.mark("fail_write");
    code.emit(&[0xb4, 0x3e, 0xcd, 0x21]); // best-effort close after a write error
    emit_print(&mut code, origin, "message_write_error")?;
    emit_exit(&mut code, 2);

    code.mark("fail_close");
    emit_print(&mut code, origin, "message_close_error")?;
    emit_exit(&mut code, 3);

    code.mark("message_start");
    code.emit(START_MESSAGE);
    code.mark("file_name");
    code.emit(PROBE_FILE_NAME.as_bytes());
    code.emit(&[0]);
    code.mark("file_contents");
    code.emit(PROBE_FILE_CONTENTS);
    code.mark("message_pass");
    code.emit(PASS_MESSAGE);
    code.mark("message_create_error");
    code.emit(CREATE_ERROR);
    code.mark("message_write_error");
    code.emit(WRITE_ERROR);
    code.mark("message_close_error");
    code.emit(CLOSE_ERROR);

    Ok(AssembledProbe {
        bytes: code.finish(origin)?,
    })
}

fn emit_print(code: &mut CodeBuilder, origin: u16, message: &'static str) -> Result<(), ProbeBuildError> {
    code.emit_address(origin, message)?; // mov dx, message
    code.emit(&[0xb4, 0x09, 0xcd, 0x21]); // DOS print `$`-terminated DS:DX
    Ok(())
}

fn emit_exit(code: &mut CodeBuilder, status: u8) {
    code.emit(&[0xb8, status, 0x4c, 0xcd, 0x21]); // mov ax, 4c00h|status; exit
}

fn build_mz_probe() -> Result<Vec<u8>, ProbeBuildError> {
    // The immediate segment at bytes 1..3 is the single MZ relocation. The
    // loader adds the module load segment, giving DS the code/data segment.
    let assembled = assemble_probe(0, &[0xb8, 0x00, 0x00, 0x8e, 0xd8])?;
    let header_size = 32usize;
    let total_size = header_size
        .checked_add(assembled.bytes.len())
        .ok_or_else(|| build_error("MZ image length overflow"))?;
    let pages = total_size
        .checked_add(511)
        .ok_or_else(|| build_error("MZ page count overflow"))?
        / 512;
    let last_page_bytes = total_size % 512;
    let stack_pointer = assembled
        .bytes
        .len()
        .checked_add(1024)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| build_error("MZ image leaves no representable stack location"))?;

    let mut output = vec![0u8; header_size];
    output[0..2].copy_from_slice(b"MZ");
    put_header_word(&mut output, 2, last_page_bytes as u16);
    put_header_word(
        &mut output,
        4,
        u16::try_from(pages).map_err(|_| build_error("MZ image needs too many DOS pages"))?,
    );
    put_header_word(&mut output, 6, 1); // relocation count
    put_header_word(&mut output, 8, 2); // 32-byte header
    put_header_word(&mut output, 10, 0x40); // reserve 1 KiB for the guest stack
    put_header_word(&mut output, 12, 0xffff); // let DOS allocate available memory
    put_header_word(&mut output, 14, 0); // SS relative to the image base
    put_header_word(&mut output, 16, stack_pointer);
    put_header_word(&mut output, 18, 0); // checksum unused
    put_header_word(&mut output, 20, 0); // IP
    put_header_word(&mut output, 22, 0); // CS relative to the image base
    put_header_word(&mut output, 24, 0x1c); // relocation table offset
    put_header_word(&mut output, 26, 0); // overlay number
    put_header_word(&mut output, 28, 1); // relocation target offset: mov ax, imm16
    put_header_word(&mut output, 30, 0); // relocation target segment
    output.extend_from_slice(&assembled.bytes);
    Ok(output)
}

fn put_header_word(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[derive(Default)]
pub(super) struct CodeBuilder {
    bytes: Vec<u8>,
    labels: Vec<(&'static str, usize)>,
    relative_branches: Vec<(usize, &'static str)>,
    near_relative_branches: Vec<(usize, &'static str)>,
    address_fixups: Vec<(usize, u16, &'static str)>,
}

impl CodeBuilder {
    pub(super) fn emit(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(super) fn emit_word(&mut self, word: u16) {
        self.bytes.extend_from_slice(&word.to_le_bytes());
    }

    pub(super) fn emit_address(&mut self, origin: u16, label: &'static str) -> Result<(), ProbeBuildError> {
        self.bytes.push(0xba); // mov dx, imm16
        self.emit_offset(origin, label)
    }

    pub(super) fn emit_offset(
        &mut self,
        origin: u16,
        label: &'static str,
    ) -> Result<(), ProbeBuildError> {
        let fixup = self.bytes.len();
        self.emit_word(0);
        self.address_fixups.push((fixup, origin, label));
        Ok(())
    }

    pub(super) fn branch(&mut self, opcode: u8, label: &'static str) {
        self.bytes.push(opcode);
        let fixup = self.bytes.len();
        self.bytes.push(0);
        self.relative_branches.push((fixup, label));
    }

    /// Emit an 8086 near jump, used after a short conditional branch when a
    /// distant common failure path would exceed the signed-byte range.
    pub(super) fn jump_near(&mut self, label: &'static str) {
        self.bytes.push(0xe9);
        let fixup = self.bytes.len();
        self.emit_word(0);
        self.near_relative_branches.push((fixup, label));
    }

    pub(super) fn mark(&mut self, label: &'static str) {
        self.labels.push((label, self.bytes.len()));
    }

    pub(super) fn finish(mut self, _origin: u16) -> Result<Vec<u8>, ProbeBuildError> {
        for (fixup, label) in self.relative_branches {
            let target = self
                .labels
                .iter()
                .find_map(|(candidate, offset)| (*candidate == label).then_some(*offset))
                .ok_or_else(|| build_error(format!("missing internal probe label `{label}`")))?;
            let displacement = target as isize - (fixup + 1) as isize;
            let displacement = i8::try_from(displacement)
                .map_err(|_| build_error(format!("probe branch to `{label}` is out of range")))?;
            self.bytes[fixup] = displacement.to_le_bytes()[0];
        }

        for (fixup, label) in self.near_relative_branches {
            let target = self
                .labels
                .iter()
                .find_map(|(candidate, offset)| (*candidate == label).then_some(*offset))
                .ok_or_else(|| build_error(format!("missing internal probe label `{label}`")))?;
            let displacement = target as isize - (fixup + 2) as isize;
            let displacement = i16::try_from(displacement).map_err(|_| {
                build_error(format!("probe near jump to `{label}` is out of range"))
            })?;
            self.bytes[fixup..fixup + 2].copy_from_slice(&displacement.to_le_bytes());
        }

        for (fixup, origin, label) in self.address_fixups {
            let target = self
                .labels
                .iter()
                .find_map(|(candidate, offset)| (*candidate == label).then_some(*offset))
                .ok_or_else(|| build_error(format!("missing internal probe label `{label}`")))?;
            let target = origin
                .checked_add(u16::try_from(target).map_err(|_| {
                    build_error(format!("probe label `{label}` is outside a 16-bit segment"))
                })?)
                .ok_or_else(|| build_error(format!("probe label `{label}` address overflow")))?;
            self.bytes[fixup..fixup + 2].copy_from_slice(&target.to_le_bytes());
        }
        Ok(self.bytes)
    }
}

pub(super) fn build_error(message: impl Into<String>) -> ProbeBuildError {
    ProbeBuildError {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
