//! Byte-oriented DOS filename scanning, separate from host path parsing.
use crate::{DosCallAddressSpace, DosError, DosFarPointer, DosSpanPolicy};
use text_codec::CodePage;

pub(super) struct Parsed {
    pub drive: Option<u8>,
    pub name: Option<[u8; 8]>,
    pub extension: Option<[u8; 3]>,
    pub consumed: u16,
    pub status: u8,
}

struct Cursor<'a, M> {
    memory: &'a mut M,
    pointer: DosFarPointer,
    position: usize,
    code_page: CodePage,
}

pub(super) fn parse(
    memory: &mut impl DosCallAddressSpace,
    pointer: DosFarPointer,
    flags: u8,
    code_page: CodePage,
    drives: u8,
) -> Result<Parsed, DosError> {
    if drives > 26 {
        return Err(DosError::HostContractViolation(
            "invalid DOS logical drive count",
        ));
    }
    let mut cursor = Cursor {
        memory,
        pointer,
        position: 0,
        code_page,
    };
    // DOS always removes blanks/tabs, then optionally one other separator.
    // A second separator stays at SI; this is not an ASCIIZ path splitter.
    cursor.skip_blanks()?;
    if flags & 1 != 0
        && matches!(
            cursor.peek(0)?,
            b':' | b';' | b',' | b'=' | b'+' | b'<' | b'>' | b'|'
        )
    {
        cursor.position += 1;
        cursor.skip_blanks()?;
    }
    let first = cursor.peek(0)?;
    let mut invalid_drive = false;
    let drive = if !terminates(first) && !cursor.is_lead(first) && cursor.peek(1)? == b':' {
        let value = first.to_ascii_uppercase().wrapping_sub(b'@');
        invalid_drive = value == 0 || value > drives;
        cursor.position += 2;
        Some(value)
    } else {
        None
    };
    let mut wildcard = false;
    let name = cursor.field::<8>(&mut wildcard)?;
    let extension = if cursor.peek(0)? == b'.' {
        cursor.position += 1;
        Some(cursor.field::<3>(&mut wildcard)?.unwrap_or([b' '; 3]))
    } else {
        None
    };
    Ok(Parsed {
        drive,
        name,
        extension,
        consumed: cursor.position as u16,
        status: if invalid_drive {
            0xff
        } else {
            u8::from(wildcard)
        },
    })
}

impl<M: DosCallAddressSpace> Cursor<'_, M> {
    fn peek(&mut self, extra: usize) -> Result<u8, DosError> {
        let offset = self
            .position
            .checked_add(extra)
            .filter(|offset| *offset < 0x1_0000)
            .ok_or(DosError::MalformedGuestInput(
                "DOS filename scan has no terminator within its segment",
            ))?;
        let mut byte = [0];
        self.memory.read_caller_range(
            self.pointer,
            offset,
            &mut byte,
            DosSpanPolicy::OffsetWrap,
        )?;
        Ok(byte[0])
    }

    fn is_lead(&self, byte: u8) -> bool {
        self.code_page
            .dbcs_lead_byte_ranges()
            .iter()
            .any(|&(first, last)| (first..=last).contains(&byte))
    }

    fn skip_blanks(&mut self) -> Result<(), DosError> {
        loop {
            match self.peek(0)? {
                b' ' | b'\t' => self.position += 1,
                // The PRC DOS profile uses A1 A1 for a DBCS blank. This is a
                // byte convention, not a Unicode whitespace classification.
                0xa1 if self.code_page == CodePage::Cp936 && self.peek(1)? == 0xa1 => {
                    self.position += 2
                }
                _ => return Ok(()),
            }
        }
    }

    fn field<const N: usize>(&mut self, wildcard: &mut bool) -> Result<Option<[u8; N]>, DosError> {
        if terminates(self.peek(0)?) {
            return Ok(None);
        }
        let mut bytes = [b' '; N];
        let mut written = 0;
        let tables = text_codec::dos_code_page_tables(self.code_page).ok_or(
            DosError::HostContractViolation("missing DOS filename uppercase profile"),
        )?;
        loop {
            let byte = self.peek(0)?;
            if terminates(byte) {
                return Ok(Some(bytes));
            }
            if self.is_lead(byte) {
                let trail = self.peek(1)?;
                if N - written >= 2 {
                    bytes[written..written + 2].copy_from_slice(&[byte, trail]);
                    written += 2;
                } else if written < N {
                    // Do not publish a lead byte at the end of an 8/3 field.
                    written = N;
                }
                self.position += 2;
            } else {
                self.position += 1;
                if written < N {
                    if byte == b'*' {
                        bytes[written..].fill(b'?');
                        written = N;
                        *wildcard = true;
                    } else {
                        bytes[written] = tables.uppercase_byte(byte);
                        written += 1;
                        *wildcard |= byte == b'?';
                    }
                }
            }
        }
    }
}

fn terminates(byte: u8) -> bool {
    byte <= b' '
        || matches!(
            byte,
            b'.' | b':'
                | b';'
                | b','
                | b'='
                | b'+'
                | b'/'
                | b'\\'
                | b'"'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'|'
        )
}
