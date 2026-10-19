use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

/// Keep UTF-8 characters intact when a running child has written only a prefix.
pub(crate) struct LogReader {
    file: File,
    pending: Vec<u8>,
}
impl LogReader {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            file: File::open(path)?,
            pending: Vec::new(),
        })
    }
    pub fn read(&mut self, finished: bool) -> String {
        let skipped = match (self.file.metadata(), self.file.stream_position()) {
            (Ok(metadata), Ok(position)) if metadata.len().saturating_sub(position) > 64 * 1024 => {
                self.pending.clear();
                self.file.seek(SeekFrom::End(-64 * 1024)).is_ok()
            }
            _ => false,
        };
        let _ = (&mut self.file)
            .take(if finished { 256 * 1024 } else { 8 * 1024 })
            .read_to_end(&mut self.pending);
        let mut output = if skipped {
            "\r\n……部分日志已省略，完整内容保存在日志文件。\r\n".into()
        } else {
            String::new()
        };
        let mut offset = 0;
        while offset < self.pending.len() {
            match std::str::from_utf8(&self.pending[offset..]) {
                Ok(text) => {
                    output.push_str(text);
                    offset = self.pending.len();
                }
                Err(error) => {
                    let valid_end = offset + error.valid_up_to();
                    output.push_str(
                        std::str::from_utf8(&self.pending[offset..valid_end])
                            .expect("validated UTF-8 prefix"),
                    );
                    offset = valid_end;
                    if let Some(length) = error.error_len() {
                        output.push('\u{fffd}');
                        offset += length;
                    } else if finished {
                        output.push('\u{fffd}');
                        offset = self.pending.len();
                    } else {
                        break;
                    }
                }
            }
        }
        self.pending.drain(..offset);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn live_log_keeps_split_characters_and_reports_invalid_final_bytes() {
        let fixture = crate::test_support::Fixture::new();
        let path = fixture.file("live.log");
        let mut file = File::options().append(true).open(&path).unwrap();
        let mut reader = LogReader::open(&path).unwrap();
        file.write_all(&[0xe4, 0xb8]).unwrap();
        file.flush().unwrap();
        assert!(reader.read(false).is_empty());
        file.write_all(&[0xad, b'\n', 0xff, 0xe4]).unwrap();
        file.flush().unwrap();
        assert_eq!(reader.read(false), "中\n\u{fffd}");
        assert_eq!(reader.read(true), "\u{fffd}");
        assert!(reader.read(true).is_empty());
    }
}
