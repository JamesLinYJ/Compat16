use std::io::{self, BufWriter, Write};

use super::write_complete_row;

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    flushed: Vec<Vec<u8>>,
    fail_after: Option<usize>,
    fail_flush: bool,
}

impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.fail_after.map_or(bytes.len(), |limit| {
            bytes.len().min(limit.saturating_sub(self.bytes.len()))
        });
        if count == 0 && !bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "trace write failed"));
        }
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushed.push(self.bytes.clone());
        if self.fail_flush {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "trace flush failed"));
        }
        Ok(())
    }
}

#[test]
fn complete_trace_flushes_each_terminated_row_before_returning() {
    let enter = "service-boundary stage=dispatch-enter module=KERNEL name=InitTask ordinal=91 instruction=42 guest=1234:5678";
    let leave = "service-boundary stage=dispatch-return module=KERNEL name=InitTask ordinal=91 instruction=42 guest=1234:5678";
    let mut writer = BufWriter::with_capacity(4096, RecordingWriter::default());

    write_complete_row(&mut writer, 0, &enter).unwrap();
    let first = format!("@0 {enter}\n").into_bytes();
    assert!(writer.buffer().is_empty());
    assert_eq!(writer.get_ref().bytes, first);
    assert_eq!(writer.get_ref().flushed, [first.clone()]);

    write_complete_row(&mut writer, 1, &leave).unwrap();
    let both = format!("@0 {enter}\n@1 {leave}\n").into_bytes();
    assert!(writer.buffer().is_empty());
    assert_eq!(writer.get_ref().bytes, both);
    assert_eq!(writer.get_ref().flushed, [first, both]);
}

#[test]
fn complete_trace_propagates_partial_write_failure_without_flushing() {
    let mut writer = RecordingWriter { fail_after: Some(4), ..Default::default() };

    let error = write_complete_row(&mut writer, 0, &"event").unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(writer.bytes, b"@0 e");
    assert!(writer.flushed.is_empty());
}

#[test]
fn complete_trace_propagates_buffered_write_failure_without_flushing_sink() {
    let sink = RecordingWriter { fail_after: Some(0), ..Default::default() };
    let mut writer = BufWriter::with_capacity(4096, sink);

    let error = write_complete_row(&mut writer, 0, &"event").unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert!(writer.get_ref().bytes.is_empty());
    assert!(writer.get_ref().flushed.is_empty());
}

#[test]
fn complete_trace_propagates_flush_failure_after_writing_the_full_row() {
    let sink = RecordingWriter { fail_flush: true, ..Default::default() };
    let mut writer = BufWriter::with_capacity(4096, sink);

    let error = write_complete_row(&mut writer, 7, &"event").unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(writer.buffer().is_empty());
    assert_eq!(writer.get_ref().bytes, b"@7 event\n");
    assert_eq!(writer.get_ref().flushed, [b"@7 event\n".to_vec()]);
}
