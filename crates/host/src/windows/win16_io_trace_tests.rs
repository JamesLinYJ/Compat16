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

fn exhaust_prefix(trace: &mut super::Win16IoTrace) {
    for _ in 0..super::MAX_ROWS + 4 {
        trace.record(&runtime::Win16IoEvent::ModuleFileName {
            path: b"APP.EXE", copied: 7,
        }).unwrap();
    }
}

fn get_message(module: &'static [u8]) -> runtime::Win16IoEvent<'static> {
    runtime::Win16IoEvent::ServiceBoundary {
        module, name: Some(b"GetMessage"), ordinal: Some(108), instruction: 10000,
        selector: 8, offset: 16, stage: runtime::Win16ServiceBoundaryStage::DispatchEnter,
    }
}

#[test]
fn complete_trace_publishes_monotonic_timing_without_changing_event_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("timing.log");
    let mut trace = super::Win16IoTrace::create(&path, true).unwrap();
    trace.record(&get_message(b"USER")).unwrap();
    let first = std::fs::read_to_string(&path).unwrap();
    assert!(first.starts_with("@0 service-boundary stage=dispatch-enter module=USER name=GetMessage ordinal=108 instruction=10000 guest=0008:0010"));
    trace.record(&get_message(b"USER")).unwrap();
    let rows = std::fs::read_to_string(&path).unwrap();
    let times: Vec<u128> = rows.lines().map(|line| line.rsplit_once(" elapsed-us=").unwrap().1.parse().unwrap()).collect();
    assert_eq!(times.len(), 2);
    assert!(times[1] >= times[0]);
    assert!(rows.starts_with(&first));
}

#[test]
fn native_pixel_context_is_complete_only_and_preserves_sequence_identity() {
    let directory = tempfile::tempdir().unwrap();
    for complete in [false, true] {
        let path = directory.path().join(format!("pixel-{complete}.log"));
        let mut trace = super::Win16IoTrace::create(&path, complete).unwrap();
        trace.native_pixel(7, 2, 3, 10, Some((8, 6, 32, 1, 32, true))).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        if complete {
            assert!(contents.starts_with("@0 native-pixel dc=7 x=2 y=3 dc-kind=10 bitmap=Some((8, 6, 32, 1, 32, true)) elapsed-us="));
            trace.record(&get_message(b"USER")).unwrap();
            assert!(std::fs::read_to_string(&path).unwrap().contains("@1 service-boundary"));
        } else { assert!(contents.is_empty()); }
    }
}

fn null_callback(id: u64, returned: bool) -> runtime::Win16IoEvent<'static> {
    runtime::Win16IoEvent::WindowCallback {
        callback: id, window: 2,
        procedure: runtime::Win16WindowCallbackProcedure::WindowProcedure,
        phase: if returned { runtime::Win16WindowCallbackPhase::GuestReturn }
            else { runtime::Win16WindowCallbackPhase::GuestEntry },
        message: 0,
        return_value: returned.then_some(runtime::Win16WindowCallbackReturn::WindowProcedure(0)),
        dialog_message_result: None,
    }
}

#[test]
fn bounded_trace_exposes_a_late_message_loop_before_drop_and_keeps_its_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("startup.log");
    let mut trace = super::Win16IoTrace::create(&path, false).unwrap();
    exhaust_prefix(&mut trace);
    let before = std::fs::metadata(&path).unwrap().len();
    trace.record(&get_message(b"OTHER")).unwrap();
    trace.record(&null_callback(0, false)).unwrap();
    trace.record(&null_callback(0, true)).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
    trace.record(&get_message(b"USER")).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("stage=dispatch-enter module=USER name=GetMessage ordinal=108"));
    assert!(contents.contains("recent observations (bounded tail; first service may be partial):"));
    let after = std::fs::metadata(&path).unwrap().len();
    for _ in 0..1000 { trace.record(&get_message(b"USER")).unwrap(); }
    assert_eq!(std::fs::metadata(&path).unwrap().len(), after);
    assert!(after < 1024 * 1024);
}

#[test]
fn bounded_trace_preserves_real_null_entry_return_pairs_with_a_finite_live_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("probes.log");
    let mut trace = super::Win16IoTrace::create(&path, false).unwrap();
    exhaust_prefix(&mut trace);
    trace.record(&get_message(b"USER")).unwrap();
    let mut previous = std::fs::metadata(&path).unwrap().len();
    for id in 1..=super::startup::MAX_LIVE_NULL_RETURNS as u64 + 4 {
        trace.record(&null_callback(id, false)).unwrap();
        trace.record(&null_callback(id, true)).unwrap();
        let current = std::fs::metadata(&path).unwrap().len();
        if id <= super::startup::MAX_LIVE_NULL_RETURNS as u64 {
            assert!(current > previous);
        } else { assert_eq!(current, previous); }
        previous = current;
    }
    let contents = std::fs::read_to_string(&path).unwrap();
    for id in 1..=super::startup::MAX_LIVE_NULL_RETURNS {
        let enter = format!("phase=guest-entry procedure=wndproc callback={id} window=0002 message=0000 return=pending");
        let leave = format!("phase=guest-return procedure=wndproc callback={id} window=0002 message=0000 return=WNDPROC32:00000000");
        assert!(contents.find(&enter).unwrap() < contents.find(&leave).unwrap());
    }
    assert!(!contents.contains("callback=9 "));
}
