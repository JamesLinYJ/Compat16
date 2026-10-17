//! Guest MMIO buffer windows for MMSYSTEM 1215–1217, 1219, 1221, and 1222.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16HostMediaIoHandle, Win16HostMediaIoOperation,
    Win16HostMediaIoResult,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, PhysAddr, Selector};
use win16_abi::{
    Access, AccessRights, ExportLookupTarget, MMIOINFO16_SIZE, SegmentedPointer,
    Win16MediaIoRequest, Win16MmioInfo16, lookup_export,
};

const MMIO_READWRITE: u32 = 2;
const MMIO_WRITE: u32 = 1;
const MMIO_ALLOCBUF: u32 = 0x0001_0000;
const MMIO_DIRTY: u32 = 0x1000_0000;
const INSTALL: u32 = 0x0001_0000;
const REMOVE: u32 = 0x0002_0000;
const FIND: u32 = 0x0004_0000;
const INVALHANDLE: u32 = 5;
const INVALFLAG: u32 = 10;
const INVALPARAM: u32 = 11;
const OUTOFMEMORY: u32 = 258;
const CANNOTWRITE: u32 = 262;
const UNBUFFERED: u32 = 266;
const BUFFER_BASE: u32 = 0x6_0000;
const INFO_BASE: u32 = 0x7_0000;
const COPY_BASE: u32 = 0x8_0000;

struct MemHost {
    data: Vec<u8>,
    pos: u64,
    closed: bool,
    fail_write: bool,
    reads: u32,
    writes: u32,
    flushes: u32,
}

impl MemHost {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            pos: 0,
            closed: false,
            fail_write: false,
            reads: 0,
            writes: 0,
            flushes: 0,
        }
    }

    fn expect(&self, handle: Win16HostMediaIoHandle) {
        assert_eq!(handle.0, 1);
        assert!(!self.closed);
    }

    fn seek(&mut self, offset: i32, origin: i16) -> i32 {
        let base = match origin {
            0 => 0_i64,
            1 => self.pos as i64,
            2 => self.data.len() as i64,
            _ => return -1,
        };
        let next = base.saturating_add(i64::from(offset));
        if next < 0 || next > i64::from(i32::MAX) {
            return -1;
        }
        self.pos = next as u64;
        next as i32
    }
}

impl DosHost for MemHost {
    fn read_stdin(&mut self, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _: &[u8], _: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(&mut self, _: &[u8], _: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _: &[u8],
        _: DosFileAccess,
        _: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _: DosHostFile, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _: DosHostFile, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(&mut self, _: DosHostFile, _: i32, _: DosSeekOrigin) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _: DosHostFile, _: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(&mut self, _: u8, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _: &[u8], _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _: &[u8], _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for MemHost {
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }

    fn win16_media_io(
        &mut self,
        operation: Win16HostMediaIoOperation,
    ) -> Result<Win16HostMediaIoResult, RuntimeError> {
        match operation {
            Win16HostMediaIoOperation::Read { handle, count } => {
                self.expect(handle);
                self.reads += 1;
                if count < 0 {
                    return Ok(Win16HostMediaIoResult::Transfer {
                        result: -1,
                        bytes: Vec::new(),
                    });
                }
                let start = self.pos as usize;
                let end = start.saturating_add(count as usize).min(self.data.len());
                let bytes = self.data.get(start..end).unwrap_or_default().to_vec();
                self.pos = end as u64;
                Ok(Win16HostMediaIoResult::Transfer {
                    result: bytes.len() as i32,
                    bytes,
                })
            }
            Win16HostMediaIoOperation::Write { handle, data } => {
                self.expect(handle);
                self.writes += 1;
                if self.fail_write {
                    return Ok(Win16HostMediaIoResult::Transfer {
                        result: -1,
                        bytes: Vec::new(),
                    });
                }
                let start = self.pos as usize;
                let end = start + data.len();
                if end > self.data.len() {
                    self.data.resize(end, 0);
                }
                self.data[start..end].copy_from_slice(&data);
                self.pos = end as u64;
                Ok(Win16HostMediaIoResult::Transfer {
                    result: data.len() as i32,
                    bytes: Vec::new(),
                })
            }
            Win16HostMediaIoOperation::Seek {
                handle,
                offset,
                origin,
            } => {
                self.expect(handle);
                Ok(Win16HostMediaIoResult::Transfer {
                    result: self.seek(offset, origin),
                    bytes: Vec::new(),
                })
            }
            Win16HostMediaIoOperation::Flush { handle, flags: _ } => {
                self.expect(handle);
                self.flushes += 1;
                Ok(Win16HostMediaIoResult::Scalar(0))
            }
            Win16HostMediaIoOperation::Close { handle, flags: _ } => {
                self.expect(handle);
                self.closed = true;
                Ok(Win16HostMediaIoResult::Scalar(0))
            }
            other => panic!("unexpected mmio host operation {other:?}"),
        }
    }
}

impl crate::RuntimeDdeHost for MemHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for MemHost {}
impl crate::RuntimeMidiHost for MemHost {}
impl crate::RuntimeNetbiosHost for MemHost {}

fn load_guest() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\MMIO.NE").unwrap()
}

fn api(runtime: &mut Runtime, host: &mut MemHost, request: Win16MediaIoRequest) -> u32 {
    runtime
        .win16
        .as_mut()
        .unwrap()
        .media_io_api(request, &mut runtime.memory, host)
        .unwrap()
}

fn open_alias(runtime: &mut Runtime, flags: u32) -> u16 {
    runtime
        .win16
        .as_mut()
        .unwrap()
        .media_services
        .insert_mmio(Win16HostMediaIoHandle(1), flags)
        .unwrap()
}

fn map(runtime: &mut Runtime, base: u32, len: u32) -> u32 {
    runtime
        .memory
        .write_physical(PhysAddr(base), &vec![0; len as usize])
        .unwrap();
    let selector = runtime
        .win16
        .as_mut()
        .unwrap()
        .selectors
        .alloc_block(
            PhysAddr(base),
            len,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    SegmentedPointer::new(selector, 0).far_value()
}

fn read_guest(runtime: &Runtime, far: u32, len: usize) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let address = state
        .selectors
        .translate(pointer, Access::Read, len, &runtime.memory)
        .unwrap();
    let mut bytes = vec![0; len];
    runtime.memory.read(address, &mut bytes).unwrap();
    bytes
}

fn write_guest(runtime: &mut Runtime, far: u32, bytes: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
}

fn read_info(runtime: &Runtime, far: u32) -> Win16MmioInfo16 {
    let bytes: [u8; MMIOINFO16_SIZE] = read_guest(runtime, far, MMIOINFO16_SIZE)
        .try_into()
        .unwrap();
    Win16MmioInfo16::decode(&bytes)
}

fn write_info(runtime: &mut Runtime, far: u32, info: Win16MmioInfo16) {
    write_guest(runtime, far, &info.encode());
}

#[test]
fn buffered_read_fills_one_guest_window_then_the_next() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"abcdefghij");
    let guest = open_alias(&mut runtime, MMIO_READWRITE);
    let buffer = map(&mut runtime, BUFFER_BASE, 4);
    let info = map(&mut runtime, INFO_BASE, MMIOINFO16_SIZE as u32);
    let copy = map(&mut runtime, COPY_BASE, 8);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer,
                size: 4,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info: 0,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(read_guest(&runtime, buffer, 4), b"abcd");
    assert_eq!(host.reads, 1);
    let record = {
        assert_eq!(
            api(
                &mut runtime,
                &mut host,
                Win16MediaIoRequest::GetInfo {
                    handle: guest,
                    info,
                    flags: 0,
                }
            ),
            0
        );
        read_info(&runtime, info)
    };
    assert_eq!(record.buffer, buffer);
    assert_eq!(record.next, buffer);
    assert_eq!(record.end_read, buffer.wrapping_add(4));
    assert_eq!(record.end_write, buffer.wrapping_add(4));
    assert_eq!(record.handle, guest);
    assert_eq!(record.buffer_size, 4);
    assert_eq!(record.io_proc, 0);
    assert_eq!(record.task, 0);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Read {
                handle: guest,
                buffer: copy,
                count: 3,
            }
        ),
        3
    );
    assert_eq!(read_guest(&runtime, copy, 3), b"abc");
    assert_eq!(host.reads, 1);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Read {
                handle: guest,
                buffer: copy,
                count: 3,
            }
        ),
        3
    );
    assert_eq!(read_guest(&runtime, copy, 3), b"def");
    assert_eq!(host.reads, 2);
    assert_eq!(read_guest(&runtime, buffer, 4), b"efgh");
}

#[test]
fn buffered_seek_cur_zero_stays_at_the_logical_cursor() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"abcdefghijklmnopqrst");
    let guest = open_alias(&mut runtime, 0);
    let buffer = map(&mut runtime, BUFFER_BASE, 8);
    let copy = map(&mut runtime, COPY_BASE, 4);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer,
                size: 8,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info: 0,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(host.pos, 8);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Read {
                handle: guest,
                buffer: copy,
                count: 3,
            }
        ),
        3
    );
    assert_eq!(read_guest(&runtime, copy, 3), b"abc");
    assert_eq!(host.pos, 8);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Seek {
                handle: guest,
                offset: 0,
                origin: 1,
            }
        ),
        3
    );
    assert_eq!(host.pos, 3);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Read {
                handle: guest,
                buffer: copy,
                count: 3,
            }
        ),
        3
    );
    assert_eq!(read_guest(&runtime, copy, 3), b"def");
}

#[test]
fn direct_dirty_bytes_flush_on_write_advance_seek_and_close() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    let guest = open_alias(&mut runtime, MMIO_READWRITE);
    let buffer = map(&mut runtime, BUFFER_BASE, 4);
    let info = map(&mut runtime, INFO_BASE, MMIOINFO16_SIZE as u32);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer,
                size: 4,
                flags: 0,
            }
        ),
        0
    );
    write_guest(&mut runtime, buffer, b"WXYZ");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        0
    );
    let mut record = read_info(&runtime, info);
    record.next = buffer.wrapping_add(4);
    record.flags |= MMIO_DIRTY;
    write_info(&mut runtime, info, record);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info,
                flags: MMIO_WRITE as u16,
            }
        ),
        0
    );
    assert_eq!(host.data, b"WXYZ");
    let record = read_info(&runtime, info);
    assert_eq!(record.next, buffer);
    assert_eq!(record.flags & MMIO_DIRTY, 0);
    assert_eq!(record.buffer_offset, 4);

    write_guest(&mut runtime, buffer, b"AB");
    let mut record = read_info(&runtime, info);
    record.next = buffer.wrapping_add(2);
    record.flags |= MMIO_DIRTY;
    write_info(&mut runtime, info, record);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Flush {
                handle: guest,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(&host.data[..6], b"WXYZAB");
    assert_eq!(host.flushes, 1);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Seek {
                handle: guest,
                offset: 0,
                origin: 0,
            }
        ),
        0
    );
    let copy = map(&mut runtime, COPY_BASE, 6);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Read {
                handle: guest,
                buffer: copy,
                count: 6,
            }
        ),
        6
    );
    assert_eq!(read_guest(&runtime, copy, 6), b"WXYZAB");
}

#[test]
fn read_only_write_stops_and_failed_flush_keeps_the_handle() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"abcd");
    let guest = open_alias(&mut runtime, 0);
    let buffer = map(&mut runtime, BUFFER_BASE, 4);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer,
                size: 4,
                flags: 0,
            }
        ),
        0
    );
    let source = map(&mut runtime, COPY_BASE, 1);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Write {
                handle: guest,
                buffer: source,
                count: 1,
            }
        ),
        u32::MAX
    );
    assert_eq!(host.writes, 0);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info: 0,
                flags: MMIO_WRITE as u16,
            }
        ),
        INVALFLAG
    );

    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    host.fail_write = true;
    let guest = open_alias(&mut runtime, MMIO_READWRITE);
    let buffer = map(&mut runtime, BUFFER_BASE, 4);
    let source = map(&mut runtime, COPY_BASE, 2);
    write_guest(&mut runtime, source, b"AB");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer,
                size: 4,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Write {
                handle: guest,
                buffer: source,
                count: 2,
            }
        ),
        2
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Close {
                handle: guest,
                flags: 0,
            }
        ),
        CANNOTWRITE
    );
    assert!(!host.closed);
    assert!(host.data.is_empty());
    let info = map(&mut runtime, INFO_BASE, MMIOINFO16_SIZE as u32);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(read_info(&runtime, info).handle, guest);
}

#[test]
fn buffer_helpers_reject_bad_handles_flags_and_unusable_windows() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"abcd");
    let guest = open_alias(&mut runtime, MMIO_ALLOCBUF | MMIO_READWRITE);
    let info = map(&mut runtime, INFO_BASE, MMIOINFO16_SIZE as u32);
    write_guest(&mut runtime, info, &[0x5A; MMIOINFO16_SIZE]);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        UNBUFFERED
    );
    assert_eq!(
        read_guest(&runtime, info, MMIOINFO16_SIZE),
        vec![0x5A; MMIOINFO16_SIZE]
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        0
    );
    let record = read_info(&runtime, info);
    assert_eq!(record.flags, MMIO_ALLOCBUF | MMIO_READWRITE);
    assert_eq!(record.buffer, 0);
    assert_eq!(record.handle, guest);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info,
                flags: 1,
            }
        ),
        INVALFLAG
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: 0,
                info,
                flags: 0,
            }
        ),
        INVALHANDLE
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info: 0,
                flags: 0,
            }
        ),
        INVALPARAM
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: 0,
                size: -1,
                flags: 0,
            }
        ),
        INVALPARAM
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: 1,
                size: 0,
                flags: 0,
            }
        ),
        INVALPARAM
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: 0,
                size: 70_000,
                flags: 0,
            }
        ),
        OUTOFMEMORY
    );
    let too_big = map(&mut runtime, BUFFER_BASE, 4);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: too_big,
                size: 70_000,
                flags: 0,
            }
        ),
        INVALPARAM
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: 9,
                info: 0,
                flags: 0,
            }
        ),
        INVALHANDLE
    );

    let buffer = map(&mut runtime, BUFFER_BASE, 4);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer,
                size: 4,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: 0,
                size: 0,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info: 0,
                flags: 0,
            }
        ),
        UNBUFFERED
    );
}

#[test]
fn install_io_proc_stores_a_guest_pointer_and_send_message_returns_zero() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    let procedure = 0x1234_5678;
    let fourcc = 0x2053_494d;
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::InstallIoProc {
                fourcc,
                procedure,
                flags: INSTALL,
            }
        ),
        procedure
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::InstallIoProc {
                fourcc,
                procedure: 0,
                flags: FIND,
            }
        ),
        procedure
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::InstallIoProc {
                fourcc,
                procedure: 0,
                flags: INSTALL | REMOVE,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::InstallIoProc {
                fourcc,
                procedure: 0,
                flags: REMOVE,
            }
        ),
        procedure
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::InstallIoProc {
                fourcc,
                procedure: 0,
                flags: FIND,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::InstallIoProc {
                fourcc: 0,
                procedure,
                flags: INSTALL,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SendMessage {
                handle: 0,
                message: 1,
                param1: 2,
                param2: 3,
            }
        ),
        0
    );
    assert_eq!(host.reads, 0);
    assert_eq!(host.writes, 0);
}

#[test]
fn internal_buffer_is_process_memory_and_close_writes_it_back() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    let guest = open_alias(&mut runtime, MMIO_READWRITE);
    let source = map(&mut runtime, COPY_BASE, 2);
    write_guest(&mut runtime, source, b"Hi");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: 0,
                size: 16,
                flags: 0,
            }
        ),
        0
    );
    let info = map(&mut runtime, INFO_BASE, MMIOINFO16_SIZE as u32);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        0
    );
    let record = read_info(&runtime, info);
    assert_ne!(record.buffer, 0);
    assert_eq!(read_guest(&runtime, record.buffer, 16), vec![0; 16]);
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Write {
                handle: guest,
                buffer: source,
                count: 2,
            }
        ),
        2
    );
    assert_eq!(read_guest(&runtime, record.buffer, 2), b"Hi");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Close {
                handle: guest,
                flags: 0,
            }
        ),
        0
    );
    assert!(host.closed);
    assert_eq!(host.data, b"Hi");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::GetInfo {
                handle: guest,
                info,
                flags: 0,
            }
        ),
        INVALHANDLE
    );
}

#[test]
fn service_gate_returns_word_far_pointer_and_dword_results() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    let origin_sp = runtime.cpu.regs.sp();
    let (return_cs, return_ip, return_sp) = push(&mut runtime, 1215, &{
        let mut frame = 0_u16.to_le_bytes().to_vec();
        frame.extend_from_slice(&0_u32.to_le_bytes());
        frame.extend_from_slice(&0xffff_u16.to_le_bytes());
        frame
    });
    runtime.cpu.regs.set_dx(0x5aa5);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), INVALHANDLE as u16);
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        (return_cs, return_ip, return_sp)
    );

    let procedure = 0x1234_5678_u32;
    runtime.cpu.regs.set_sp(origin_sp);
    let (return_cs, return_ip, return_sp) = push(&mut runtime, 1221, &{
        let mut frame = INSTALL.to_le_bytes().to_vec();
        frame.extend_from_slice(&procedure.to_le_bytes());
        frame.extend_from_slice(&0x2053_494d_u32.to_le_bytes());
        frame
    });
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), procedure as u16);
    assert_eq!(runtime.cpu.regs.dx(), (procedure >> 16) as u16);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        (return_cs, return_ip, return_sp)
    );

    runtime.cpu.regs.set_sp(origin_sp);
    let (return_cs, return_ip, return_sp) = push(&mut runtime, 1222, &{
        let mut frame = 3_i32.to_le_bytes().to_vec();
        frame.extend_from_slice(&2_i32.to_le_bytes());
        frame.extend_from_slice(&1_u16.to_le_bytes());
        frame.extend_from_slice(&0_u16.to_le_bytes());
        frame
    });
    runtime.cpu.regs.set_ax(0x1111);
    runtime.cpu.regs.set_dx(0x2222);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), 0);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        (return_cs, return_ip, return_sp)
    );
    assert_eq!(host.reads, 0);
}

fn push(runtime: &mut Runtime, ordinal: u16, args: &[u8]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(args);
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &frame)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    (return_cs, return_ip, stack + 4 + args.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut MemHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

#[test]
fn task_cleanup_flushes_a_dirty_internal_buffer() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    let guest = open_alias(&mut runtime, MMIO_READWRITE);
    let source = map(&mut runtime, COPY_BASE, 2);
    write_guest(&mut runtime, source, b"OK");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::SetBuffer {
                handle: guest,
                buffer: 0,
                size: 8,
                flags: 0,
            }
        ),
        0
    );
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Write {
                handle: guest,
                buffer: source,
                count: 2,
            }
        ),
        2
    );
    runtime
        .win16
        .as_mut()
        .unwrap()
        .retire_mmio_guest_buffers(&mut runtime.memory, &mut host)
        .unwrap();
    assert_eq!(host.data, b"OK");
    assert_eq!(
        api(
            &mut runtime,
            &mut host,
            Win16MediaIoRequest::Advance {
                handle: guest,
                info: 0,
                flags: 0,
            }
        ),
        UNBUFFERED
    );
    runtime
        .win16
        .as_mut()
        .unwrap()
        .media_services
        .retire_all(&mut host)
        .unwrap();
    assert!(host.closed);
}

#[test]
fn task_cleanup_preserves_dirty_buffer_and_file_after_write_failure() {
    let mut runtime = load_guest();
    let mut host = MemHost::new(b"");
    let guest = open_alias(&mut runtime, MMIO_READWRITE);
    let source = map(&mut runtime, COPY_BASE, 2);
    write_guest(&mut runtime, source, b"OK");
    assert_eq!(api(&mut runtime, &mut host, Win16MediaIoRequest::SetBuffer {
        handle: guest, buffer: 0, size: 8, flags: 0,
    }), 0);
    assert_eq!(api(&mut runtime, &mut host, Win16MediaIoRequest::Write {
        handle: guest, buffer: source, count: 2,
    }), 2);
    host.fail_write = true;
    let state = runtime.win16.as_mut().unwrap();
    assert!(state.retire_mmio_guest_buffers(&mut runtime.memory, &mut host).is_err());
    assert!(state.media_services.mmio_buffer(guest).unwrap().dirty);
    assert!(state.media_services.retire_all(&mut host).is_err());
    assert!(!host.closed);
    assert!(!state.media_services.native_sources_quiescent());
    host.fail_write = false;
    state.retire_mmio_guest_buffers(&mut runtime.memory, &mut host).unwrap();
    assert_eq!(host.data, b"OK");
    assert!(state.media_services.mmio_buffer(guest).is_none());
    state.media_services.retire_all(&mut host).unwrap();
    assert!(host.closed);
    assert!(state.media_services.native_sources_quiescent());
}
