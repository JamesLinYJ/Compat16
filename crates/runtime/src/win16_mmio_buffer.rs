//! Guest-side MMIO buffers for MMSYSTEM 1215–1217, 1219, 1221, and 1222.
//!
//! Buffer addresses are guest far pointers into checked process memory. An
//! internal buffer is a locked guest global allocation, not a host pointer.
//! A buffer must fit in one descriptor, including the one-past HPSTR, so this
//! path does not invent a huge-pointer tile. `MMIO_ALLOCBUF` on `mmioOpen`
//! still belongs to the native file and is not reported here.

use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{
    Access, MMIOINFO16_SIZE, Win16MediaIoRequest, Win16MmioInfo16,
    global::{GMEM_MOVEABLE, GMEM_ZEROINIT},
};

use super::super::Win16State;
use super::super::guest_ranges::{GuestOutputRange, commit_guest_writes};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMediaIoHandle,
    Win16HostMediaIoOperation as Operation, Win16HostMediaIoResult as ResultValue,
    win16_media_services::Win16MmioBufferState,
};

const MMIO_WRITE: u32 = 1;
const MMIO_READWRITE: u32 = 2;
const MMIO_DIRTY: u32 = 0x1000_0000;
const MMSYSERR_INVALHANDLE: u32 = 5;
/// The SDK says the reserved flag must be zero and does not name the failure.
const MMSYSERR_INVALFLAG: u32 = 10;
const MMSYSERR_INVALPARAM: u32 = 11;
const MMIOERR_OUTOFMEMORY: u32 = 258;
const MMIOERR_CANNOTREAD: u32 = 261;
const MMIOERR_CANNOTWRITE: u32 = 262;
const MMIOERR_CANNOTSEEK: u32 = 263;
const MMIOERR_UNBUFFERED: u32 = 266;
const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
/// One-past HPSTR must stay in the same 16-bit offset.
const MAX_BUFFER: u32 = 0xFFFF;

impl Win16State {
    pub(super) fn mmio_buffer_request(
        &mut self,
        request: Win16MediaIoRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16MediaIoRequest::GetInfo {
                handle,
                info,
                flags,
            } => self.mmio_get_info(handle, info, flags, memory),
            Win16MediaIoRequest::SetInfo {
                handle,
                info,
                flags,
            } => self.mmio_set_info(handle, info, flags, memory),
            Win16MediaIoRequest::SetBuffer {
                handle,
                buffer,
                size,
                flags,
            } => self.mmio_set_buffer(handle, buffer, size, flags, memory, host),
            Win16MediaIoRequest::Advance {
                handle,
                info,
                flags,
            } => self.mmio_advance(handle, info, flags, memory, host),
            Win16MediaIoRequest::InstallIoProc {
                fourcc,
                procedure,
                flags,
            } => Ok(self
                .media_services
                .mmio_install_io_proc(fourcc, procedure, flags)),
            // No open file is bound to a guest I/O procedure, and the built-in
            // DOS procedure is not entered from this call. Unrecognized
            // messages return zero.
            Win16MediaIoRequest::SendMessage { .. } => Ok(0),
            _ => Err(super::invariant(
                "MMIO buffer request was routed to the wrong helper",
            )),
        }
    }

    pub(super) fn read_through_mmio_buffer(
        &mut self,
        guest: u16,
        output: u32,
        count: i32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if count < 0 {
            return Ok(u32::MAX);
        }
        if count == 0 {
            return Ok(0);
        }
        let capacity = count as u32;
        let destination = match super::capture_huge_output(self, memory, output, count as usize) {
            Ok(range) => range,
            Err(error) if super::is_guest_api_failure(&error) => return Ok(u32::MAX),
            Err(error) => return Err(error),
        };
        let mut pending = Vec::new();
        let mut left = capacity;
        while left > 0 {
            let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
                return Ok(u32::MAX);
            };
            let available = buffer.end_read.saturating_sub(buffer.next);
            if available == 0 {
                let code = self.advance_read(guest, memory, host)?;
                if code != 0 {
                    return Ok(if pending.is_empty() {
                        u32::MAX
                    } else {
                        pending.len() as u32
                    });
                }
                let Some(buffer) = self.media_services.mmio_buffer(guest) else {
                    return Ok(u32::MAX);
                };
                if buffer.end_read.saturating_sub(buffer.next) == 0 {
                    break;
                }
                continue;
            }
            let count = available.min(left);
            let copied = match self.read_guest_span(buffer.base, buffer.next, count, memory) {
                Ok(bytes) => bytes,
                Err(error) if super::is_guest_api_failure(&error) => return Ok(u32::MAX),
                Err(error) => return Err(error),
            };
            let mut buffer = self
                .media_services
                .mmio_buffer(guest)
                .cloned()
                .ok_or_else(|| super::invariant("MMIO buffer disappeared during a read"))?;
            buffer.next = buffer.next.saturating_add(count);
            self.media_services.set_mmio_buffer(guest, buffer);
            pending.extend(copied);
            left -= count;
        }
        match commit_guest_writes(self, memory, vec![(destination, pending.clone())]) {
            Ok(()) => Ok(pending.len() as u32),
            Err(error) if super::is_guest_api_failure(&error) => Ok(u32::MAX),
            Err(error) => Err(error),
        }
    }

    pub(super) fn write_through_mmio_buffer(
        &mut self,
        guest: u16,
        input: u32,
        count: i32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if count < 0 {
            return Ok(u32::MAX);
        }
        if count == 0 {
            return Ok(0);
        }
        let source = match self.read_caller_bytes(input, count as usize, memory) {
            Ok(bytes) => bytes,
            Err(error) if super::is_guest_api_failure(&error) => return Ok(u32::MAX),
            Err(error) => return Err(error),
        };
        let mut written = 0_u32;
        while (written as usize) < source.len() {
            let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
                return Ok(u32::MAX);
            };
            let available = buffer.end_write.saturating_sub(buffer.next);
            if available == 0 {
                let code = self.advance_write(guest, memory, host)?;
                if code != 0 {
                    return Ok(if written == 0 { u32::MAX } else { written });
                }
                let refilled = self
                    .media_services
                    .mmio_buffer(guest)
                    .is_some_and(|buffer| buffer.end_write > buffer.next);
                if !refilled {
                    return Ok(if written == 0 { u32::MAX } else { written });
                }
                continue;
            }
            let count = available.min((source.len() as u32) - written);
            let start = written as usize;
            let end = start + count as usize;
            if let Err(error) =
                self.write_guest_span(buffer.base, buffer.next, &source[start..end], memory)
            {
                if super::is_guest_api_failure(&error) {
                    return Ok(if written == 0 { u32::MAX } else { written });
                }
                return Err(error);
            }
            let mut buffer = self
                .media_services
                .mmio_buffer(guest)
                .cloned()
                .ok_or_else(|| super::invariant("MMIO buffer disappeared during a write"))?;
            buffer.next = buffer.next.saturating_add(count);
            buffer.dirty = true;
            self.media_services.set_mmio_buffer(guest, buffer);
            written += count;
        }
        Ok(written)
    }

    pub(super) fn seek_through_mmio_buffer(
        &mut self,
        guest: u16,
        offset: i32,
        origin: i16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let code = self.flush_mmio_buffer(guest, memory, host)?;
        if code != 0 {
            return Ok(u32::MAX);
        }
        // A buffered read leaves the native cursor at the end of the prefetched
        // window (`disk_offset`). The guest cursor is `file_offset + next`.
        // Re-anchor before a relative seek so SEEK_CUR 0 stays on that cursor.
        if origin == SEEK_CUR {
            if let Some(code) = self.reanchor_buffered_cursor(guest, host)? {
                return Ok(code);
            }
        }
        let Some(native) = self.media_services.mmio_handle(guest) else {
            return Ok(u32::MAX);
        };
        let position = self.native_seek(native, offset, origin, host)?;
        if position < 0 {
            return Ok(position as u32);
        }
        self.reset_window(guest, position);
        Ok(position as u32)
    }

    /// Write a dirty window at its file offset and leave the cursor in place.
    pub(super) fn flush_mmio_buffer(
        &mut self,
        guest: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(0);
        };
        if !buffer.dirty || buffer.next == 0 {
            if let Some(mut buffer) = self.media_services.mmio_buffer(guest).cloned() {
                buffer.dirty = false;
                self.media_services.set_mmio_buffer(guest, buffer);
            }
            return Ok(0);
        }
        let code =
            self.write_guest_span_to_file(guest, buffer.file_offset, 0, buffer.next, memory, host)?;
        if code != 0 {
            return Ok(code);
        }
        if let Some(mut buffer) = self.media_services.mmio_buffer(guest).cloned() {
            buffer.dirty = false;
            buffer.error = 0;
            self.media_services.set_mmio_buffer(guest, buffer);
        }
        Ok(0)
    }

    pub(super) fn release_mmio_allocation(&mut self, owned: u16) -> Result<(), RuntimeError> {
        if owned == 0 {
            return Ok(());
        }
        for _ in 0..16 {
            if self.global_unlock(owned)? == 0 {
                break;
            }
        }
        if self.global_free(owned)? != 0 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 MMIO internal buffer stayed locked after unlock",
            ));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn retire_mmio_guest_buffers(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first = None;
        let guests: Vec<u16> = self.media_services.mmio_buffer_guests();
        for guest in guests {
            match self.flush_mmio_buffer(guest, memory, host) {
                Ok(0) => {}
                Ok(code) => {
                    keep(&mut first, RuntimeError::new(
                        Kind::HostFailure,
                        format!(
                            "Win16 MMIO buffer flush failed during task cleanup (0x{code:04X})"
                        ),
                    ));
                    continue;
                }
                Err(error) => {
                    keep(&mut first, error);
                    continue;
                }
            }
            let owned = self.media_services.mmio_buffer(guest).map_or(0, |buffer| buffer.owned);
            if let Err(error) = self.release_mmio_allocation(owned) {
                keep(&mut first, error);
                continue;
            }
            self.media_services.clear_mmio_buffer(guest);
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn mmio_get_info(
        &mut self,
        guest: u16,
        info: u32,
        flags: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let Some(open_flags) = self.media_services.mmio_open_flags(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let record = match self.media_services.mmio_buffer(guest).cloned() {
            Some(buffer) => self.info_from_buffer(guest, open_flags, &buffer)?,
            None => Win16MmioInfo16 {
                flags: open_flags & !MMIO_DIRTY,
                handle: guest,
                ..Win16MmioInfo16::default()
            },
        };
        self.write_info(info, record, memory)
    }

    fn mmio_set_info(
        &mut self,
        guest: u16,
        info: u32,
        flags: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(MMSYSERR_INVALFLAG);
        }
        if self.media_services.mmio_handle(guest).is_none() {
            return Ok(MMSYSERR_INVALHANDLE);
        }
        if !self.media_services.mmio_is_buffered(guest) {
            return Ok(MMIOERR_UNBUFFERED);
        }
        let record = match self.read_info(info, memory)? {
            Ok(record) => record,
            Err(code) => return Ok(code),
        };
        let Some(mut buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(MMIOERR_UNBUFFERED);
        };
        let Some(next) = index_of(buffer.base, buffer.size, record.next) else {
            return Ok(MMSYSERR_INVALPARAM);
        };
        let Some(end_read) = index_of(buffer.base, buffer.size, record.end_read) else {
            return Ok(MMSYSERR_INVALPARAM);
        };
        let Some(end_write) = index_of(buffer.base, buffer.size, record.end_write) else {
            return Ok(MMSYSERR_INVALPARAM);
        };
        if record.buffer != buffer.base {
            return Ok(MMSYSERR_INVALPARAM);
        }
        buffer.next = next;
        buffer.end_read = end_read;
        buffer.end_write = end_write;
        buffer.dirty = record.flags & MMIO_DIRTY != 0;
        buffer.error = 0;
        self.media_services.set_mmio_buffer(guest, buffer);
        Ok(0)
    }

    fn mmio_set_buffer(
        &mut self,
        guest: u16,
        buffer: u32,
        size: i32,
        flags: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(MMSYSERR_INVALFLAG);
        }
        if self.media_services.mmio_handle(guest).is_none() {
            return Ok(MMSYSERR_INVALHANDLE);
        }
        if size < 0 || (buffer != 0 && size == 0) {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let size = size as u32;
        if size > MAX_BUFFER {
            return Ok(if buffer == 0 {
                MMIOERR_OUTOFMEMORY
            } else {
                MMSYSERR_INVALPARAM
            });
        }
        let position = match self.anchor_position(guest, memory, host)? {
            Ok(position) => position,
            Err(code) => return Ok(code),
        };
        if size == 0 {
            let owned = self.media_services.clear_mmio_buffer(guest);
            self.release_mmio_allocation(owned)?;
            return Ok(0);
        }
        let (base, owned) = if buffer == 0 {
            match self.allocate_internal_buffer(size, memory, host)? {
                Ok(value) => value,
                Err(code) => return Ok(code),
            }
        } else if self.buffer_fits(memory, buffer, size)? {
            (buffer, 0)
        } else {
            return Ok(MMSYSERR_INVALPARAM);
        };
        let previous = self.media_services.mmio_buffer(guest).cloned();
        let open_flags = self.media_services.mmio_open_flags(guest).unwrap_or(0);
        let mut installed = Win16MmioBufferState {
            base,
            size,
            next: 0,
            end_read: 0,
            end_write: if can_write(open_flags) { size } else { 0 },
            file_offset: position,
            disk_offset: position,
            dirty: false,
            owned,
            info: previous
                .as_ref()
                .map(|buffer| buffer.info)
                .unwrap_or([0; 3]),
            error: 0,
        };
        if let Some(previous) = previous.as_ref() {
            installed.info = previous.info;
        }
        self.media_services.set_mmio_buffer(guest, installed);
        if let Some(previous) = previous {
            if previous.owned != 0 && previous.owned != owned {
                self.release_mmio_allocation(previous.owned)?;
            }
        }
        Ok(0)
    }

    fn mmio_advance(
        &mut self,
        guest: u16,
        info: u32,
        flags: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if flags > 1 {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let Some(open_flags) = self.media_services.mmio_open_flags(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if !self.media_services.mmio_is_buffered(guest) {
            return Ok(MMIOERR_UNBUFFERED);
        }
        if info != 0 {
            let code = self.mmio_set_info(guest, info, 0, memory)?;
            if code != 0 {
                return Ok(code);
            }
        }
        let code = if flags == 0 {
            if !can_read(open_flags) {
                MMSYSERR_INVALFLAG
            } else {
                self.advance_read(guest, memory, host)?
            }
        } else if !can_write(open_flags) {
            MMSYSERR_INVALFLAG
        } else {
            self.advance_write(guest, memory, host)?
        };
        if code != 0 {
            return Ok(self.note_error(guest, code));
        }
        if info != 0 {
            self.mmio_get_info(guest, info, 0, memory)
        } else {
            Ok(0)
        }
    }

    fn advance_read(
        &mut self,
        guest: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(open_flags) = self.media_services.mmio_open_flags(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if !can_read(open_flags) {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(MMIOERR_UNBUFFERED);
        };
        if can_write(open_flags) && buffer.dirty {
            let code = self.flush_mmio_buffer(guest, memory, host)?;
            if code != 0 {
                return Ok(code);
            }
        }
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(MMIOERR_UNBUFFERED);
        };
        let Some(native) = self.media_services.mmio_handle(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let start = buffer.disk_offset;
        if self.native_seek(native, start, SEEK_SET, host)? < 0 {
            return Ok(MMIOERR_CANNOTSEEK);
        }
        let read = self.native_read(native, buffer.size, host)?;
        let Ok(bytes) = read else {
            return Ok(MMIOERR_CANNOTREAD);
        };
        if !bytes.is_empty() {
            self.write_guest_span(buffer.base, 0, &bytes, memory)?;
        }
        let mut buffer = buffer;
        buffer.file_offset = start;
        buffer.next = 0;
        buffer.end_read = bytes.len() as u32;
        buffer.end_write = if can_write(open_flags) {
            buffer.size
        } else {
            0
        };
        buffer.disk_offset = start
            .checked_add(bytes.len() as i32)
            .ok_or_else(|| super::invariant("MMIO buffer disk offset overflowed LONG"))?;
        buffer.dirty = false;
        buffer.error = 0;
        self.media_services.set_mmio_buffer(guest, buffer);
        Ok(0)
    }

    fn advance_write(
        &mut self,
        guest: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(open_flags) = self.media_services.mmio_open_flags(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if !can_write(open_flags) {
            return Ok(MMSYSERR_INVALFLAG);
        }
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(MMIOERR_UNBUFFERED);
        };
        if buffer.dirty {
            let code = self.flush_mmio_buffer(guest, memory, host)?;
            if code != 0 {
                return Ok(code);
            }
        }
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(MMIOERR_UNBUFFERED);
        };
        let Some(advanced) = buffer
            .file_offset
            .checked_add(i32::try_from(buffer.next).unwrap_or(i32::MAX))
        else {
            return Ok(MMIOERR_CANNOTSEEK);
        };
        let Some(native) = self.media_services.mmio_handle(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let position = self.native_seek(native, advanced, SEEK_SET, host)?;
        if position < 0 {
            return Ok(MMIOERR_CANNOTSEEK);
        }
        self.reset_window(guest, position);
        Ok(0)
    }

    fn reanchor_buffered_cursor(
        &mut self,
        guest: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u32>, RuntimeError> {
        if !self.media_services.mmio_is_buffered(guest) {
            return Ok(None);
        }
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(None);
        };
        let Some(logical) = buffer
            .file_offset
            .checked_add(i32::try_from(buffer.next).unwrap_or(i32::MAX))
        else {
            return Ok(Some(u32::MAX));
        };
        let Some(native) = self.media_services.mmio_handle(guest) else {
            return Ok(Some(u32::MAX));
        };
        if self.native_seek(native, logical, SEEK_SET, host)? < 0 {
            return Ok(Some(u32::MAX));
        }
        Ok(None)
    }

    fn anchor_position(
        &mut self,
        guest: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<i32, u32>, RuntimeError> {
        if self.media_services.mmio_is_buffered(guest) {
            let code = self.flush_mmio_buffer(guest, memory, host)?;
            if code != 0 {
                return Ok(Err(code));
            }
            let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
                return Ok(Err(MMIOERR_CANNOTSEEK));
            };
            let Some(logical) = buffer
                .file_offset
                .checked_add(i32::try_from(buffer.next).unwrap_or(i32::MAX))
            else {
                return Ok(Err(MMIOERR_CANNOTSEEK));
            };
            let Some(native) = self.media_services.mmio_handle(guest) else {
                return Ok(Err(MMSYSERR_INVALHANDLE));
            };
            let position = self.native_seek(native, logical, SEEK_SET, host)?;
            return Ok(if position < 0 {
                Err(MMIOERR_CANNOTSEEK)
            } else {
                Ok(position)
            });
        }
        let Some(native) = self.media_services.mmio_handle(guest) else {
            return Ok(Err(MMSYSERR_INVALHANDLE));
        };
        let position = self.native_seek(native, 0, SEEK_CUR, host)?;
        Ok(if position < 0 {
            Err(MMIOERR_CANNOTSEEK)
        } else {
            Ok(position)
        })
    }

    fn allocate_internal_buffer(
        &mut self,
        size: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<(u32, u16), u32>, RuntimeError> {
        let owned = self.global_alloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size, memory, host)?;
        if owned == 0 {
            return Ok(Err(MMIOERR_OUTOFMEMORY));
        }
        let far = self.global_lock(owned, memory)?;
        if far == 0 || !self.buffer_fits(memory, far, size)? {
            self.release_mmio_allocation(owned)?;
            return Ok(Err(MMIOERR_OUTOFMEMORY));
        }
        Ok(Ok((far, owned)))
    }

    fn reset_window(&mut self, guest: u16, position: i32) {
        let Some(open_flags) = self.media_services.mmio_open_flags(guest) else {
            return;
        };
        let Some(mut buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return;
        };
        buffer.file_offset = position;
        buffer.disk_offset = position;
        buffer.next = 0;
        buffer.end_read = 0;
        buffer.end_write = if can_write(open_flags) {
            buffer.size
        } else {
            0
        };
        buffer.dirty = false;
        self.media_services.set_mmio_buffer(guest, buffer);
    }

    fn info_from_buffer(
        &self,
        guest: u16,
        open_flags: u32,
        buffer: &Win16MmioBufferState,
    ) -> Result<Win16MmioInfo16, RuntimeError> {
        let flags = (open_flags & !MMIO_DIRTY) | if buffer.dirty { MMIO_DIRTY } else { 0 };
        Ok(Win16MmioInfo16 {
            flags,
            error: buffer.error,
            buffer_size: i32::try_from(buffer.size).unwrap_or(i32::MAX),
            buffer: buffer.base,
            next: far_add(buffer.base, buffer.next)
                .ok_or_else(|| super::invariant("MMIO pchNext left its descriptor"))?,
            end_read: far_add(buffer.base, buffer.end_read)
                .ok_or_else(|| super::invariant("MMIO pchEndRead left its descriptor"))?,
            end_write: far_add(buffer.base, buffer.end_write)
                .ok_or_else(|| super::invariant("MMIO pchEndWrite left its descriptor"))?,
            buffer_offset: buffer.file_offset,
            disk_offset: buffer.disk_offset,
            info: buffer.info,
            handle: guest,
            ..Win16MmioInfo16::default()
        })
    }

    fn note_error(&mut self, guest: u16, code: u32) -> u32 {
        if let Some(mut buffer) = self.media_services.mmio_buffer(guest).cloned() {
            buffer.error = code as u16;
            self.media_services.set_mmio_buffer(guest, buffer);
        }
        code
    }

    fn write_info(
        &self,
        far: u32,
        info: Win16MmioInfo16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if far == 0 {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let pointer = match self.selectors.pointer_from_far(far) {
            Ok(pointer) => pointer,
            Err(error) => return guest_code(crate::runtime_error(error), MMSYSERR_INVALPARAM),
        };
        let range = match GuestOutputRange::capture(self, memory, pointer, MMIOINFO16_SIZE) {
            Ok(range) => range,
            Err(error) => return guest_code(error, MMSYSERR_INVALPARAM),
        };
        match commit_guest_writes(self, memory, vec![(range, info.encode().to_vec())]) {
            Ok(()) => Ok(0),
            Err(error) => guest_code(error, MMSYSERR_INVALPARAM),
        }
    }

    fn read_info(
        &self,
        far: u32,
        memory: &Memory,
    ) -> Result<Result<Win16MmioInfo16, u32>, RuntimeError> {
        if far == 0 {
            return Ok(Err(MMSYSERR_INVALPARAM));
        }
        let pointer = match self.selectors.pointer_from_far(far) {
            Ok(pointer) => pointer,
            Err(error) => {
                return guest_code(crate::runtime_error(error), MMSYSERR_INVALPARAM).map(Err);
            }
        };
        match self
            .selectors
            .translate(pointer, Access::Read, MMIOINFO16_SIZE, memory)
        {
            Ok(address) => {
                let mut bytes = [0_u8; MMIOINFO16_SIZE];
                memory
                    .read(address, &mut bytes)
                    .map_err(crate::runtime_error)?;
                Ok(Ok(Win16MmioInfo16::decode(&bytes)))
            }
            Err(error) => guest_code(crate::runtime_error(error), MMSYSERR_INVALPARAM).map(Err),
        }
    }

    fn buffer_fits(&self, memory: &Memory, far: u32, size: u32) -> Result<bool, RuntimeError> {
        if far == 0 || size == 0 || size > MAX_BUFFER {
            return Ok(false);
        }
        let pointer = match self.selectors.pointer_from_far(far) {
            Ok(pointer) => pointer,
            Err(error) => {
                let error = crate::runtime_error(error);
                if super::is_guest_api_failure(&error) {
                    return Ok(false);
                }
                return Err(error);
            }
        };
        let Some(end) = u32::from(pointer.offset()).checked_add(size) else {
            return Ok(false);
        };
        if end > MAX_BUFFER {
            return Ok(false);
        }
        let described = self
            .selectors
            .describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let available = described
            .limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|length| length.checked_add(1))
            .unwrap_or(0);
        if size > available {
            return Ok(false);
        }
        match self
            .selectors
            .translate(pointer, Access::Write, size as usize, memory)
        {
            Ok(_) => Ok(true),
            Err(error) => {
                let error = crate::runtime_error(error);
                if super::is_guest_api_failure(&error) {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    }

    fn read_guest_span(
        &self,
        base: u32,
        index: u32,
        length: u32,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        let pointer = self.mmio_slice(base, index)?;
        self.read_text_bytes(memory, pointer, length as usize)
    }

    fn write_guest_span(
        &self,
        base: u32,
        index: u32,
        bytes: &[u8],
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let pointer = self.mmio_slice(base, index)?;
        self.write_text_bytes(memory, pointer, bytes)
    }

    fn write_guest_span_to_file(
        &mut self,
        guest: u16,
        file_offset: i32,
        index: u32,
        length: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if length == 0 {
            return Ok(0);
        }
        let Some(buffer) = self.media_services.mmio_buffer(guest).cloned() else {
            return Ok(MMIOERR_UNBUFFERED);
        };
        let Some(native) = self.media_services.mmio_handle(guest) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let data = self.read_guest_span(buffer.base, index, length, memory)?;
        if self.native_seek(native, file_offset, SEEK_SET, host)? < 0 {
            return Ok(MMIOERR_CANNOTSEEK);
        }
        match self.native_write(native, data, host)? {
            Ok(written) if written == length => Ok(0),
            Ok(_) | Err(()) => Ok(MMIOERR_CANNOTWRITE),
        }
    }

    fn read_caller_bytes(
        &self,
        far: u32,
        length: usize,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.read_text_bytes(memory, pointer, length)
    }

    fn mmio_slice(
        &self,
        base: u32,
        index: u32,
    ) -> Result<win16_abi::SegmentedPointer, RuntimeError> {
        let start = self
            .selectors
            .pointer_from_far(base)
            .map_err(crate::runtime_error)?;
        self.selectors
            .add_bytes(start, index)
            .map_err(crate::runtime_error)
    }

    fn native_seek(
        &mut self,
        native: Win16HostMediaIoHandle,
        offset: i32,
        origin: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<i32, RuntimeError> {
        match host.win16_media_io(Operation::Seek {
            handle: native,
            offset,
            origin,
        })? {
            ResultValue::Transfer { result, bytes } if bytes.is_empty() => Ok(result),
            ResultValue::Transfer { .. } => Err(super::invariant(
                "mmioSeek returned unexpected output bytes",
            )),
            _ => Err(super::invariant(
                "mmioSeek returned the wrong host result shape",
            )),
        }
    }

    fn native_read(
        &mut self,
        native: Win16HostMediaIoHandle,
        count: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<Vec<u8>, ()>, RuntimeError> {
        let count =
            i32::try_from(count).map_err(|_| super::invariant("MMIO buffer read exceeds LONG"))?;
        match host.win16_media_io(Operation::Read {
            handle: native,
            count,
        })? {
            ResultValue::Transfer { result, bytes }
                if result >= 0
                    && bytes.len() == result as usize
                    && (result as u32) <= count as u32 =>
            {
                Ok(Ok(bytes))
            }
            ResultValue::Transfer { result, bytes } if result < 0 && bytes.is_empty() => {
                Ok(Err(()))
            }
            ResultValue::Transfer { .. } => Err(super::invariant(
                "mmioRead returned an inconsistent buffer fill",
            )),
            _ => Err(super::invariant(
                "mmioRead returned the wrong host result shape",
            )),
        }
    }

    fn native_write(
        &mut self,
        native: Win16HostMediaIoHandle,
        data: Vec<u8>,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<u32, ()>, RuntimeError> {
        let length = data.len() as u32;
        match host.win16_media_io(Operation::Write {
            handle: native,
            data,
        })? {
            ResultValue::Transfer { result, bytes } if bytes.is_empty() && result >= 0 => {
                Ok(Ok(result as u32))
            }
            ResultValue::Transfer { result, bytes } if bytes.is_empty() && result < 0 => {
                Ok(Err(()))
            }
            ResultValue::Transfer { .. } => Err(super::invariant(
                "mmioWrite returned unexpected output bytes",
            )),
            _ => Err(super::invariant(
                "mmioWrite returned the wrong host result shape",
            )),
        }
        .map(|result| result.map(|written| written.min(length)))
    }
}

fn can_read(open_flags: u32) -> bool {
    open_flags & 3 != MMIO_WRITE
}

fn can_write(open_flags: u32) -> bool {
    let mode = open_flags & 3;
    mode == MMIO_WRITE || mode == MMIO_READWRITE
}

fn far_add(base: u32, index: u32) -> Option<u32> {
    let sum = u32::from(base as u16).checked_add(index)?;
    if sum > MAX_BUFFER {
        return None;
    }
    Some((base & 0xFFFF_0000) | sum)
}

fn index_of(base: u32, size: u32, far: u32) -> Option<u32> {
    if far >> 16 != base >> 16 {
        return None;
    }
    let delta = u32::from(far as u16).checked_sub(u32::from(base as u16))?;
    if delta > size {
        return None;
    }
    Some(delta)
}

fn guest_code(error: RuntimeError, code: u32) -> Result<u32, RuntimeError> {
    if super::is_guest_api_failure(&error) {
        Ok(code)
    } else {
        Err(error)
    }
}

fn keep(first: &mut Option<RuntimeError>, error: RuntimeError) {
    if first.is_none() {
        *first = Some(error);
    }
}
