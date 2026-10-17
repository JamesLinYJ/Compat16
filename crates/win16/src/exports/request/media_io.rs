//! Synchronous Win16 MMIO requests and fixed MMCKINFO16 conversion.

use zerocopy::byteorder::little_endian::U32;
use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MMCKINFO16_SIZE: usize = 20;
pub const MMIOINFO16_SIZE: usize = 66;
pub const MMIOINFO16_ERROR_OFFSET: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MediaIoRequest {
    Open { path_far: u32, info: u32, flags: u32 },
    Close { handle: u16, flags: u16 },
    Read { handle: u16, buffer: u32, count: i32 },
    Write { handle: u16, buffer: u32, count: i32 },
    Seek { handle: u16, offset: i32, origin: i16 },
    Flush { handle: u16, flags: u16 },
    StringToFourCc { text: Option<Vec<u8>>, flags: u16 },
    Descend { handle: u16, chunk: u32, parent: u32, flags: u16 },
    Ascend { handle: u16, chunk: u32, flags: u16 },
    CreateChunk { handle: u16, chunk: u32, flags: u16 },
    Rename { old_path: Vec<u8>, new_path: Vec<u8>, info: u32, flags: u32 },
    GetInfo { handle: u16, info: u32, flags: u16 },
    SetInfo { handle: u16, info: u32, flags: u16 },
    SetBuffer { handle: u16, buffer: u32, size: i32, flags: u16 },
    Advance { handle: u16, info: u32, flags: u16 },
    InstallIoProc { fourcc: u32, procedure: u32, flags: u32 },
    SendMessage { handle: u16, message: u16, param1: i32, param2: i32 },
}

/// SDK 3.1 `MMIOINFO` as a 66-byte packed guest record.
///
/// Pointer fields are guest `selector:offset` values. They are never host addresses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Win16MmioInfo16 {
    pub flags: u32,
    pub io_proc_id: u32,
    pub io_proc: u32,
    pub error: u16,
    pub task: u16,
    pub buffer_size: i32,
    pub buffer: u32,
    pub next: u32,
    pub end_read: u32,
    pub end_write: u32,
    pub buffer_offset: i32,
    pub disk_offset: i32,
    pub info: [u32; 3],
    pub reserved_1: u32,
    pub reserved_2: u32,
    pub handle: u16,
}

/// The five DWORDs in the SDK 3.1 `MMCKINFO` record, without native padding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Win16MmckInfo16 {
    pub chunk_id: u32,
    pub chunk_size: u32,
    pub form_type: u32,
    pub data_offset: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MmckInfo16Wire {
    chunk_id: U32,
    chunk_size: U32,
    form_type: U32,
    data_offset: U32,
    flags: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MmioInfo16Wire {
    flags: U32,
    io_proc_id: U32,
    io_proc: U32,
    error: U16,
    task: U16,
    buffer_size: U32,
    buffer: U32,
    next: U32,
    end_read: U32,
    end_write: U32,
    buffer_offset: U32,
    disk_offset: U32,
    info: [U32; 3],
    reserved_1: U32,
    reserved_2: U32,
    handle: U16,
}

impl Win16MmioInfo16 {
    /// Convert the fixed Win16 little-endian record to an owned host-neutral value.
    pub fn decode(bytes: &[u8; MMIOINFO16_SIZE]) -> Self {
        let wire: MmioInfo16Wire = zerocopy::transmute!(*bytes);
        Self {
            flags: wire.flags.get(),
            io_proc_id: wire.io_proc_id.get(),
            io_proc: wire.io_proc.get(),
            error: wire.error.get(),
            task: wire.task.get(),
            buffer_size: wire.buffer_size.get() as i32,
            buffer: wire.buffer.get(),
            next: wire.next.get(),
            end_read: wire.end_read.get(),
            end_write: wire.end_write.get(),
            buffer_offset: wire.buffer_offset.get() as i32,
            disk_offset: wire.disk_offset.get() as i32,
            info: [wire.info[0].get(), wire.info[1].get(), wire.info[2].get()],
            reserved_1: wire.reserved_1.get(),
            reserved_2: wire.reserved_2.get(),
            handle: wire.handle.get(),
        }
    }

    /// Encode an exact 66-byte guest `MMIOINFO` record.
    pub fn encode(self) -> [u8; MMIOINFO16_SIZE] {
        zerocopy::transmute!(MmioInfo16Wire {
            flags: U32::new(self.flags),
            io_proc_id: U32::new(self.io_proc_id),
            io_proc: U32::new(self.io_proc),
            error: U16::new(self.error),
            task: U16::new(self.task),
            buffer_size: U32::new(self.buffer_size as u32),
            buffer: U32::new(self.buffer),
            next: U32::new(self.next),
            end_read: U32::new(self.end_read),
            end_write: U32::new(self.end_write),
            buffer_offset: U32::new(self.buffer_offset as u32),
            disk_offset: U32::new(self.disk_offset as u32),
            info: [U32::new(self.info[0]), U32::new(self.info[1]), U32::new(self.info[2])],
            reserved_1: U32::new(self.reserved_1),
            reserved_2: U32::new(self.reserved_2),
            handle: U16::new(self.handle),
        })
    }
}

impl Win16MmckInfo16 {
    /// Convert the fixed Win16 little-endian record to an owned host-neutral value.
    pub fn decode(bytes: &[u8; MMCKINFO16_SIZE]) -> Self {
        let wire: MmckInfo16Wire = zerocopy::transmute!(*bytes);
        Self {
            chunk_id: wire.chunk_id.get(),
            chunk_size: wire.chunk_size.get(),
            form_type: wire.form_type.get(),
            data_offset: wire.data_offset.get(),
            flags: wire.flags.get(),
        }
    }

    /// Encode an exact 20-byte guest `MMCKINFO` record.
    pub fn encode(self) -> [u8; MMCKINFO16_SIZE] {
        // The SDK record is five consecutive DWORDs. The private zerocopy wire
        // type avoids host alignment and endianness assumptions at this ABI.
        zerocopy::transmute!(MmckInfo16Wire {
            chunk_id: U32::new(self.chunk_id),
            chunk_size: U32::new(self.chunk_size),
            form_type: U32::new(self.form_type),
            data_offset: U32::new(self.data_offset),
            flags: U32::new(self.flags),
        })
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmckInfo16Wire>() == MMCKINFO16_SIZE);
    assert!(core::mem::align_of::<MmckInfo16Wire>() == 1);
    assert!(core::mem::offset_of!(MmckInfo16Wire, chunk_id) == 0);
    assert!(core::mem::offset_of!(MmckInfo16Wire, chunk_size) == 4);
    assert!(core::mem::offset_of!(MmckInfo16Wire, form_type) == 8);
    assert!(core::mem::offset_of!(MmckInfo16Wire, data_offset) == 12);
    assert!(core::mem::offset_of!(MmckInfo16Wire, flags) == 16);
    assert!(core::mem::size_of::<MmioInfo16Wire>() == MMIOINFO16_SIZE);
    assert!(core::mem::align_of::<MmioInfo16Wire>() == 1);
    assert!(core::mem::offset_of!(MmioInfo16Wire, error) == MMIOINFO16_ERROR_OFFSET);
    assert!(core::mem::offset_of!(MmioInfo16Wire, buffer) == 20);
    assert!(core::mem::offset_of!(MmioInfo16Wire, next) == 24);
    assert!(core::mem::offset_of!(MmioInfo16Wire, end_read) == 28);
    assert!(core::mem::offset_of!(MmioInfo16Wire, end_write) == 32);
    assert!(core::mem::offset_of!(MmioInfo16Wire, handle) == 64);
};
