//! Typed LZEXPAND file API arguments; HFILEs share the guest DOS handle space.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16LzExpandRequest {
    LzCopy { source: i16, destination: i16 },
    LzOpenFile { path: Vec<u8>, ofstruct: u32, style: u16 },
    LzInit { file: i16 },
    LzSeek { file: i16, offset: i32, origin: u16 },
    LzRead { file: i16, output: u32, count: u16 },
    LzClose { file: i16 },
    LzStart,
    LzCopyFile { source: i16, destination: i16 },
    LzDone,
    LzGetExpandedName { source: Vec<u8>, output: u32 },
}
