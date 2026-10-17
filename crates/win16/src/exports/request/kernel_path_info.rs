//! KERNEL path-query arguments. Output FAR values remain raw until a result
//! determines whether the guest buffer is used by the Win16 contract.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelPathInfoRequest {
    /// Raw char bits: low seven bits select a drive and bit 7 forces it.
    GetTempDrive { drive: u8 },
    /// Keep the raw output address until runtime knows whether the caller's
    /// capacity is large enough to require an actual guest-memory write.
    GetWindowsDirectory { output: u32, capacity: u16 },
    GetSystemDirectory { output: u32, capacity: u16 },
    GetTempFileName {
        drive: u8,
        prefix: Option<Vec<u8>>,
        unique: u16,
        output: u32,
    },
    /// Long path bytes stay guest ANSI/DBCS. The output address is raw until
    /// the short-path length is known, so a short buffer is not written.
    GetShortPathName {
        long_path: Option<Vec<u8>>,
        output: u32,
        capacity: u16,
    },
}
