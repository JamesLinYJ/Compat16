//! Decoded GDI spool-job calls with copied Win16 input bytes.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiSpoolRequest {
    OpenJob {
        output_target: Vec<u8>,
        document_name: Vec<u8>,
        legacy_argument: u16,
    },
    WriteSpool {
        job: u16,
        byte_count: i16,
        bytes: Vec<u8>,
    },
    CloseJob {
        job: u16,
    },
    DeleteJob {
        job: u16,
        legacy_argument: i16,
    },
    StartSpoolPage {
        job: u16,
    },
    EndSpoolPage {
        job: u16,
    },
    /// Counted environment bytes. `None` is a null pointer or a zero count,
    /// both of which leave the guest pointer unread.
    SetEnvironment {
        port: Option<Vec<u8>>,
        environment: Option<Vec<u8>>,
        capacity: u16,
    },
    /// `environment` is a guest far address. Zero asks for the stored size
    /// and does not name an output buffer.
    GetEnvironment {
        port: Option<Vec<u8>>,
        environment: u32,
        capacity: u16,
    },
    /// `dc` is a guest HDC word. `code` is the abort-procedure code, not a pointer.
    QueryAbort {
        dc: u16,
        code: i16,
    },
}
