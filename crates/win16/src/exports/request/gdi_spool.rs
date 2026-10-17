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
}
