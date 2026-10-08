//! Borrowed PE metadata for optional module-search observations.

use object::endian::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, PeFile32, PeFile64};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeHeaderKind {
    Pe32,
    Pe32Plus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeImageHeader {
    pub kind: PeHeaderKind,
    pub machine: u16,
    pub is_dll: bool,
}

/// Inspect bytes already owned by the module search, without loading code.
/// Unrecognized or malformed files have no validated PE header observation;
/// the real guest loader remains responsible for its detailed failure.
pub fn inspect_pe_header(bytes: &[u8]) -> Option<PeImageHeader> {
    // Reuse object for both header widths. Diagnostic inspection must not
    // recreate a PE wire reader or make a native image into guest code.
    match object::FileKind::parse(bytes).ok()? {
        object::FileKind::Pe32 => {
            let file = PeFile32::parse(bytes).ok()?;
            Some(metadata(PeHeaderKind::Pe32, file.nt_headers()))
        }
        object::FileKind::Pe64 => {
            let file = PeFile64::parse(bytes).ok()?;
            Some(metadata(PeHeaderKind::Pe32Plus, file.nt_headers()))
        }
        _ => None,
    }
}

fn metadata(kind: PeHeaderKind, headers: &impl ImageNtHeaders) -> PeImageHeader {
    let file = headers.file_header();
    PeImageHeader {
        kind,
        machine: file.machine.get(LE).0,
        is_dll: file.characteristics.get(LE).0 & object::pe::IMAGE_FILE_DLL.0 != 0,
    }
}
