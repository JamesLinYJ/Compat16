//! DOC_INFO_1W preparation shared by the GDI and WNet byte-stream bridges.
use std::ptr;
use windows_sys::Win32::Graphics::Printing::{DOC_INFO_1W, PRINTER_HANDLE};

const RAW_DATATYPE: [u16; 4] = [b'R' as u16, b'A' as u16, b'W' as u16, 0];

pub(super) fn start_with(
    printer: PRINTER_HANDLE,
    document: Option<&[u16]>,
    start: impl FnOnce(PRINTER_HANDLE, u32, &DOC_INFO_1W) -> u32,
) -> u32 {
    let info = DOC_INFO_1W {
        pDocName: document.map_or(ptr::null_mut(), |value| value.as_ptr().cast_mut()),
        // The target port locates the Windows queue before this call. Treating
        // LPT1: as a modern output filename would change the guest operation.
        pOutputFile: ptr::null_mut(),
        // DDK WriteSpool supplies device-dependent data. RAW keeps the GDI and
        // WNet streams intact even when the queue's default processor is TEXT.
        pDatatype: RAW_DATATYPE.as_ptr().cast_mut(),
    };
    start(printer, 1, &info)
}

#[cfg(test)]
#[path = "win16_spool_document_tests.rs"]
mod spool_document_tests;
