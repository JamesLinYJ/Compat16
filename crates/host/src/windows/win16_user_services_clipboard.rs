//! Native clipboard adapter using owned byte copies at the Win16 boundary.
//!
//! Native HGLOBAL values are allocated here and transferred to User32 only
//! after SetClipboardData succeeds. GetClipboardData is copied while locked;
//! neither handle nor pointer escapes this worker adapter.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostClipboardData as Data,
    Win16HostClipboardOperation as Operation, Win16HostClipboardResult as ResultValue,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::{GlobalFree, HWND};
use windows_sys::Win32::System::DataExchange::{
    ChangeClipboardChain, CloseClipboard, CountClipboardFormats, EmptyClipboard,
    EnumClipboardFormats, GetClipboardData, GetClipboardOwner, GetClipboardSequenceNumber,
    GetClipboardViewer, GetOpenClipboardWindow, GetPriorityClipboardFormat,
    IsClipboardFormatAvailable, OpenClipboard, SetClipboardData, SetClipboardViewer,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock};
use windows_sys::Win32::System::Ole::{CF_OEMTEXT, CF_TEXT, CF_UNICODETEXT};

use super::win16_window_worker::{self as worker, WorkerState};

const GMEM_MOVEABLE: u32 = 0x0002;
const GMEM_ZEROINIT: u32 = 0x0040;
const MAX_CLIPBOARD_BYTES: usize = 16 * 1024 * 1024;

type SharedWorker = Rc<RefCell<WorkerState>>;

pub(super) fn execute(
    state: &SharedWorker,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    use Data as ClipboardData;
    use Operation as Call;
    use ResultValue as Result;

    let (ansi_codec, oem_codec) = {
        let worker = state.borrow();
        (worker.text_codec, worker.oem_text_codec)
    };
    let result = match operation {
        Call::Open { owner } => {
            let owner = match owner {
                Some(owner) => match native_window(state, owner) {
                    Some(hwnd) => hwnd,
                    None => return Ok(Result::Bool(false)),
                },
                None => std::ptr::null_mut(),
            };
            Result::Bool(unsafe { OpenClipboard(owner) != 0 })
        }
        Call::Close => Result::Bool(unsafe { CloseClipboard() != 0 }),
        Call::Empty => Result::Bool(unsafe { EmptyClipboard() != 0 }),
        Call::Owner => Result::Window(token_for_native(state, unsafe { GetClipboardOwner() })?),
        Call::SetData { format, data } => {
            let accepted = match data {
                ClipboardData::GlobalMemory(bytes) => {
                    set_global_data(ansi_codec, oem_codec, format, &bytes)?
                }
                // A null HGLOBAL requests delayed rendering. This adapter has
                // no WM_RENDERFORMAT guest callback route, so accepting the
                // native request would promise data that can never be rendered.
                ClipboardData::Delayed => false,
                ClipboardData::GdiObject(_) => false,
            };
            Result::SetData(accepted)
        }
        Call::GetData { format } => Result::Data(get_global_data(ansi_codec, oem_codec, format)?),
        Call::CountFormats => {
            Result::Count(unsafe { CountClipboardFormats() }.clamp(0, i32::from(u16::MAX)) as u16)
        }
        Call::EnumFormats { previous } => {
            // Enumeration reflects formats actually present on the native
            // clipboard. The CF_TEXT/CF_OEMTEXT compatibility views below
            // are lookup aliases to CF_UNICODETEXT, not synthetic enum items.
            Result::Format(unsafe { EnumClipboardFormats(u32::from(previous)) } as u16)
        }
        Call::RegisterFormat { name } => Result::Format(
            super::super::win16_registered_names::register_clipboard_format(
                ansi_codec,
                Some(&name),
            )?,
        ),
        Call::GetFormatName { format, capacity } => {
            let (bytes, copied) =
                super::super::win16_registered_names::clipboard_format_name_prefix(
                    ansi_codec,
                    format,
                    usize::from(capacity),
                )?;
            let copied = i16::try_from(copied).map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "guest clipboard format-name result exceeds Win16 signed range",
                    error,
                )
            })?;
            Result::FormatName { copied, bytes }
        }
        Call::IsFormatAvailable { format } => Result::Bool(unsafe {
            IsClipboardFormatAvailable(native_clipboard_format(format)) != 0
        }),
        Call::GetPriorityFormat { formats } => {
            let count = i32::try_from(formats.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::InvalidInput,
                    "Win16 clipboard format priority list is too long",
                    error,
                )
            })?;
            let mut formats32 = Vec::new();
            formats32
                .try_reserve_exact(formats.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "allocate Win16 clipboard priority list",
                        error,
                    )
                })?;
            formats32.extend(formats.iter().copied().map(native_clipboard_format));
            let pointer = if formats32.is_empty() {
                std::ptr::null()
            } else {
                formats32.as_ptr()
            };
            let native = unsafe { GetPriorityClipboardFormat(pointer, count) };
            let guest = if native > 0 {
                formats
                    .iter()
                    .zip(&formats32)
                    .find_map(|(guest, native_format)| {
                        (*native_format == native as u32).then_some(*guest)
                    })
                    .unwrap_or(native as u16)
            } else {
                native as u16
            };
            Result::PriorityFormat(guest as i16)
        }
        Call::SetViewer { viewer } => {
            let viewer = match viewer {
                Some(viewer) => match native_window(state, viewer) {
                    Some(hwnd) => hwnd,
                    None => return Ok(Result::Window(None)),
                },
                None => std::ptr::null_mut(),
            };
            Result::Window(token_for_native(state, unsafe {
                SetClipboardViewer(viewer)
            })?)
        }
        Call::GetViewer => {
            Result::Window(token_for_native(state, unsafe { GetClipboardViewer() })?)
        }
        Call::GetOpenClipboardWindow => Result::Window(token_for_native(state, unsafe {
            GetOpenClipboardWindow()
        })?),
        Call::ChangeViewerChain { remove, next } => {
            let Some(remove) = native_window(state, remove) else {
                return Ok(Result::Bool(false));
            };
            let next = match next {
                Some(next) => match native_window(state, next) {
                    Some(hwnd) => hwnd,
                    None => return Ok(Result::Bool(false)),
                },
                None => std::ptr::null_mut(),
            };
            Result::Bool(unsafe { ChangeClipboardChain(remove, next) != 0 })
        }
    };
    let sequence = unsafe { GetClipboardSequenceNumber() };
    Ok(Result::Sequenced {
        sequence,
        result: Box::new(result),
    })
}

fn set_global_data(
    ansi_codec: super::super::guest_text::GuestTextCodec,
    oem_codec: super::super::guest_text::GuestTextCodec,
    format: u16,
    bytes: &[u8],
) -> Result<bool, RuntimeError> {
    if bytes.len() > MAX_CLIPBOARD_BYTES {
        return Ok(false);
    }
    let native_format = native_clipboard_format(format);
    let converted = if is_guest_legacy_text_format(format) {
        let codec = clipboard_text_codec(format, ansi_codec, oem_codec);
        match guest_clipboard_text_to_unicode(codec, bytes)? {
            Some(converted) => converted,
            None => return Ok(false),
        }
    } else {
        Vec::new()
    };
    let bytes = if is_guest_legacy_text_format(format) {
        converted.as_slice()
    } else {
        bytes
    };
    let size = bytes.len().max(1);
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size) };
    if memory.is_null() {
        return Ok(false);
    }
    let destination = unsafe { GlobalLock(memory) };
    if destination.is_null() {
        unsafe {
            GlobalFree(memory);
        }
        return Ok(false);
    }
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast::<u8>(), bytes.len());
        }
    }
    unsafe {
        GlobalUnlock(memory);
    }
    let transferred =
        unsafe { SetClipboardData(native_format, memory.cast::<core::ffi::c_void>()) };
    if transferred.is_null() {
        unsafe {
            GlobalFree(memory);
        }
        Ok(false)
    } else {
        // The clipboard now owns `memory`; freeing it here would invalidate
        // the newly published clipboard data.
        Ok(true)
    }
}

fn get_global_data(
    ansi_codec: super::super::guest_text::GuestTextCodec,
    oem_codec: super::super::guest_text::GuestTextCodec,
    format: u16,
) -> Result<Option<Data>, RuntimeError> {
    let native = unsafe { GetClipboardData(native_clipboard_format(format)) };
    if native.is_null() {
        return Ok(None);
    }
    let size = unsafe { GlobalSize(native.cast()) };
    if size > MAX_CLIPBOARD_BYTES {
        return Ok(None);
    }
    if size == 0 {
        if is_guest_legacy_text_format(format) {
            return native_clipboard_text_to_guest(
                clipboard_text_codec(format, ansi_codec, oem_codec),
                Vec::new(),
            )
            .map(|bytes| bytes.map(Data::GlobalMemory));
        }
        return Ok(Some(Data::GlobalMemory(Vec::new())));
    }
    let source = unsafe { GlobalLock(native.cast()) };
    if source.is_null() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    if let Err(error) = bytes.try_reserve_exact(size) {
        unsafe {
            GlobalUnlock(native.cast());
        }
        return Err(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy native clipboard global block",
            error,
        ));
    }
    bytes.resize(size, 0);
    unsafe {
        std::ptr::copy_nonoverlapping(source.cast::<u8>(), bytes.as_mut_ptr(), size);
    }
    unsafe {
        GlobalUnlock(native.cast());
    }
    if is_guest_legacy_text_format(format) {
        return native_clipboard_text_to_guest(
            clipboard_text_codec(format, ansi_codec, oem_codec),
            bytes,
        )
        .map(|bytes| bytes.map(Data::GlobalMemory));
    }
    Ok(Some(Data::GlobalMemory(bytes)))
}

fn is_guest_legacy_text_format(format: u16) -> bool {
    format == CF_TEXT || format == CF_OEMTEXT
}

fn clipboard_text_codec(
    format: u16,
    ansi_codec: super::super::guest_text::GuestTextCodec,
    oem_codec: super::super::guest_text::GuestTextCodec,
) -> super::super::guest_text::GuestTextCodec {
    if format == CF_OEMTEXT {
        oem_codec
    } else {
        ansi_codec
    }
}

// Win16 CF_TEXT and CF_OEMTEXT are guest-side views over one native Unicode
// text block. Read/write/availability queries translate either ID; format
// enumeration above intentionally preserves the native IDs that Windows owns.
fn native_clipboard_format(format: u16) -> u32 {
    if is_guest_legacy_text_format(format) {
        u32::from(CF_UNICODETEXT)
    } else {
        u32::from(format)
    }
}

fn guest_clipboard_text_to_unicode(
    codec: super::super::guest_text::GuestTextCodec,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let wide = codec.to_wide_z(&bytes[..end])?;
    let size = wide
        .len()
        .checked_mul(2)
        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted, "size Unicode clipboard text"))?;
    if size > MAX_CLIPBOARD_BYTES {
        return Ok(None);
    }
    let mut result = Vec::new();
    result.try_reserve_exact(size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Unicode clipboard text",
            error,
        )
    })?;
    for unit in wide {
        result.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(Some(result))
}

fn native_clipboard_text_to_guest(
    codec: super::super::guest_text::GuestTextCodec,
    bytes: Vec<u8>,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    if bytes.is_empty() {
        return Ok(Some(vec![0]));
    }
    if bytes.len() % 2 != 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "native CF_UNICODETEXT global block has an odd byte length",
        ));
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(bytes.len() / 2).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "decode native Unicode clipboard text",
            error,
        )
    })?;
    wide.extend(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    );
    let Some(end) = wide.iter().position(|unit| *unit == 0) else {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "native CF_UNICODETEXT global block has no UTF-16 terminator",
        ));
    };
    let mut encoded = codec.from_wide(&wide[..end])?.bytes;
    if encoded.len() >= MAX_CLIPBOARD_BYTES {
        return Ok(None);
    }
    encoded.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "terminate guest clipboard text",
            error,
        )
    })?;
    encoded.push(0);
    Ok(Some(encoded))
}

fn native_window(state: &SharedWorker, token: Win16HostWindow) -> Option<HWND> {
    state.borrow().windows.get(&token).copied()
}

fn token_for_native(
    state: &SharedWorker,
    native: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if native.is_null() {
        return Ok(None);
    }
    worker::token_for_native(state, native).map(Some)
}
