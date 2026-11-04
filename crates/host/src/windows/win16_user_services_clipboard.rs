//! Native clipboard adapter using owned byte copies at the Win16 boundary.
//!
//! Native HGLOBAL values are allocated here and transferred to User32 only
//! after SetClipboardData succeeds. GetClipboardData is copied while locked;
//! neither handle nor pointer escapes this worker adapter.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostClipboardData as Data,
    Win16HostClipboardOperation as Operation, Win16HostClipboardResult as ResultValue,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::{GlobalFree, HWND};
use windows_sys::Win32::System::DataExchange::{
    ChangeClipboardChain, CloseClipboard, EmptyClipboard,
    EnumClipboardFormats, GetClipboardData, GetClipboardOwner, GetClipboardSequenceNumber,
    GetUpdatedClipboardFormats,
    GetClipboardViewer, GetOpenClipboardWindow, IsClipboardFormatAvailable, OpenClipboard,
    SetClipboardData, SetClipboardViewer,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock};
use windows_sys::Win32::System::Ole::{CF_LOCALE, CF_OEMTEXT, CF_TEXT, CF_UNICODETEXT};

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
            // SAFETY: OpenClipboard opens the clipboard for this thread.
            Result::Bool(unsafe { OpenClipboard(owner) != 0 })
        }
        // SAFETY: CloseClipboard closes the clipboard this thread opened.
        Call::Close => Result::Bool(unsafe { CloseClipboard() != 0 }),
        Call::Empty => {
            // SAFETY: EmptyClipboard clears the clipboard this thread opened.
            let emptied = unsafe { EmptyClipboard() != 0 };
            if emptied {
                clear_guest_text_format();
            }
            Result::Bool(emptied)
        }
        // SAFETY: `GetClipboardOwner` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
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
            if accepted {
                if is_guest_legacy_text_format(format) {
                    note_guest_text_format(format);
                } else {
                    note_clipboard_contents_changed();
                }
            }
            Result::SetData(accepted)
        }
        Call::GetData { format } => {
            // CF_UNICODETEXT and CF_LOCALE are Win32 formats. A Win3.1 caller
            // reads text through CF_TEXT or CF_OEMTEXT.
            if format == CF_UNICODETEXT || format == CF_LOCALE {
                Result::Data(None)
            } else {
                Result::Data(get_global_data(ansi_codec, oem_codec, format)?)
            }
        }
        Call::CountFormats => Result::Count(guest_format_count()),
        Call::EnumFormats { previous } => Result::Format(next_guest_format(previous)?),
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
        Call::IsFormatAvailable { format } => Result::Bool(guest_format_available(format)),
        Call::GetPriorityFormat { formats } => {
            // Programmer's Reference: the first listed format that is present,
            // NULL when the clipboard is empty, and -1 when it holds data in
            // none of the requested formats.
            let value = if let Some(format) = formats
                .into_iter()
                .find(|format| guest_format_available(*format))
            {
                format as i16
            } else if guest_format_count() == 0 {
                0
            } else {
                -1
            };
            Result::PriorityFormat(value)
        }
        Call::SetViewer { viewer } => {
            let viewer = match viewer {
                Some(viewer) => match native_window(state, viewer) {
                    Some(hwnd) => hwnd,
                    None => return Ok(Result::Window(None)),
                },
                None => std::ptr::null_mut(),
            };
            // SAFETY: `SetClipboardViewer` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            Result::Window(token_for_native(state, unsafe {
                SetClipboardViewer(viewer)
            })?)
        }
        Call::GetViewer => {
            // SAFETY: `GetClipboardViewer` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            Result::Window(token_for_native(state, unsafe { GetClipboardViewer() })?)
        }
        // SAFETY: `GetOpenClipboardWindow` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
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
            // SAFETY: `ChangeClipboardChain` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            Result::Bool(unsafe { ChangeClipboardChain(remove, next) != 0 })
        }
    };
    // SAFETY: `GetClipboardSequenceNumber` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
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
    // SAFETY: GlobalAlloc returns a new HGLOBAL or null. The pointer is not a guest address.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size) };
    if memory.is_null() {
        return Ok(false);
    }
    // SAFETY: GlobalLock locks an HGLOBAL this owner holds and returns a pointer valid until GlobalUnlock.
    let destination = unsafe { GlobalLock(memory) };
    if destination.is_null() {
        // SAFETY: GlobalFree releases an HGLOBAL this owner holds.
        unsafe {
            GlobalFree(memory);
        }
        return Ok(false);
    }
    if !bytes.is_empty() {
        // SAFETY: The source and destination are non-overlapping, and both spans were checked to cover the copied length.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast::<u8>(), bytes.len());
        }
    }
    // SAFETY: GlobalUnlock balances one GlobalLock on this HGLOBAL.
    unsafe {
        GlobalUnlock(memory);
    }
    let transferred =
        // SAFETY: SetClipboardData transfers an HGLOBAL this owner allocated.
        unsafe { SetClipboardData(native_format, memory.cast::<core::ffi::c_void>()) };
    if transferred.is_null() {
        // SAFETY: GlobalFree releases an HGLOBAL this owner holds.
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
    // SAFETY: GetClipboardData returns a handle valid until the clipboard is closed.
    let native = unsafe { GetClipboardData(native_clipboard_format(format)) };
    if native.is_null() {
        return Ok(None);
    }
    // SAFETY: `GlobalSize` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
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
    // SAFETY: GlobalLock locks an HGLOBAL this owner holds and returns a pointer valid until GlobalUnlock.
    let source = unsafe { GlobalLock(native.cast()) };
    if source.is_null() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    if let Err(error) = bytes.try_reserve_exact(size) {
        // SAFETY: GlobalUnlock balances one GlobalLock on this HGLOBAL.
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
    // SAFETY: The source and destination are non-overlapping, and both spans were checked to cover the copied length.
    unsafe {
        std::ptr::copy_nonoverlapping(source.cast::<u8>(), bytes.as_mut_ptr(), size);
    }
    // SAFETY: GlobalUnlock balances one GlobalLock on this HGLOBAL.
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

/// The Win16 text format this worker last placed, with the clipboard sequence
/// observed after that placement. A later host change advances the sequence
/// and the recorded format is no longer the placed Win3.1 format.
#[derive(Clone, Copy)]
struct GuestTextPlacement {
    format: u16,
    sequence: u32,
}

thread_local! {
    static GUEST_TEXT_PLACEMENT: Cell<Option<GuestTextPlacement>> = Cell::new(None);
}

fn note_guest_text_format(format: u16) {
    // SAFETY: GetClipboardSequenceNumber takes no pointers.
    let sequence = unsafe { GetClipboardSequenceNumber() };
    GUEST_TEXT_PLACEMENT.with(|slot| {
        slot.set(Some(GuestTextPlacement { format, sequence }));
    });
}

fn note_clipboard_contents_changed() {
    // SAFETY: GetClipboardSequenceNumber takes no pointers.
    let sequence = unsafe { GetClipboardSequenceNumber() };
    GUEST_TEXT_PLACEMENT.with(|slot| {
        if let Some(mut placed) = slot.get() {
            placed.sequence = sequence;
            slot.set(Some(placed));
        }
    });
}

fn clear_guest_text_format() {
    GUEST_TEXT_PLACEMENT.with(|slot| slot.set(None));
}

fn placed_guest_text_format() -> Option<u16> {
    let placed = GUEST_TEXT_PLACEMENT.with(|slot| slot.get())?;
    // SAFETY: GetClipboardSequenceNumber takes no pointers.
    let sequence = unsafe { GetClipboardSequenceNumber() };
    (sequence == placed.sequence && is_guest_legacy_text_format(placed.format))
        .then_some(placed.format)
}

fn native_format_available(format: u16) -> bool {
    // SAFETY: IsClipboardFormatAvailable takes a format integer and no pointers.
    unsafe { IsClipboardFormatAvailable(u32::from(format)) != 0 }
}

/// Win3.1 synthesizes `CF_TEXT` and `CF_OEMTEXT` from each other. Win32 also
/// synthesizes `CF_UNICODETEXT` and adds `CF_LOCALE` when the clipboard
/// closes. Those two are not Windows 3.1 formats (`WINDOWS.H` stops the
/// predefined list at `CF_WAVE`).
fn guest_format_available(format: u16) -> bool {
    if is_guest_legacy_text_format(format) {
        return native_format_available(CF_TEXT)
            || native_format_available(CF_OEMTEXT)
            || native_format_available(CF_UNICODETEXT);
    }
    if format == CF_UNICODETEXT || format == CF_LOCALE {
        return false;
    }
    native_format_available(format)
}

// CountClipboardFormats may be called without opening the clipboard, whereas
// EnumClipboardFormats requires it to be open. GetUpdatedClipboardFormats
// supplies a snapshot without changing clipboard ownership.
fn guest_format_count() -> u16 {
    const MAX_SNAPSHOT_FORMATS: u32 = 1_000_000;
    const SNAPSHOT_ATTEMPTS: usize = 4;
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

    for _ in 0..SNAPSHOT_ATTEMPTS {
        let mut required = 0u32;
        // SAFETY: A null buffer and zero capacity request only the format count.
        let ok = unsafe {
            GetUpdatedClipboardFormats(std::ptr::null_mut(), 0, &mut required)
        } != 0;
        let error = crate::windows::win32_safe::last_error();
        if !ok && error != ERROR_INSUFFICIENT_BUFFER {
            return 0;
        }
        if required == 0 {
            return 0;
        }
        // Avoid uncontrolled allocation from an externally owned clipboard.
        if required > MAX_SNAPSHOT_FORMATS {
            return 0;
        }
        let mut formats = Vec::<u32>::new();
        if formats.try_reserve_exact(required as usize).is_err() {
            return 0;
        }
        formats.resize(required as usize, 0);
        let mut returned = 0u32;
        // SAFETY: The vector owns required initialized UINT slots; returned is
        // a writable local. Neither pointer escapes the synchronous call.
        let ok = unsafe {
            GetUpdatedClipboardFormats(formats.as_mut_ptr(), required, &mut returned)
        } != 0;
        if !ok {
            if crate::windows::win32_safe::last_error() == ERROR_INSUFFICIENT_BUFFER {
                continue;
            }
            return 0;
        }
        if returned > required {
            return 0;
        }
        let mut count = 0u32;
        let mut saw_text = false;
        for &raw in &formats[..returned as usize] {
            let Ok(format) = u16::try_from(raw) else { continue; };
            if format == CF_LOCALE {
                continue;
            }
            if is_guest_legacy_text_format(format) || format == CF_UNICODETEXT {
                if !saw_text {
                    count = count.saturating_add(2);
                    saw_text = true;
                }
            } else {
                count = count.saturating_add(1);
            }
        }
        return count.min(u32::from(u16::MAX)) as u16;
    }
    // A rapidly changing clipboard never yielded a complete snapshot.
    0
}

fn next_guest_format(previous: u16) -> Result<u16, RuntimeError> {
    let formats = win31_clipboard_formats()?;
    if previous == 0 {
        return Ok(formats.first().copied().unwrap_or(0));
    }
    Ok(formats
        .iter()
        .position(|format| *format == previous)
        .and_then(|index| formats.get(index + 1).copied())
        .unwrap_or(0))
}

fn win31_clipboard_formats() -> Result<Vec<u16>, RuntimeError> {
    const MAX_SNAPSHOT_FORMATS: usize = 1_000_000;
    let mut native = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut previous = 0u32;
    loop {
        // SAFETY: EnumClipboardFormats takes a format id and no guest address.
        // It fails with zero when this thread does not have the clipboard open.
        let next = unsafe { EnumClipboardFormats(previous) };
        if next == 0 || seen.contains(&next) {
            break;
        }
        if seen.len() >= MAX_SNAPSHOT_FORMATS {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "native clipboard format list exceeds the snapshot limit"));
        }
        seen.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "track native clipboard format identifiers", error))?;
        seen.insert(next);
        let Ok(id) = u16::try_from(next) else {
            previous = next;
            continue;
        };
        native.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "enumerate native clipboard formats", error))?;
        native.push(id);
        previous = next;
    }
    project_win31_formats(&native, placed_guest_text_format())
}

/// The format placed by the guest comes first. Win32 CF_UNICODETEXT is host
/// storage and is projected to the two guest legacy text views.
fn project_win31_formats(
    native: &[u16],
    placed_text: Option<u16>,
) -> Result<Vec<u16>, RuntimeError> {
    let mut guest = Vec::new();
    guest.try_reserve(native.len().saturating_add(2)).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "project Win16 clipboard formats", error))?;
    let (primary, _) = win31_text_pair(native, placed_text);
    let mut emitted_text = false;
    let mut emitted_oem = false;
    for &format in native {
        if format == CF_LOCALE {
            continue;
        }
        if format == CF_UNICODETEXT {
            // Represent native Unicode by one guest text view at this position.
            // Preserve later guest-representable formats in native order.
            if !emitted_text && !emitted_oem {
                guest.push(primary);
                emitted_text = primary == CF_TEXT;
                emitted_oem = primary == CF_OEMTEXT;
            }
            continue;
        }
        if format == CF_TEXT {
            if !emitted_text {
                guest.push(format);
                emitted_text = true;
            }
            continue;
        }
        if format == CF_OEMTEXT {
            if !emitted_oem {
                guest.push(format);
                emitted_oem = true;
            }
            continue;
        }
        guest.push(format);
    }
    // Add only a missing conversion view after the native enumeration,
    // so intervening formats retain their relative priority.
    if emitted_text && !emitted_oem {
        guest.push(CF_OEMTEXT);
    } else if emitted_oem && !emitted_text {
        guest.push(CF_TEXT);
    }
    Ok(guest)
}

fn win31_text_pair(native: &[u16], placed_text: Option<u16>) -> (u16, u16) {
    let primary = placed_text
        .filter(|format| is_guest_legacy_text_format(*format))
        .or_else(|| {
            native
                .iter()
                .copied()
                .find(|format| is_guest_legacy_text_format(*format))
        })
        .unwrap_or(CF_TEXT);
    if primary == CF_OEMTEXT {
        (CF_OEMTEXT, CF_TEXT)
    } else {
        (CF_TEXT, CF_OEMTEXT)
    }
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
// text block. Read and write translate either ID. Enumeration, counts, and
// availability above present only the two Win3.1 formats.
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
