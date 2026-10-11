//! Native USER cursor, accelerator, and WinHelp operations on the USER worker.

use std::cell::RefCell;
use std::rc::Rc;

use crate::windows::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostAccelEntry, Win16HostAccelerator,
    Win16HostHelpData, Win16HostUserCursorAcceleratorOperation as Operation,
    Win16HostUserCursorAcceleratorResult as ResultValue, Win16MessageParam, Win16MessageSource,
};
use windows_sys::Win32::Foundation::{GetLastError, HWND, POINT, SetLastError};
use windows_sys::Win32::UI::Shell::{HELPWININFOW, MULTIKEYHELPW, WinHelpW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    ACCEL, CreateAcceleratorTableW, DestroyAcceleratorTable, GetCursor, HCURSOR, IsWindow, MSG, SetCursor,
    ShowCursor, TranslateAcceleratorW,
};

use super::win16_window_worker::WorkerState;

const ACCEL_FVIRTKEY: u8 = 0x01;

/// Owns native HACCEL values exclusively on the USER worker thread. Guest
/// resource tables live until the task's worker shuts down, matching the SDK
/// 3.1 LoadAccelerators lifetime contract.
pub(super) struct Win16AcceleratorTables {
    tables: Vec<(Win16HostAccelerator, usize)>,
    next_token: u64,
}

impl Default for Win16AcceleratorTables {
    fn default() -> Self {
        Self::new()
    }
}

impl Win16AcceleratorTables {
    pub(super) fn new() -> Self {
        Self {
            tables: Vec::new(),
            next_token: 1,
        }
    }

    pub(super) fn create(
        &mut self,
        entries: &[Win16HostAccelEntry],
        text_codec: GuestTextCodec,
    ) -> Result<Option<Win16HostAccelerator>, RuntimeError> {
        if entries.is_empty() {
            return Ok(None);
        }
        let count = i32::try_from(entries.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 accelerator table exceeds native count width",
                error,
            )
        })?;
        let token = Win16HostAccelerator(self.next_token);
        let next_token = self.next_token.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host accelerator identities are exhausted",
            )
        })?;
        if self.tables.iter().any(|(existing, _)| *existing == token) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 host accelerator identity was already allocated",
            ));
        }
        self.tables.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a native Win16 accelerator table slot",
                error,
            )
        })?;
        let mut native_entries = Vec::new();
        native_entries
            .try_reserve_exact(entries.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native Win16 accelerator entries",
                    error,
                )
            })?;
        for entry in entries {
            // The host ACCEL is constructed field by field. The guest's packed
            // five-byte records are never reinterpreted as native structures.
            native_entries.push(ACCEL {
                fVirt: entry.flags,
                key: native_accelerator_key(text_codec, entry.flags, entry.key)?,
                cmd: entry.command,
            });
        }
        // SAFETY: the vector contains `count` initialized native ACCEL values
        // and remains alive for this synchronous USER call.
        let native = unsafe { CreateAcceleratorTableW(native_entries.as_ptr(), count) };
        if native.is_null() {
            return Ok(None);
        }
        // Token arithmetic and both Rust allocations are complete before the
        // native resource is created; this push therefore publishes without
        // allocating or needing a compensating native destroy.
        self.tables.push((token, native as usize));
        self.next_token = next_token;
        Ok(Some(token))
    }

    pub(super) fn native(
        &self,
        token: Win16HostAccelerator,
    ) -> Option<windows_sys::Win32::UI::WindowsAndMessaging::HACCEL> {
        self.tables
            .iter()
            .find_map(|(candidate, handle)| (*candidate == token).then_some(*handle as _))
    }
}

fn native_accelerator_key(
    text_codec: GuestTextCodec,
    flags: u8,
    key: u16,
) -> Result<u16, RuntimeError> {
    if flags & ACCEL_FVIRTKEY != 0 {
        return Ok(key);
    }

    // Win16 character keys occupy one byte, or two little-endian guest bytes
    // for a DBCS character. W ACCEL entries instead require one UTF-16 code
    // unit; decode only through the executable's fixed guest codec.
    let encoded = key.to_le_bytes();
    let guest_byte_count = if key <= u16::from(u8::MAX) { 1 } else { 2 };
    let wide = text_codec
        .to_wide(&encoded[..guest_byte_count])
        .map_err(|error| error.with_context(format!(
            "decode Win16 character accelerator key 0x{key:04X} using the guest code page",
        )))?;
    if wide.len() != 1 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!(
                "Win16 character accelerator key 0x{key:04X} does not decode to one UTF-16 code unit",
            ),
        ));
    }
    Ok(wide[0])
}

impl Drop for Win16AcceleratorTables {
    fn drop(&mut self) {
        for (_, native) in std::mem::take(&mut self.tables) {
            // WorkerState owns this table and is created/dropped on the USER
            // worker, after its synchronous operations and callback frames end.
            unsafe {
                DestroyAcceleratorTable(native as _);
            }
        }
    }
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::GetCursor => {
            let images = state.borrow().images.clone();
            // Read the existing USER worker's cursor context. NULL is a valid
            // result; an externally owned cursor must remain borrowed.
            get_cursor_with(&images, || unsafe { GetCursor() })
        }
        Operation::SetCursor { cursor } => {
            let (images, native_cursor) = {
                let state = state.borrow();
                let native_cursor = match cursor {
                    Some(cursor) => state.images.native_cursor(cursor)?.ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 cursor token has no native USER image",
                        )
                    })?,
                    None => std::ptr::null_mut(),
                };
                (state.images.clone(), native_cursor)
            };
            // SAFETY: the opaque image token resolves to a live HCURSOR, or
            // null requests removal; both values belong to this host process.
            let previous = unsafe { SetCursor(native_cursor) };
            // SetCursor returns the previous native cursor, which may be a
            // system or app cursor outside this bridge's table. Register it as
            // borrowed instead of discarding that actual result.
            let previous = images.adopt_borrowed_cursor(previous)?;
            Ok(ResultValue::SetCursor(previous))
        }
        Operation::ShowCursor { show } => {
            // SAFETY: ShowCursor accepts a BOOL and returns the updated native
            // display count; the runtime later writes the Win16 low-word bits.
            Ok(ResultValue::ShowCursor(unsafe {
                ShowCursor(i32::from(show))
            }))
        }
        Operation::WinHelp {
            window,
            help_file,
            command,
            data,
        } => execute_win_help(state, window, help_file, command, data),
        Operation::LoadAccelerators { entries } => {
            let mut state = state.borrow_mut();
            let text_codec = state.text_codec;
            let table = state.accelerator_tables.create(&entries, text_codec)?;
            Ok(ResultValue::LoadAccelerators(table))
        }
        Operation::TranslateAccelerator {
            window,
            table,
            message,
        } => {
            let (native_window, native_message_window, native_table) = {
                let state = state.borrow();
                let Some(native_window) = resolve_window(&state, window) else {
                    return Ok(ResultValue::TranslateAccelerator(0));
                };
                let Some(native_message_window) = resolve_window(&state, message.window) else {
                    return Ok(ResultValue::TranslateAccelerator(0));
                };
                let native_table = state.accelerator_tables.native(table).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 accelerator token has no native USER table",
                    )
                })?;
                (native_window, native_message_window, native_table)
            };
            if message.source != Win16MessageSource::GuestMessage {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "TranslateAccelerator received a native-queue message instead of MSG16",
                ));
            }
            let l_param = match message.l_param {
                Win16MessageParam::GuestBits(value) | Win16MessageParam::Scalar(value) => {
                    (value as i32) as isize
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "TranslateAccelerator received a pointer-bearing host message payload",
                    ));
                }
            };
            let native_message = MSG {
                hwnd: native_message_window,
                message: u32::from(message.message),
                wParam: usize::from(message.w_param),
                lParam: l_param,
                time: message.time,
                pt: POINT {
                    x: message.point.x,
                    y: message.point.y,
                },
            };
            // SAFETY: the HWND/HACCEL were resolved from worker-owned opaque
            // tokens, and every MSG field was copied from the fixed Win16 ABI.
            // TranslateAccelerator may synchronously enter the Win16 WndProc;
            // run_operation keeps this host call on the callback-capable worker.
            let result =
                unsafe { TranslateAcceleratorW(native_window, native_table, &native_message) };
            Ok(ResultValue::TranslateAccelerator(result))
        }
    }
}

fn execute_win_help(
    state: &Rc<RefCell<WorkerState>>,
    window: Option<runtime::Win16HostWindow>,
    help_file: Option<Vec<u8>>,
    command: u16,
    data: Win16HostHelpData,
) -> Result<ResultValue, RuntimeError> {
    let (native_window, text_codec) = {
        let state = state.borrow();
        let Some(window) = resolve_window(&state, window) else {
            return Ok(ResultValue::WinHelp(false));
        };
        (window, state.text_codec)
    };
    if !help_data_matches_command(command, &data) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 WinHelp data type does not match its documented command",
        ));
    }
    let help_file = help_file
        .map(|bytes| {
            text_codec.to_wide_z(&bytes).map_err(|error| {
                error.with_context("decode WinHelp file name using the guest code page")
            })
        })
        .transpose()?;
    let help_file_pointer = help_file
        .as_ref()
        .map_or(std::ptr::null(), |bytes| bytes.as_ptr());
    let native_data = NativeHelpData::new(data, text_codec)?;
    // SAFETY: all strings and native structures referenced by dwData are
    // locally owned UTF-16 values that remain alive for this synchronous call.
    // WinHelpW receives no guest FAR address or guest structure layout.
    let result = unsafe {
        // WinHelp does not guarantee extended error information. Clear the
        // thread-local value so diagnostics cannot report an older API error.
        SetLastError(0);
        WinHelpW(
            native_window,
            help_file_pointer,
            u32::from(command),
            native_data.argument(),
        )
    };
    if result == 0 {
        let error = unsafe { GetLastError() };
        let file = help_file.as_ref().map_or_else(
            || "<NULL>".to_owned(),
            |path| String::from_utf16_lossy(&path[..path.len().saturating_sub(1)]),
        );
        super::win16_window_position::report_diagnostic(
            state,
            Kind::HostFailure,
            format!(
                "WinHelpW failed for {file}, command 0x{command:04X}; native last-error {error} (zero means no extended error was supplied)"
            ),
        );
    }
    Ok(ResultValue::WinHelp(result != 0))
}

fn resolve_window(state: &WorkerState, window: Option<runtime::Win16HostWindow>) -> Option<HWND> {
    let Some(window) = window else {
        return Some(std::ptr::null_mut());
    };
    let hwnd = *state.windows.get(&window)?;
    (unsafe { IsWindow(hwnd) } != 0).then_some(hwnd)
}

enum NativeHelpData {
    Scalar(usize),
    String(Option<Vec<u16>>),
    MultiKey(Vec<MULTIKEYHELPW>),
    WindowPosition(Vec<HELPWININFOW>),
    Null,
}

impl NativeHelpData {
    fn new(
        data: Win16HostHelpData,
        text_codec: GuestTextCodec,
    ) -> Result<Self, RuntimeError> {
        Ok(match data {
            Win16HostHelpData::Ignored => Self::Scalar(0),
            Win16HostHelpData::Scalar(value) => Self::Scalar(value as usize),
            Win16HostHelpData::String(value) => Self::String(
                value
                    .map(|bytes| {
                        text_codec
                            .to_wide_z(&bytes)
                            .map_err(|error| error.with_context(
                                "decode WinHelp string data using the guest code page",
                            ))
                    })
                    .transpose()?,
            ),
            Win16HostHelpData::MultiKey {
                key_list,
                key_phrase,
            } => Self::MultiKey(native_help_multi_key(
                text_codec,
                key_list,
                &key_phrase,
            )?),
            Win16HostHelpData::WindowPosition {
                x,
                y,
                width,
                height,
                max_state,
                member,
            } => Self::WindowPosition(native_help_window_position(
                text_codec,
                x,
                y,
                width,
                height,
                max_state,
                &member,
            )?),
            Win16HostHelpData::NullPointer => Self::Null,
        })
    }

    fn argument(&self) -> usize {
        match self {
            Self::Scalar(value) => *value,
            Self::String(None) | Self::Null => 0,
            Self::String(Some(bytes)) => bytes.as_ptr() as usize,
            Self::MultiKey(structures) => structures.as_ptr() as usize,
            Self::WindowPosition(info) => info.as_ptr() as usize,
        }
    }
}

fn native_help_multi_key(
    text_codec: GuestTextCodec,
    key_list: u8,
    key_phrase: &[u8],
) -> Result<Vec<MULTIKEYHELPW>, RuntimeError> {
    let native_key_list = text_codec
        .to_wide(&[key_list])
        .map_err(|error| error.with_context(
            "decode Win16 MULTIKEYHELP key-list character using the guest code page",
        ))?;
    if native_key_list.len() != 1 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 MULTIKEYHELP key-list character is not one UTF-16 code unit",
        ));
    }
    let key_phrase = text_codec
        .to_wide(key_phrase)
        .map_err(|error| error.with_context(
            "decode Win16 MULTIKEYHELP key phrase using the guest code page",
        ))?;
    if key_phrase.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 WinHelp key phrase contains an embedded terminator",
        ));
    }
    let header_bytes = core::mem::offset_of!(MULTIKEYHELPW, szKeyphrase);
    let native_size = core::mem::size_of::<MULTIKEYHELPW>();
    let tail_units = key_phrase.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW phrase size overflow",
        )
    })?;
    let tail_bytes = tail_units.checked_mul(core::mem::size_of::<u16>()).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW UTF-16 tail byte size overflow",
        )
    })?;
    let tail_end = header_bytes.checked_add(tail_bytes).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW tail offset overflow",
        )
    })?;
    let phrase_bytes = key_phrase
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW phrase byte size overflow",
        ))?;
    let declared_bytes = native_size.checked_add(phrase_bytes).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW declared size overflow",
        )
    })?;
    if declared_bytes < tail_end {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MULTIKEYHELPW native size does not cover its variable UTF-16 phrase tail",
        ));
    }
    let declared_size = u32::try_from(declared_bytes).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW exceeds native size width",
            error,
        )
    })?;
    let storage_bytes = declared_bytes;
    let element_count = storage_bytes.checked_add(native_size - 1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW allocation size overflow",
        )
    })? / native_size;
    let mut storage = Vec::new();
    storage.try_reserve_exact(element_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve aligned WinHelp MULTIKEYHELPW storage",
            error,
        )
    })?;
    storage.push(MULTIKEYHELPW {
        mkSize: declared_size,
        mkKeylist: native_key_list[0],
        szKeyphrase: [0; 1],
    });
    for _ in 1..element_count {
        storage.push(MULTIKEYHELPW::default());
    }
    let storage_bytes = storage.len().checked_mul(native_size).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp MULTIKEYHELPW backing size overflow",
        )
    })?;
    // SAFETY: Vec length/capacity are complete and checked; MULTIKEYHELPW is
    // made only of integer fields, so an all-zero representation is valid.
    // No typed borrow is live while the initialized buffer bytes are cleared.
    unsafe {
        std::ptr::write_bytes(storage.as_mut_ptr().cast::<u8>(), 0, storage_bytes);
    }
    {
        let header = storage.first_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WinHelp MULTIKEYHELPW storage has no header",
            )
        })?;
        header.mkSize = declared_size;
        header.mkKeylist = native_key_list[0];
    }

    // mkSize is measured in bytes; sizeof already includes one WCHAR for the
    // phrase, so each additional UTF-16 code unit adds two bytes. The binding's
    // szKeyphrase[1] is only the fixed C header declaration. Vec<MULTIKEYHELPW>
    // preserves native alignment and structure layout for the variable tail.
    // SAFETY: storage has enough zeroed contiguous MULTIKEYHELPW objects for
    // declared_size; the destination starts at szKeyphrase and stays in that
    // allocation. No typed reference is live while the variable tail is copied.
    unsafe {
        let tail = storage
            .as_mut_ptr()
            .cast::<u8>()
            .add(header_bytes)
            .cast::<u16>();
        if !key_phrase.is_empty() {
            std::ptr::copy_nonoverlapping(key_phrase.as_ptr(), tail, key_phrase.len());
        }
        *tail.add(key_phrase.len()) = 0;
    }
    Ok(storage)
}

fn native_help_window_position(
    text_codec: GuestTextCodec,
    x: i16,
    y: i16,
    width: i16,
    height: i16,
    max_state: i16,
    member: &[u8],
) -> Result<Vec<HELPWININFOW>, RuntimeError> {
    let member = text_codec
        .to_wide(member)
        .map_err(|error| error.with_context(
            "decode Win16 HELPWININFO member name using the guest code page",
        ))?;
    if member.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 WinHelp member name contains an embedded terminator",
        ));
    }
    let header_bytes = core::mem::offset_of!(HELPWININFOW, rgchMember);
    let native_size = core::mem::size_of::<HELPWININFOW>();
    let tail_units = member.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW member size overflow",
        )
    })?;
    let tail_bytes = tail_units.checked_mul(core::mem::size_of::<u16>()).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW UTF-16 tail byte size overflow",
        )
    })?;
    let tail_end = header_bytes.checked_add(tail_bytes).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW tail offset overflow",
        )
    })?;
    // wStructSize is a byte count: six fixed INTs, followed by each UTF-16
    // member unit and its terminating WCHAR. The fixed rgchMember[2] array is
    // part of the header in sizeof(), so its two units are not counted twice.
    let declared_size = i32::try_from(tail_end).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW exceeds native size width",
            error,
        )
    })?;
    let storage_bytes = usize::try_from(declared_size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW size is not representable",
            error,
        )
    })?;
    let element_count = storage_bytes.checked_add(native_size - 1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW allocation size overflow",
        )
    })? / native_size;
    let mut storage = Vec::new();
    storage.try_reserve_exact(element_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve aligned WinHelp HELPWININFOW storage",
            error,
        )
    })?;
    storage.push(HELPWININFOW {
        wStructSize: declared_size,
        x: i32::from(x),
        y: i32::from(y),
        dx: i32::from(width),
        dy: i32::from(height),
        wMax: i32::from(max_state),
        rgchMember: [0; 2],
    });
    for _ in 1..element_count {
        storage.push(HELPWININFOW::default());
    }
    let storage_bytes = storage.len().checked_mul(native_size).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinHelp HELPWININFOW backing size overflow",
        )
    })?;
    // SAFETY: Vec length/capacity are complete and checked; HELPWININFOW is
    // made only of integer fields, so an all-zero representation is valid.
    // No typed borrow is live while the initialized buffer bytes are cleared.
    unsafe {
        std::ptr::write_bytes(storage.as_mut_ptr().cast::<u8>(), 0, storage_bytes);
    }
    {
        let header = storage.first_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WinHelp HELPWININFOW storage has no header",
            )
        })?;
        header.wStructSize = declared_size;
        header.x = i32::from(x);
        header.y = i32::from(y);
        header.dx = i32::from(width);
        header.dy = i32::from(height);
        header.wMax = i32::from(max_state);
    }

    // HELPWININFOW declares two fixed WCHARs, while WinHelp's byte-size
    // contract permits a longer UTF-16 member string. A typed vector supplies
    // native alignment; only the variable tail is copied into its allocation.
    // SAFETY: `storage` contains enough zeroed, contiguous HELPWININFOW
    // objects for `declared_size`, and the target range begins at rgchMember
    // and ends within that allocation. No typed reference is live during copy.
    unsafe {
        let tail = storage
            .as_mut_ptr()
            .cast::<u8>()
            .add(header_bytes)
            .cast::<u16>();
        if !member.is_empty() {
            std::ptr::copy_nonoverlapping(member.as_ptr(), tail, member.len());
        }
        *tail.add(member.len()) = 0;
    }
    Ok(storage)
}

fn help_data_matches_command(command: u16, data: &Win16HostHelpData) -> bool {
    match command {
        0x0001 | 0x0005 | 0x0008 => matches!(data, Win16HostHelpData::Scalar(_)),
        0x0002 | 0x0003 | 0x0004 | 0x0009 => matches!(data, Win16HostHelpData::Ignored),
        0x0101 | 0x0102 | 0x0105 => matches!(
            data,
            Win16HostHelpData::String(_) | Win16HostHelpData::NullPointer
        ),
        0x0201 => matches!(
            data,
            Win16HostHelpData::MultiKey { .. } | Win16HostHelpData::NullPointer
        ),
        0x0203 => matches!(
            data,
            Win16HostHelpData::WindowPosition { .. } | Win16HostHelpData::NullPointer
        ),
        _ => false,
    }
}

/// Keep the one native read separate from token adoption for deterministic tests.
pub(super) fn get_cursor_with(
    images: &super::win16_images::Win16Images,
    read: impl FnOnce() -> HCURSOR,
) -> Result<ResultValue, RuntimeError> {
    images.adopt_borrowed_cursor(read()).map(ResultValue::GetCursor)
}
