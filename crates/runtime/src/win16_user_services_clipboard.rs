//! USER clipboard format marshalling and guest-handle lifetime.

use std::collections::BTreeMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use guest_core::memory::Memory;
use win16_abi::{
    Access, GlobalHandle, Win16ReturnKind,
    Win16UserClipboardRequest as ClipboardRequest,
};

use crate::win16_runtime::global_memory::GlobalTeardownResult;
use super::Win16State;
#[path = "win16_user_services_clipboard_retirement.rs"]
mod retirement;
use retirement::{ClipboardRetirementCause, RetiredClipboardOwner};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostClipboardData, Win16HostClipboardOperation as ClipboardOperation,
    Win16HostClipboardResult as ClipboardResult, Win16HostUserServiceOperation,
    Win16HostWindow,
};

const GMEM_MOVEABLE: u16 = 0x0002;
const GMEM_ZEROINIT: u16 = 0x0040;
const MAX_CLIPBOARD_BYTES: usize = 16 * 1024 * 1024;

/// Guest HGLOBAL ownership held by USER while a clipboard format is live.
/// The native adapter owns a separate copy of the bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuestClipboardOwnership {
    TransferredToClipboard,
    BorrowedFromClipboard,
    /// `CF_PRIVATEFIRST`..=`CF_PRIVATELAST`. The owner frees this HGLOBAL,
    /// normally from `WM_DESTROYCLIPBOARD`. EmptyClipboard must not.
    CallerRetained,
}

impl GuestClipboardOwnership {
    pub(super) fn cleanup_context(self) -> &'static str {
        match self {
            Self::TransferredToClipboard =>
                "retiring guest HGLOBAL transferred to the native clipboard",
            Self::BorrowedFromClipboard =>
                "retiring guest copy of native clipboard data",
            Self::CallerRetained =>
                "forgetting caller-owned private clipboard HGLOBAL",
        }
    }

    pub(super) fn system_frees(self) -> bool {
        !matches!(self, Self::CallerRetained)
    }
}

#[derive(Clone, Debug)]
pub(super) struct GuestClipboardEntry {
    pub handle: Option<u16>,
    pub identity: Option<GlobalHandle>,
    /// Preserve transfer direction in typed cleanup diagnostics; this exact
    /// handle generation remains the owner root for both clipboard sources.
    pub ownership: GuestClipboardOwnership,
    pub bytes: Option<Vec<u8>>,
    native_sequence: Option<u32>,
}

/// Runtime-owned Win16 aliases for clipboard data. No native pointer or
/// HGLOBAL enters this table. Entries are retired format-by-format when their
/// content is replaced or unavailable, and all entries are retired on a
/// successful EmptyClipboard or task cleanup.
#[derive(Default)]
pub(in crate::win16_runtime) struct GuestClipboardState {
    entries: BTreeMap<u16, GuestClipboardEntry>,
    /// Displaced guest owners retained because a selector alias or page lock
    /// still names their exact GlobalHandle generation.
    retired: Vec<RetiredClipboardOwner>,
    reserved_retired: usize,
    native_sequence: Option<u32>,
}

impl GuestClipboardState {
    pub(in crate::win16_runtime) fn owns_identity(
        &self,
        handle: u16,
        identity: Option<GlobalHandle>,
    ) -> bool {
        let Some(identity) = identity else { return false; };
        self.entries.values().chain(self.retired.iter().map(|owner| &owner.entry)).any(|entry|
            entry.handle == Some(handle) && entry.identity == Some(identity))
    }

    fn get(&self, format: u16) -> Option<&GuestClipboardEntry> {
        self.entries.get(&format)
    }

    fn insert(&mut self, format: u16, entry: GuestClipboardEntry) -> Option<GuestClipboardEntry> {
        self.entries.insert(format, entry)
    }

    pub(in crate::win16_runtime) fn observe_native_sequence(&mut self, sequence: u32) {
        self.native_sequence = Some(sequence);
    }

    fn mark_format_observed(&mut self, format: u16) {
        if let Some(entry) = self.entries.get_mut(&format) {
            entry.native_sequence = self.native_sequence;
        }
    }

    fn remove(&mut self, format: u16) -> Option<GuestClipboardEntry> {
        self.entries.remove(&format)
    }

    fn reserve_retired_for_host(&mut self, count: usize) -> Result<(), RuntimeError> {
        let reserved = self.reserved_retired.checked_add(count).ok_or_else(||
            RuntimeError::new(crate::DiagnosticKind::ResourceExhausted,
                "Win16 clipboard retirement reservation count overflowed"))?;
        self.retired.try_reserve(reserved).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve retained Win16 clipboard owner records before host operation",
            error,
        ))?;
        self.reserved_retired = reserved;
        Ok(())
    }

    fn ensure_retired_capacity(&mut self, count: usize) -> Result<(), RuntimeError> {
        let additional = self.reserved_retired.checked_add(count).ok_or_else(||
            RuntimeError::new(crate::DiagnosticKind::ResourceExhausted,
                "Win16 clipboard retirement capacity count overflowed"))?;
        self.retired.try_reserve(additional).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve retained Win16 clipboard owner records before releasing ownership",
            error,
        ))
    }

    pub(in crate::win16_runtime) fn release_retired_reservation(&mut self, count: usize) {
        self.reserved_retired = self.reserved_retired.saturating_sub(count);
    }

    fn consume_retired_reservation(&mut self, reservation: &mut usize) -> bool {
        if *reservation == 0 { return false; }
        *reservation -= 1;
        self.release_retired_reservation(1);
        true
    }
}

#[derive(Clone, Debug)]
pub(in crate::win16_runtime) enum ClipboardCompletion {
    Plain,
    Empty { reserved_retirements: ClipboardRetirementReservation },
    FormatAvailable { format: u16, reserved_retirements: ClipboardRetirementReservation },
    FormatName {
        range: super::super::guest_ranges::GuestOutputRange,
        capacity: u16,
    },
    SetData {
        format: u16,
        handle: Option<u16>,
        identity: Option<GlobalHandle>,
        bytes: Option<Vec<u8>>,
        reserved_retirements: ClipboardRetirementReservation,
    },
    GetData { format: u16, reserved_retirements: ClipboardRetirementReservation },
}

/// Cloned USER continuations share one exact-once reservation token. A failed
/// frame push or post-quiescence cancellation atomically returns its capacity.
#[derive(Clone, Debug)]
pub(in crate::win16_runtime) struct ClipboardRetirementReservation(Arc<AtomicUsize>);

impl Default for ClipboardRetirementReservation {
    fn default() -> Self { Self(Arc::new(AtomicUsize::new(0))) }
}

impl ClipboardRetirementReservation {
    fn set(&self, count: usize) { self.0.store(count, Ordering::Release); }
    fn take(&self) -> usize { self.0.swap(0, Ordering::AcqRel) }
}

impl ClipboardCompletion {
    pub(super) fn take_retirement_reservation(&self) -> usize {
        match self {
            Self::Empty { reserved_retirements }
            | Self::FormatAvailable { reserved_retirements, .. }
            | Self::SetData { reserved_retirements, .. }
            | Self::GetData { reserved_retirements, .. } => reserved_retirements.take(),
            Self::Plain | Self::FormatName { .. } => 0,
        }
    }

    fn set_retirement_reservation(&mut self, count: usize) {
        match self {
            Self::Empty { reserved_retirements }
            | Self::FormatAvailable { reserved_retirements, .. }
            | Self::SetData { reserved_retirements, .. }
            | Self::GetData { reserved_retirements, .. } => reserved_retirements.set(count),
            Self::Plain | Self::FormatName { .. } => {}
        }
    }
}

impl Win16State {
    pub(super) fn prepare_clipboard_family(
        &mut self,
        request: ClipboardRequest,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        return_kind: Win16ReturnKind,
    ) -> Result<super::Win16UserFamilyPreparation, RuntimeError> {
        use ClipboardRequest as Request;
        use super::Win16UserFamilyPreparation as Prepared;

        let (operation, completion) = match request {
            Request::Open { owner } => {
                let owner = match self.clipboard_window(owner) {
                    Some(owner) => Some(owner),
                    None if owner == 0 => None,
                    None => return Ok(Prepared::immediate(0, return_kind)),
                };
                (ClipboardOperation::Open { owner }, ClipboardCompletion::Plain)
            }
            Request::Close => (ClipboardOperation::Close, ClipboardCompletion::Plain),
            Request::Empty => (ClipboardOperation::Empty,
                ClipboardCompletion::Empty { reserved_retirements: ClipboardRetirementReservation::default() }),
            Request::Owner => (ClipboardOperation::Owner, ClipboardCompletion::Plain),
            Request::SetData { format, handle } => {
                if handle != 0 && !is_global_clipboard_format(format) {
                    // Bitmap, palette, metafile, and owner-display handles are
                    // not HGLOBALs. Returning a copied global would claim a
                    // transfer this bridge does not perform.
                    return Ok(Prepared::immediate(0, return_kind));
                }
                let identity = self.global_handles.get(&handle).copied();
                if handle != 0 && self.clipboard_state.owns_identity(handle, identity) {
                    return Ok(Prepared::immediate(0, return_kind));
                }
                if handle == 0 {
                    // Native delayed rendering would later call WM_RENDERFORMAT
                    // on the owner window. Until that callback path has a
                    // guest continuation, returning native success would leave
                    // the guest clipboard format permanently unrendered.
                    host.report_diagnostic(&crate::Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "SetClipboardData with a null HGLOBAL needs WM_RENDERFORMAT support",
                    ));
                    return Ok(Prepared::immediate(0, return_kind));
                } else {
                    let Some((identity, bytes)) = self.clipboard_global_bytes(handle, memory)? else {
                        return Ok(Prepared::immediate(0, return_kind));
                    };
                    (
                        ClipboardOperation::SetData {
                            format, data: Win16HostClipboardData::GlobalMemory(bytes.clone()),
                        },
                        ClipboardCompletion::SetData {
                            format, handle: Some(handle), identity: Some(identity),
                            bytes: Some(bytes), reserved_retirements: ClipboardRetirementReservation::default(),
                        },
                    )
                }
            }
            Request::RegisterFormat { name } => {
                let Some(name) = name else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                (ClipboardOperation::RegisterFormat { name }, ClipboardCompletion::Plain)
            }
            Request::GetFormatName { format, output, capacity } => {
                if capacity <= 0 || output == 0 {
                    return Ok(Prepared::immediate(0, return_kind));
                }
                let capacity = capacity as u16;
                let pointer = self.checked_pointer(
                    output, Access::Write, usize::from(capacity), memory,
                )?;
                let range = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, usize::from(capacity),
                )?;
                (
                    ClipboardOperation::GetFormatName { format, capacity },
                    ClipboardCompletion::FormatName { range, capacity },
                )
            }
            Request::GetData { format } => {
                if !is_global_clipboard_format(format) {
                    return Ok(Prepared::immediate(0, return_kind));
                }
                (ClipboardOperation::GetData { format }, ClipboardCompletion::GetData {
                    format, reserved_retirements: ClipboardRetirementReservation::default(),
                })
            }
            Request::CountFormats => (ClipboardOperation::CountFormats, ClipboardCompletion::Plain),
            Request::EnumFormats { previous } => (
                ClipboardOperation::EnumFormats { previous }, ClipboardCompletion::Plain,
            ),
            Request::IsFormatAvailable { format } => (
                ClipboardOperation::IsFormatAvailable { format },
                ClipboardCompletion::FormatAvailable { format,
                    reserved_retirements: ClipboardRetirementReservation::default() },
            ),
            Request::GetPriorityFormat { formats, count } => {
                let Some(formats) = priority_query_formats(formats, count) else {
                    return Ok(Prepared::immediate(0xffff, return_kind));
                };
                (ClipboardOperation::GetPriorityFormat { formats }, ClipboardCompletion::Plain)
            }
            Request::SetViewer { viewer } => {
                let viewer = match self.clipboard_window(viewer) {
                    Some(viewer) => Some(viewer),
                    None if viewer == 0 => None,
                    None => return Ok(Prepared::immediate(0, return_kind)),
                };
                (ClipboardOperation::SetViewer { viewer }, ClipboardCompletion::Plain)
            }
            Request::GetViewer => (ClipboardOperation::GetViewer, ClipboardCompletion::Plain),
            Request::ChangeViewerChain { remove, next } => {
                let Some(remove) = self.clipboard_window(remove) else {
                    return Ok(Prepared::immediate(0, return_kind));
                };
                let next = match self.clipboard_window(next) {
                    Some(next) => Some(next),
                    None if next == 0 => None,
                    None => return Ok(Prepared::immediate(0, return_kind)),
                };
                (ClipboardOperation::ChangeViewerChain { remove, next }, ClipboardCompletion::Plain)
            }
            Request::GetOpenClipboardWindow => {
                (ClipboardOperation::GetOpenClipboardWindow, ClipboardCompletion::Plain)
            }
        };
        let retirement_capacity = match &completion {
            ClipboardCompletion::Empty { .. } => self.clipboard_state.entries.len(),
            ClipboardCompletion::FormatAvailable { .. }
            | ClipboardCompletion::SetData { .. }
            | ClipboardCompletion::GetData { .. } => 1,
            _ => 0,
        };
        self.clipboard_state.reserve_retired_for_host(retirement_capacity)?;
        let mut completion = completion;
        completion.set_retirement_reservation(retirement_capacity);
        Ok(Prepared::window(
            Win16HostUserServiceOperation::Clipboard(operation), return_kind,
            super::FamilyCompletion::Clipboard(completion),
        ))
    }

    pub(super) fn finish_clipboard(
        &mut self,
        completion: ClipboardCompletion,
        result: ClipboardResult,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let mut reservation = completion.take_retirement_reservation();
        let result = self.finish_clipboard_inner(
            completion, result, memory, host, &mut reservation,
        );
        self.clipboard_state.release_retired_reservation(reservation);
        result
    }

    fn finish_clipboard_inner(
        &mut self,
        completion: ClipboardCompletion,
        result: ClipboardResult,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        reservation: &mut usize,
    ) -> Result<u32, RuntimeError> {
        use ClipboardCompletion as Completion;
        use ClipboardResult as ResultValue;

        // Only a sequence returned with this operation can support the wider
        // text-prefix match. A remembered sequence may already be stale.
        let sequence_was_reported = matches!(&result, ResultValue::Sequenced { .. });
        let (sequence, result) = match result {
            ResultValue::Sequenced { sequence, result } => {
                self.clipboard_state.observe_native_sequence(sequence);
                (Some(sequence), *result)
            }
            result => (self.clipboard_state.native_sequence, result),
        };

        match (completion, result) {
            (Completion::Plain, ResultValue::Bool(value)) => Ok(u32::from(value)),
            (Completion::Empty { .. }, ResultValue::Bool(value)) => {
                if value { self.retire_all_clipboard_data_with_reservation(Some(reservation))?; }
                Ok(u32::from(value))
            }
            (Completion::FormatAvailable { format, .. }, ResultValue::Bool(value)) => {
                if !value {
                    let _ = self.retire_clipboard_format(format, None, Some(reservation))?;
                }
                Ok(u32::from(value))
            }
            (Completion::Plain, ResultValue::Window(window)) => match window {
                Some(window) => Ok(u32::from(self.map_window_handle(window, false)?)),
                None => Ok(0),
            },
            (Completion::Plain, ResultValue::Count(value)) => Ok(u32::from(value)),
            (Completion::Plain, ResultValue::Format(value)) => Ok(u32::from(value)),
            (Completion::FormatName { range, capacity },
                ResultValue::FormatName { copied, bytes }) => {
                if copied <= 0 { return Ok(0); }
                if bytes.len() > usize::from(capacity)
                    || bytes.len() > range.length()
                    || usize::try_from(copied).unwrap_or(usize::MAX) > bytes.len()
                    || usize::try_from(copied).ok().and_then(|count| count.checked_add(1))
                        != Some(bytes.len())
                    || bytes.last() != Some(&0)
                    || bytes[..bytes.len().saturating_sub(1)].contains(&0)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 clipboard format name exceeds its checked output buffer"));
                }
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    &self.selectors, memory, &range, &bytes,
                )?;
                Ok(u32::from(copied as u16))
            }
            (Completion::Plain, ResultValue::PriorityFormat(value)) => {
                Ok(value as u16 as u32)
            }
            (Completion::SetData { format, handle, identity, bytes, .. },
                ResultValue::SetData(succeeded)) => {
                if !succeeded { return Ok(0); }
                let replacement = GuestClipboardEntry {
                    handle, identity,
                    ownership: if caller_retains_clipboard_memory(format) {
                        GuestClipboardOwnership::CallerRetained
                    } else {
                        GuestClipboardOwnership::TransferredToClipboard
                    },
                    bytes,
                    native_sequence: sequence,
                };
                let displaced = self.clipboard_state.insert(format, replacement);
                if let Some(displaced) = displaced {
                    let _ = self.retire_displaced_clipboard_entry(displaced, reservation)
                        .map_err(|error| error.with_context(
                            "retiring displaced Win16 clipboard owner after SetClipboardData"))?;
                }
                Ok(u32::from(handle.unwrap_or(0)))
            }
            (Completion::GetData { format, .. },
                ResultValue::Data(Some(Win16HostClipboardData::Delayed))) => {
                let _ = self.retire_clipboard_format(format, None, Some(reservation))?;
                Ok(0)
            }
            (Completion::GetData { format, .. }, ResultValue::Data(data)) => {
                let Some(Win16HostClipboardData::GlobalMemory(bytes)) = data else {
                    let _ = self.retire_clipboard_format(format, None, Some(reservation))?;
                    return Ok(0);
                };
                if bytes.len() > MAX_CLIPBOARD_BYTES {
                    return Err(RuntimeError::new(Kind::ResourceExhausted,
                        "host clipboard block exceeds the Win16 copy limit"));
                }
                let format_changed = self.clipboard_state.get(format)
                    .is_some_and(|entry| entry.native_sequence != sequence);
                if let Some(entry) = self.clipboard_state.get(format) {
                    let unchanged = entry.bytes.as_deref().is_some_and(|stored| {
                        stored == bytes.as_slice()
                            || (sequence_was_reported
                                && sequence.is_some_and(|value| value != 0)
                                && entry.native_sequence == sequence
                                && clipboard_payload_matches(format, stored, &bytes))
                    });
                    if unchanged {
                        if let (Some(handle), Some(identity)) = (entry.handle, entry.identity) {
                            if self.global_handles.get(&handle).copied() == Some(identity) {
                                if format_changed {
                                    self.clipboard_state.mark_format_observed(format);
                                }
                                return Ok(u32::from(handle));
                            }
                        }
                    }
                }
                let _ = self.retire_clipboard_format(format, None, Some(reservation))?;
                let handle = self.allocate_clipboard_global(&bytes, memory, host)?;
                if handle == 0 { return Ok(0); }
                let identity = self.global_handles.get(&handle).copied().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "new Win16 clipboard allocation has no global identity"))?;
                self.clipboard_state.insert(format, GuestClipboardEntry {
                    handle: Some(handle), identity: Some(identity),
                    ownership: GuestClipboardOwnership::BorrowedFromClipboard,
                    bytes: Some(bytes),
                    native_sequence: sequence,
                });
                Ok(u32::from(handle))
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 clipboard result does not match its continuation")),
        }
    }

    fn allocate_clipboard_global(
        &mut self,
        bytes: &[u8],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if bytes.len() > MAX_CLIPBOARD_BYTES { return Ok(0); }
        self.clipboard_state.ensure_retired_capacity(1)?;
        let size = bytes.len().max(1);
        let size = u32::try_from(size).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "Win16 clipboard allocation size exceeds DWORD", error))?;
        let handle = self.global_alloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size, memory, host)?;
        if handle == 0 { return Ok(0); }
        let selector = self.global_selectors.get(&handle).copied().ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 clipboard allocation has no selector"))?;
        let pointer = self.selectors.pointer_from_raw(selector.raw(), 0)
            .map_err(crate::runtime_error)?;
        if let Err(error) = self.write_text_bytes(memory, pointer, bytes) {
            let identity = self.global_handles.get(&handle).copied().ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "failed clipboard allocation has no global identity"))?;
            match self.free_global_on_teardown(handle, identity) {
                Ok(GlobalTeardownResult::Freed) => {}
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    self.clipboard_state.retired.push(RetiredClipboardOwner {
                        entry: GuestClipboardEntry {
                            handle: Some(handle), identity: Some(identity),
                            ownership: GuestClipboardOwnership::BorrowedFromClipboard,
                            bytes: None, native_sequence: None,
                        },
                        cause: ClipboardRetirementCause::retained(retained),
                    });
                    return Err(error.with_cleanup("retiring failed clipboard allocation",
                        retained.retained_error("clipboard allocation rollback")
                            .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                                "clipboard allocation lost its retained cleanup result"))));
                }
                Err(cleanup) => {
                    let (cause, cleanup_report) = ClipboardRetirementCause::from_error(cleanup);
                    self.clipboard_state.retired.push(RetiredClipboardOwner {
                        entry: GuestClipboardEntry {
                            handle: Some(handle), identity: Some(identity),
                            ownership: GuestClipboardOwnership::BorrowedFromClipboard,
                            bytes: None, native_sequence: None,
                        },
                        cause,
                    });
                    return Err(error.with_cleanup(
                        "retiring failed clipboard allocation",
                        cleanup_report,
                    ));
                }
            }
            return Err(error);
        }
        Ok(handle)
    }

    fn clipboard_global_bytes(
        &self,
        handle: u16,
        memory: &Memory,
    ) -> Result<Option<(GlobalHandle, Vec<u8>)>, RuntimeError> {
        let Some(identity) = self.global_handles.get(&handle).copied() else {
            return Ok(None);
        };
        let info = match self.heap.info(identity) {
            Ok(info) => info,
            Err(win16_abi::Win16Error::InvalidHandle) => return Ok(None),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let Ok(length) = usize::try_from(info.size) else { return Ok(None); };
        if info.discarded || length > MAX_CLIPBOARD_BYTES { return Ok(None); }
        let selector = self.global_selectors.get(&handle).copied().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 clipboard global handle has no selector")
        })?;
        let pointer = self.selectors.pointer_from_raw(selector.raw(), 0)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, length)?;
        Ok(Some((identity, bytes)))
    }

    fn clipboard_window(&self, guest: u16) -> Option<Win16HostWindow> {
        if guest == 0 { None } else { self.window_handles.get(&guest).copied() }
    }
}

/// Bitmap, palette, metafile, and owner-display handles are not HGLOBALs this
/// bridge can copy. `CF_PRIVATEFIRST`..=`CF_PRIVATELAST` (0x0200..=0x02FF) and
/// the Win32 `CF_GDIOBJ` range (0x0300..=0x03FF) are `GlobalAlloc` memory.
fn is_global_clipboard_format(format: u16) -> bool {
    !matches!(format, 2 | 3 | 9 | 14 | 0x80 | 0x82 | 0x83 | 0x8e)
}

/// Private clipboard formats stay allocated until the owner frees them.
/// `CF_GDIOBJFIRST`..=`CF_GDIOBJLAST` did not exist in Windows 3.1; those
/// format numbers are ordinary global-memory formats and the system frees them.
fn caller_retains_clipboard_memory(format: u16) -> bool {
    (0x0200..=0x02ff).contains(&format)
}

/// `GetPriorityClipboardFormat` returns NULL when the clipboard is empty and
/// -1 when it holds data in none of the listed formats. A negative count names
/// no entries, so it uses that same pair of results. The caller's array is
/// left unread. A non-negative count that does not match the copied words is
/// not a documented success and stays -1.
fn priority_query_formats(formats: Vec<u16>, count: i16) -> Option<Vec<u16>> {
    if count < 0 {
        return Some(Vec::new());
    }
    if usize::try_from(count).unwrap_or(usize::MAX) != formats.len() {
        return None;
    }
    Some(formats)
}

/// Windows 3.1 `CF_TEXT` (1) and `CF_OEMTEXT` (7). The HGLOBAL may be larger
/// than the NUL-terminated string. `GetClipboardData` returns that same
/// handle while the string is unchanged.
fn is_clipboard_text_format(format: u16) -> bool {
    format == 1 || format == 7
}

fn clipboard_payload_matches(format: u16, stored: &[u8], retrieved: &[u8]) -> bool {
    if is_clipboard_text_format(format) {
        match (nul_terminated_prefix(stored), nul_terminated_prefix(retrieved)) {
            (Some(stored), Some(retrieved)) => stored == retrieved,
            _ => false,
        }
    } else {
        // GlobalSize can exceed the placed length. The extra bytes are the
        // zero fill from GMEM_ZEROINIT, not a new clipboard object. The caller
        // only uses this comparison when the clipboard sequence is unchanged.
        retrieved.len() >= stored.len()
            && &retrieved[..stored.len()] == stored
            && retrieved[stored.len()..].iter().all(|byte| *byte == 0)
    }
}

#[cfg(test)]
mod clipboard_contract_tests {
    use super::{
        caller_retains_clipboard_memory, clipboard_payload_matches, is_global_clipboard_format,
        priority_query_formats,
    };

    #[test]
    fn clipboard_close_private_formats_round_trip_as_caller_owned_memory() {
        assert!(is_global_clipboard_format(0x0200));
        assert!(is_global_clipboard_format(0x02ff));
        assert!(caller_retains_clipboard_memory(0x0200));
        assert!(caller_retains_clipboard_memory(0x02ff));
        assert!(!caller_retains_clipboard_memory(0x01ff));
        assert!(!caller_retains_clipboard_memory(0x0300));
    }

    #[test]
    fn clipboard_close_gdi_object_range_is_system_freed_global_memory() {
        assert!(is_global_clipboard_format(0x0300));
        assert!(is_global_clipboard_format(0x03ff));
        assert!(!caller_retains_clipboard_memory(0x0300));
        assert!(!caller_retains_clipboard_memory(1));
        assert!(!is_global_clipboard_format(2));
        assert!(!is_global_clipboard_format(3));
        assert!(!is_global_clipboard_format(9));
        assert!(!is_global_clipboard_format(14));
        assert!(!is_global_clipboard_format(0x80));
        assert!(!is_global_clipboard_format(0x82));
        assert!(!is_global_clipboard_format(0x83));
        assert!(!is_global_clipboard_format(0x8e));
    }

    #[test]
    fn clipboard_close_negative_priority_count_is_an_empty_list() {
        assert_eq!(priority_query_formats(vec![1, 7], -1), Some(Vec::new()));
        assert_eq!(priority_query_formats(vec![1], i16::MIN), Some(Vec::new()));
        assert_eq!(priority_query_formats(Vec::new(), 0), Some(Vec::new()));
        assert_eq!(priority_query_formats(vec![1, 8], 2), Some(vec![1, 8]));
        assert_eq!(priority_query_formats(vec![1], 2), None);
    }

    #[test]
    fn clipboard_close_unchanged_block_keeps_zero_allocator_padding() {
        assert!(clipboard_payload_matches(8, b"abcd", b"abcd\0\0"));
        assert!(!clipboard_payload_matches(8, b"abcd", b"abcd\x01"));
        assert!(!clipboard_payload_matches(8, b"abcd", b"abc"));
        assert!(clipboard_payload_matches(1, b"ab\0xx", b"ab\0"));
        assert!(!clipboard_payload_matches(1, b"ab", b"ab\0"));
    }
}

fn nul_terminated_prefix(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    Some(&bytes[..end])
}
