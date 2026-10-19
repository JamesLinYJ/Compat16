//! Native Win32 wire helpers for classic WM_DDE messages.
//!
//! This module belongs on the host USER worker. It deals only in native
//! LPARAM/HGLOBAL/ATOM values locally and returns owned values to the runtime.

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16ClassicDdeAtom};
use windows_sys::Win32::Foundation::{GlobalFree, HGLOBAL, LPARAM};
use windows_sys::Win32::System::DataExchange::{
    FreeDDElParam, GlobalAddAtomW, GlobalDeleteAtom, GlobalGetAtomNameW, PackDDElParam,
    UnpackDDElParam,
};
use windows_sys::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};

use super::guest_text::GuestTextCodec;

const STRING_ATOM_BASE: u16 = 0xc000;
const MAX_ATOM_NAME_UNITS: usize = 255;
const DDE_FIXED_HEADER_BYTES: usize = 4;

// The bit positions below are the field order in the Windows 3.1 SDK
// DDE.H `DDEADVISE`, `DDEDATA`, and `DDEPOKE` definitions. In particular,
// DDEPOKE's fRelease is bit 13; the older reversed interpretation mentioned
// by that header is intentionally not used.
const DDEADVISE_DEFER_UPDATES: u16 = 0x4000;
const DDEADVISE_ACK_REQUESTED: u16 = 0x8000;
const DDEADVISE_UNUSED_MASK: u16 = 0x3fff;
const DDEDATA_RESPONSE: u16 = 0x1000;
const DDEDATA_RELEASE: u16 = 0x2000;
const DDEDATA_RESERVED: u16 = 0x4000;
const DDEDATA_ACK_REQUESTED: u16 = 0x8000;
const DDEDATA_UNUSED_MASK: u16 = 0x0fff;
const DDEPOKE_RELEASE: u16 = 0x2000;
const DDEPOKE_RESERVED_MASK: u16 = 0xc000;
const DDEPOKE_UNUSED_MASK: u16 = 0x1fff;

/// DDE lParams backed by PackDDElParam. Ownership transfers to USER/receiver
/// only after the corresponding native send/post call has been entered and
/// accepted. On preflight or failed PostMessage, Drop frees the exact block.
pub(super) struct PackedDdeLParam {
    message: u32,
    value: LPARAM,
    owned: bool,
}

/// An unshared native movable global-memory block. It remains locally owned
/// until the exact DDE message has been successfully sent/posted and its
/// protocol-specific ownership has been recorded in the endpoint ledger.
pub(super) struct NativeGlobalBlockLease {
    handle: HGLOBAL,
    owned: bool,
}

impl NativeGlobalBlockLease {
    pub(super) fn copy_from(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.is_empty() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE global blocks must have a nonzero exact size",
            ));
        }
        // SAFETY: The requested size is the exact owned DTO byte length and
        // GMEM_MOVEABLE is required for legacy DDE HGLOBAL transfers.
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) };
        if handle.is_null() {
            return Err(last_error("GlobalAlloc classic DDE block"));
        }
        // SAFETY: `handle` is the exact movable block allocated immediately above.
        let pointer = unsafe { GlobalLock(handle) };
        if pointer.is_null() {
            // SAFETY: No other owner has received this locally allocated block.
            let freed = unsafe { GlobalFree(handle) }.is_null();
            let mut error = last_error("GlobalLock classic DDE block");
            if !freed {
                error = RuntimeError::new(
                    Kind::HostFailure,
                    "GlobalLock failed and GlobalFree could not roll back the DDE block",
                );
            }
            return Err(error);
        }
        // SAFETY: The block is locked and has the exact requested byte extent.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast::<u8>(), bytes.len()) };
        // Zero can mean a successful final unlock or an error; inspect the
        // thread's last-error value immediately as required by GlobalUnlock.
        (crate::windows::win32_safe::set_last_error(0));
        // SAFETY: Balance the single successful GlobalLock above.
        let still_locked = unsafe { GlobalUnlock(handle) };
        // SAFETY: Read the result from the just-completed GlobalUnlock call.
        let unlock_error = crate::windows::win32_safe::last_error();
        if still_locked == 0 && unlock_error != 0 {
            // SAFETY: Ownership has not been transferred to any DDE peer.
            let freed = unsafe { GlobalFree(handle) }.is_null();
            return Err(if freed {
                RuntimeError::new(
                    Kind::HostFailure,
                    format!(
                        "GlobalUnlock failed for classic DDE block with Windows error {unlock_error}"
                    ),
                )
            } else {
                RuntimeError::new(
                    Kind::HostFailure,
                    "GlobalUnlock failed and GlobalFree could not roll back the DDE block",
                )
            });
        }
        Ok(Self {
            handle,
            owned: true,
        })
    }

    pub(super) const fn handle(&self) -> HGLOBAL {
        self.handle
    }

    pub(super) fn transfer_to_ledger(&mut self) -> HGLOBAL {
        self.owned = false;
        self.handle
    }

    /// The exact posted DDE message now gives the peer ownership. When the
    /// sender keeps a protocol transfer record, that record is the owner until
    /// the ACK decides whether ownership actually moves to the peer.
    pub(super) fn transfer_to_receiver(&mut self) {
        self.owned = false;
    }
}

impl Drop for NativeGlobalBlockLease {
    fn drop(&mut self) {
        if self.owned && !self.handle.is_null() {
            // SAFETY: The block has not been transferred and this guard is
            // its sole owner.
            unsafe { GlobalFree(self.handle) };
        }
    }
}

fn last_error(context: &'static str) -> RuntimeError {
    // SAFETY: Read the native error immediately after the failed API call.
    let code = crate::windows::win32_safe::last_error();
    RuntimeError::new(
        Kind::HostFailure,
        format!("{context} failed with Windows error {code}"),
    )
}

impl PackedDdeLParam {
    pub(super) fn new(message: u16, low: usize, high: usize) -> Result<Self, RuntimeError> {
        let message = u32::from(message);
        // SAFETY: PackDDElParam receives the exact documented DDE message ID
        // and two scalar DDE words/handles. It creates the opaque LPARAM block.
        let value = unsafe { PackDDElParam(message, low, high) };
        if value == 0 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "PackDDElParam could not allocate a native DDE parameter",
            ));
        }
        Ok(Self {
            message,
            value,
            owned: true,
        })
    }

    pub(super) fn value(&self) -> LPARAM {
        self.value
    }

    /// Successful SendMessage/PostMessage transfers the packed LPARAM to the
    /// receiver-side DDE contract, where UnpackDDElParam/FreeDDElParam retire it.
    pub(super) fn transfer_to_receiver(&mut self) {
        self.owned = false;
    }
}

impl Drop for PackedDdeLParam {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: `value` is the still-owned PackDDElParam result created
            // by this exact guard and has not been handed to USER/receiver.
            let _ = unsafe { FreeDDElParam(self.message, self.value) };
        }
    }
}

/// Unpack and consume a Win32 packed DDE LPARAM. Do not call this for
/// WM_DDE_INITIATE (raw atom pair) or WM_DDE_TERMINATE (zero).
pub(super) fn unpack_and_free(message: u16, value: LPARAM) -> Result<(usize, usize), RuntimeError> {
    let unpacked = unpack_without_free(message, value);
    // NTVDM's WMSG16 path explicitly frees packed ACK/DATA/POKE/ADVISE blocks
    // after decoding. Free exactly once even if unpacking failed.
    // SAFETY: `value` belongs to this received DDE message and has not yet been freed.
    let freed = unsafe { FreeDDElParam(u32::from(message), value) };
    let fields = unpacked?;
    if freed == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "FreeDDElParam could not retire the consumed native DDE parameter",
        ));
    }
    Ok(fields)
}

/// Unpack but retain a synchronous callback's LPARAM until the exact runtime
/// reply chooses either translated handling or native DefWindowProc. The
/// caller must subsequently FreeDDElParam or transfer the original message to
/// DefWindowProc on every path.
pub(super) fn unpack_without_free(
    message: u16,
    value: LPARAM,
) -> Result<(usize, usize), RuntimeError> {
    if !uses_packed_lparam(message) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE message does not use PackDDElParam",
        ));
    }
    let mut low = 0usize;
    let mut high = 0usize;
    // SAFETY: USER owns and validates the message-specific packed parameter;
    // output pointers address live local usize values.
    let unpacked = unsafe { UnpackDDElParam(u32::from(message), value, &mut low, &mut high) };
    if unpacked == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "UnpackDDElParam rejected the native DDE parameter",
        ));
    }
    Ok((low, high))
}

pub(super) const fn uses_packed_lparam(message: u16) -> bool {
    matches!(
        message,
        runtime::WM_DDE_ACK
            | runtime::WM_DDE_ADVISE
            | runtime::WM_DDE_UNADVISE
            | runtime::WM_DDE_DATA
            | runtime::WM_DDE_REQUEST
            | runtime::WM_DDE_POKE
            | runtime::WM_DDE_EXECUTE
    )
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
pub(super) unsafe fn free_packed_lparam(message: u16, value: LPARAM) {
    if uses_packed_lparam(message) {
        // SAFETY: The caller transfers one still-owned PackDDElParam result.
        unsafe { FreeDDElParam(u32::from(message), value) };
    }
}

/// WM_DDE_INITIATE and its ACK use the raw low/high WORD pair, not a packed
/// DDE LPARAM allocation. Values are only protocol atoms and never pointers.
pub(super) const fn raw_atom_pair(application: u16, topic: u16) -> LPARAM {
    ((topic as u32) << 16 | application as u32) as LPARAM
}

pub(super) fn split_raw_atom_pair(value: LPARAM) -> (u16, u16) {
    let bits = value as u32;
    (bits as u16, (bits >> 16) as u16)
}

/// Resolve a typed guest atom spelling to the native global atom used only on
/// the Windows wire. The guest WORD is retained for runtime bookkeeping and
/// is never treated as a host ATOM value.
pub(super) fn create_native_atom(
    atom: Option<&Win16ClassicDdeAtom>,
    codec: GuestTextCodec,
) -> Result<(u16, Option<NativeGlobalAtomLease>), RuntimeError> {
    match atom {
        None => Ok((0, None)),
        Some(Win16ClassicDdeAtom::Integer(value)) if *value < STRING_ATOM_BASE => {
            Ok((*value, None))
        }
        Some(Win16ClassicDdeAtom::Integer(_)) => Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE integer atom is outside the integer-atom range",
        )),
        Some(Win16ClassicDdeAtom::Name { name_bytes, .. }) => {
            NativeGlobalAtomLease::from_guest_name(name_bytes, codec)
                .map(|(value, lease)| (value, Some(lease)))
        }
    }
}

/// Native atom lease retained while an event/conversation references a
/// string atom. Integer atoms do not participate in the global atom table.
pub(super) struct NativeGlobalAtomLease {
    atom: u16,
    owned: bool,
}

impl NativeGlobalAtomLease {
    pub(super) fn from_guest_name(
        name_bytes: &[u8],
        codec: GuestTextCodec,
    ) -> Result<(u16, Self), RuntimeError> {
        let wide = codec.to_wide_z(name_bytes)?;
        // SAFETY: `wide` is an owned, NUL-terminated UTF-16 atom spelling.
        let atom = unsafe { GlobalAddAtomW(wide.as_ptr()) };
        if atom == 0 || atom < STRING_ATOM_BASE {
            if atom >= STRING_ATOM_BASE {
                // SAFETY: Undo the exact atom reference just acquired.
                unsafe { GlobalDeleteAtom(atom) };
            }
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "GlobalAddAtomW did not create a string atom for the guest name",
            ));
        }
        Ok((atom, Self { atom, owned: true }))
    }

    /// A successful DDE send transfers the one GlobalAddAtom reference to the
    /// receiver, whose protocol cleanup calls GlobalDeleteAtom.
    pub(super) fn transfer_to_receiver(&mut self) {
        self.owned = false;
    }

    /// Release a retained string-atom reference while its owning endpoint
    /// record is still live. GlobalDeleteAtom returns zero on success, so
    /// clear and inspect last-error to distinguish a failed release.
    pub(super) fn release(&mut self) -> Result<(), RuntimeError> {
        if !self.owned {
            return Ok(());
        }
        // SAFETY: Reset the thread-local last-error value before the API whose
        // documented return value is always zero.
        (crate::windows::win32_safe::set_last_error(0));
        // SAFETY: This lease owns exactly one reference to this string atom.
        unsafe { GlobalDeleteAtom(self.atom) };
        // SAFETY: Read the error immediately after GlobalDeleteAtom.
        let error = crate::windows::win32_safe::last_error();
        if error != 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!("GlobalDeleteAtom failed with Windows error {error}"),
            ));
        }
        self.owned = false;
        Ok(())
    }

    pub(super) fn retain(
        atom: u16,
        codec: GuestTextCodec,
    ) -> Result<(Vec<u8>, Option<Self>), RuntimeError> {
        if atom == 0 {
            return Ok((Vec::new(), None));
        }
        if atom < STRING_ATOM_BASE {
            return Ok((Vec::new(), None));
        }
        let guest_name = Self::snapshot_name(atom, codec)?;
        // The sender's GlobalAddAtom reference is transferred with the DDE
        // message. This lease owns that exact reference until event/frame
        // retirement; do not manufacture a second atom reference here.
        Ok((guest_name, Some(Self { atom, owned: true })))
    }

    /// Read an atom spelling without claiming its reference. WM_DDE_INITIATE
    /// borrows the sender's atom pair: the initiating client deletes those
    /// references when its synchronous SendMessage returns.
    pub(super) fn snapshot_name(atom: u16, codec: GuestTextCodec) -> Result<Vec<u8>, RuntimeError> {
        let mut wide = Vec::new();
        wide.try_reserve_exact(MAX_ATOM_NAME_UNITS + 1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve a Win32 global atom-name snapshot",
                    error,
                )
            })?;
        wide.resize(MAX_ATOM_NAME_UNITS + 1, 0);
        // SAFETY: `wide` is writable for the complete documented atom name
        // bound and stays live for this GlobalGetAtomNameW call.
        let length = unsafe { GlobalGetAtomNameW(atom, wide.as_mut_ptr(), wide.len() as i32) };
        if length == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "GlobalGetAtomNameW could not resolve a DDE string atom",
            ));
        }
        let length = usize::try_from(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "validate DDE atom-name length",
                error,
            )
        })?;
        if length > MAX_ATOM_NAME_UNITS {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "GlobalGetAtomNameW returned a name beyond its documented bound",
            ));
        }
        wide.truncate(length);
        let guest_name = codec.from_wide(&wide)?.bytes;
        Ok(guest_name)
    }
}

impl Drop for NativeGlobalAtomLease {
    fn drop(&mut self) {
        if self.owned {
            // All protocol-complete paths call `release` while their owner
            // ledger is live. Drop remains a last-resort rollback for an
            // early-return path where no durable endpoint record exists.
            let _ = self.release();
        }
    }
}

/// Copy one live native DDE HGLOBAL using its exact GlobalSize. The caller
/// decides protocol ownership/freeing; this helper only balances its lock.
pub(super) fn snapshot_global_block(handle: HGLOBAL) -> Result<Vec<u8>, RuntimeError> {
    if handle.is_null() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "a required classic DDE global block is NULL",
        ));
    }
    // SAFETY: GlobalSize inspects an opaque handle received from the exact
    // native DDE message or a retained transfer record; no pointer is read.
    let size = unsafe { GlobalSize(handle) };
    if size == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "GlobalSize returned zero for a required classic DDE block",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact classic DDE global snapshot",
            error,
        )
    })?;
    bytes.resize(size, 0);
    // SAFETY: This exact non-null HGLOBAL remains owned by the native DDE
    // message/transfer record for the duration of the copy.
    let pointer = unsafe { GlobalLock(handle) };
    if pointer.is_null() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "GlobalLock rejected a required classic DDE block",
        ));
    }
    // SAFETY: GlobalSize established `size`, GlobalLock returned a readable
    // block, and `bytes` has exactly that writable length.
    unsafe { std::ptr::copy_nonoverlapping(pointer.cast::<u8>(), bytes.as_mut_ptr(), size) };
    // Zero can mean either final unlock or failure; GetLastError distinguishes
    // them, as required by the GlobalUnlock contract.
    (crate::windows::win32_safe::set_last_error(0));
    // SAFETY: Balance the one successful GlobalLock above.
    let still_locked = unsafe { GlobalUnlock(handle) };
    // SAFETY: GetLastError is read immediately after GlobalUnlock on this thread.
    let last_error = crate::windows::win32_safe::last_error();
    if still_locked == 0 && last_error != 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "GlobalUnlock failed while snapshotting a classic DDE block",
        ));
    }
    Ok(bytes)
}

/// Parse the exact four-byte DDEADVISE wire header; trailing bytes are retained
/// by the caller's whole-block snapshot and never inferred as a value length.
pub(super) fn parse_advise_header(bytes: &[u8]) -> Result<(u16, u16), RuntimeError> {
    let flags = first_word(bytes, "DDEADVISE")?;
    let format = word_at(bytes, 2, "DDEADVISE")?;
    Ok((format, flags))
}

pub(super) fn parse_data_header(bytes: &[u8]) -> Result<(u16, u16), RuntimeError> {
    let flags = first_word(bytes, "DDEDATA")?;
    let format = word_at(bytes, 2, "DDEDATA")?;
    Ok((format, flags))
}

pub(super) fn parse_poke_header(bytes: &[u8]) -> Result<(u16, u16), RuntimeError> {
    let flags = first_word(bytes, "DDEPOKE")?;
    let format = word_at(bytes, 2, "DDEPOKE")?;
    Ok((format, flags))
}

pub(super) fn advise_options(raw_flags: u16) -> runtime::Win16ClassicDdeAdviseOptions {
    runtime::Win16ClassicDdeAdviseOptions {
        raw_flags,
        unused_bits: raw_flags & DDEADVISE_UNUSED_MASK,
        defer_updates: raw_flags & DDEADVISE_DEFER_UPDATES != 0,
        acknowledge_each_update: raw_flags & DDEADVISE_ACK_REQUESTED != 0,
    }
}

pub(super) fn data_flags(raw_flags: u16) -> runtime::Win16ClassicDdeDataFlags {
    runtime::Win16ClassicDdeDataFlags {
        raw_flags,
        unused_bits: raw_flags & DDEDATA_UNUSED_MASK,
        response: raw_flags & DDEDATA_RESPONSE != 0,
        release_after_receive: raw_flags & DDEDATA_RELEASE != 0,
        reserved: raw_flags & DDEDATA_RESERVED != 0,
        acknowledge_requested: raw_flags & DDEDATA_ACK_REQUESTED != 0,
    }
}

pub(super) fn poke_flags(raw_flags: u16) -> runtime::Win16ClassicDdePokeFlags {
    runtime::Win16ClassicDdePokeFlags {
        raw_flags,
        unused_bits: raw_flags & DDEPOKE_UNUSED_MASK,
        release_after_receive: raw_flags & DDEPOKE_RELEASE != 0,
        reserved_bits: raw_flags & DDEPOKE_RESERVED_MASK,
    }
}

fn first_word(bytes: &[u8], kind: &'static str) -> Result<u16, RuntimeError> {
    if bytes.len() < DDE_FIXED_HEADER_BYTES {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{kind} global block is shorter than its four-byte SDK header"),
        ));
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn word_at(bytes: &[u8], offset: usize, kind: &'static str) -> Result<u16, RuntimeError> {
    let pair = bytes.get(offset..offset + 2).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            format!("{kind} global block is shorter than its four-byte SDK header"),
        )
    })?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}
