//! Win16 USER window properties backed by native HWND properties and host sidecars.
//!
//! Guest atoms remain opaque identifiers. String names acquire their own
//! GlobalAddAtom reference, while physical USER keys use a private host-only
//! string namespace so this adapter never replaces the native window-identity
//! property or exposes host handles to EnumProps callbacks.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use runtime::{
    DiagnosticKind as Kind, RuntimeError,
    Win16HostPropertyCallbackName, Win16HostPropertyName, Win16HostWindow,
    Win16WindowCall, Win16WindowCallResult, Win16WindowTarget,
};
use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::System::DataExchange::{
    GlobalAddAtomW, GlobalDeleteAtom, GlobalFindAtomW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetPropW, RemovePropW, SetPropW,
};

use crate::windows::guest_text::GuestTextCodec;
use super::win16_window_worker::WorkerState;

#[path = "win16_window_property_native.rs"]
mod native;
#[path = "win16_window_property_enum.rs"]
mod enumeration;

type SharedWorker = Rc<RefCell<WorkerState>>;

const FIRST_STRING_ATOM: u16 = 0xC000;
const MAX_PROPERTY_NAME_BYTES: usize = 255;
const PROPERTY_KEY_PREFIX: &str = "__win16_window_property_v1_";
const PROPERTY_KEY_LENGTH: usize = PROPERTY_KEY_PREFIX.len() + 4 + 1;

static NEXT_PROPERTY_MARKER: AtomicUsize = AtomicUsize::new(1);

/// One host-owned USER property namespace shared by the worker's HWND table.
///
/// `generation` changes whenever a canonical atom is removed and then added
/// again. EnumProps captures generations so a replacement created from inside
/// a callback is not mistaken for the property present when enumeration began.
pub(super) struct WindowPropertyStore {
    entries: BTreeMap<Win16HostWindow, BTreeMap<u16, PropertyEntry>>,
    next_generation: u64,
}

impl Default for WindowPropertyStore {
    fn default() -> Self {
        Self { entries: BTreeMap::new(), next_generation: 1 }
    }
}

#[derive(Clone)]
struct PropertyEntry {
    hwnd: usize,
    identity_cookie: Option<usize>,
    marker: usize,
    native_key_atom: u16,
    generation: u64,
    data: u16,
    callback_name: Win16HostPropertyCallbackName,
    owns_string_atom_reference: bool,
}

#[derive(Clone, Copy)]
pub(super) struct EnumPropertySnapshot {
    pub(super) generation: u64,
    pub(super) native_key_atom: u16,
}

/// Handle one of the four USER property calls. Other window calls remain in
/// `win16_window_ops`; routing them here is an internal wiring error.
pub(super) fn execute(
    state: &SharedWorker,
    call: Win16WindowCall,
) -> Result<Win16WindowCallResult, RuntimeError> {
    use Win16WindowCall as Call;
    use Win16WindowCallResult as ResultValue;

    match call {
        Call::SetWindowProperty { window, name, data } => {
            Ok(ResultValue::PropertySet(set_property(state, window, name, data)))
        }
        Call::GetWindowProperty { window, name } => {
            Ok(ResultValue::PropertyValue(get_property(state, window, name)))
        }
        Call::RemoveWindowProperty { window, name } => {
            Ok(ResultValue::PropertyValue(remove_property(state, window, name)))
        }
        Call::EnumWindowProperties { window } => {
            enumeration::enumerate(state, window).map(ResultValue::PropertyEnumeration)
        }
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "non-property USER call reached the Win16 property host")),
    }
}

fn set_property(
    state: &SharedWorker,
    target: Win16WindowTarget,
    name: Win16HostPropertyName,
    data: u16,
) -> bool {
    let codec = state.borrow().text_codec;
    let Some((atom, callback_name, owns_lookup_reference)) = add_name(codec, name) else {
        return false;
    };
    let Some((window, hwnd, identity_cookie)) = resolve_window(state, target) else {
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    };

    let key = property_key(atom);
    if let Some(existing) = entry(state, window, atom) {
        let current_marker = native_property_value(hwnd, &key);
        if existing.hwnd == hwnd as usize
            && existing.identity_cookie == identity_cookie
            && identity_matches(state, window, hwnd, identity_cookie)
            && current_marker == existing.marker
        {
            // SetPropW has no compare-and-update form. The marker and identity
            // checks immediately precede this write; an external owner can
            // still race a replacement between USER calls.
            // SAFETY: The current USER key still carries this property's
            // marker, and the private key and HWND identity are unchanged.
            if unsafe { SetPropW(hwnd, key.as_ptr(), existing.marker as HANDLE) } == 0 {
                release_atom_reference(atom, owns_lookup_reference);
                return false;
            }
            let updated = {
                let mut worker = state.borrow_mut();
                worker.window_properties.entries.get_mut(&window)
                    .and_then(|properties| properties.get_mut(&atom))
                    .filter(|current| current.generation == existing.generation
                        && current.marker == existing.marker)
                    .map(|current| {
                        current.data = data;
                        true
                    })
                    .unwrap_or(false)
            };
            release_atom_reference(atom, owns_lookup_reference);
            return updated;
        }
        discard_stale_entry(state, window, atom, existing.generation);
    }

    // EnumProps distinguishes a missing key from a key whose HANDLE is null.
    // Never replace even a null-valued native property in our private namespace.
    let Some(native_key_atom) = add_native_key_atom(&key) else {
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    };
    if native::property_exists(hwnd, &key, native_key_atom) {
        release_atom_reference(native_key_atom, native_key_atom >= FIRST_STRING_ATOM);
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    }

    let Some(marker) = allocate_marker() else {
        release_atom_reference(native_key_atom, native_key_atom >= FIRST_STRING_ATOM);
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    };
    let Some(generation) = next_generation(state) else {
        release_atom_reference(native_key_atom, native_key_atom >= FIRST_STRING_ATOM);
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    };
    if !identity_matches(state, window, hwnd, identity_cookie) {
        release_atom_reference(native_key_atom, native_key_atom >= FIRST_STRING_ATOM);
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    }

    // SAFETY: `hwnd` still resolves to this token and identity generation;
    // `key` is a NUL-terminated private key and `marker` is a nonzero opaque
    // value that is never dereferenced.
    if unsafe { SetPropW(hwnd, key.as_ptr(), marker as HANDLE) } == 0 {
        release_atom_reference(native_key_atom, native_key_atom >= FIRST_STRING_ATOM);
        release_atom_reference(atom, owns_lookup_reference);
        return false;
    }

    let inserted = {
        let mut worker = state.borrow_mut();
        let current_hwnd = worker.windows.get(&window).copied();
        let current_identity = worker.windows_by_native.get(&(hwnd as usize))
            .is_some_and(|identity| identity.window == window);
        let current_cookie = worker.window_identity_cookies.get(&window)
            .filter(|binding| binding.hwnd == hwnd as usize && binding.value != 0)
            .map(|binding| binding.value);
        if current_hwnd != Some(hwnd) || !current_identity || current_cookie != identity_cookie {
            false
        } else {
            worker.window_properties.entries.entry(window).or_default().insert(atom,
                PropertyEntry {
                    hwnd: hwnd as usize,
                    identity_cookie,
                    marker,
                    native_key_atom,
                    generation,
                    data,
                    callback_name,
                    owns_string_atom_reference: owns_lookup_reference,
                });
            true
        }
    };
    if !inserted {
        // SAFETY: Restore no other key; remove only the marker just installed
        // for this exact private key if the HWND identity changed meanwhile.
        remove_property_if_matches(hwnd, &key, native_key_atom, marker);
        release_atom_reference(native_key_atom, native_key_atom >= FIRST_STRING_ATOM);
        release_atom_reference(atom, owns_lookup_reference);
    }
    inserted
}

fn get_property(
    state: &SharedWorker,
    target: Win16WindowTarget,
    name: Win16HostPropertyName,
) -> Option<u16> {
    let atom = find_lookup_name(state.borrow().text_codec, name)?;
    let Some((window, hwnd, identity_cookie)) = resolve_window(state, target) else {
        return None;
    };
    let Some(existing) = entry(state, window, atom) else {
        return None;
    };
    let key = property_key(atom);
    let valid = existing.hwnd == hwnd as usize
        && existing.identity_cookie == identity_cookie
        && identity_matches(state, window, hwnd, identity_cookie)
        && native_property_value(hwnd, &key) == existing.marker;
    if !valid {
        discard_stale_entry(state, window, atom, existing.generation);
        return None;
    }
    Some(existing.data)
}

fn remove_property(
    state: &SharedWorker,
    target: Win16WindowTarget,
    name: Win16HostPropertyName,
) -> Option<u16> {
    let atom = find_lookup_name(state.borrow().text_codec, name)?;
    let Some((window, hwnd, identity_cookie)) = resolve_window(state, target) else {
        return None;
    };
    let Some(existing) = entry(state, window, atom) else {
        return None;
    };
    let key = property_key(atom);
    let valid = existing.hwnd == hwnd as usize
        && existing.identity_cookie == identity_cookie
        && identity_matches(state, window, hwnd, identity_cookie)
        && native_property_value(hwnd, &key) == existing.marker;
    if !valid {
        discard_stale_entry(state, window, atom, existing.generation);
        return None;
    }

    // GetPropW and RemovePropW have no atomic compare-and-remove operation.
    // Identity and marker were checked immediately before this call, but an
    // external owner can still race a replacement between USER calls.
    // SAFETY: `key` is a NUL-terminated private name. RemovePropW returns the
    // opaque HANDLE without dereferencing it.
    let removed = unsafe { RemovePropW(hwnd, key.as_ptr()) } as usize;
    if removed != existing.marker {
        // If another same-process thread replaced the private key between the
        // check and removal, put its value back when the key is still vacant.
        // The vacancy check and SetPropW restore are separate calls, so they
        // cannot exclude a concurrent insertion in that interval.
        if removed != 0 && !native::property_exists(hwnd, &key, existing.native_key_atom) {
            // SAFETY: The returned HANDLE is opaque and the key is still the
            // same NUL-terminated private name.
            unsafe { SetPropW(hwnd, key.as_ptr(), removed as HANDLE) };
        }
        discard_stale_entry(state, window, atom, existing.generation);
        return None;
    }

    let removed_entry = take_entry(state, window, atom, existing.generation);
    enumeration::mark_property_removed(window, atom, existing.generation);
    if let Some(removed_entry) = removed_entry {
        release_entry_atom(atom, &removed_entry);
    }
    Some(existing.data)
}

fn find_lookup_name(codec: GuestTextCodec, name: Win16HostPropertyName) -> Option<u16> {
    match name {
        Win16HostPropertyName::Atom(0) => None,
        Win16HostPropertyName::Atom(atom) => Some(atom),
        Win16HostPropertyName::String(bytes)
            if bytes.is_empty() || bytes.len() > MAX_PROPERTY_NAME_BYTES
                || bytes.contains(&0) => None,
        Win16HostPropertyName::String(bytes) => {
            let wide = codec.to_wide_z(&bytes).ok()?;
            // SAFETY: The guest name is a valid NUL-terminated UTF-16 copy.
            // FindAtom does not acquire a reference or invent a raw atom.
            let atom = unsafe { GlobalFindAtomW(wide.as_ptr()) };
            (atom != 0).then_some(atom)
        }
    }
}

fn add_native_key_atom(key: &[u16]) -> Option<u16> {
    // SAFETY: `key` is a NUL-terminated private UTF-16 string generated locally.
    let atom = unsafe { GlobalAddAtomW(key.as_ptr()) };
    (atom != 0).then_some(atom)
}

fn add_name(
    codec: GuestTextCodec,
    name: Win16HostPropertyName,
) -> Option<(u16, Win16HostPropertyCallbackName, bool)> {
    match name {
        Win16HostPropertyName::Atom(0) => None,
        Win16HostPropertyName::Atom(atom) => Some((atom,
            Win16HostPropertyCallbackName::Atom(atom), false)),
        Win16HostPropertyName::String(bytes)
            if bytes.is_empty() || bytes.len() > MAX_PROPERTY_NAME_BYTES
                || bytes.contains(&0) => None,
        Win16HostPropertyName::String(bytes) => {
            let wide = codec.to_wide_z(&bytes).ok()?;
            // SAFETY: The guest name is nonempty, has no embedded NUL,
            // respects the Win16 255-byte limit, and is terminated here.
            let atom = unsafe { GlobalAddAtomW(wide.as_ptr()) };
            (atom != 0).then_some((atom,
                Win16HostPropertyCallbackName::String(bytes),
                atom >= FIRST_STRING_ATOM))
        }
    }
}

fn release_atom_reference(atom: u16, owns_reference: bool) {
    if owns_reference && atom >= FIRST_STRING_ATOM {
        // SAFETY: This is one reference acquired from GlobalAddAtomW for the
        // same string atom. GlobalDeleteAtom's return value is not its status.
        unsafe { GlobalDeleteAtom(atom) };
    }
}

fn release_entry_atom(atom: u16, entry: &PropertyEntry) {
    release_atom_reference(atom, entry.owns_string_atom_reference);
    release_atom_reference(entry.native_key_atom,
        entry.native_key_atom >= FIRST_STRING_ATOM);
}

fn resolve_window(
    state: &SharedWorker,
    target: Win16WindowTarget,
) -> Option<(Win16HostWindow, HWND, Option<usize>)> {
    let Win16WindowTarget::Mapped(window) = target else { return None; };
    let hwnd = super::win16_window_identity::resolve_user_window(state, window)?;
    let identity_cookie = identity_cookie(state, window, hwnd)?;
    Some((window, hwnd, identity_cookie))
}

fn identity_cookie(
    state: &SharedWorker,
    window: Win16HostWindow,
    hwnd: HWND,
) -> Option<Option<usize>> {
    let cookie = {
        let worker = state.borrow();
        if worker.windows.get(&window).copied()? != hwnd
            || !worker.windows_by_native.get(&(hwnd as usize))
                .is_some_and(|identity| identity.window == window)
        {
            return None;
        }
        match worker.window_identity_cookies.get(&window).copied() {
            Some(binding) if binding.hwnd == hwnd as usize && binding.value != 0 => {
                Some(binding.value)
            }
            Some(_) => return None,
            None => None,
        }
    };
    if identity_matches(state, window, hwnd, cookie) { Some(cookie) } else { None }
}

fn identity_matches(
    state: &SharedWorker,
    window: Win16HostWindow,
    hwnd: HWND,
    expected_cookie: Option<usize>,
) -> bool {
    let current_cookie = {
        let worker = state.borrow();
        if worker.windows.get(&window).copied() != Some(hwnd)
            || !worker.windows_by_native.get(&(hwnd as usize))
                .is_some_and(|identity| identity.window == window)
        {
            return false;
        }
        match worker.window_identity_cookies.get(&window).copied() {
            Some(binding) if binding.hwnd == hwnd as usize && binding.value != 0 => {
                Some(binding.value)
            }
            Some(_) => return false,
            None => None,
        }
    };
    if current_cookie != expected_cookie { return false; }
    // Borrowed windows outside this worker have no host identity cookie.
    // Their token mapping plus USER validity check is the available proof, but
    // it cannot distinguish an external HWND recycled between observations.
    match expected_cookie {
        Some(_) => super::win16_window_identity::resolve(state, window) == Some(hwnd),
        None => super::win16_window_identity::resolve_user_window(state, window) == Some(hwnd),
    }
}

fn entry(
    state: &SharedWorker,
    window: Win16HostWindow,
    atom: u16,
) -> Option<PropertyEntry> {
    state.borrow().window_properties.entries.get(&window)?.get(&atom).cloned()
}

fn take_entry(
    state: &SharedWorker,
    window: Win16HostWindow,
    atom: u16,
    generation: u64,
) -> Option<PropertyEntry> {
    let mut worker = state.borrow_mut();
    let properties = worker.window_properties.entries.get_mut(&window)?;
    if properties.get(&atom)?.generation != generation { return None; }
    let removed = properties.remove(&atom);
    if properties.is_empty() {
        worker.window_properties.entries.remove(&window);
    }
    removed
}

fn discard_stale_entry(
    state: &SharedWorker,
    window: Win16HostWindow,
    atom: u16,
    generation: u64,
) {
    if let Some(stale) = take_entry(state, window, atom, generation) {
        release_entry_atom(atom, &stale);
    }
}

fn next_generation(state: &SharedWorker) -> Option<u64> {
    let mut worker = state.borrow_mut();
    let properties = &mut worker.window_properties;
    let generation = properties.next_generation;
    properties.next_generation = generation.checked_add(1)?;
    (generation != 0).then_some(generation)
}

fn allocate_marker() -> Option<usize> {
    NEXT_PROPERTY_MARKER.try_update(Ordering::Relaxed, Ordering::Relaxed,
        |current| current.checked_add(1)).ok()
}

fn property_key(atom: u16) -> [u16; PROPERTY_KEY_LENGTH] {
    let mut key = [0_u16; PROPERTY_KEY_LENGTH];
    // The private key is fixed ASCII, not guest text; widen its ASCII code
    // units directly so its host identity does not depend on the guest page.
    for (destination, source) in key.iter_mut().zip(PROPERTY_KEY_PREFIX.bytes()) {
        *destination = u16::from(source);
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let offset = PROPERTY_KEY_PREFIX.len();
    key[offset] = u16::from(HEX[usize::from((atom >> 12) & 0x0f)]);
    key[offset + 1] = u16::from(HEX[usize::from((atom >> 8) & 0x0f)]);
    key[offset + 2] = u16::from(HEX[usize::from((atom >> 4) & 0x0f)]);
    key[offset + 3] = u16::from(HEX[usize::from(atom & 0x0f)]);
    key[offset + 4] = 0;
    key
}

fn native_property_value(hwnd: HWND, key: &[u16]) -> usize {
    // SAFETY: `key` is generated as a NUL-terminated host-private key and
    // callers have just resolved `hwnd` through the current identity token.
    unsafe { GetPropW(hwnd, key.as_ptr()) as usize }
}

fn remove_property_if_matches(
    hwnd: HWND,
    key: &[u16],
    native_key_atom: u16,
    marker: usize,
) {
    if native_property_value(hwnd, key) != marker { return; }
    // GetPropW and RemovePropW have no compare-and-remove operation. The marker
    // check is immediate, and any unexpected returned value is treated as a
    // foreign replacement; a concurrent owner can still race these calls.
    // SAFETY: The property was just verified to carry our opaque marker; the
    // returned HANDLE is opaque and is checked before any restoration.
    let removed = unsafe { RemovePropW(hwnd, key.as_ptr()) } as usize;
    if removed != marker && removed != 0
        && !native::property_exists(hwnd, key, native_key_atom)
    {
        // The vacancy probe and SetPropW restore are separate calls; another
        // owner can insert a value between them.
        // SAFETY: Restore an unexpected removed value only when the key is
        // vacant. The HANDLE is an opaque value returned by USER.
        unsafe { SetPropW(hwnd, key.as_ptr(), removed as HANDLE) };
    }
}

/// Remove all sidecars and release their owned atom references before the
/// worker retires this HWND's identity cookie. A mismatched identity or marker
/// is never removed from USER, even if the numeric HWND has been recycled.
pub(super) fn retire_window(
    state: &SharedWorker,
    window: Win16HostWindow,
    hwnd: HWND,
) {
    let properties = {
        let mut worker = state.borrow_mut();
        worker.window_properties.entries.remove(&window).unwrap_or_default()
    };
    enumeration::mark_window_retired(window);
    for (atom, property) in properties {
        let key = property_key(atom);
        if property.hwnd == hwnd as usize
            && identity_cookie(state, window, hwnd) == Some(property.identity_cookie)
            && identity_matches(state, window, hwnd, property.identity_cookie)
        {
            remove_property_if_matches(hwnd, &key, property.native_key_atom, property.marker);
        }
        release_entry_atom(atom, &property);
    }
}

/// Worker shutdown cleanup covers borrowed HWND aliases as well as windows
/// which were destroyed through their ordinary NCDESTROY retirement path.
pub(super) fn retire_all(state: &SharedWorker) {
    let entries = {
        let mut worker = state.borrow_mut();
        std::mem::take(&mut worker.window_properties.entries)
    };
    for (window, properties) in entries {
        enumeration::mark_window_retired(window);
        for (atom, property) in properties {
            let key = property_key(atom);
            let hwnd = property.hwnd as HWND;
            if identity_cookie(state, window, hwnd) == Some(property.identity_cookie)
                && identity_matches(state, window, hwnd, property.identity_cookie)
            {
                remove_property_if_matches(hwnd, &key, property.native_key_atom, property.marker);
            }
            release_entry_atom(atom, &property);
        }
    }
}
