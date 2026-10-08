//! Native key-name handling for Win16 window-property sidecars.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::UI::WindowsAndMessaging::EnumPropsW;

use super::EnumPropertySnapshot;

thread_local! {
    static ACTIVE_KEY_SEARCHES: RefCell<Vec<*mut KeySearchContext>> = const { RefCell::new(Vec::new()) };
}

struct KeySearchContext {
    key: Vec<u16>,
    atom: u16,
    found: bool,
    failed: bool,
}

struct KeySearchGuard {
    context: *mut KeySearchContext,
}

impl KeySearchGuard {
    fn push(context: &mut KeySearchContext) -> Self {
        let context = context as *mut KeySearchContext;
        ACTIVE_KEY_SEARCHES.with(|stack| stack.borrow_mut().push(context));
        Self { context }
    }
}

impl Drop for KeySearchGuard {
    fn drop(&mut self) {
        ACTIVE_KEY_SEARCHES.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(index) = stack.iter().rposition(|context| *context == self.context) {
                stack.remove(index);
            }
        });
    }
}

/// Check the complete native property table so a null-valued foreign property
/// is not mistaken for an absent key and replaced by SetPropW.
pub(super) fn property_exists(hwnd: HWND, key: &[u16], atom: u16) -> bool {
    let key = key.strip_suffix(&[0]).unwrap_or(key);
    let mut owned_key = Vec::new();
    if owned_key.try_reserve_exact(key.len()).is_err() {
        return true;
    }
    owned_key.extend_from_slice(key);
    let mut context = KeySearchContext {
        key: owned_key, atom, found: false, failed: false,
    };
    let _active = KeySearchGuard::push(&mut context);
    // SAFETY: Callers validate `hwnd` first. The callback compares a copied
    // wide name or MAKEINTATOM value and retains neither native pointer.
    unsafe { EnumPropsW(hwnd, Some(property_key_search_callback)) };
    context.found || context.failed
}

/// Resolve either representation EnumPropsW may use for our private string
/// key. SetPropW can expose a MAKEINTATOM after USER canonicalizes a name.
pub(super) fn property_atom(
    pointer: windows_sys::core::PCWSTR,
    snapshot: &BTreeMap<u16, EnumPropertySnapshot>,
) -> Option<u16> {
    match read_native_name(pointer)? {
        NativePropertyName::Atom(native_atom) => snapshot.iter().find_map(|(guest_atom, entry)| {
            (entry.native_key_atom == native_atom).then_some(*guest_atom)
        }),
        NativePropertyName::String(wide_name) => parse_private_key(&wide_name),
    }
}

unsafe extern "system" fn property_key_search_callback(
    _hwnd: HWND,
    name: windows_sys::core::PCWSTR,
    _data: HANDLE,
) -> windows_sys::core::BOOL {
    match catch_unwind(AssertUnwindSafe(|| {
        let Some(context) = current_key_search() else { return 1; };
        let Some(name) = read_native_name(name) else { return 1; };
        // SAFETY: The search frame is scoped around EnumPropsW and remains
        // alive throughout this native callback.
        let context = unsafe { &mut *context };
        let matches = match name {
            NativePropertyName::Atom(atom) => atom == context.atom,
            NativePropertyName::String(wide_name) => {
                wide_ascii_eq_ignore_case(&wide_name, &context.key)
            }
        };
        if matches {
            context.found = true;
            0
        } else {
            1
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            if let Some(context) = current_key_search() {
                // SAFETY: The active search context is scoped to EnumPropsW.
                unsafe { (*context).failed = true; }
            }
            0
        }
    }
}

enum NativePropertyName {
    Atom(u16),
    String(Vec<u16>),
}

fn read_native_name(pointer: windows_sys::core::PCWSTR) -> Option<NativePropertyName> {
    if pointer.is_null() { return None; }
    if pointer as usize <= usize::from(u16::MAX) {
        return Some(NativePropertyName::Atom(pointer as usize as u16));
    }
    // EnumPropsW guarantees a live NUL-terminated name for the callback. This
    // small copier is needed because Rust's CStr type has no UTF-16 equivalent.
    let mut length = 0_usize;
    loop {
        // SAFETY: The callback supplies a readable NUL-terminated UTF-16 name.
        if unsafe { pointer.add(length).read() } == 0 {
            break;
        }
        length = length.checked_add(1)?;
    }
    // SAFETY: The scan above found the terminator and the same callback keeps
    // the name alive while this exact non-terminator span is copied.
    let source = unsafe { slice::from_raw_parts(pointer, length) };
    let mut owned = Vec::new();
    owned.try_reserve_exact(length).ok()?;
    owned.extend_from_slice(source);
    Some(NativePropertyName::String(owned))
}

fn parse_private_key(name: &[u16]) -> Option<u16> {
    let prefix = super::PROPERTY_KEY_PREFIX.as_bytes();
    if name.len() != prefix.len() + 4
        || !name[..prefix.len()].iter().zip(prefix)
            .all(|(wide, ascii)| fold_ascii(*wide) == fold_ascii(u16::from(*ascii)))
    {
        return None;
    }
    let mut atom = 0_u16;
    for unit in &name[prefix.len()..] {
        let ascii = u8::try_from(*unit).ok()?;
        let digit = match ascii {
            b'0'..=b'9' => ascii - b'0',
            b'A'..=b'F' => ascii - b'A' + 10,
            b'a'..=b'f' => ascii - b'a' + 10,
            _ => return None,
        };
        atom = (atom << 4) | u16::from(digit);
    }
    (atom != 0).then_some(atom)
}

fn wide_ascii_eq_ignore_case(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
}

fn fold_ascii(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + u16::from(b'a' - b'A')
    } else {
        unit
    }
}

fn current_key_search() -> Option<*mut KeySearchContext> {
    ACTIVE_KEY_SEARCHES.with(|stack| stack.borrow().last().copied())
}
