//! Explicit guest-code-page conversion for native menu strings.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostGdiObject, Win16HostMenu,
    Win16MenuItem, Win16MenuItemContent, Win16MenuItemIdentity, Win16MenuResult};
use windows_sys::Win32::UI::WindowsAndMessaging::GetMenuStringW;

use super::super::win16_window_worker::WorkerState;

pub(super) fn get_menu_string(
    state: &Rc<RefCell<WorkerState>>,
    menu: Win16HostMenu,
    item: u16,
    flags: u16,
    capacity: i16,
) -> Result<Win16MenuResult, RuntimeError> {
    let Some(native) = super::native_menu(state, menu) else {
        return Ok(Win16MenuResult::MenuString { count: 0, buffer: Vec::new() });
    };
    if capacity < 0 {
        return Ok(Win16MenuResult::MenuString { count: 0, buffer: Vec::new() });
    }

    // GetMenuStringW's zero-capacity form is a length query. The worker is the
    // sole menu owner and this query does not enter a guest callback.
    let native_length = unsafe {
        GetMenuStringW(native, u32::from(item), std::ptr::null_mut(), 0,
            u32::from(flags))
    };
    if native_length < 0 {
        return Ok(Win16MenuResult::MenuString { count: native_length as i16, buffer: Vec::new() });
    }
    let length = usize::try_from(native_length).map_err(|_| RuntimeError::new(
        Kind::CompatibilityGap, "native menu text length is outside the host range"))?;
    if length > runtime::WIN16_CONTROL_TEXT_CAPACITY.saturating_mul(2) {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native menu string exceeds its checked UTF-16 staging bound"));
    }
    if length == 0 {
        if capacity > 0 {
            return Ok(Win16MenuResult::MenuString { count: 0, buffer: vec![0] });
        }
        return Ok(Win16MenuResult::MenuString { count: 0, buffer: Vec::new() });
    }

    let allocation = length.checked_add(1).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "native menu string staging size overflowed"))?;
    let mut wide = Vec::new();
    wide.try_reserve_exact(allocation).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate native UTF-16 menu text", error))?;
    wide.resize(allocation, 0xffff);
    let copied = unsafe {
        GetMenuStringW(native, u32::from(item), wide.as_mut_ptr(),
            i32::try_from(allocation).map_err(|_| RuntimeError::new(
                Kind::CompatibilityGap, "native menu string capacity exceeds Win32 range"))?,
            u32::from(flags))
    };
    if copied < 0 || usize::try_from(copied).ok() != Some(length)
        || wide.get(length) != Some(&0)
        || wide[..length].contains(&0)
    {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native GetMenuStringW violated its checked output contract"));
    }

    let codec = state.borrow().text_codec;
    if capacity == 0 {
        let encoded = codec.from_wide(&wide[..length])?;
        let count = encoded.bytes.len() as i16;
        return Ok(Win16MenuResult::MenuString { count, buffer: Vec::new() });
    }

    let output_capacity = usize::try_from(capacity).unwrap_or(0);
    let bounded = codec.from_wide_bounded(&wide[..length], output_capacity.saturating_sub(1))?;
    let count = i16::try_from(bounded.bytes.len()).map_err(|_| RuntimeError::new(
        Kind::CompatibilityGap, "guest menu string byte count exceeds the Win16 result range"))?;
    let mut buffer = bounded.bytes;
    buffer.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "terminate guest menu string output", error))?;
    buffer.push(0);
    Ok(Win16MenuResult::MenuString { count, buffer })
}

pub(super) fn native_item(
    state: &Rc<RefCell<WorkerState>>,
    bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
    item: Win16MenuItem,
) -> Result<Option<PreparedMenuItem>, RuntimeError> {
    let value = match item.identity {
        Win16MenuItemIdentity::Command(id) => usize::from(id),
        Win16MenuItemIdentity::Submenu(token) => match super::native_menu(state, token) {
            Some(menu) => menu as usize,
            None => return Ok(None),
        },
    };
    let prepared = match item.content {
        Win16MenuItemContent::Text(Some(bytes)) => {
            if bytes.contains(&0) {
                return Err(RuntimeError::new(Kind::InvalidInput,
                    "menu text contains an embedded terminator"));
            }
            let text = wide_z(state, &bytes)?;
            PreparedMenuItem { value, text: Some(text), pointer: None }
        }
        Win16MenuItemContent::Text(None) | Win16MenuItemContent::Separator => {
            PreparedMenuItem { value, text: None, pointer: None }
        }
        Win16MenuItemContent::Bitmap(bitmap) => {
            let pointer = match bitmap {
                Some(bitmap) => match bitmaps.get(&bitmap).copied().flatten() {
                    Some(bitmap) => Some(bitmap),
                    None => return Ok(None),
                },
                None => None,
            };
            PreparedMenuItem { value, text: None, pointer }
        }
        // Owner-draw values are numeric guest data, never native pointers.
        // The checked MEASUREITEM/DRAWITEM bridge is not part of this path.
        Win16MenuItemContent::OwnerDraw(_) => return Ok(None),
    };
    Ok(Some(prepared))
}

pub(super) fn wide_z(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
) -> Result<Vec<u16>, RuntimeError> {
    state.borrow().text_codec.to_wide_z(bytes)
}

pub(super) struct PreparedMenuItem {
    pub(super) value: usize,
    text: Option<Vec<u16>>,
    pointer: Option<usize>,
}

impl PreparedMenuItem {
    pub(super) fn pointer(&self) -> windows_sys::core::PCWSTR {
        if let Some(pointer) = self.pointer {
            pointer as windows_sys::core::PCWSTR
        } else {
            self.text.as_ref().map_or(std::ptr::null(), |text| text.as_ptr())
        }
    }
}
