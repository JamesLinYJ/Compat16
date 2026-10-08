//! Checked Win16 WINDOWPOS translation shared by standalone messages and NCCALCSIZE.

use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, window_geometry::WindowPos16};

use super::GuestWindowPayload;
use super::super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMessageOutput, Win16HostWindow,
    Win16HostWindowPos, Win16WindowInsertAfter,
};

// Windows 3.1 SDK WINDOWS.H:3178–3200, 3217–3231.
pub(in crate::win16_runtime) const WM_WINDOWPOSCHANGING: u16 = 0x0046;
pub(in crate::win16_runtime) const WM_WINDOWPOSCHANGED: u16 = 0x0047;
const HWND_TOP: u16 = 0;
const HWND_BOTTOM: u16 = 1;
const HWND_TOPMOST: u16 = 0xffff;
const HWND_NOTOPMOST: u16 = 0xfffe;

#[derive(Debug)]
pub(in crate::win16_runtime) struct MessageOutput {
    pub(in crate::win16_runtime) range: super::super::guest_ranges::GuestOutputRange,
}

/// Read a standalone WINDOWPOS. CHANGING retains a write target and preflights
/// the whole read/write range; CHANGED is input-only and reads exactly 14 bytes.
pub(in crate::win16_runtime) fn prepare_guest_message(
    state: &Win16State,
    changing: bool,
    l_param: u32,
    memory: &Memory,
) -> Result<Option<(Win16HostWindowPos, Option<MessageOutput>)>, RuntimeError> {
    if l_param == 0 {
        return Ok(None);
    }
    let pointer = state.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
    state.selectors.translate(pointer, Access::Read, WindowPos16::SIZE, memory)
        .map_err(crate::runtime_error)?;
    if changing {
        state.selectors.translate(pointer, Access::Write, WindowPos16::SIZE, memory)
            .map_err(crate::runtime_error)?;
    }
    let mut bytes = [0; WindowPos16::SIZE];
    state.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
    match host_position(state, WindowPos16::decode(&bytes)) {
        Ok(position) => Ok(Some((position, changing.then_some(MessageOutput {
            range: super::super::guest_ranges::GuestOutputRange::capture(
                state, memory, pointer, WindowPos16::SIZE,
            )?,
        })))),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

/// Revalidate the original guest selector generation and write the complete
/// CHANGING structure only after every output field has been translated.
pub(in crate::win16_runtime) fn write_guest_result(
    state: &mut Win16State,
    output: MessageOutput,
    position: Win16HostWindowPos,
    memory: &mut Memory,
) -> Result<(), RuntimeError> {
    let bytes = guest_wire_position(state, position)?.encode();
    super::super::guest_ranges::commit_guest_output_with_selectors(
        &state.selectors, memory, &output.range, &bytes,
    )
}

/// Copy a native callback's value into an owned 14-byte guest allocation.
pub(in crate::win16_runtime) fn prepare_callback_payload(
    state: &mut Win16State,
    changing: bool,
    w_param: u16,
    position: Win16HostWindowPos,
    memory: &mut Memory,
) -> Result<GuestWindowPayload, RuntimeError> {
    let bytes = guest_wire_position(state, position)?.encode();
    let (allocation, pointer) = state.allocate_window_payload(memory, WindowPos16::SIZE)?;
    if let Err(error) = state.selectors.write(memory, pointer, &bytes) {
        return Err(state.cleanup_after_error(allocation, crate::runtime_error(error)));
    }
    Ok(GuestWindowPayload {
        message: if changing { WM_WINDOWPOSCHANGING } else { WM_WINDOWPOSCHANGED },
        w_param,
        l_param: pointer.far_value(),
        allocation: Some(allocation),
        output: changing.then_some((pointer, WindowPos16::SIZE as u16)),
        callback_dc: None,
        command_control: None,
        command_parent: None,
        common_dialog_request: None,
    })
}

/// CHANGED is const/input-only. For CHANGING, malformed guest memory remains
/// an error; an unresolvable non-NULL HWND is a normal no-output fallback.
pub(in crate::win16_runtime) fn finish_callback_payload(
    state: &Win16State,
    changing: bool,
    l_param: u32,
    output: Option<(SegmentedPointer, u16)>,
    value: u32,
    dialog_proc: bool,
    memory: &Memory,
) -> Result<Win16HostMessageOutput, RuntimeError> {
    if (dialog_proc && value == 0) || !changing {
        return Ok(Win16HostMessageOutput::None);
    }
    let (pointer, _) = output.filter(|(pointer, size)| {
        pointer.far_value() == l_param && usize::from(*size) == WindowPos16::SIZE
    }).ok_or_else(|| invariant("Win16 WINDOWPOSCHANGING callback has no owned buffer"))?;
    let mut bytes = [0; WindowPos16::SIZE];
    state.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
    match host_position(state, WindowPos16::decode(&bytes)) {
        Ok(position) => Ok(Win16HostMessageOutput::WindowPosition(position)),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(Win16HostMessageOutput::None),
        Err(error) => Err(error),
    }
}

/// Convert owned host fields to the fixed Win16 wire representation.
pub(super) fn guest_wire_position(
    state: &mut Win16State,
    position: Win16HostWindowPos,
) -> Result<WindowPos16, RuntimeError> {
    guest_wire_position_with(position, |window| state.map_window_handle(window, false))
}

pub(in crate::win16_runtime) fn guest_wire_position_with(
    position: Win16HostWindowPos,
    mut guest_handle: impl FnMut(Win16HostWindow) -> Result<u16, RuntimeError>,
) -> Result<WindowPos16, RuntimeError> {
    let hwnd = match position.window {
        Some(window) => guest_handle(window)?,
        None => 0,
    };
    let hwnd_insert_after = match position.insert_after {
        Win16WindowInsertAfter::Top => HWND_TOP,
        Win16WindowInsertAfter::Bottom => HWND_BOTTOM,
        Win16WindowInsertAfter::Topmost => HWND_TOPMOST,
        Win16WindowInsertAfter::NotTopmost => HWND_NOTOPMOST,
        Win16WindowInsertAfter::Window(window) => guest_handle(window)?,
    };
    // Win16 int and UINT are 16-bit; retain the guest-visible low words.
    Ok(WindowPos16 {
        hwnd,
        hwnd_insert_after,
        x: position.x as i16,
        y: position.y as i16,
        cx: position.width as i16,
        cy: position.height as i16,
        flags: position.flags as u16,
    })
}

/// Convert the fixed Win16 wire structure to owned host fields. NULL in hwnd
/// remains NULL; stale non-NULL values never become NULL or native handles.
pub(super) fn host_position(
    state: &Win16State,
    position: WindowPos16,
) -> Result<Win16HostWindowPos, RuntimeError> {
    let window = host_window(state, position.hwnd)?;
    let insert_after = match position.hwnd_insert_after {
        HWND_TOP => Win16WindowInsertAfter::Top,
        HWND_BOTTOM => Win16WindowInsertAfter::Bottom,
        HWND_TOPMOST => Win16WindowInsertAfter::Topmost,
        HWND_NOTOPMOST => Win16WindowInsertAfter::NotTopmost,
        handle => Win16WindowInsertAfter::Window(host_window(state, handle)?.ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput,
                "Win16 WINDOWPOS hwndInsertAfter is null where a window token is required")
        })?),
    };
    Ok(Win16HostWindowPos {
        window,
        insert_after,
        x: i32::from(position.x),
        y: i32::from(position.y),
        width: i32::from(position.cx),
        height: i32::from(position.cy),
        flags: u32::from(position.flags),
    })
}

fn host_window(state: &Win16State, guest: u16) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if guest == 0 {
        Ok(None)
    } else {
        state.window_handles.get(&guest).copied().map(Some).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput,
                format!("Win16 WINDOWPOS refers to unmapped HWND 0x{guest:04X}"))
        })
    }
}

fn invariant(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
