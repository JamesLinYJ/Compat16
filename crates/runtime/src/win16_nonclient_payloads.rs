//! Win16 `WM_NCCALCSIZE` buffers and pointer-free host conversion.
//!
//! Windows 3.1 SDK `WINDOWSX.H` (Disk 3, lines 346–350) keeps the message's
//! BOOL16 and casts the handler result through `UINT`; `WINDOWS.H` (Disk 3,
//! lines 3221–3231 and 3473–3478) defines 14-byte `WINDOWPOS` and the 28-byte
//! three-RECT true branch. The source headers are under
//! `../../work/reference/windows-sdk/3.1/files/expanded/Disk 3 (050-151-053)/INC/`.
//! False-branch buffers contain only the leading RECT. No host pointer or
//! unvalidated alternate guest FAR pointer crosses this module boundary.

use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer};
use win16_abi::window_geometry::{Rect16, WindowPos16};
use win16_abi::window_nonclient::NonClientCalcSize16;

use super::GuestWindowPayload;
use super::window_position_payloads::{guest_wire_position, host_position};
use super::super::{Win16State, guest_ranges::GuestOutputRange};
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMessageOutput,
    Win16HostNonClientCalcSize, Win16HostRect,
};

pub(in crate::win16_runtime) const WM_NCCALCSIZE: u16 = 0x0083;
const NCCALC_WITH_POSITION_SIZE: usize = NonClientCalcSize16::SIZE + WindowPos16::SIZE;

/// Checked writeback targets retained across the native call. Each pointer
/// carries its original selector generation; every range is translated again
/// before result bytes are written.
#[derive(Clone, Debug)]
pub(in crate::win16_runtime) enum MessageOutput {
    Rect { rect: GuestOutputRange },
    ValidRects {
        params: GuestOutputRange,
        position: Option<GuestOutputRange>,
        original_lppos: u32,
    },
}

/// Copy a guest `WM_NCCALCSIZE` input into owned host values and retain only
/// checked guest locations needed for a later output writeback.
pub(in crate::win16_runtime) fn prepare_guest_message(
    state: &Win16State,
    w_param: u16,
    l_param: u32,
    memory: &Memory,
) -> Result<Option<(Win16HostNonClientCalcSize, MessageOutput)>, RuntimeError> {
    let outer = checked_far_pointer(state, l_param)?;
    if w_param == 0 {
        preflight(state, outer, Rect16::SIZE, memory)?;
        let mut bytes = [0; Rect16::SIZE];
        state.selectors.read(memory, outer, &mut bytes).map_err(crate::runtime_error)?;
        let rect = Rect16::decode(&bytes);
        let output = GuestOutputRange::capture(state, memory, outer, Rect16::SIZE)?;
        return Ok(Some((
            Win16HostNonClientCalcSize::Rect(host_rect(rect)),
            MessageOutput::Rect { rect: output },
        )));
    }

    preflight(state, outer, NonClientCalcSize16::SIZE, memory)?;
    let mut bytes = [0; NonClientCalcSize16::SIZE];
    state.selectors.read(memory, outer, &mut bytes).map_err(crate::runtime_error)?;
    let params = NonClientCalcSize16::decode(&bytes).map_err(crate::runtime_error)?;
    let position_pointer = if params.lppos == 0 {
        None
    } else {
        let pointer = checked_far_pointer(state, params.lppos)?;
        preflight(state, pointer, WindowPos16::SIZE, memory)?;
        Some(pointer)
    };
    let params_output = GuestOutputRange::capture(state, memory, outer, NonClientCalcSize16::SIZE)?;
    let position_output = position_pointer.map(|pointer|
        GuestOutputRange::capture(state, memory, pointer, WindowPos16::SIZE))
        .transpose()?;
    let position = match position_pointer {
        Some(pointer) => {
            let mut bytes = [0; WindowPos16::SIZE];
            state.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
            match host_position(state, WindowPos16::decode(&bytes)) {
                Ok(position) => Some(position),
                // Invalid embedded HWNDs are ordinary API input failures.
                // The complete guest memory ranges were already checked;
                // rejecting a handle must not disguise a storage/selector fault.
                Err(error) if error.kind() == Kind::InvalidInput => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        None => None,
    };
    Ok(Some((
        Win16HostNonClientCalcSize::ValidRects {
            rects: params.rgrc.map(host_rect),
            position,
        },
        MessageOutput::ValidRects {
            params: params_output,
            position: position_output,
            original_lppos: params.lppos,
        },
    )))
}

/// Apply a copied native message result to the original guest structures.
/// All output representations and memory ranges are checked before the first
/// write; the original raw `lppos` value is restored unchanged.
pub(in crate::win16_runtime) fn write_guest_result(
    state: &mut Win16State,
    output: MessageOutput,
    data: Win16HostNonClientCalcSize,
    memory: &mut Memory,
) -> Result<(), RuntimeError> {
    match (output, data) {
        (MessageOutput::Rect { rect: output }, Win16HostNonClientCalcSize::Rect(rect)) => {
            super::super::guest_ranges::commit_guest_output(
                state, memory, &output, &guest_rect(rect).encode(),
            )
        }
        (
            MessageOutput::ValidRects { params, position, original_lppos },
            Win16HostNonClientCalcSize::ValidRects { rects, position: host_position },
        ) => {
            if position.is_some() != host_position.is_some()
                || (original_lppos == 0) != position.is_none()
            {
                return Err(invariant(
                    "native WM_NCCALCSIZE result changed the guest WINDOWPOS nullness",
                ));
            }

            if params.length() != NonClientCalcSize16::SIZE
                || position.as_ref().is_some_and(|range| range.length() != WindowPos16::SIZE)
            {
                return Err(invariant("captured NCCALCSIZE output extent changed"));
            }
            let position_bytes = host_position.map(|position| guest_wire_position(state, position))
                .transpose()?
                .map(WindowPos16::encode);
            let params_bytes = NonClientCalcSize16 {
                rgrc: rects.map(guest_rect),
                lppos: original_lppos,
            }.encode();

            // Re-translate retained SelectorRefs after the native call. The
            // outer record restores the original lppos bits, and any aliased
            // WINDOWPOS write must agree with the complete outer record.
            if let (Some(position), Some(bytes)) = (position.as_ref(), position_bytes.as_ref()) {
                params.ensure_compatible_output(&params_bytes, position, bytes)?;
            }
            let mut writes = Vec::new();
            writes.try_reserve_exact(if position_bytes.is_some() { 2 } else { 1 })
                .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                    "retain WM_NCCALCSIZE output transaction", error))?;
            writes.push((params.try_clone()?, params_bytes.to_vec()));
            if let (Some(output), Some(bytes)) = (position, position_bytes.as_ref()) {
                writes.push((output.try_clone()?, bytes.to_vec()));
            }
            super::super::guest_ranges::commit_guest_writes(state, memory, writes)
        }
        _ => Err(invariant(
            "native WM_NCCALCSIZE result does not match the guest wParam layout",
        )),
    }
}

pub(in crate::win16_runtime) fn write_guest_result_with_selectors(
    output: MessageOutput,
    data: Win16HostNonClientCalcSize,
    selectors: &win16_abi::SelectorTable,
    memory: &mut Memory,
    mut map_window: impl FnMut(crate::Win16HostWindow) -> Result<u16, RuntimeError>,
) -> Result<(), RuntimeError> {
    match (output, data) {
        (MessageOutput::Rect { rect }, Win16HostNonClientCalcSize::Rect(value)) =>
            super::super::guest_ranges::commit_guest_output_with_selectors(
                selectors, memory, &rect, &guest_rect(value).encode(),
            ),
        (
            MessageOutput::ValidRects { params, position, original_lppos },
            Win16HostNonClientCalcSize::ValidRects { rects, position: host_position },
        ) => {
            if position.is_some() != host_position.is_some()
                || (original_lppos == 0) != position.is_none()
            {
                return Err(invariant(
                    "native WM_NCCALCSIZE result changed the guest WINDOWPOS nullness",
                ));
            }
            if params.length() != NonClientCalcSize16::SIZE
                || position.as_ref().is_some_and(|range| range.length() != WindowPos16::SIZE)
            {
                return Err(invariant("captured NCCALCSIZE output extent changed"));
            }
            let position_bytes = host_position.map(|position|
                super::window_position_payloads::guest_wire_position_with(position,
                    &mut map_window))
                .transpose()?
                .map(WindowPos16::encode);
            let params_bytes = NonClientCalcSize16 {
                rgrc: rects.map(guest_rect),
                lppos: original_lppos,
            }.encode();
            if let (Some(position), Some(bytes)) = (position.as_ref(), position_bytes.as_ref()) {
                params.ensure_compatible_output(&params_bytes, position, bytes)?;
            }
            let mut writes = Vec::new();
            writes.try_reserve_exact(if position_bytes.is_some() { 2 } else { 1 })
                .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                    "retain WM_NCCALCSIZE output transaction", error))?;
            writes.push((params.try_clone()?, params_bytes.to_vec()));
            if let (Some(range), Some(bytes)) = (position, position_bytes.as_ref()) {
                writes.push((range.try_clone()?, bytes.to_vec()));
            }
            super::super::guest_ranges::commit_guest_writes_with_selectors(
                selectors, memory, writes,
            )
        }
        _ => Err(invariant(
            "native WM_NCCALCSIZE result does not match the guest wParam layout",
        )),
    }
}

/// Prepare an incoming host callback in a runtime-owned Win16 allocation.
/// The true branch stores its optional WINDOWPOS immediately after the
/// 28-byte outer record, so callback cleanup owns both records together.
pub(in crate::win16_runtime) fn prepare_callback_payload(
    state: &mut Win16State,
    w_param: u16,
    data: Win16HostNonClientCalcSize,
    memory: &mut Memory,
) -> Result<GuestWindowPayload, RuntimeError> {
    let (size, bytes) = match (w_param == 0, data) {
        (true, Win16HostNonClientCalcSize::Rect(rect)) => {
            let bytes = guest_rect(rect).encode();
            (Rect16::SIZE, CallbackBytes::Rect(bytes))
        }
        (false, Win16HostNonClientCalcSize::ValidRects { rects, position }) => {
            let guest_position = position.map(|position| guest_wire_position(state, position))
                .transpose()?;
            let size = if guest_position.is_some() {
                NCCALC_WITH_POSITION_SIZE
            } else {
                NonClientCalcSize16::SIZE
            };
            (size, CallbackBytes::ValidRects { rects, position: guest_position })
        }
        _ => return Err(invariant(
            "host WM_NCCALCSIZE data does not match its BOOL16 wParam",
        )),
    };

    let (allocation, pointer) = state.allocate_window_payload(memory, size)?;
    let write_result = match bytes {
        CallbackBytes::Rect(bytes) => state.selectors.write(memory, pointer, &bytes)
            .map_err(crate::runtime_error),
        CallbackBytes::ValidRects { rects, position } => {
            let position_far = match position {
                Some(_) => match nested_position_pointer(pointer) {
                    Ok(pointer) => pointer.far_value(),
                    Err(error) => return Err(state.cleanup_after_error(allocation, error)),
                },
                None => 0,
            };
            let params = NonClientCalcSize16 {
                rgrc: rects.map(guest_rect),
                lppos: position_far,
            };
            let mut combined = [0; NCCALC_WITH_POSITION_SIZE];
            combined[..NonClientCalcSize16::SIZE].copy_from_slice(&params.encode());
            if let Some(position) = position {
                combined[NonClientCalcSize16::SIZE..].copy_from_slice(&position.encode());
            }
            state.selectors.write(memory, pointer, &combined[..size])
                .map_err(crate::runtime_error)
        }
    };
    if let Err(error) = write_result {
        return Err(state.cleanup_after_error(allocation, error));
    }

    Ok(GuestWindowPayload {
        message: WM_NCCALCSIZE,
        w_param,
        l_param: pointer.far_value(),
        allocation: Some(allocation),
        output: Some((pointer, size as u16)),
        callback_dc: None,
        command_control: None,
        command_parent: None,
        common_dialog_request: None,
    })
}

enum CallbackBytes {
    Rect([u8; Rect16::SIZE]),
    ValidRects {
        rects: [Win16HostRect; 3],
        position: Option<WindowPos16>,
    },
}

/// Read callback output and project any nested position to an owned host
/// value. The guest FAR pointer is validated and copied; it never crosses the
/// host boundary. The native callback's original WINDOWPOS target remains
/// owned by the host operation.
pub(in crate::win16_runtime) fn finish_callback_payload(
    state: &mut Win16State,
    w_param: u16,
    l_param: u32,
    output: Option<(SegmentedPointer, u16)>,
    value: u32,
    dialog_proc: bool,
    memory: &Memory,
) -> Result<Win16HostMessageOutput, RuntimeError> {
    let (pointer, _) = output.filter(|(pointer, size)| {
        pointer.far_value() == l_param && match (w_param == 0, usize::from(*size)) {
            (true, size) => size == Rect16::SIZE,
            (false, size) => size == NonClientCalcSize16::SIZE
                || size == NCCALC_WITH_POSITION_SIZE,
        }
    }).ok_or_else(|| invariant("Win16 WM_NCCALCSIZE callback has no matching owned buffer"))?;

    // An unhandled DLGPROC message has no output contract. Do not interpret
    // guest-modified bytes on this path; the original owned allocation is
    // still released by the caller after this return.
    if dialog_proc && value == 0 {
        return Ok(Win16HostMessageOutput::None);
    }

    if w_param == 0 {
        let mut bytes = [0; Rect16::SIZE];
        state.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        return Ok(Win16HostMessageOutput::NonClientCalcSize(
            Win16HostNonClientCalcSize::Rect(host_rect(Rect16::decode(&bytes))),
        ));
    }

    let mut bytes = [0; NonClientCalcSize16::SIZE];
    state.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
    let params = NonClientCalcSize16::decode(&bytes).map_err(crate::runtime_error)?;
    let position_pointer = if params.lppos == 0 {
        None
    } else {
        let pointer = checked_far_pointer(state, params.lppos)?;
        state.selectors.translate(pointer, Access::Read, WindowPos16::SIZE, memory)
            .map_err(crate::runtime_error)?;
        Some(pointer)
    };
    let position = match position_pointer {
        Some(position_pointer) => {
            let mut bytes = [0; WindowPos16::SIZE];
            state.selectors.read(memory, position_pointer, &mut bytes).map_err(crate::runtime_error)?;
            Some(host_position(state, WindowPos16::decode(&bytes))?)
        }
        None => None,
    };
    Ok(Win16HostMessageOutput::NonClientCalcSize(
        Win16HostNonClientCalcSize::ValidRects {
            rects: params.rgrc.map(host_rect),
            position,
        },
    ))
}

fn checked_far_pointer(state: &Win16State, far: u32) -> Result<SegmentedPointer, RuntimeError> {
    state.selectors.pointer_from_far(far).map_err(crate::runtime_error)
}

fn preflight(
    state: &Win16State,
    pointer: SegmentedPointer,
    size: usize,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    state.selectors.translate(pointer, Access::Read, size, memory)
        .map_err(crate::runtime_error)?;
    state.selectors.translate(pointer, Access::Write, size, memory)
        .map_err(crate::runtime_error)?;
    Ok(())
}

fn nested_position_pointer(pointer: SegmentedPointer) -> Result<SegmentedPointer, RuntimeError> {
    let offset = pointer.offset().checked_add(NonClientCalcSize16::SIZE as u16)
        .ok_or_else(|| invariant("Win16 NCCALCSIZE temporary WINDOWPOS offset overflowed"))?;
    Ok(SegmentedPointer::new(pointer.selector(), offset))
}

fn host_rect(rect: Rect16) -> Win16HostRect {
    Win16HostRect {
        left: i32::from(rect.left),
        top: i32::from(rect.top),
        right: i32::from(rect.right),
        bottom: i32::from(rect.bottom),
    }
}

fn guest_rect(rect: Win16HostRect) -> Rect16 {
    // Win16 int is signed 16-bit; like the existing MINMAXINFO bridge, narrow
    // native LONG coordinates by retaining their guest-visible low word.
    Rect16 {
        left: rect.left as i16,
        top: rect.top as i16,
        right: rect.right as i16,
        bottom: rect.bottom as i16,
    }
}

fn invariant(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
