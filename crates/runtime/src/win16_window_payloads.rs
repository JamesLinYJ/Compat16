//! Checked guest buffers for synchronous window-procedure callbacks.
//!
//! Payload pointers refer only to temporary Win16 heap blocks owned by this
//! runtime. Native message data is copied into guest-format structures before
//! a callback is scheduled, and callback output is copied back before release.

use guest_core::{OwnerId, memory::Memory};
use win16_abi::{AllocationFlags, GlobalHandle, SegmentedPointer};

use super::Win16State;
use super::geometry::{WM_GETMINMAXINFO, host_minmax_info};
use win16_abi::window_geometry::MinMaxInfo16;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMessageResult,
    Win16HostMessageOutput, Win16HostDc, Win16HostWindow,
};

#[path = "win16_window_queued_messages.rs"]
mod queued_messages;
#[path = "win16_nonclient_payloads.rs"]
pub(super) mod nonclient_payloads;
#[path = "win16_window_position_payloads.rs"]
pub(super) mod window_position_payloads;

const WM_GETTEXT: u16 = 0x000d;
const WM_CTLCOLOR: u16 = 0x0019;
const WIN16_COLOR_ENDCOLORS: u16 = 20;
const WINDOW_PAYLOAD_OWNER: OwnerId = OwnerId(1);

/// Win16 callback arguments plus ownership metadata for any temporary buffer.
pub(super) struct GuestWindowPayload {
    pub message: u16,
    pub w_param: u16,
    pub l_param: u32,
    pub allocation: Option<GlobalHandle>,
    pub output: Option<(SegmentedPointer, u16)>,
    /// Guest HDC token for WM_ERASEBKGND, retired when its WndProc returns.
    pub callback_dc: Option<(u16, Win16HostDc)>,
    /// Opaque control HWND used to translate a nested DefWindowProc call.
    pub command_control: Option<Win16HostWindow>,
    /// Actual native parent copied with WM_COMMAND, when supplied by host.
    pub command_parent: Option<Win16HostWindow>,
    /// Runtime session associated with this exact Find/Replace callback.
    pub common_dialog_request: Option<u64>,
}

// This copyable view contains only checked guest message data. Allocation
// and HDC ownership stay on the callback frame; cloning the owner-bearing
// payload would duplicate retirement obligations.
#[derive(Clone, Copy)]
pub(in crate::win16_runtime) struct WindowPayloadProjection {
    message: u16,
    w_param: u16,
    l_param: u32,
    output: Option<(SegmentedPointer, u16)>,
    common_dialog_request: Option<u64>,
}

impl GuestWindowPayload {
    pub(in crate::win16_runtime) fn projection(&self) -> WindowPayloadProjection {
        WindowPayloadProjection {
            message: self.message,
            w_param: self.w_param,
            l_param: self.l_param,
            output: self.output,
            common_dialog_request: self.common_dialog_request,
        }
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn project_callback_window_payload(
        &mut self,
        projection: WindowPayloadProjection,
        value: u32,
        dialog_result: Option<u32>,
        dialog_proc: bool,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostMessageResult, RuntimeError> {
        let WindowPayloadProjection {
            message, w_param, l_param, output, common_dialog_request,
        } = projection;
        let result: Result<Win16HostMessageResult, RuntimeError> = (|| {
            let output = if let Some(request_id) = common_dialog_request {
                Win16HostMessageOutput::FindReplace { request_id,
                    update: self.finish_find_replace_guest_callback(memory, request_id, host)?,
                }
            } else if message == WM_GETTEXT {
                if dialog_proc && value == 0 {
                    Win16HostMessageOutput::None
                } else if w_param == 0 {
                    // No bytes are transferable at zero capacity. Keep an
                    // ordinary WndProc's complete return value unchanged;
                    // DLGPROC's BOOL and DWL_MSGRESULT remain independent.
                    Win16HostMessageOutput::Text(Vec::new())
                } else if value == u32::MAX && !dialog_proc {
                    // Windows 3.1 Programmer's Reference, Vol. 3, PDF p. 139:
                    // WM_GETTEXT sent to a combo box without an edit control
                    // returns CB_ERR (-1), so there is no text to read back.
                    Win16HostMessageOutput::None
                } else if l_param == 0 {
                    // A native caller's null LPARAM is not a guest address.
                    // Preserve its callback result without reading any bytes;
                    // guest API output pointers are preflighted separately.
                    Win16HostMessageOutput::Text(Vec::new())
                } else if dialog_proc {
                    let count = dialog_result.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DLGPROC WM_GETTEXT has no DWL_MSGRESULT value",
                    ))?;
                    if count == u32::MAX {
                        Win16HostMessageOutput::None
                    } else {
                        self.read_gettext_result(count, w_param, output, memory)?
                    }
                } else {
                    self.read_gettext_result(value, w_param, output, memory)?
                }
            } else if message == WM_CTLCOLOR {
                // Windows 3.1 WINDOWSX.H SetDlgMsgResult excludes WM_CTLCOLOR
                // from DWL_MSGRESULT: DLGPROC returns LOWORD(result) as HBRUSH.
                Win16HostMessageOutput::ControlColor(self.control_color_brush(value as u16))
            } else if message == crate::win16_host_owner_draw::WM_MEASUREITEM {
                if dialog_proc && value == 0 {
                    Win16HostMessageOutput::None
                } else {
                    let (pointer, _) = output.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant, "Win16 MEASUREITEM has no owned output record"))?;
                    let mut bytes = [0; win16_abi::owner_draw::MeasureItemStruct16::SIZE];
                    self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
                    let data = win16_abi::owner_draw::MeasureItemStruct16::decode(&bytes)
                        .map_err(crate::runtime_error)?;
                    Win16HostMessageOutput::OwnerDrawMeasure {
                        width: data.item_width, height: data.item_height,
                    }
                }
            } else if message == WM_GETMINMAXINFO {
                if dialog_proc && value == 0 {
                    return Ok(Win16HostMessageResult { dialog_result,
                        value, output: Win16HostMessageOutput::None,
                    });
                }
                let (pointer, _) = output.filter(|(_, size)| usize::from(*size) == MinMaxInfo16::SIZE)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "Win16 WM_GETMINMAXINFO has no owned geometry buffer"))?;
                let mut bytes = [0_u8; MinMaxInfo16::SIZE];
                self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
                Win16HostMessageOutput::MinMaxInfo(host_minmax_info(MinMaxInfo16::decode(&bytes)))
            } else if message == nonclient_payloads::WM_NCCALCSIZE {
                nonclient_payloads::finish_callback_payload(
                    self, w_param, l_param, output, value, dialog_proc, memory,
                )?
            } else if message == window_position_payloads::WM_WINDOWPOSCHANGING {
                window_position_payloads::finish_callback_payload(
                    self, true, l_param, output, value, dialog_proc, memory,
                )?
            } else if message == window_position_payloads::WM_WINDOWPOSCHANGED && output.is_none() {
                Win16HostMessageOutput::None
            } else {
                if output.is_some() {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 message unexpectedly owns a callback output buffer",
                    ));
                }
                Win16HostMessageOutput::None
            };
            let value = if message == nonclient_payloads::WM_NCCALCSIZE && !dialog_proc {
                // WINDOWSX.H HANDLE_WM_NCCALCSIZE casts the guest handler's
                // UINT result through DWORD, so retain the unsigned 16-bit
                // result instead of extending a signed host LRESULT.
                u32::from(value as u16)
            } else {
                value
            };
            Ok(Win16HostMessageResult { dialog_result, value, output })
        })();

        result
    }

    fn control_color_brush(&self, guest_handle: u16)
        -> crate::Win16HostControlColorBrush
    {
        match guest_handle {
            0 => crate::Win16HostControlColorBrush::Null,
            handle if (1..=WIN16_COLOR_ENDCOLORS + 1).contains(&handle) => {
                // Windows 3.1 WINDOWS.H defines COLOR_* as 0..=20; WM_CTLCOLOR
                // returns those system-color brushes as COLOR_* + 1. Keep this
                // pseudo-handle meaning local to the callback result.
                crate::Win16HostControlColorBrush::Brush(
                    crate::Win16HostBrush::SystemColor(handle - 1),
                )
            }
            handle => self.guest_gdi.object(handle).map_or(
                crate::Win16HostControlColorBrush::Invalid(handle),
                |object| crate::Win16HostControlColorBrush::Brush(
                    crate::Win16HostBrush::Object(object),
                ),
            ),
        }
    }

    pub(in crate::win16_runtime) fn discard_callback_window_payload_resources(
        access: &mut super::global_teardown::GlobalMemoryTeardownAccess<'_>,
        guest_gdi: &mut super::gdi::GuestGdiHandles,
        payload: &mut GuestWindowPayload,
        guest_drop_global: &mut Option<win16_abi::GlobalHandle>,
        allocation_locked: &mut bool,
    ) -> Result<super::global_memory::GlobalTeardownResult, RuntimeError> {
        if let Some((guest, native)) = payload.callback_dc {
            if !guest_gdi.forget_dc(guest, native) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "callback-scoped Win16 HDC changed before its owner retired"));
            }
            payload.callback_dc = None;
        }
        use super::global_memory::GlobalTeardownResult as Teardown;
        let drop_result = if let Some(allocation) = *guest_drop_global {
            let result = access.free_runtime_global_on_teardown(allocation)?;
            if matches!(result, Teardown::Freed) {
                *guest_drop_global = None;
            }
            result
        } else {
            Teardown::Freed
        };
        let payload_result = if let Some(allocation) = payload.allocation {
            if *allocation_locked {
                let (heap, selectors) = access.heap_and_selectors_mut();
                heap.unlock(allocation, selectors).map_err(crate::runtime_error)?;
                *allocation_locked = false;
            }
            let result = access.free_runtime_global_on_teardown(allocation)?;
            if matches!(result, Teardown::Freed) {
                payload.allocation = None;
            }
            result
        } else {
            Teardown::Freed
        };
        match (drop_result, payload_result) {
            (Teardown::Freed, result) | (result, Teardown::Freed) => Ok(result),
            (
                Teardown::Retained { selector_aliases: left_aliases, page_locks: left_locks,
                    internal_pins: left_pins },
                Teardown::Retained { selector_aliases: right_aliases, page_locks: right_locks,
                    internal_pins: right_pins },
            ) => Ok(Teardown::Retained {
                selector_aliases: left_aliases.checked_add(right_aliases).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "aggregate Win16 callback selector ownership overflow"))?,
                page_locks: left_locks.checked_add(right_locks).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "aggregate Win16 callback page-lock ownership overflow"))?,
                internal_pins: left_pins.checked_add(right_pins).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "aggregate Win16 callback allocator-pin ownership overflow"))?,
            }),
        }
    }

    fn read_gettext_result(
        &self,
        value: u32,
        capacity: u16,
        output: Option<(SegmentedPointer, u16)>,
        memory: &Memory,
    ) -> Result<Win16HostMessageOutput, RuntimeError> {
        if capacity == 0 {
            if output.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "zero-capacity Win16 WM_GETTEXT unexpectedly owns a guest output buffer",
                ));
            }
            // No bytes can be copied, but a custom WndProc's native result is
            // still returned unchanged to the caller.
            return Ok(Win16HostMessageOutput::Text(Vec::new()));
        }

        let (pointer, output_capacity) = output.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 WM_GETTEXT capacity has no owned guest output buffer",
            )
        })?;
        if output_capacity != capacity {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 WM_GETTEXT output capacity changed during callback",
            ));
        }
        if value >= u32::from(capacity) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 WM_GETTEXT returned a character count outside its buffer",
            ));
        }

        let count = usize::try_from(value)
            .map_err(|_| RuntimeError::new(Kind::GuestFault, "invalid Win16 WM_GETTEXT count"))?;
        let length = count
            .checked_add(1)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "Win16 WM_GETTEXT count overflow"))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "cannot allocate the Win16 WM_GETTEXT result buffer",
                error,
            )
        })?;
        bytes.resize(length, 0);
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        // With count zero, only an explicitly written NUL proves an empty
        // string; the non-NUL fill means the procedure supplied no output.
        if value == 0 && bytes.first() != Some(&0) {
            return Ok(Win16HostMessageOutput::None);
        }
        if bytes.last() != Some(&0) || bytes[..count].contains(&0) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 WM_GETTEXT result is not terminated at its returned length",
            ));
        }
        Ok(Win16HostMessageOutput::Text(bytes))
    }

    pub(super) fn allocate_window_payload(
        &mut self,
        memory: &mut Memory,
        size: usize,
    ) -> Result<(GlobalHandle, SegmentedPointer), RuntimeError> {
        if size == 0 || size > usize::from(u16::MAX) {
            return Err(payload_size_error("invalid Win16 temporary payload size"));
        }
        let size = u32::try_from(size)
            .map_err(|_| payload_size_error("Win16 temporary payload size is not representable"))?;
        let callback_id = self.preparing_window_callback_id();
        if callback_id.is_some() && self.window_callbacks.last()
            .is_some_and(|frame| frame.payload.allocation.is_some())
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "callback payload allocation would replace its retained owner"));
        }
        let allocation = self
            .heap
            .alloc(
                memory,
                WINDOW_PAYLOAD_OWNER,
                size,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(crate::runtime_error)?;
        if let Some(id) = callback_id {
            self.retain_preparing_window_payload_allocation(id, allocation, false, None);
        }
        match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => {
                if let Some(id) = callback_id {
                    self.retain_preparing_window_payload_allocation(
                        id, allocation, true, Some(pointer.selector()),
                    );
                }
                Ok((allocation, pointer))
            }
            Err(error) => {
                let primary = crate::runtime_error(error);
                if let Some(id) = callback_id {
                    return Err(self.retain_preparing_window_callback_error(id, primary));
                }
                let cleanup = self
                    .heap
                    .free(allocation, &mut self.selectors)
                    .map_err(crate::runtime_error);
                Err(match cleanup {
                    Ok(()) => primary,
                    Err(cleanup_error) => combine_cleanup_failure(primary, cleanup_error),
                })
            }
        }
    }

    fn release_window_payload(&mut self, allocation: GlobalHandle) -> Result<(), RuntimeError> {
        let unlock = self
            .heap
            .unlock(allocation, &mut self.selectors)
            .map_err(crate::runtime_error);
        let free = self
            .heap
            .free(allocation, &mut self.selectors)
            .map_err(crate::runtime_error);
        match (unlock, free) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup_error)) => {
                Err(combine_cleanup_failure(error, cleanup_error))
            }
        }
    }

    pub(super) fn cleanup_after_error(
        &mut self,
        allocation: GlobalHandle,
        error: RuntimeError,
    ) -> RuntimeError {
        if let Some(id) = self.preparing_window_callback_id()
            && self.window_callbacks.last()
                .is_some_and(|frame| frame.payload.allocation == Some(allocation))
        {
            return self.retain_preparing_window_callback_error(id, error);
        }
        match self.release_window_payload(allocation) {
            Ok(()) => error,
            Err(cleanup_error) => combine_cleanup_failure(error, cleanup_error),
        }
    }
}

pub(super) fn payload_size_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, message)
}

fn combine_cleanup_failure(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    primary.with_cleanup(
        "failed to release a temporary Win16 window payload",
        cleanup,
    )
}

pub(in crate::win16_runtime) fn repeat_callback_payload_failure(
    error: std::sync::Arc<RuntimeError>,
) -> RuntimeError {
    RuntimeError::with_source(error.kind(),
        "Win16 callback payload retains its original failure", error)
}

pub(in crate::win16_runtime) fn combine_callback_payload_failure(
    primary: std::sync::Arc<RuntimeError>,
    cleanup: RuntimeError,
) -> RuntimeError {
    repeat_callback_payload_failure(primary)
        .with_cleanup("retire Win16 callback payload", cleanup)
}
