//! Host-only native HBRUSH result storage for synchronous Win16 messages.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostBrush, Win16HostControlColorBrush,
    Win16HostMessageOutput, Win16WindowOperation, Win16WindowReply,
};

use super::Win16Objects;

/// A native HBRUSH result remains host-only until the USER coordinator checks
/// its type and interns it into the shared GDI identity table. This wrapper
/// carries pointer bits only between private host worker/coordinator code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostNativeBrushResult {
    Null,
    Handle(NonZeroUsize),
}

impl HostNativeBrushResult {
    pub(super) fn from_lresult(value: isize) -> Self {
        Self::from_handle_bits(value as usize)
    }

    pub(super) fn from_handle_bits(value: usize) -> Self {
        NonZeroUsize::new(value).map_or(Self::Null, Self::Handle)
    }

    pub(super) fn handle_bits(self) -> Option<usize> {
        match self {
            Self::Null => None,
            Self::Handle(handle) => Some(handle.get()),
        }
    }

    pub(super) fn native_lresult(self) -> isize {
        self.handle_bits().unwrap_or_default() as isize
    }
}

/// Typed native brush identity retained until coordinator validation.
#[derive(Clone)]
pub(super) struct ControlColorReturnSlot(Arc<Mutex<Option<HostNativeBrushResult>>>);

const WIN16_COLOR_ENDCOLORS: u16 = 20;

pub(super) fn control_color_result_from_native(
    objects: &mut Win16Objects,
    native: HostNativeBrushResult,
) -> Result<Win16HostControlColorBrush, RuntimeError> {
    let Some(bits) = native.handle_bits() else {
        return Ok(Win16HostControlColorBrush::Null);
    };
    let native_brush = bits as windows_sys::Win32::Graphics::Gdi::HBRUSH;
    // Native Win32 USER returns real system HBRUSH values. Compare by handle
    // identity and restore the Windows 3.1 logical pseudo-brush only after that
    // provenance check; small pointer integers are never treated as colors.
    for index in 0..=WIN16_COLOR_ENDCOLORS {
        // SAFETY: the index is one of the Windows 3.1 SDK COLOR_* values.
        let system_brush = unsafe {
            windows_sys::Win32::Graphics::Gdi::GetSysColorBrush(i32::from(index))
        };
        if !system_brush.is_null() && system_brush as usize == bits {
            return Ok(Win16HostControlColorBrush::Brush(Win16HostBrush::SystemColor(index)));
        }
    }
    let object = objects.intern_borrowed_brush(native_brush)?.ok_or_else(|| {
        RuntimeError::new(Kind::InvalidInput,
            "native control-color result is neither NULL nor a live HBRUSH")
    })?;
    Ok(Win16HostControlColorBrush::Brush(Win16HostBrush::Object(object)))
}

pub(super) fn native_control_color_result(
    objects: &Win16Objects,
    reply: &Win16WindowReply,
) -> Result<Option<HostNativeBrushResult>, RuntimeError> {
    match &reply.result.output {
        Win16HostMessageOutput::ControlColor(brush) => {
            native_control_color_brush_result(objects, *brush).map(Some)
        }
        _ => Ok(None),
    }
}

pub(super) fn native_control_color_brush_result(
    objects: &Win16Objects,
    brush: Win16HostControlColorBrush,
) -> Result<HostNativeBrushResult, RuntimeError> {
    match brush {
        Win16HostControlColorBrush::Null => Ok(HostNativeBrushResult::Null),
        Win16HostControlColorBrush::Brush(Win16HostBrush::Object(object)) => {
            objects.native_brush(object)
                .map(|brush| HostNativeBrushResult::from_handle_bits(brush as usize))
                .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                    "Win16 control-color HBRUSH alias is stale or is not a native brush"))
        }
        Win16HostControlColorBrush::Brush(Win16HostBrush::SystemColor(index)) => {
            // The guest callback contract encodes system brushes as COLOR_*+1.
            // Native Win32 WM_CTLCOLOR* instead requires a real HBRUSH, so
            // resolve the logical index at this host boundary.
            if index > WIN16_COLOR_ENDCOLORS {
                return Err(RuntimeError::new(Kind::InvalidInput,
                    "Win16 control-color pseudo brush exceeds COLOR_ENDCOLORS"));
            }
            // SAFETY: the validated SDK color index contains no pointer.
            let brush = unsafe {
                windows_sys::Win32::Graphics::Gdi::GetSysColorBrush(i32::from(index))
            };
            if brush.is_null() {
                Err(RuntimeError::new(Kind::HostFailure,
                    "Windows could not resolve the control-color system brush"))
            } else {
                Ok(HostNativeBrushResult::from_handle_bits(brush as usize))
            }
        }
        Win16HostControlColorBrush::Invalid(handle) => Err(RuntimeError::new(Kind::InvalidInput,
            format!("Win16 control-color callback returned invalid HBRUSH16 0x{handle:04X}"))),
    }
}

impl ControlColorReturnSlot {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    pub(super) fn store(&self, value: isize) -> Result<(), RuntimeError> {
        let mut slot = self.0.lock().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 control-color result slot mutex is poisoned",
        ))?;
        if slot.is_some() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 control-color native call returned more than once"));
        }
        *slot = Some(HostNativeBrushResult::from_lresult(value));
        Ok(())
    }

    pub(super) fn load(&self) -> Result<Option<HostNativeBrushResult>, RuntimeError> {
        self.0.lock().map(|slot| *slot).map_err(|_| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 control-color result slot mutex is poisoned",
        ))
    }
}

pub(super) fn operation_control_color_message(operation: &Win16WindowOperation) -> bool {
    let message = match operation {
        Win16WindowOperation::Default { message, .. }
        | Win16WindowOperation::DefFrameProc { message, .. }
        | Win16WindowOperation::DefaultMdiChild { message, .. }
        | Win16WindowOperation::Send { message, .. }
        | Win16WindowOperation::CallProcedure { message, .. } => Some(message),
        Win16WindowOperation::UserService(runtime::Win16HostUserServiceOperation::Dialog(
            runtime::Win16HostDialogOperation::DefaultProcedure { message, .. },
        )) => Some(message),
        _ => None,
    };
    matches!(message, Some(runtime::Win16HostMessage::ControlColor(_)))
}
