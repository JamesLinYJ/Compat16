//! Borrowed completion phases for USER paint and window-DC leases.

use super::*;
use super::completion_access::WindowProjectionAccess;
use super::operation_frame::{
    CompensationProjection, CompensationProjectionPhase as CompensationPhase,
    DcAcquisitionProjection, DcAcquisitionProjectionPhase as AcquisitionPhase,
    DcRetirementProjection, DcRetirementProjectionPhase as RetirementPhase,
    PaintProjection, PaintProjectionPhase as PaintPhase,
};
use win16_abi::user_service_abi::PaintStruct16;
use std::sync::Arc;

/// Turns a failed guest projection into an exact retained native-HDC cleanup
/// owner when the real host result proves that the HDC was acquired.
pub(super) fn compensation_return_after_projection_failure(
    continuation: &WindowReturn,
    result: &Win16WindowResult,
    cause: Arc<RuntimeError>,
) -> Option<WindowReturn> {
    match (continuation, result) {
        (
            WindowReturn::Paint {
                guest_dc_reserved, native_window, ..
            },
            Win16WindowResult::Paint { acquired: Some((native_dc, paint_info)) },
        ) => Some(WindowReturn::CleanupPaint {
            guest_dc_reserved: *guest_dc_reserved,
            native_dc: *native_dc,
            native_window: *native_window,
            paint_info: *paint_info,
            original_error: cause,
        }),
        (
            WindowReturn::AcquireWindowDc { guest_dc_reserved, native_window, .. },
            Win16WindowResult::WindowDc(Some(native_dc)),
        ) => Some(WindowReturn::CleanupWindowDc {
            guest_dc_reserved: *guest_dc_reserved,
            native_dc: *native_dc,
            native_window: *native_window,
            original_error: cause,
        }),
        _ => None,
    }
}

/// Builds the real USER-worker release stage from the payload retained by the
/// exact failed projection frame. The frame remains the owner of this operation
/// until its normal source-return proof is consumed.
pub(super) fn prepare_dc_compensation_operation(
    continuation: &WindowReturn,
) -> Option<Win16WindowOperation> {
    match continuation {
        WindowReturn::CleanupPaint {
            native_window, native_dc, paint_info, ..
        } => Some(Win16WindowOperation::EndPaint {
            window: *native_window,
            dc: *native_dc,
            info: *paint_info,
        }),
        WindowReturn::CleanupWindowDc {
            native_window, native_dc, ..
        } => Some(Win16WindowOperation::ReleaseWindowDc {
            window: Some(*native_window),
            dc: *native_dc,
        }),
        _ => None,
    }
}

pub(super) fn finish_paint(
    output: &super::super::guest_ranges::GuestOutputRange,
    guest_dc_reserved: u16,
    acquired: Option<(crate::Win16HostDc, crate::Win16HostPaintInfo)>,
    owner: &mut PaintProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    if owner.phase == PaintPhase::Complete {
        return owner.value.map(|value| (u32::from(value), Win16ReturnKind::Word))
            .ok_or_else(|| invariant("BeginPaint projection lost its cached HDC"));
    }
    let Some((native_dc, paint)) = acquired else {
        if owner.phase == PaintPhase::Ready {
            if !access.guest_gdi.cancel_dc(guest_dc_reserved) {
                return Err(invariant("BeginPaint failure lost its exact reserved HDC"));
            }
            owner.value = Some(0);
            owner.phase = PaintPhase::ReturnReady;
        }
        owner.phase = PaintPhase::Complete;
        return Ok((0, Win16ReturnKind::Word));
    };

    if owner.phase == PaintPhase::Ready {
        if output.length() != PaintStruct16::SIZE {
            return Err(invariant("BeginPaint output is not the captured PAINTSTRUCT16 extent"));
        }
        let structure = super::super::user_services_paint::paintstruct_from_host(
            guest_dc_reserved, paint,
        );
        super::super::guest_ranges::commit_guest_output_with_selectors(
            access.selectors, memory, output, &structure.encode(),
        )?;
        owner.native_dc = Some(native_dc);
        owner.phase = PaintPhase::GuestOutputCommitted;
    }
    if owner.phase == PaintPhase::GuestOutputCommitted {
        if !access.guest_gdi.bind_dc(guest_dc_reserved,
            owner.native_dc.ok_or_else(|| invariant(
                "BeginPaint output was committed without retaining its exact native HDC"))?)
        {
            return Err(invariant("BeginPaint cannot bind its reserved guest HDC"));
        }
        owner.value = Some(guest_dc_reserved);
        owner.phase = PaintPhase::DcLeaseCommitted;
    }
    if owner.phase == PaintPhase::DcLeaseCommitted {
        owner.phase = PaintPhase::ReturnReady;
    }
    if owner.phase == PaintPhase::ReturnReady { owner.phase = PaintPhase::Complete; }
    owner.value.map(|value| (u32::from(value), Win16ReturnKind::Word))
        .ok_or_else(|| invariant("BeginPaint projection lost its completed HDC"))
}

pub(super) fn finish_acquire_dc(
    guest_dc_reserved: u16,
    acquired: Option<crate::Win16HostDc>,
    consumed_region: Option<crate::Win16HostGdiObject>,
    owner: &mut DcAcquisitionProjection,
    access: &mut WindowProjectionAccess<'_>,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    if acquired.is_some() && let Some(region) = consumed_region {
        access.guest_gdi.retire_object_aliases(region);
    }
    if owner.phase == AcquisitionPhase::Complete {
        return owner.guest_dc.map(|value| (u32::from(value), Win16ReturnKind::Word))
            .ok_or_else(|| invariant("GetDC projection lost its cached HDC"));
    }
    match acquired {
        None if owner.phase == AcquisitionPhase::Ready => {
            if !access.guest_gdi.cancel_dc(guest_dc_reserved) {
                return Err(invariant("GetDC failure lost its exact reserved HDC"));
            }
            owner.guest_dc = Some(0);
            owner.phase = AcquisitionPhase::ReturnReady;
        }
        Some(native_dc) if owner.phase == AcquisitionPhase::Ready => {
            if !access.guest_gdi.bind_dc(guest_dc_reserved, native_dc) {
                return Err(invariant("GetDC cannot bind its reserved guest HDC"));
            }
            owner.guest_dc = Some(guest_dc_reserved);
            owner.phase = AcquisitionPhase::NativeDcBound;
        }
        None | Some(_) => {}
    }
    if owner.phase == AcquisitionPhase::NativeDcBound {
        owner.phase = AcquisitionPhase::ReturnReady;
    }
    if owner.phase == AcquisitionPhase::ReturnReady { owner.phase = AcquisitionPhase::Complete; }
    owner.guest_dc.map(|value| (u32::from(value), Win16ReturnKind::Word))
        .ok_or_else(|| invariant("GetDC projection has no cached result"))
}

pub(super) fn finish_dc_retirement(
    guest_dc: u16,
    native_dc: crate::Win16HostDc,
    succeeded: bool,
    return_kind: Win16ReturnKind,
    owner: &mut DcRetirementProjection,
    access: &mut WindowProjectionAccess<'_>,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    if owner.phase == RetirementPhase::Complete {
        return owner.value.map(|value| (value, return_kind))
            .ok_or_else(|| invariant("DC retirement lost its cached BOOL"));
    }
    if owner.phase == RetirementPhase::Ready {
        if succeeded {
            owner.phase = RetirementPhase::NativeRetired;
        } else {
            owner.value = Some(0);
            owner.phase = RetirementPhase::ReturnReady;
        }
    }
    if owner.phase == RetirementPhase::NativeRetired {
        if !access.guest_gdi.forget_dc(guest_dc, native_dc) {
            return Err(invariant("native DC retirement no longer matches the guest HDC lease"));
        }
        owner.phase = RetirementPhase::GuestLeaseRetired;
        owner.value = Some(1);
    }
    if owner.phase == RetirementPhase::GuestLeaseRetired {
        owner.phase = RetirementPhase::ReturnReady;
    }
    if owner.phase == RetirementPhase::ReturnReady { owner.phase = RetirementPhase::Complete; }
    owner.value.map(|value| (value, return_kind))
        .ok_or_else(|| invariant("DC retirement lost its completed BOOL"))
}

pub(super) fn finish_dc_compensation(
    guest_dc_reserved: u16,
    native_cleanup_succeeded: bool,
    owner: &mut CompensationProjection,
    access: &mut WindowProjectionAccess<'_>,
) -> Result<(), RuntimeError> {
    if owner.phase == CompensationPhase::Complete {
        return Err(original_compensation_error(owner));
    }
    if owner.phase == CompensationPhase::NativeCleanupPending {
        if !native_cleanup_succeeded {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "Win16 USER worker did not retire the exact native HDC",
                Arc::clone(&owner.original_cause),
            ));
        }
        owner.phase = CompensationPhase::NativeCleanupRetired;
    } else if owner.phase != CompensationPhase::NativeCleanupRetired
        && owner.phase != CompensationPhase::GuestLeaseRetired
    {
        return Err(invariant(
            "Win16 native HDC cleanup result has no started exact follow-up owner",
        ));
    }
    if owner.phase == CompensationPhase::NativeCleanupRetired {
        if !access.guest_gdi.cancel_dc(guest_dc_reserved) {
            return Err(invariant(
                "Win16 HDC cleanup cannot retire its exact reserved guest handle",
            ));
        }
        owner.phase = CompensationPhase::GuestLeaseRetired;
    }
    if owner.phase == CompensationPhase::GuestLeaseRetired {
        owner.phase = CompensationPhase::Complete;
    }
    Err(original_compensation_error(owner))
}

/// Retires the unpublished guest reservation after the USER worker has proved
/// native HDC release. The cached phase makes terminal retries idempotent.
pub(super) fn retire_dc_compensation_resources(
    guest_dc_reserved: u16,
    owner: &mut CompensationProjection,
    guest_gdi: &mut super::super::gdi::GuestGdiHandles,
) -> Result<(), RuntimeError> {
    if owner.phase == CompensationPhase::Complete { return Ok(()); }
    if owner.phase == CompensationPhase::GuestLeaseRetired {
        owner.phase = CompensationPhase::Complete;
        return Ok(());
    }
    if owner.phase != CompensationPhase::NativeCleanupRetired {
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "Win16 task ended before exact USER-worker HDC cleanup was proven",
            Arc::clone(&owner.original_cause),
        ));
    }
    if !guest_gdi.cancel_dc(guest_dc_reserved) {
        return Err(invariant("DC compensation cannot retire its exact unpublished guest HDC"));
    }
    owner.phase = CompensationPhase::GuestLeaseRetired;
    if owner.phase == CompensationPhase::GuestLeaseRetired {
        owner.phase = CompensationPhase::Complete;
    }
    Ok(())
}

fn original_compensation_error(owner: &CompensationProjection) -> RuntimeError {
    RuntimeError::with_source(owner.original_cause.kind(),
        "Win16 DC cleanup completed after the retained original failure",
        Arc::clone(&owner.original_cause))
}

fn invariant(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
