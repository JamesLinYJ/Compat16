//! Guest GDI handle translation across device contexts and objects.

use std::collections::BTreeMap;
use guest_core::memory::Memory;

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDc, Win16HostGdiCleanup,
    Win16HostGdiObject, Win16SelectObjectResult,
};

#[derive(Clone, Copy)]
enum GuestGdiObject {
    ReservedDc,
    ReservedObject,
    Dc(Win16HostDc),
    Object(Win16HostGdiObject),
}

#[derive(Default)]
struct DcAttributes {
    rel_abs: Option<u16>,
    state: Option<u16>,
    code_page: Option<u16>,
    layout: Option<u32>,
}

pub(super) struct GuestGdiHandles {
    objects: BTreeMap<u16, GuestGdiObject>,
    next_handle: u16,
    dc_attributes: BTreeMap<u16, DcAttributes>,
    session_text_code_page: u16,
}

// WNDCLASS16.hbrBackground reserves values 1..=31 for COLOR_* + 1.
// Allocate guest HDC/HGDIOBJ tokens above that range so the two meanings
// never collide when RegisterClass decodes a background brush.
const FIRST_GUEST_GDI_HANDLE: u16 = 32;

impl GuestGdiHandles {
    pub(super) fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            next_handle: FIRST_GUEST_GDI_HANDLE,
            dc_attributes: BTreeMap::new(),
            session_text_code_page: 0,
        }
    }

    fn dc_attributes_mut(&mut self, handle: u16) -> &mut DcAttributes {
        self.dc_attributes.entry(handle).or_default()
    }

    pub(super) fn rel_abs(&self, handle: u16) -> Option<u16> {
        self.dc_attributes.get(&handle).and_then(|entry| entry.rel_abs)
    }

    pub(super) fn set_rel_abs(&mut self, handle: u16, mode: u16) {
        self.dc_attributes_mut(handle).rel_abs = Some(mode);
    }

    pub(super) fn dc_state(&self, handle: u16) -> Option<u16> {
        self.dc_attributes.get(&handle).and_then(|entry| entry.state)
    }

    pub(super) fn set_dc_state(&mut self, handle: u16, state: u16) {
        self.dc_attributes_mut(handle).state = Some(state);
    }

    pub(super) fn dc_code_page(&self, handle: u16) -> Option<u16> {
        self.dc_attributes.get(&handle).and_then(|entry| entry.code_page)
    }

    pub(super) fn set_dc_code_page(&mut self, handle: u16, page: u16) {
        self.dc_attributes_mut(handle).code_page = Some(page);
    }

    pub(super) fn dc_layout(&self, handle: u16) -> Option<u32> {
        self.dc_attributes.get(&handle).and_then(|entry| entry.layout)
    }

    pub(super) fn set_dc_layout(&mut self, handle: u16, layout: u32) {
        self.dc_attributes_mut(handle).layout = Some(layout);
    }

    pub(super) fn session_text_code_page(&self) -> u16 {
        self.session_text_code_page
    }

    pub(super) fn set_session_text_code_page(&mut self, page: u16) {
        self.session_text_code_page = page;
    }

    fn forget_dc_attributes(&mut self, handle: u16) {
        self.dc_attributes.remove(&handle);
    }

    fn allocate(&mut self, object: GuestGdiObject) -> Option<u16> {
        for _ in FIRST_GUEST_GDI_HANDLE..=u16::MAX {
            let handle = self.next_handle;
            self.next_handle = if handle == u16::MAX {
                FIRST_GUEST_GDI_HANDLE
            } else { handle + 1 };
            if let std::collections::btree_map::Entry::Vacant(slot) = self.objects.entry(handle) {
                slot.insert(object);
                return Some(handle);
            }
        }
        None
    }

    pub(super) fn allocate_dc(&mut self, dc: Win16HostDc) -> Option<u16> {
        self.allocate(GuestGdiObject::Dc(dc))
    }

    /// Reserves one guest HDC value before an asynchronous USER worker call.
    /// The reservation is not exposed as a usable DC until `bind_dc` succeeds.
    pub(super) fn reserve_dc(&mut self) -> Option<u16> {
        self.allocate(GuestGdiObject::ReservedDc)
    }

    pub(super) fn bind_dc(&mut self, handle: u16, dc: Win16HostDc) -> bool {
        let Some(object) = self.objects.get_mut(&handle) else { return false; };
        if !matches!(object, GuestGdiObject::ReservedDc) { return false; }
        *object = GuestGdiObject::Dc(dc);
        true
    }

    /// Cancels an unpublished HDC reservation after its host acquisition
    /// failed. A bound or reused handle is left untouched.
    pub(super) fn cancel_dc(&mut self, handle: u16) -> bool {
        if !matches!(self.objects.get(&handle), Some(GuestGdiObject::ReservedDc)) {
            return false;
        }
        self.objects.remove(&handle);
        self.forget_dc_attributes(handle);
        true
    }

    /// Removes a guest HDC only after USER confirms the matching native
    /// ReleaseDC/EndPaint operation succeeded. The expected opaque token
    /// prevents a stale release from deleting a reused guest handle.
    pub(super) fn forget_dc(&mut self, handle: u16, expected: Win16HostDc) -> bool {
        if !matches!(self.objects.get(&handle), Some(GuestGdiObject::Dc(current)) if *current == expected) {
            return false;
        }
        self.objects.remove(&handle);
        self.forget_dc_attributes(handle);
        true
    }

    pub(super) fn allocate_object(&mut self, object: Win16HostGdiObject) -> Option<u16> {
        self.allocate(GuestGdiObject::Object(object))
    }

    /// Reserves an HGDIOBJ token before a native factory creates the object.
    /// The guest cannot resolve the token until the exact native object binds.
    pub(super) fn reserve_object(&mut self) -> Option<u16> {
        self.allocate(GuestGdiObject::ReservedObject)
    }

    pub(super) fn bind_object(&mut self, handle: u16, object: Win16HostGdiObject) -> bool {
        let Some(entry) = self.objects.get_mut(&handle) else { return false; };
        if !matches!(entry, GuestGdiObject::ReservedObject) { return false; }
        *entry = GuestGdiObject::Object(object);
        true
    }

    /// Removes only a still-unpublished HGDIOBJ reservation after failure.
    pub(super) fn cancel_object(&mut self, handle: u16) -> bool {
        if !matches!(self.objects.get(&handle), Some(GuestGdiObject::ReservedObject)) {
            return false;
        }
        self.objects.remove(&handle);
        true
    }

    /// Retires only the guest alias that still names this host object token.
    pub(super) fn forget_object(&mut self, handle: u16, expected: Win16HostGdiObject) -> bool {
        if !matches!(self.objects.get(&handle), Some(GuestGdiObject::Object(current)) if *current == expected) {
            return false;
        }
        self.objects.remove(&handle);
        true
    }

    /// Retire every alias of the exact transferred region token. Reentrant
    /// deletion/reuse of a guest word cannot remove a different new object.
    pub(super) fn retire_object_aliases(&mut self, expected: Win16HostGdiObject) {
        self.objects.retain(|_, object|
            !matches!(object, GuestGdiObject::Object(current) if *current == expected));
    }

    pub(super) fn dc(&self, handle: u16) -> Option<Win16HostDc> {
        match self.objects.get(&handle)? {
            GuestGdiObject::Dc(native) => Some(*native),
            GuestGdiObject::ReservedDc | GuestGdiObject::ReservedObject
            | GuestGdiObject::Object(_) => None,
        }
    }

    pub(super) fn contains_handle(&self, handle: u16) -> bool {
        self.objects.contains_key(&handle)
    }

    pub(super) fn object(&self, handle: u16) -> Option<Win16HostGdiObject> {
        match self.objects.get(&handle)? {
            GuestGdiObject::Object(native) => Some(*native),
            GuestGdiObject::ReservedDc | GuestGdiObject::ReservedObject
            | GuestGdiObject::Dc(_) => None,
        }
    }

    pub(super) fn existing_object(&self, native: Win16HostGdiObject) -> Option<u16> {
        self.objects.iter().find_map(|(&handle, object)| match object {
            GuestGdiObject::Object(found) if *found == native => Some(handle),
            _ => None,
        })
    }
}

/// GDI.128 rounds exact halves away from zero and saturates a signed 16-bit
/// result. The sign-based overflow result follows Microsoft's description of
/// the original Win16 API (Raymond Chen, Microsoft Dev Blogs, 2012-05-14);
/// the guest computation avoids historical arithmetic overflow in the minimum
/// signed divisor case.
pub(super) fn mul_div16(multiplicand: i16, multiplier: i16, divisor: i16) -> i16 {
    let product = i64::from(multiplicand) * i64::from(multiplier);
    if divisor == 0 {
        return if product < 0 { i16::MIN } else { i16::MAX };
    }
    let denominator = i64::from(divisor).abs();
    let magnitude = (product.abs() + denominator / 2) / denominator;
    let result = if (product < 0) ^ (divisor < 0) { -magnitude } else { magnitude };
    result.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16
}

impl Win16State {
    pub(super) fn get_dc(
        &mut self,
        window: u16,
        whole_window: bool,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        // A nonzero HWND requires a guest-window to native-window mapping.
        // That mapping is established by Win16 window creation, not by GDI.
        if window != 0 { return Ok(0); }
        let Some(native) = host.win16_acquire_screen_dc(whole_window)? else { return Ok(0); };
        match self.guest_gdi.allocate(GuestGdiObject::Dc(native)) {
            Some(handle) => Ok(handle),
            None => {
                let _ = host.win16_release_screen_dc(native)?;
                Ok(0)
            }
        }
    }

    pub(super) fn release_dc(
        &mut self,
        window: u16,
        handle: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if window != 0 { return Ok(0); }
        let Some(native) = self.guest_gdi.dc(handle) else { return Ok(0); };
        if !host.win16_release_screen_dc(native)? { return Ok(0); }
        if !self.guest_gdi.forget_dc(handle, native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "released Win16 screen DC lost its guest HDC mapping"));
        }
        Ok(1)
    }

    pub(super) fn create_compatible_dc(
        &mut self,
        source: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let source = if source == 0 {
            None
        } else {
            let Some(native) = self.guest_gdi.dc(source) else { return Ok(0); };
            Some(native)
        };
        let Some(native) = host.win16_create_compatible_dc(source)? else { return Ok(0); };
        match self.guest_gdi.allocate(GuestGdiObject::Dc(native)) {
            Some(handle) => Ok(handle),
            None => {
                let _ = host.win16_delete_dc(native)?;
                Ok(0)
            }
        }
    }

    pub(super) fn delete_dc(
        &mut self,
        handle: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(native) = self.guest_gdi.dc(handle) else { return Ok(0); };
        if !host.win16_delete_dc(native)? { return Ok(0); }
        if !self.guest_gdi.forget_dc(handle, native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "deleted Win16 DC lost its guest HDC mapping"));
        }
        Ok(1)
    }

    pub(super) fn get_device_caps(
        &self,
        handle: u16,
        index: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<i16, RuntimeError> {
        let Some(native) = self.guest_gdi.dc(handle) else { return Ok(0); };
        Ok(host.win16_get_device_caps(native, index)?.unwrap_or(0))
    }

    pub(super) fn get_stock_object(
        &mut self,
        index: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(native) = host.win16_get_stock_object(index)? else { return Ok(0); };
        if let Some(handle) = self.guest_gdi.existing_object(native) { return Ok(handle); }
        Ok(self.guest_gdi.allocate(GuestGdiObject::Object(native)).unwrap_or(0))
    }

    pub(super) fn select_object(
        &mut self,
        dc: u16,
        object: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(native_dc) = self.guest_gdi.dc(dc) else { return Ok(0); };
        let Some(native_object) = self.guest_gdi.object(object) else { return Ok(0); };
        match host.win16_select_object(native_dc, native_object)? {
            Some(Win16SelectObjectResult::Recorded) => Ok(1),
            Some(Win16SelectObjectResult::RegionComplexity(value)) => Ok(value),
            Some(Win16SelectObjectResult::CallbackBitmap { object, dc }) => {
                self.retain_function_bitmap(dc, object)?;
                if let Some(handle) = self.guest_gdi.existing_object(object) { return Ok(handle); }
                Ok(self.guest_gdi.allocate(GuestGdiObject::Object(object)).unwrap_or(0))
            }
            Some(Win16SelectObjectResult::Object(previous)) => {
                if let Some(handle) = self.guest_gdi.existing_object(previous) { return Ok(handle); }
                Ok(self.guest_gdi.allocate(GuestGdiObject::Object(previous)).unwrap_or(0))
            }
            None => Ok(0),
        }
    }

    pub(super) fn unrealize_object(
        &self, handle: u16, host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(object) = self.guest_gdi.object(handle) else { return Ok(false); };
        match host.win16_gdi_device(crate::Win16GdiDeviceOperation::UnrealizeObject { object })? {
            crate::Win16GdiDeviceResult::Bool(result) => Ok(result),
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "host UnrealizeObject returned a different GDI result family")),
        }
    }

    pub(super) fn delete_object(
        &mut self,
        handle: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if let Some(result) = self.delete_wing_bitmap(handle, memory, host)? {
            return Ok(result);
        }
        let Some(native) = self.guest_gdi.object(handle) else { return Ok(0); };
        if !host.win16_delete_object(native)? { return Ok(0); }
        if !self.guest_gdi.forget_object(handle, native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "deleted Win16 GDI object lost its guest mapping"));
        }
        Ok(1)
    }

    pub(super) fn close_gdi(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        // A live HDC may still select an owned GDI object. Snapshot and retire
        // every DC first, preserving any token whose native cleanup fails.
        let dc_handles: Vec<_> = self.guest_gdi.objects.iter().filter_map(|(&handle, object)| {
            match object {
                GuestGdiObject::ReservedDc => Some((handle, None)),
                GuestGdiObject::Dc(native) => Some((handle, Some(*native))),
                GuestGdiObject::ReservedObject | GuestGdiObject::Object(_) => None,
            }
        }).collect();
        let mut first_error = None;
        for (handle, native) in dc_handles {
            match native {
                None => {
                    // An unpublished reservation has no native HDC to release.
                    if !self.guest_gdi.cancel_dc(handle) && first_error.is_none() {
                        first_error = Some(RuntimeError::new(Kind::InternalInvariant,
                            "reserved Win16 HDC changed during state cleanup"));
                    }
                }
                Some(native) => match host.win16_cleanup_dc_state(native) {
                    Ok(Win16HostGdiCleanup::Released
                        | Win16HostGdiCleanup::Borrowed
                        | Win16HostGdiCleanup::Absent) => {
                            if !self.guest_gdi.forget_dc(handle, native) && first_error.is_none() {
                                first_error = Some(RuntimeError::new(Kind::InternalInvariant,
                                    "cleaned Win16 HDC lost its guest mapping"));
                            }
                        }
                    Ok(Win16HostGdiCleanup::Failed) => {
                        if first_error.is_none() {
                            first_error = Some(RuntimeError::new(Kind::HostFailure,
                                "failed to clean up a Win16 HDC during state shutdown"));
                        }
                    }
                    Err(error) => if first_error.is_none() { first_error = Some(error); },
                },
            }
        }
        // If any DC is still live, its selected objects must remain available
        // for a retry; do not attempt the object phase yet.
        if let Some(error) = first_error { return Err(error); }

        self.close_wing_bitmaps(memory, host)?;

        let object_handles: Vec<_> = self.guest_gdi.objects.iter().filter_map(|(&handle, object)| {
            match object {
                GuestGdiObject::ReservedObject => Some((handle, *object)),
                GuestGdiObject::Object(_) => Some((handle, *object)),
                GuestGdiObject::ReservedDc | GuestGdiObject::Dc(_) => None,
            }
        }).collect();
        let mut first_error = None;
        for (handle, object) in object_handles {
            match object {
                GuestGdiObject::ReservedObject => {
                    // A reserved object has no native resource yet; cancel its
                    // guest token explicitly instead of leaving it in the table.
                    if !self.guest_gdi.cancel_object(handle) && first_error.is_none() {
                        first_error = Some(RuntimeError::new(Kind::InternalInvariant,
                            "reserved Win16 GDI object changed during state cleanup"));
                    }
                }
                GuestGdiObject::Object(native) => {
                    match host.win16_cleanup_gdi_object(native) {
                        Ok(Win16HostGdiCleanup::Released
                            | Win16HostGdiCleanup::Borrowed
                            | Win16HostGdiCleanup::Absent) => {
                            if !self.guest_gdi.forget_object(handle, native)
                                && first_error.is_none()
                            {
                                first_error = Some(RuntimeError::new(Kind::InternalInvariant,
                                    "cleaned Win16 GDI object lost its guest mapping"));
                            }
                        }
                        Ok(Win16HostGdiCleanup::Failed) => {
                            if first_error.is_none() {
                                first_error = Some(RuntimeError::new(Kind::HostFailure,
                                    "failed to clean up a Win16 GDI object during state shutdown"));
                            }
                        }
                        Err(error) => if first_error.is_none() { first_error = Some(error); },
                    }
                }
                GuestGdiObject::ReservedDc | GuestGdiObject::Dc(_) => {
                    unreachable!("object snapshot contains a device context")
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
