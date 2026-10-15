//! Native GDI object identities and their ownership.

use std::{collections::BTreeMap, sync::Arc};

#[path = "win16_gdi_region_lease.rs"]
mod win16_gdi_region_lease;
pub(super) use self::win16_gdi_region_lease::Win16RegionLease;

#[path = "win16_gdi_object_query.rs"]
mod object_query;

#[path = "win16_gdi_object_enumeration.rs"]
mod object_enumeration;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostGdiCleanup, Win16HostGdiObject,
    Win16SelectObjectResult,
};
use windows_sys::Win32::Graphics::Gdi::{
    CombineRgn, CreateRectRgn, CreateSolidBrush, DeleteObject, GetObjectType,
    GetStockObject, SelectObject, HDC, HGDIOBJ, OBJ_BITMAP, OBJ_BRUSH, OBJ_REGION, OBJ_METADC,
    RGN_COPY, RGN_ERROR,
};
use super::win16_wing_dib_storage::Win16DibSectionOwner;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ObjectOwnership {
    Owned,
    Borrowed,
    CallbackBitmap(runtime::Win16HostDc),
}

#[derive(Clone)]
struct NativeObject {
    handle: HGDIOBJ,
    ownership: ObjectOwnership,
    dib_owner: Option<Arc<Win16DibSectionOwner>>,
}

impl NativeObject {
    fn is_owned(&self) -> bool { self.ownership == ObjectOwnership::Owned }
}

pub(super) struct Win16Objects {
    objects: BTreeMap<Win16HostGdiObject, NativeObject>,
    by_native: BTreeMap<usize, Win16HostGdiObject>,
    next_id: u64,
}

impl Win16Objects {
    pub(super) fn new() -> Self {
        Self { objects: BTreeMap::new(), by_native: BTreeMap::new(), next_id: 1 }
    }

    pub(super) fn lease_region(
        &self,
        token: Win16HostGdiObject,
    ) -> Result<Option<Win16RegionLease>, RuntimeError> {
        let Some(object) = self.objects.get(&token) else { return Ok(None); };
        // SAFETY: `object.handle` is the native object from this table;
        // GetObjectType returns zero for a stale handle.
        if unsafe { GetObjectType(object.handle) } != OBJ_REGION as u32 {
            return Ok(None);
        }
        // GDI does not synchronize cross-thread object use. Pass the worker an
        // independent output-capable snapshot so guest deletion of the source
        // cannot race with native USER's callback path.
        let snapshot = unsafe { CreateRectRgn(0, 0, 0, 0) };
        if snapshot.is_null() {
            // Native GDI allocation limits are an ordinary API failure, not
            // evidence that the guest state or identity table is damaged.
            return Ok(None);
        }
        // SAFETY: `object.handle` was verified as OBJ_REGION above; `snapshot`
        // is a new owned HRGN, NULL is ignored for RGN_COPY, and no callback
        // or mutable Rust borrow crosses this synchronous GDI copy.
        if unsafe { CombineRgn(snapshot, object.handle.cast(), std::ptr::null_mut(), RGN_COPY) }
            == RGN_ERROR
        {
            // SAFETY: `snapshot` is still the unshared HRGN allocated above.
            unsafe { DeleteObject(snapshot.cast()); }
            return Ok(None);
        }
        Ok(Some(Win16RegionLease::new(token, snapshot)))
    }

    /// Retire the original identity after USER accepted an independent clip
    /// copy. Reentrant guest deletion is harmless: tokens are never reused.
    pub(super) fn consume_region(&mut self, token: Win16HostGdiObject)
        -> Result<(), RuntimeError> {
        let Some(object) = self.objects.get(&token).cloned() else { return Ok(()); };
        // SAFETY: The opaque identity still names this table's retained object.
        if unsafe { GetObjectType(object.handle) } != OBJ_REGION as u32 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "GetDCEx region transfer retained a different object type"));
        }
        if object.is_owned() && !self.delete(token) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "GetDCEx could not retire its transferred clipping region"));
        }
        if !object.is_owned() {
            // A callback's borrowed object still belongs to its native lender;
            // USER took our independent copy, so only the guest alias expires.
            self.objects.remove(&token);
            self.by_native.remove(&(object.handle as usize));
        }
        Ok(())
    }

    pub(super) fn commit_region(
        &self,
        token: Win16HostGdiObject,
        lease: &Win16RegionLease,
    ) -> Result<Option<bool>, RuntimeError> {
        if lease.source_token() != token {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 region snapshot was committed to a different object token"));
        }
        let Some(object) = self.objects.get(&token) else { return Ok(None); };
        // SAFETY: The token still resolves to this table's native object;
        // type-check again because the guest may have deleted it in flight.
        if unsafe { GetObjectType(object.handle) } != OBJ_REGION as u32 {
            return Ok(None);
        }
        // SAFETY: The source is a live region for this exact token and the
        // snapshot is owned by `lease`; NULL is ignored for RGN_COPY. The
        // caller invokes commit after the worker's native USER operation ends.
        let result = unsafe {
            CombineRgn(object.handle.cast(), lease.native(), std::ptr::null_mut(), RGN_COPY)
        };
        Ok(Some(result != RGN_ERROR))
    }

    pub(super) fn intern_borrowed(&mut self, native: HGDIOBJ) -> Result<Win16HostGdiObject, RuntimeError> {
        self.intern_borrowed_in_callback(native, None)
    }

    fn intern_borrowed_in_callback(&mut self, native: HGDIOBJ,
        callback: Option<runtime::Win16HostDc>) -> Result<Win16HostGdiObject, RuntimeError> {
        let identity = native as usize;
        if let Some(&token) = self.by_native.get(&identity) { return Ok(token); }
        let next_id = self.next_id.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 host GDI object identity exhausted",
        ))?;
        let token = Win16HostGdiObject(self.next_id);
        self.next_id = next_id;
        self.objects.insert(token, NativeObject {
            handle: native,
            ownership: if unsafe { GetObjectType(native) } == OBJ_BITMAP as u32 {
                callback.map(ObjectOwnership::CallbackBitmap).unwrap_or(ObjectOwnership::Borrowed)
            } else { ObjectOwnership::Borrowed },
            dib_owner: None,
        });
        self.by_native.insert(identity, token);
        Ok(token)
    }

    /// Register a borrowed native HBRUSH only after the host GDI table
    /// confirms its runtime type; raw handles never enter runtime state.
    pub(super) fn intern_borrowed_brush(
        &mut self,
        native: windows_sys::Win32::Graphics::Gdi::HBRUSH,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        // SAFETY: GetObjectType inspects the opaque handle in GDI's object table;
        // it does not dereference guest-provided memory.
        if native.is_null() || unsafe { GetObjectType(native.cast()) } != OBJ_BRUSH as u32 {
            return Ok(None);
        }
        self.intern_borrowed(native.cast()).map(Some)
    }

    pub(super) fn stock(&mut self, index: i16) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        // SAFETY: The index is passed as a scalar. GDI owns the returned stock
        // object and null means the index has no object.
        let native = unsafe { GetStockObject(i32::from(index)) };
        if native.is_null() { return Ok(None); }
        self.intern_borrowed(native).map(Some)
    }

    pub(super) fn create_solid_brush(
        &mut self,
        color: u32,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        // SAFETY: COLORREF is a scalar and a successful brush becomes owned by
        // this table until DeleteObject or its Drop cleanup.
        let native = unsafe { CreateSolidBrush(color) };
        if native.is_null() { return Ok(None); }
        let Some(next_id) = self.next_id.checked_add(1) else {
            // SAFETY: `native` is a newly-created brush not transferred to a guest.
            unsafe { DeleteObject(native.cast()) };
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 host GDI object identity exhausted"));
        };
        let token = Win16HostGdiObject(self.next_id);
        self.next_id = next_id;
        self.objects.insert(token, NativeObject {
            handle: native.cast(),
            ownership: ObjectOwnership::Owned,
            dib_owner: None,
        });
        self.by_native.insert(native as usize, token);
        Ok(Some(token))
    }

    /// Takes ownership of an object created by another GDI adapter and adds
    /// it to the shared guest-object identity table.
    pub(super) fn adopt_owned(
        &mut self,
        native: HGDIOBJ,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        if native.is_null() { return Ok(None); }
        let identity = native as usize;
        if let Some(&token) = self.by_native.get(&identity) {
            if self.objects.get(&token).is_some_and(|object|
                matches!(object.ownership, ObjectOwnership::CallbackBitmap(_))) {
                // A newly-created owned bitmap is a different lifetime even
                // if GDI recycled a private callback bitmap's native bits.
                // Keep the old opaque token retired; never promote its aliases.
                self.objects.remove(&token);
                self.by_native.remove(&identity);
            } else if let Some(object) = self.objects.get_mut(&token) {
                object.ownership = ObjectOwnership::Owned;
                return Ok(Some(token));
            }
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            // SAFETY: Ownership was transferred by the caller, but no guest
            // token can be allocated; release the otherwise-unreachable object.
            unsafe { DeleteObject(native) };
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 host GDI object identity exhausted"));
        };
        let token = Win16HostGdiObject(self.next_id);
        self.next_id = next_id;
        self.objects.insert(token, NativeObject {
            handle: native,
            ownership: ObjectOwnership::Owned,
            dib_owner: None,
        });
        self.by_native.insert(identity, token);
        Ok(Some(token))
    }

    pub(super) fn select(
        &mut self,
        dc: HDC,
        token: Win16HostGdiObject,
        callback_scope: Option<runtime::Win16HostDc>,
    ) -> Result<Option<Win16SelectObjectResult>, RuntimeError> {
        let Some(object) = self.objects.get(&token) else { return Ok(None); };
        // SAFETY: Both handles are live native GDI handles retained by their
        // host tables. GDI determines whether this object type is selectable.
        let object_type = unsafe { GetObjectType(object.handle) };
        let recording = unsafe { GetObjectType(dc) } == OBJ_METADC as u32;
        let previous = unsafe { SelectObject(dc, object.handle) };
        if previous.is_null() || previous as isize == -1 { return Ok(None); }
        // A metafile DC records a copy and returns TRUE, not a previous
        // HGDIOBJ. Never intern that Boolean as a borrowed native object.
        if recording { return Ok(Some(Win16SelectObjectResult::Recorded)); }
        if object_type == OBJ_REGION as u32 {
            return Ok(Some(Win16SelectObjectResult::RegionComplexity(previous as usize as u16)));
        }
        let token = self.intern_borrowed_in_callback(previous, callback_scope)?;
        Ok(Some(match self.objects.get(&token).map(|object| object.ownership) {
            Some(ObjectOwnership::CallbackBitmap(dc)) =>
                Win16SelectObjectResult::CallbackBitmap { object: token, dc },
            _ => Win16SelectObjectResult::Object(token),
        }))
    }

    /// USER owns these private bitmaps. Retire only their exact aliases;
    /// deleting a bitmap here would double-delete the native function's data.
    pub(super) fn retire_function_bitmaps(&mut self, dc: runtime::Win16HostDc) {
        let by_native = &mut self.by_native;
        self.objects.retain(|token, object| {
            if object.ownership != ObjectOwnership::CallbackBitmap(dc) { return true; }
            let identity = object.handle as usize;
            if by_native.get(&identity) == Some(token) { by_native.remove(&identity); }
            false
        });
    }

    pub(super) fn adopt_dib_section(
        &mut self,
        native: windows_sys::Win32::Graphics::Gdi::HBITMAP,
        owner: Arc<Win16DibSectionOwner>,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        if native.is_null() { return Ok(None); }
        if !owner.matches_bitmap(native) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG DIB owner was paired with a different native bitmap",
            ));
        }
        let identity = native as usize;
        if let Some(&token) = self.by_native.get(&identity) {
            let Some(object) = self.objects.get(&token) else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 native GDI reverse index lost a DIB bitmap",
                ));
            };
            if object.dib_owner.as_ref().is_some_and(|current| Arc::ptr_eq(current, &owner)) {
                return Ok(Some(token));
            }
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "new WinG DIB bitmap collides with a retained native GDI identity",
            );
            return Err(finish_unpublished_dib(native, owner, primary));
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            let primary = RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host GDI object identity exhausted for WinG bitmap",
            );
            return Err(finish_unpublished_dib(native, owner, primary));
        };
        let token = Win16HostGdiObject(self.next_id);
        self.next_id = next_id;
        self.objects.insert(token, NativeObject {
            handle: native.cast(),
            ownership: ObjectOwnership::Owned,
            dib_owner: Some(owner),
        });
        self.by_native.insert(identity, token);
        Ok(Some(token))
    }

    pub(super) fn dib_owner_for_native(
        &self,
        native: HGDIOBJ,
    ) -> Option<Arc<Win16DibSectionOwner>> {
        let token = self.by_native.get(&(native as usize))?;
        self.objects.get(token)?.dib_owner.as_ref().map(Arc::clone)
    }

    pub(super) fn dib_owner(
        &self,
        token: Win16HostGdiObject,
    ) -> Option<Arc<Win16DibSectionOwner>> {
        self.objects.get(&token)?.dib_owner.as_ref().map(Arc::clone)
    }

    /// Legacy region-cleanup path. Its callers create and validate a region
    /// immediately before deletion, so no WinG DIB lifetime gate is involved.
    pub(super) fn delete(&mut self, token: Win16HostGdiObject) -> bool {
        let Some(object) = self.objects.get(&token).cloned() else { return false; };
        if !object.is_owned() || object.dib_owner.is_some() { return false; }
        let handle = object.handle;
        // SAFETY: Owned objects are created by this host adapter. Borrowed
        // stock/default objects are never passed to DeleteObject here.
        let deleted = unsafe { DeleteObject(handle) } != 0;
        if !deleted { return false; }
        self.objects.remove(&token);
        self.by_native.remove(&(handle as usize));
        true
    }

    /// Typed guest deletion owns WinG DIB phase changes and native receipts.
    pub(super) fn delete_owned(&mut self, token: Win16HostGdiObject)
        -> Result<bool, RuntimeError> {
        let Some(object) = self.objects.get(&token).cloned() else { return Ok(false); };
        if !object.is_owned() { return Ok(false); }
        let handle = object.handle;
        let delete_lease = match &object.dib_owner {
            Some(owner) => match owner.begin_delete()? {
                Some(lease) => Some(lease),
                None => return Ok(false),
            },
            None => None,
        };
        // SAFETY: Owned objects are created by this host adapter. Borrowed
        // stock/default objects are never passed to DeleteObject here.
        let deleted = unsafe { DeleteObject(handle) } != 0;
        if let Some(lease) = delete_lease { lease.finish(deleted)?; }
        if !deleted { return Ok(false); }
        self.objects.remove(&token);
        self.by_native.remove(&(handle as usize));
        Ok(true)
    }

    /// Typed state shutdown preserves native lifetime errors instead of
    /// reducing them to an untyped cleanup result.
    pub(super) fn cleanup_owned(&mut self, token: Win16HostGdiObject)
        -> Result<Win16HostGdiCleanup, RuntimeError> {
        let Some(object) = self.objects.get(&token).cloned() else {
            return Ok(Win16HostGdiCleanup::Absent);
        };
        if !object.is_owned() {
            return Ok(Win16HostGdiCleanup::Borrowed);
        }
        Ok(if self.delete_owned(token)? {
            Win16HostGdiCleanup::Released
        } else {
            Win16HostGdiCleanup::Failed
        })
    }

    pub(super) fn native_brush(&self, token: Win16HostGdiObject) -> Option<HGDIOBJ> {
        let native = self.objects.get(&token)?.handle;
        // SAFETY: The token resolves to a retained native object handle.
        (unsafe { GetObjectType(native) } == OBJ_BRUSH as u32).then_some(native)
    }

    pub(super) fn native_region(
        &self,
        token: Win16HostGdiObject,
    ) -> Option<windows_sys::Win32::Graphics::Gdi::HRGN> {
        let native = self.objects.get(&token)?.handle;
        // SAFETY: The token resolves to a retained native object handle.
        (unsafe { GetObjectType(native) } == OBJ_REGION as u32).then_some(native.cast())
    }

    pub(super) fn create_region(
        &mut self,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        // SAFETY: All coordinates are scalar; the resulting HRGN is newly owned.
        let native = unsafe { CreateRectRgn(0, 0, 0, 0) };
        self.adopt_owned(native.cast())
    }

    pub(super) fn native_bitmap(
        &self,
        token: Win16HostGdiObject,
    ) -> Option<windows_sys::Win32::Graphics::Gdi::HBITMAP> {
        let native = self.objects.get(&token)?.handle;
        // SAFETY: The token resolves to a retained native object handle.
        (unsafe { GetObjectType(native) } == OBJ_BITMAP as u32).then_some(native.cast())
    }

    pub(super) fn native_palette(
        &self,
        token: Win16HostGdiObject,
    ) -> Option<windows_sys::Win32::Graphics::Gdi::HPALETTE> {
        let native = self.objects.get(&token)?.handle;
        // SAFETY: The token resolves to a retained native GDI object handle.
        (unsafe { GetObjectType(native) } == windows_sys::Win32::Graphics::Gdi::OBJ_PAL as u32)
            .then_some(native.cast())
    }

    pub(super) fn unrealize(&self, token: Win16HostGdiObject) -> bool {
        let Some(object) = self.objects.get(&token) else { return false; };
        // Windows 3.1 SDK WINDOWS.H:1379 takes HGDIOBJ and returns BOOL.
        // The mapped object's ownership and identity remain unchanged; Windows
        // owns palette/brush realization state, so no guest-side cache is needed.
        // SAFETY: Only a registered native GDI handle reaches the system API.
        unsafe { windows_sys::Win32::Graphics::Gdi::UnrealizeObject(object.handle) != 0 }
    }

    pub(super) fn native_font(
        &self, token: Win16HostGdiObject,
    ) -> Option<windows_sys::Win32::Graphics::Gdi::HFONT> {
        let native = self.objects.get(&token)?.handle;
        // SAFETY: This is a mapped GDI handle, not a guest address. Windows
        // validates its type; the application retains ownership of the font.
        (unsafe { GetObjectType(native) } == windows_sys::Win32::Graphics::Gdi::OBJ_FONT as u32)
            .then_some(native.cast())
    }
}

impl Drop for Win16Objects {
    fn drop(&mut self) {
        for (_, object) in std::mem::take(&mut self.objects) {
            if object.is_owned() {
                if let Some(owner) = object.dib_owner {
                    if let Ok(Some(lease)) = owner.begin_delete() {
                        // SAFETY: The exact DIB owner is live and unpinned. A
                        // failed DeleteObject leaves its section resources live.
                        let deleted = unsafe { DeleteObject(object.handle) } != 0;
                        let _receipt = lease.finish(deleted);
                    }
                } else {
                    // SAFETY: Remaining owned objects were not deleted earlier.
                    unsafe { DeleteObject(object.handle) };
                }
            }
        }
    }
}

fn finish_unpublished_dib(
    bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    owner: Arc<Win16DibSectionOwner>,
    primary: RuntimeError,
) -> RuntimeError {
    let cleanup = match owner.begin_delete() {
        Ok(Some(lease)) => {
            let deleted = unsafe { DeleteObject(bitmap.cast()) } != 0;
            match lease.finish(deleted) {
                Ok(()) if deleted => Ok(()),
                Ok(()) => Err(RuntimeError::new(
                    Kind::HostFailure, "failed to delete unpublished WinG DIB bitmap",
                )),
                Err(error) => Err(error),
            }
        }
        Ok(None) => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "unpublished WinG DIB bitmap unexpectedly has an active lease",
        )),
        Err(error) => Err(error),
    };
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => RuntimeError::with_source(
            Kind::HostFailure,
            "WinG bitmap registration and native cleanup both failed",
            DibAdoptionFailure { primary, cleanup },
        ),
    }
}

#[derive(Debug)]
struct DibAdoptionFailure { primary: RuntimeError, cleanup: RuntimeError }

impl std::fmt::Display for DibAdoptionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for DibAdoptionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
