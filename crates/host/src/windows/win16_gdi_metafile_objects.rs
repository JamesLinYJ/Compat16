//! Actual GDI object queries and incarnation retirement for WMF table effects.

use super::*;
use windows_sys::Win32::Graphics::Gdi::{GetObjectW, GetRgnBox};

// GetObjectType can still report OBJ_PEN after successful deletion because
// its type bits do not prove that an object remains queryable. Check real
// object data, or region geometry for HRGN (which GetObjectW does not support).
fn metafile_object_is_live(handle: HGDIOBJ) -> Result<bool, RuntimeError> {
    if (crate::windows::win32_safe::get_object_type(handle)) == OBJ_REGION as u32 {
        let mut rect = windows_sys::Win32::Foundation::RECT::default();
        // SAFETY: `GetRgnBox` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        return Ok(unsafe { GetRgnBox(handle.cast(), &mut rect) } != 0);
    }
    // SAFETY: GetObjectW writes into a caller-owned buffer of the byte count passed with it.
    let count = unsafe { GetObjectW(handle, 0, std::ptr::null_mut()) };
    if count <= 0 {
        return Ok(false);
    }
    // A NULL size query also returns sizeof(LOGPEN) for a deleted pen. Only
    // copying actual object data proves liveness. Keep fixed structures on
    // the stack; variable EXTLOGPEN data gets an aligned, fallible buffer.
    let mut fixed = [0u64; 16];
    if count as usize <= std::mem::size_of_val(&fixed) {
        // SAFETY: GetObjectW writes into a caller-owned buffer of the byte count passed with it.
        return Ok(unsafe { GetObjectW(handle, count, fixed.as_mut_ptr().cast()) } != 0);
    }
    let words = (count as usize).div_ceil(8);
    let mut data = Vec::<u64>::new();
    data.try_reserve_exact(words).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "query WMF object lifetime", error)
    })?;
    data.resize(words, 0);
    // SAFETY: GetObjectW writes into a caller-owned buffer of the byte count passed with it.
    Ok(unsafe { GetObjectW(handle, count, data.as_mut_ptr().cast()) } != 0)
}

#[derive(Clone)]
pub(in crate::windows) struct MetafileObjectNote {
    pub(in crate::windows) token: Win16HostGdiObject,
    pub(in crate::windows) handle: usize,
    retired: Arc<AtomicBool>,
}
impl MetafileObjectNote {
    pub(in crate::windows) fn acknowledge_deletion(&self) -> Result<(), RuntimeError> {
        // SAFETY: Native EnumMetaFile just returned after cleaning this table.
        if !metafile_object_is_live(self.handle as _)? {
            self.retired.store(true, Ordering::Release);
        }
        Ok(())
    }
    pub(in crate::windows) fn retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
}

impl Win16Objects {
    /// Finish shared-storage retirement on its owner thread, including native
    /// enumeration aborts and a native handle reused before result projection.
    pub(in crate::windows) fn acknowledge_metafile_storage_retirements(
        &self,
    ) -> Result<(), RuntimeError> {
        for object in self
            .objects
            .values()
            .filter(|object| object.retired.load(Ordering::Acquire))
        {
            if let Some(owner) = &object.dib_owner {
                owner.acknowledge_external_deletion()?;
            }
        }
        Ok(())
    }

    pub(in crate::windows) fn metafile_note(
        &self,
        token: Win16HostGdiObject,
    ) -> Option<MetafileObjectNote> {
        let object = self.live_object(&token)?;
        Some(MetafileObjectNote {
            token,
            handle: object.handle as usize,
            retired: Arc::clone(&object.retired),
        })
    }

    pub(in crate::windows) fn metafile_object(
        &self,
        token: Win16HostGdiObject,
    ) -> Result<Option<usize>, RuntimeError> {
        let Some(object) = self.live_object(&token) else {
            return Ok(None);
        };
        Ok(metafile_object_is_live(object.handle)?.then_some(object.handle as usize))
    }

    pub(in crate::windows) fn retire_metafile_object(
        &mut self,
        token: Win16HostGdiObject,
    ) -> Result<bool, RuntimeError> {
        let Some(object) = self.objects.get(&token) else {
            return Ok(false);
        };
        if !metafile_object_is_live(object.handle)? {
            if let Some(owner) = &object.dib_owner {
                owner.acknowledge_external_deletion()?;
            }
            object.retired.store(true, Ordering::Release);
            return Ok(true);
        }
        Ok(false)
    }
}
