//! Recording DCs require CloseMetaFile, including unpublished and abandoned
//! recordings. They must never enter the DeleteDC or ReleaseDC paths.
use super::{DcOrigin, NativeDc, Win16DcState, Win16Dcs};
use cap_std::fs::File;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostDc};
use windows_sys::Win32::Graphics::Gdi::{
    CloseMetaFile, DeleteMetaFile, GetObjectType, HDC, HMETAFILE, OBJ_METADC,
};

pub(in crate::windows) struct NativeMetafile(pub(in crate::windows) HMETAFILE);
impl Drop for NativeMetafile {
    fn drop(&mut self) {
        // This private object is the result of a native factory/close, never
        // a guest HMETAFILE16 (which is a checked HGLOBAL allocation).
        unsafe {
            DeleteMetaFile(self.0);
        }
    }
}
pub(in crate::windows) struct ClosedRecording {
    pub consumed: bool,
    pub metafile: Option<NativeMetafile>,
    pub output: Option<File>,
}
impl Win16Dcs {
    pub(in crate::windows) fn adopt_metafile(
        &self,
        native: HDC,
        output: Option<File>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let mut state = self.lock();
        let Some(next) = state.next_id.checked_add(1) else {
            discard(native);
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 metafile DC identity exhausted",
            ));
        };
        let token = Win16HostDc(state.next_id);
        state.next_id = next;
        state.objects.insert(
            token,
            NativeDc {
                handle: native as usize,
                origin: DcOrigin::Metafile,
                paint_info: None,
                pin_count: 0,
                release_pending: false,
                retire_on_unpin: false,
            },
        );
        state.metafile_outputs.insert(token, output);
        Ok(Some(token))
    }
    pub(in crate::windows) fn close_metafile(&self, token: Win16HostDc) -> ClosedRecording {
        self.lock().close_metafile(token)
    }
}
impl Win16DcState {
    pub(super) fn close_metafile(&mut self, token: Win16HostDc) -> ClosedRecording {
        let unchanged = || ClosedRecording {
            consumed: false,
            metafile: None,
            output: None,
        };
        let Some(dc) = self.objects.get(&token).copied() else {
            return unchanged();
        };
        if !matches!(dc.origin, DcOrigin::Metafile)
            || self.native_group_has_pin_or_pending(dc.handle)
            || dc.retire_on_unpin
        {
            return unchanged();
        }
        // Closing a recorder only appends EOF and retires GDI-owned recording
        // state. No native abort procedure/USER callback is installed here.
        let metafile = unsafe { CloseMetaFile(dc.handle()) };
        if metafile.is_null() && unsafe { GetObjectType(dc.handle()) } == OBJ_METADC as u32 {
            // Retain a still-live recorder after a native failure. A consumed
            // DC must instead be forgotten even when no output was produced.
            return unchanged();
        }
        self.objects.retain(|_, alias| alias.handle != dc.handle);
        ClosedRecording {
            consumed: true,
            metafile: (!metafile.is_null()).then(|| NativeMetafile(metafile)),
            output: self.metafile_outputs.remove(&token).flatten(),
        }
    }
}
pub(super) fn discard(native: HDC) {
    let metafile = unsafe { CloseMetaFile(native) };
    if !metafile.is_null() {
        drop(NativeMetafile(metafile));
    }
}
