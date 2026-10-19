use super::*;
use windows_sys::Win32::System::{ApplicationInstallationAndServicing::*, WindowsProgramming::*};

/// Thread-local native control theming, entered only in the launcher process.
pub(super) struct Theme {
    context: HANDLE,
    cookie: usize,
}
impl Theme {
    pub fn activate() -> Result<Self, String> {
        let request = ACTCTXW {
            cbSize: std::mem::size_of::<ACTCTXW>() as u32,
            dwFlags: ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID,
            hModule:
                // SAFETY: `GetModuleHandleW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
                unsafe { GetModuleHandleW(null()) },
            lpResourceName: 201_usize as *const u16,
            ..Default::default()
        };
        let context =
            // SAFETY: `CreateActCtxW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe { CreateActCtxW(&request) };
        if context == INVALID_HANDLE_VALUE {
            return Err(format!(
                "无法加载原生界面主题：{}",
                std::io::Error::last_os_error()
            ));
        }
        let mut cookie = 0;
        if
        // SAFETY: `ActivateActCtx` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { ActivateActCtx(context, &mut cookie) } == 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: `ReleaseActCtx` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
                ReleaseActCtx(context);
            }
            return Err(format!("无法启用原生界面主题：{error}"));
        }
        Ok(Self { context, cookie })
    }
}
impl Drop for Theme {
    fn drop(&mut self) {
        // SAFETY: `DeactivateActCtx` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            DeactivateActCtx(0, self.cookie);
            ReleaseActCtx(self.context);
        }
    }
}
