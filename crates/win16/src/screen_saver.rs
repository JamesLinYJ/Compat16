//! Windows 3.1 `SCRNSAVE.H` constants and default-procedure decisions.
//!
//! The screen saver procedure and its password callbacks are guest application
//! exports. `DefScreenSaverProc` is supplied by the static SCRNSAVE library,
//! not by a system DLL ordinal; this module returns actions for the runtime to
//! carry out through its existing checked USER and guest-callback paths.
//! `DlgChangePassword`, `DlgGetPassword`, `DlgInvalidPassword`, and
//! `HelpMessageFilterHookFunction` are app callbacks; sample `.DEF` ordinals
//! are per-application metadata and do not belong in a Windows DLL spec.

pub(crate) const ID_APP: u16 = 100;
pub(crate) const DLG_CHANGE_PASSWORD: u16 = 2000;
pub(crate) const DLG_ENTER_PASSWORD: u16 = 2001;
pub(crate) const DLG_INVALID_PASSWORD: u16 = 2002;
pub(crate) const DLG_SCREENSAVER_CONFIGURE: u16 = 2003;

pub(crate) const IDS_IS_PASSWORD: u16 = 1000;
pub(crate) const IDS_INI_FILE: u16 = 1001;
pub(crate) const IDS_SCREEN_SAVER: u16 = 1002;
pub(crate) const IDS_PASSWORD: u16 = 1003;
pub(crate) const IDS_DIFFERENT_PASSWORD: u16 = 1004;
pub(crate) const IDS_CHANGE_PASSWORD: u16 = 1005;
pub(crate) const IDS_BAD_OLD_PASSWORD: u16 = 1006;
pub(crate) const IDS_APP_NAME: u16 = 1007;
pub(crate) const IDS_NO_HELP_MEMORY: u16 = 1008;
pub(crate) const IDS_HELP_FILE: u16 = 1009;

pub(crate) const WS_GT: u32 = 0x0003_0000;
pub(crate) const MAXFILELEN: usize = 13;
pub(crate) const TITLEBARNAMELEN: usize = 40;
pub(crate) const BUFFLEN: usize = 255;
pub(crate) const SZ_NAME_LEN: usize = TITLEBARNAMELEN;
pub(crate) const SZ_IS_PASSWORD_LEN: usize = 22;
pub(crate) const SZ_INI_FILE_LEN: usize = MAXFILELEN;
pub(crate) const SZ_SCREEN_SAVER_LEN: usize = 22;
pub(crate) const SZ_PASSWORD_LEN: usize = 16;
pub(crate) const SZ_DIFFERENT_PASSWORD_LEN: usize = BUFFLEN;
pub(crate) const SZ_CHANGE_PASSWORD_LEN: usize = 30;
pub(crate) const SZ_BAD_OLD_PASSWORD_LEN: usize = BUFFLEN;
pub(crate) const SZ_HELP_FILE_LEN: usize = MAXFILELEN;
pub(crate) const SZ_NO_HELP_MEMORY_LEN: usize = BUFFLEN;

const WM_DESTROY: u16 = 0x0002;
const WM_ACTIVATE: u16 = 0x0006;
const WM_SETCURSOR: u16 = 0x0020;
const WM_NCACTIVATE: u16 = 0x0086;
const WM_ACTIVATEAPP: u16 = 0x001c;
const WM_SYSCOMMAND: u16 = 0x0112;
const WM_KEYDOWN: u16 = 0x0100;
const WM_KEYUP: u16 = 0x0101;
const WM_MOUSEMOVE: u16 = 0x0200;
const WM_LBUTTONDOWN: u16 = 0x0201;
const WM_RBUTTONDOWN: u16 = 0x0204;
const WM_MBUTTONDOWN: u16 = 0x0207;
const SC_CLOSE: u16 = 0xf060;
const SC_SCREENSAVE: u16 = 0xf140;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefaultScreenSaverAction {
    UseDefaultWindowProcedure,
    Return(u32),
    PostQuitMessage,
    HideCursor,
    PostWindowClose { window: u16 },
    InvokePasswordDialog {
        window: u16,
        message: u16,
        wparam: u16,
        lparam: u32,
    },
}

/// Decode the reusable `DefScreenSaverProc` message policy described by the
/// Windows 3.1 SDK. Host calls and password callbacks stay with the runtime.
pub(crate) fn default_screen_saver_action(
    window: u16,
    message: u16,
    wparam: u16,
    lparam: u32,
    password_enabled: bool,
) -> DefaultScreenSaverAction {
    match message {
        WM_SYSCOMMAND if matches!(wparam & 0xfff0, SC_CLOSE | SC_SCREENSAVE) => {
            DefaultScreenSaverAction::Return(0)
        }
        WM_DESTROY => DefaultScreenSaverAction::PostQuitMessage,
        WM_SETCURSOR => DefaultScreenSaverAction::HideCursor,
        WM_LBUTTONDOWN | WM_MBUTTONDOWN | WM_RBUTTONDOWN | WM_KEYDOWN | WM_KEYUP | WM_MOUSEMOVE => {
            if password_enabled {
                DefaultScreenSaverAction::InvokePasswordDialog { window, message, wparam, lparam }
            } else {
                DefaultScreenSaverAction::PostWindowClose { window }
            }
        }
        WM_NCACTIVATE | WM_ACTIVATEAPP if wparam == 0 => {
            if password_enabled {
                DefaultScreenSaverAction::Return(0)
            } else {
                DefaultScreenSaverAction::PostWindowClose { window }
            }
        }
        WM_ACTIVATE if wparam & 0x00ff == 0 => {
            if password_enabled {
                DefaultScreenSaverAction::Return(0)
            } else {
                DefaultScreenSaverAction::PostWindowClose { window }
            }
        }
        _ => DefaultScreenSaverAction::UseDefaultWindowProcedure,
    }
}
