//! Pointer-free common-dialog operations shared with the native UI worker.

use crate::{Win16HostDc, Win16HostDevMode, Win16HostLogFont, Win16HostWindow};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostOpenFileDialog {
    pub owner: Option<Win16HostWindow>,
    pub flags: u32,
    pub filter: Option<Vec<u8>>,
    pub custom_filter: Option<Vec<u8>>,
    pub filter_index: u32,
    pub file: Vec<u8>,
    pub file_title: Option<Vec<u8>>,
    pub initial_dir: Option<Vec<u8>>,
    pub title: Option<Vec<u8>>,
    pub default_extension: Option<Vec<u8>>,
    pub file_offset: u16,
    pub file_extension: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostFindReplaceDialog {
    /// Runtime-assigned opaque continuation identity. It is neither a guest
    /// address nor a native handle and remains stable for the dialog lifetime.
    pub request_id: u64,
    pub owner: Option<Win16HostWindow>,
    pub replace: bool,
    pub flags: u32,
    /// Owned native buffers; their lengths are the capacities passed to USER.
    pub find_text: Vec<u8>,
    pub replace_text: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostChooseColorDialog {
    pub owner: Option<Win16HostWindow>,
    pub initial_color: u32,
    pub custom_colors: [u32; 16],
    pub flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostChooseFontDialog {
    pub owner: Option<Win16HostWindow>,
    pub dc: Option<Win16HostDc>,
    pub log_font: Win16HostLogFont,
    pub point_size: i16,
    pub flags: u32,
    pub color: u32,
    pub style: Option<Vec<u8>>,
    pub font_type: u16,
    pub min_size: i16,
    pub max_size: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostPrintDialog {
    pub owner: Option<Win16HostWindow>,
    pub dev_mode: Option<Win16HostDevMode>,
    pub dev_names: Option<Vec<u8>>,
    pub dc: Option<Win16HostDc>,
    pub flags: u32,
    pub from_page: u16,
    pub to_page: u16,
    pub min_page: u16,
    pub max_page: u16,
    pub copies: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostCommonDialogOperation {
    OpenFile(Win16HostOpenFileDialog),
    SaveFile(Win16HostOpenFileDialog),
    FindReplace(Win16HostFindReplaceDialog),
    ChooseColor(Win16HostChooseColorDialog),
    ChooseFont(Win16HostChooseFontDialog),
    Print(Win16HostPrintDialog),
    GetFileTitle { file_name: Vec<u8>, capacity: u16, title_is_null: bool },
    ExtendedError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostCommonDialogResult {
    File {
        accepted: bool,
        extended_error: u32,
        flags: u32,
        filter_index: u32,
        file: Vec<u8>,
        file_title: Option<Vec<u8>>,
        file_offset: u16,
        file_extension: u16,
        custom_filter: Option<Vec<u8>>,
        /// Win16 nMaxFile needed by FNERR_BUFFERTOOSMALL, when the native
        /// worker received enough scratch space to read the WORD safely.
        required_size: Option<u16>,
    },
    FindReplaceCreated {
        request_id: u64,
        window: Option<Win16HostWindow>,
        find_message: u16,
        extended_error: u32,
    },
    Color {
        accepted: bool,
        extended_error: u32,
        color: u32,
        custom_colors: [u32; 16],
    },
    Font {
        accepted: bool,
        extended_error: u32,
        log_font: Win16HostLogFont,
        point_size: i16,
        color: u32,
        flags: u32,
        style: Vec<u8>,
        font_type: u16,
    },
    Print {
        accepted: bool,
        extended_error: u32,
        dev_mode: Option<Win16HostDevMode>,
        dev_names: Option<Vec<u8>>,
        dc: Option<Win16HostDc>,
        flags: u32,
        from_page: u16,
        to_page: u16,
        min_page: u16,
        max_page: u16,
        copies: u16,
    },
    FileTitle { status: i16, title: Vec<u8> },
    ExtendedError(u32),
}

/// Snapshot of a native FINDMSGSTRING notification. Guest FAR addresses and
/// capacities remain in runtime continuation state; only opaque identities
/// and owned output buffers cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostFindReplaceNotification {
    pub request_id: u64,
    pub dialog: Option<Win16HostWindow>,
    pub owner: Win16HostWindow,
    pub find_message: u16,
    pub flags: u32,
    pub find_text: Vec<u8>,
    pub replace_text: Option<Vec<u8>>,
    pub dialog_terminated: bool,
}

/// Guest WndProc edits to a live modeless Find/Replace dialog's owned native
/// record and text buffers. Guest addresses and buffer capacities stay in the
/// runtime continuation and never cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostFindReplaceUpdate {
    pub request_id: u64,
    pub flags: u32,
    pub find_text: Vec<u8>,
    pub replace_text: Option<Vec<u8>>,
}
