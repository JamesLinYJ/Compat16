//! Known-signature Win16 `COMMDLG.DLL` requests.
//!
//! Far addresses remain guest address tokens. The runtime resolves each
//! structure and member through its selector table before constructing an
//! owned host dialog request.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16CommdlgRequest {
    GetOpenFileName { structure: u32 },
    GetSaveFileName { structure: u32 },
    ChooseColor { structure: u32 },
    FindText { structure: u32 },
    ReplaceText { structure: u32 },
    ChooseFont { structure: u32 },
    PrintDlg { structure: u32 },
    GetFileTitle { file_name: Vec<u8>, title: u32, capacity: u16 },
    ExtendedError,
    /// Exported dialog-procedure entry. Inventory gives its four parameter
    /// widths but no explicit return-width modifier; preserve the frame for a
    /// future callback route without asserting its return convention.
    DialogProcedure { ordinal: u16, window: u16, message: u16, w_param: u16, l_param: u32 },
    /// Font enumeration callbacks have a declared 16-bit return and pointer
    /// parameters. The pointers remain guest FAR values until a callback frame
    /// validates and translates them.
    FontEnumerationProcedure {
        ordinal: u16,
        log_font: u32,
        text_metric: u32,
        font_type: u16,
        callback_data: u32,
    },
}
