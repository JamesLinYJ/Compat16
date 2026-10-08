//! Typed USER dialog/control, clipboard, system-parameter, and session requests.
//! The ABI catalog remains the source of stack widths; this module consumes
//! those already-decoded WORD/DWORD slots.
//!
//! The request values contain copied strings and structures or raw guest
//! addresses for runtime-side checked writeback. They never contain host
//! pointers. USER.145 and USER.146 keep typed decoder semantics for the
//! existing clipboard routes; they do not add descriptors or a second route.

use crate::{SelectorTable, Win16Argument, Win16Error, Win16ResourceName};
use guest_core::GuestMemory;

/// Dialog resources keep the resource-name-versus-integer-ordinal distinction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16DialogTemplateRef {
    Resource { instance: u16, name: Win16ResourceName },
    GlobalHandle { instance: u16, template: u16 },
    FarAddress { instance: u16, template: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserDialogRequest {
    Create {
        template: Win16DialogTemplateRef,
        owner: u16,
        procedure: u32,
        modal: bool,
        init_parameter: u32,
    },
    DefaultProcedure { dialog: u16, message: u16, w_param: u16, l_param: u32 },
    End { dialog: u16, result: i16 },
    IsMessage { dialog: u16, message: crate::user_abi::Msg16 },
    GetItem { dialog: u16, id: u16 },
    NextGroupItem { dialog: u16, control: u16, previous: bool },
    NextTabItem { dialog: u16, control: u16, previous: bool },
    SetItemText { dialog: u16, id: u16, text: Option<Vec<u8>> },
    GetItemText { dialog: u16, id: u16, output: u32, capacity: i16 },
    SetItemInteger { dialog: u16, id: u16, value: u16, signed: bool },
    GetItemInteger { dialog: u16, id: i16, signed: bool, translated_output: u32 },
    CheckButton { dialog: u16, id: u16, state: u16 },
    IsButtonChecked { dialog: u16, id: u16 },
    CheckRadioButton { dialog: u16, first: u16, last: u16, checked: u16 },
    DirectoryList {
        dialog: u16,
        path_output: u32,
        path_spec: Option<Vec<u8>>,
        list_id: u16,
        path_id: u16,
        file_type: u16,
        combo_box: bool,
    },
    DirectorySelect {
        dialog: u16,
        output: u32,
        /// `None` is the legacy API without an explicit extent; `Some` is
        /// the signed nCount supplied by the Ex variants.
        capacity: Option<i16>,
        control_id: u16,
        combo_box: bool,
    },
    AdjustWindowRect { rect: u32, style: u32, ex_style: u32, menu: bool },
    MapDialogRect { dialog: u16, rect: u32 },
}

/// Clipboard requests retain Win16 handle words and raw output addresses.
/// Global-memory ownership is resolved by runtime before the host operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserClipboardRequest {
    Open { owner: u16 },
    Close,
    Empty,
    Owner,
    SetData { format: u16, handle: u16 },
    GetData { format: u16 },
    CountFormats,
    EnumFormats { previous: u16 },
    RegisterFormat { name: Option<Vec<u8>> },
    GetFormatName { format: u16, output: u32, capacity: i16 },
    IsFormatAvailable { format: u16 },
    GetPriorityFormat { formats: Vec<u16>, count: i16 },
    SetViewer { viewer: u16 },
    GetViewer,
    ChangeViewerChain { remove: u16, next: u16 },
    GetOpenClipboardWindow,
}

/// The output pointer is kept raw until the runtime preflights the exact
/// action-specific Win16 structure size. `param` and flags retain their
/// original WORD values for actions with documented ignore semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SystemParametersInfoRequest {
    pub action: u16,
    pub param: u16,
    pub data: u32,
    pub flags: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserFamilyRequest {
    Dialog(Win16UserDialogRequest),
    Clipboard(Win16UserClipboardRequest),
    SystemParametersInfo(Win16SystemParametersInfoRequest),
    Session(Win16UserSessionRequest),
}

/// Win16 USER session and exit APIs retain their exact guest-width values.
/// The declarations return BOOL16; the ABI return kind remains on the decoded
/// service frame rather than being widened into a different guest contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserSessionRequest {
    /// USER ordinal 2; it has no stack arguments in the export catalog.
    OldExitWindows,
    /// USER ordinal 7: DWORD return/restart code followed by a WORD reserved value.
    ExitWindows { return_code: u32, reserved: u16 },
    /// USER ordinal 246: FAR ANSI executable path and nullable FAR ANSI arguments.
    ExitWindowsExec { program: Option<Vec<u8>>, parameters: Option<Vec<u8>> },
}

/// Decode one known-signature USER export in the dialog/control, clipboard,
/// system-parameter, or session family. `None` leaves other USER families to
/// their assigned decoder (menus, drawing, messages/callbacks, and window calls).
pub fn decode_user_family(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16UserFamilyRequest>, Win16Error> {
    use Win16UserClipboardRequest as Clipboard;
    use Win16UserDialogRequest as Dialog;
    use Win16UserFamilyRequest as Request;
    use Win16UserSessionRequest as Session;

    let decoded = match ordinal {
        2 => Request::Session(Session::OldExitWindows),
        7 => Request::Session(Session::ExitWindows {
            return_code: dword(arguments, 0)?,
            reserved: word(arguments, 1)?,
        }),
        246 => Request::Session(Session::ExitWindowsExec {
            program: nullable_string(dword(arguments, 0)?, selectors, memory)?,
            parameters: nullable_string(dword(arguments, 1)?, selectors, memory)?,
        }),
        308 => Request::Dialog(Dialog::DefaultProcedure {
            dialog: word(arguments, 0)?,
            message: word(arguments, 1)?,
            w_param: word(arguments, 2)?,
            l_param: dword(arguments, 3)?,
        }),
        // DialogBox / CreateDialog resource and indirect-template variants.
        87 | 89 | 239 | 241 => {
            let instance = word(arguments, 0)?;
            let name = resource_name(dword(arguments, 1)?, selectors, memory)?;
            let owner = word(arguments, 2)?;
            let procedure = dword(arguments, 3)?;
            let (modal, init_parameter) = match ordinal {
                87 => (true, 0),
                89 => (false, 0),
                239 => (true, dword(arguments, 4)?),
                241 => (false, dword(arguments, 4)?),
                _ => unreachable!(),
            };
            Request::Dialog(Dialog::Create {
                template: Win16DialogTemplateRef::Resource { instance, name },
                owner,
                procedure,
                modal,
                init_parameter,
            })
        }
        // The documented indirect APIs take a guest HGLOBAL template handle.
        218 | 240 => {
            let instance = word(arguments, 0)?;
            let template = word(arguments, 1)?;
            let owner = word(arguments, 2)?;
            let procedure = dword(arguments, 3)?;
            let (modal, init_parameter) = match ordinal {
                218 => (true, 0),
                240 => (true, dword(arguments, 4)?),
                _ => unreachable!(),
            };
            Request::Dialog(Dialog::Create {
                template: Win16DialogTemplateRef::GlobalHandle { instance, template },
                owner,
                procedure,
                modal,
                init_parameter,
            })
        }
        219 | 242 => {
            let instance = word(arguments, 0)?;
            let template = dword(arguments, 1)?;
            let owner = word(arguments, 2)?;
            let procedure = dword(arguments, 3)?;
            let (modal, init_parameter) = if ordinal == 219 {
                (false, 0)
            } else {
                (false, dword(arguments, 4)?)
            };
            Request::Dialog(Dialog::Create {
                template: Win16DialogTemplateRef::FarAddress { instance, template },
                owner,
                procedure,
                modal,
                init_parameter,
            })
        }
        88 => Request::Dialog(Dialog::End {
            dialog: word(arguments, 0)?,
            result: word(arguments, 1)? as i16,
        }),
        90 => {
            let dialog = word(arguments, 0)?;
            let message = crate::user_abi::Msg16::read_from(
                selectors,
                memory,
                selectors.pointer_from_far(dword(arguments, 1)?)?,
            )?;
            Request::Dialog(Dialog::IsMessage { dialog, message })
        }
        91 => Request::Dialog(Dialog::GetItem {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)?,
        }),
        92 => Request::Dialog(Dialog::SetItemText {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)?,
            text: nullable_string(dword(arguments, 2)?, selectors, memory)?,
        }),
        93 => Request::Dialog(Dialog::GetItemText {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)?,
            output: dword(arguments, 2)?,
            capacity: word(arguments, 3)? as i16,
        }),
        94 => Request::Dialog(Dialog::SetItemInteger {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)?,
            value: word(arguments, 2)?,
            signed: word(arguments, 3)? != 0,
        }),
        95 => Request::Dialog(Dialog::GetItemInteger {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)? as i16,
            translated_output: dword(arguments, 2)?,
            signed: word(arguments, 3)? != 0,
        }),
        96 => Request::Dialog(Dialog::CheckRadioButton {
            dialog: word(arguments, 0)?,
            first: word(arguments, 1)?,
            last: word(arguments, 2)?,
            checked: word(arguments, 3)?,
        }),
        97 => Request::Dialog(Dialog::CheckButton {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)?,
            state: word(arguments, 2)?,
        }),
        98 => Request::Dialog(Dialog::IsButtonChecked {
            dialog: word(arguments, 0)?,
            id: word(arguments, 1)?,
        }),
        99 | 194 => Request::Dialog(Dialog::DirectorySelect {
            dialog: word(arguments, 0)?,
            output: dword(arguments, 1)?,
            capacity: None,
            control_id: word(arguments, 2)?,
            combo_box: ordinal == 194,
        }),
        422 | 423 => Request::Dialog(Dialog::DirectorySelect {
            dialog: word(arguments, 0)?,
            output: dword(arguments, 1)?,
            capacity: Some(word(arguments, 2)? as i16),
            control_id: word(arguments, 3)?,
            combo_box: ordinal == 423,
        }),
        100 | 195 => Request::Dialog(Dialog::DirectoryList {
            dialog: word(arguments, 0)?,
            path_output: dword(arguments, 1)?,
            path_spec: nullable_string(dword(arguments, 1)?, selectors, memory)?,
            list_id: word(arguments, 2)?,
            path_id: word(arguments, 3)?,
            file_type: word(arguments, 4)?,
            combo_box: ordinal == 195,
        }),
        102 => Request::Dialog(Dialog::AdjustWindowRect {
            rect: dword(arguments, 0)?,
            style: dword(arguments, 1)?,
            ex_style: 0,
            menu: word(arguments, 2)? != 0,
        }),
        454 => Request::Dialog(Dialog::AdjustWindowRect {
            rect: dword(arguments, 0)?,
            style: dword(arguments, 1)?,
            ex_style: dword(arguments, 3)?,
            menu: word(arguments, 2)? != 0,
        }),
        103 => Request::Dialog(Dialog::MapDialogRect {
            dialog: word(arguments, 0)?,
            rect: dword(arguments, 1)?,
        }),
        227 | 228 => {
            let dialog = word(arguments, 0)?;
            let control = word(arguments, 1)?;
            let previous = word(arguments, 2)? != 0;
            Request::Dialog(if ordinal == 227 {
                Dialog::NextGroupItem { dialog, control, previous }
            } else {
                Dialog::NextTabItem { dialog, control, previous }
            })
        }

        // Clipboard ownership and transfer services.
        137 => Request::Clipboard(Clipboard::Open { owner: word(arguments, 0)? }),
        138 => Request::Clipboard(Clipboard::Close),
        139 => Request::Clipboard(Clipboard::Empty),
        140 => Request::Clipboard(Clipboard::Owner),
        141 => Request::Clipboard(Clipboard::SetData {
            format: word(arguments, 0)?,
            handle: word(arguments, 1)?,
        }),
        142 => Request::Clipboard(Clipboard::GetData { format: word(arguments, 0)? }),
        143 => Request::Clipboard(Clipboard::CountFormats),
        144 => Request::Clipboard(Clipboard::EnumFormats { previous: word(arguments, 0)? }),
        145 => Request::Clipboard(Clipboard::RegisterFormat {
            name: nullable_string(dword(arguments, 0)?, selectors, memory)?,
        }),
        146 => Request::Clipboard(Clipboard::GetFormatName {
            format: word(arguments, 0)?,
            output: dword(arguments, 1)?,
            capacity: word(arguments, 2)? as i16,
        }),
        147 => Request::Clipboard(Clipboard::SetViewer { viewer: word(arguments, 0)? }),
        148 => Request::Clipboard(Clipboard::GetViewer),
        149 => Request::Clipboard(Clipboard::ChangeViewerChain {
            remove: word(arguments, 0)?,
            next: word(arguments, 1)?,
        }),
        193 => Request::Clipboard(Clipboard::IsFormatAvailable { format: word(arguments, 0)? }),
        248 => Request::Clipboard(Clipboard::GetOpenClipboardWindow),
        402 => {
            let raw = dword(arguments, 0)?;
            let count = word(arguments, 1)? as i16;
            let formats = if count <= 0 {
                Vec::new()
            } else {
                read_words(raw, count as usize, selectors, memory)?
            };
            Request::Clipboard(Clipboard::GetPriorityFormat { formats, count })
        }
        483 => Request::SystemParametersInfo(Win16SystemParametersInfoRequest {
            action: word(arguments, 0)?,
            param: word(arguments, 1)?,
            data: dword(arguments, 2)?,
            flags: word(arguments, 3)?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(decoded))
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn resource_name(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ResourceName, Win16Error> {
    if raw >> 16 == 0 {
        Ok(Win16ResourceName::Id(raw as u16))
    } else {
        crate::strings::read_ansi_z(selectors, memory, raw, crate::exports::MAX_WIN16_STRING_BYTES)
            .map(Win16ResourceName::Name)
    }
}

fn nullable_string(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    if raw == 0 {
        Ok(None)
    } else {
        crate::strings::read_ansi_z(selectors, memory, raw, crate::exports::MAX_WIN16_STRING_BYTES)
            .map(Some)
    }
}

fn read_words(
    far: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u16>, Win16Error> {
    let length = count.checked_mul(2).ok_or(Win16Error::InvalidRange)?;
    // Clipboard priority arrays are a single caller-owned fixed array. The
    // runtime must not retain its address after this checked copy.
    let mut pointer = selectors.pointer_from_far(far)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Win16Error::OutOfMemory)?;
    let mut remaining = length;
    while remaining > 0 {
        let descriptor = selectors.describe(pointer.selector())?;
        let in_segment = descriptor.limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|bytes| bytes.checked_add(1))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let chunk = remaining.min(in_segment);
        if chunk == 0 { return Err(Win16Error::InvalidRange); }
        let start = bytes.len();
        bytes.resize(start.checked_add(chunk).ok_or(Win16Error::InvalidRange)?, 0);
        selectors.read(memory, pointer, &mut bytes[start..])?;
        remaining -= chunk;
        if remaining > 0 {
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(chunk).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(bytes.chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}
