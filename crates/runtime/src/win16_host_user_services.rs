//! Pointer-free USER service payloads shared by runtime and native adapters.
//!
//! Guest selectors, guest handles, callback addresses, and native HWND/HDC
//! values are deliberately absent. Runtime translates guest identities before
//! constructing these operations; the window worker executes callback-capable
//! calls on the owner thread and returns only opaque identities and copied
//! data.

use crate::{Win16HostCallback, Win16HostLogFont, Win16HostMessage,
    Win16HostWindow, Win16HostWindowCreationResult, Win16HostQueuedMessage};

/// A dialog-template atom is either a resource/class ordinal or copied ANSI
/// text. `None` is meaningful for an empty menu/class field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDialogAtom {
    None,
    Ordinal(u16),
    String(Vec<u8>),
    /// A class registered by this guest instance. Its native name is private
    /// to the HWND-owning worker and is resolved there from this identity.
    GuestClass(crate::Win16HostClass),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDialogFont {
    pub point_size: i16,
    pub face_name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDialogItem {
    pub style: u32,
    pub x: i16,
    pub y: i16,
    pub width: i16,
    pub height: i16,
    pub id: u16,
    pub class: Win16HostDialogAtom,
    pub guest_class_name: Option<crate::Win16HostClassName>,
    pub title: Win16HostDialogAtom,
    /// Opaque guest resource icon, leased by the native dialog owner before
    /// creation and installed before WM_INITDIALOG. The native title is empty.
    pub initial_icon: Option<crate::Win16HostIcon>,
    /// Dialog-item creation bytes copied from the Win16 template, including
    /// no guest pointer or selector. Empty means no creation data.
    pub creation_data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDialogTemplate {
    pub style: u32,
    pub x: i16,
    pub y: i16,
    pub width: i16,
    pub height: i16,
    pub menu: Win16HostDialogAtom,
    /// A copied, fully decoded guest RT_MENU tree. Native USER receives this
    /// through its own menu worker; no guest resource pointer crosses hosts.
    pub menu_template: Option<crate::Win16MenuTemplate>,
    pub class: Win16HostDialogAtom,
    pub guest_class_name: Option<crate::Win16HostClassName>,
    pub title: Win16HostDialogAtom,
    pub font: Option<Win16HostDialogFont>,
    pub items: Vec<Win16HostDialogItem>,
}

/// Dialog calls submitted through the native window worker. Create carries no
/// guest FARPROC: runtime keeps the dialog procedure in its callback frame and
/// the worker reports `DialogProc` callback routes explicitly.
#[derive(Clone, Debug)]
pub enum Win16HostDialogOperation {
    /// Dedicated KERNEL FatalAppExit message box with strict IDOK semantics.
    FatalAppExitMessage { message: Vec<u8> },
    FatalExitPrompt {
        error_code: i16,
        caller_selector: u16,
        caller_offset: u16,
    },
    /// A native modal message box executed by the HWND-owning worker. Its
    /// nested message loop can synchronously reenter a guest window procedure.
    MessageBox {
        owner: Option<Win16HostWindow>,
        text: Option<Vec<u8>>,
        caption: Option<Vec<u8>>,
        style: u16,
    },
    Create {
        creation: crate::Win16CreationId,
        guest_instance: u16,
        owner: Option<Win16HostWindow>,
        template: Win16HostDialogTemplate,
        modal: bool,
        init_parameter: u32,
    },
    End {
        dialog: Win16HostWindow,
        result: i16,
    },
    IsMessage {
        dialog: Win16HostWindow,
        message: Win16HostQueuedMessage,
    },
    DefaultProcedure {
        dialog: Win16HostWindow,
        callback: Win16HostCallback,
        message: Win16HostMessage,
    },
    GetBaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDialogResult {
    FatalAppExitAcknowledged,
    FatalExitChoice(crate::Win16HostFatalExitChoice),
    MessageBox(u16),
    Created {
        creation: Win16HostWindowCreationResult,
        menu: Option<crate::Win16HostMenu>,
    },
    ModalResult(Option<i16>),
    Ended(bool),
    MessageHandled(bool),
    DefaultResult(Option<crate::Win16HostMessageResult>),
    BaseUnits(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostFatalExitChoice { Abort, Break, Ignore }

/// Child-control calls are worker operations because native control messages
/// can synchronously reenter the dialog/window procedure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDialogControlOperation {
    GetItem { dialog: Win16HostWindow, id: u16 },
    GetControlId { control: Win16HostWindow },
    GetNextGroupItem { dialog: Win16HostWindow, control: Option<Win16HostWindow>, previous: bool },
    GetNextTabItem { dialog: Win16HostWindow, control: Option<Win16HostWindow>, previous: bool },
    SetItemText { dialog: Win16HostWindow, id: u16, text: Option<Vec<u8>> },
    GetItemText { dialog: Win16HostWindow, id: u16, capacity: u16, buffer_is_null: bool },
    SetItemInteger { dialog: Win16HostWindow, id: u16, value: u16, signed: bool },
    GetItemInteger { dialog: Win16HostWindow, id: i16, signed: bool },
    CheckButton { dialog: Win16HostWindow, id: u16, state: u16 },
    IsButtonChecked { dialog: Win16HostWindow, id: u16 },
    CheckRadioButton { dialog: Win16HostWindow, first: u16, last: u16, checked: u16 },
    DirectoryList {
        dialog: Win16HostWindow,
        path_spec: Option<Vec<u8>>,
        path_capacity: u16,
        list_id: u16,
        path_id: u16,
        file_type: u16,
        combo_box: bool,
    },
    DirectorySelect {
        dialog: Win16HostWindow,
        capacity: u16,
        control_id: u16,
        combo_box: bool,
    },
    AdjustWindowRect {
        rect: crate::Win16HostRect,
        style: u32,
        ex_style: u32,
        menu: bool,
    },
    MapDialogRect { dialog: Win16HostWindow, rect: crate::Win16HostRect },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDialogControlResult {
    Item(Option<Win16HostWindow>),
    ControlId(u16),
    NextItem(Option<Win16HostWindow>),
    /// Exact native UINT result and only its validated NUL-terminated prefix.
    /// `u32::MAX` is preserved as -1 with no copyback bytes.
    Text { value: u32, bytes: Vec<u8> },
    Integer { succeeded: bool, value: u16, translated: bool },
    ButtonState(u16),
    Succeeded(bool),
    DirectoryList { selected: i16, path_spec: Option<Vec<u8>> },
    DirectorySelect { selected: bool, text: Vec<u8> },
    Rect(Option<crate::Win16HostRect>),
}

/// Clipboard data after ABI translation. Global-memory formats are copied
/// bytes. Bitmap-like formats use the existing GDI object identity table;
/// unsupported clipboard-specific native objects fail at the adapter rather
/// than being cast to guest HGLOBAL values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClipboardData {
    GlobalMemory(Vec<u8>),
    GdiObject(crate::Win16HostGdiObject),
    Delayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClipboardOperation {
    Open { owner: Option<Win16HostWindow> },
    Close,
    Empty,
    Owner,
    SetData { format: u16, data: Win16HostClipboardData },
    GetData { format: u16 },
    CountFormats,
    EnumFormats { previous: u16 },
    IsFormatAvailable { format: u16 },
    RegisterFormat { name: Vec<u8> },
    GetFormatName { format: u16, capacity: u16 },
    GetPriorityFormat { formats: Vec<u16> },
    SetViewer { viewer: Option<Win16HostWindow> },
    GetViewer,
    GetOpenClipboardWindow,
    ChangeViewerChain { remove: Win16HostWindow, next: Option<Win16HostWindow> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClipboardResult {
    /// Every native clipboard operation is wrapped with the sequence observed
    /// on the USER worker after it completes. Runtime uses this to retire
    /// guest HGLOBAL aliases after external clipboard changes.
    Sequenced { sequence: u32, result: Box<Win16HostClipboardResult> },
    Bool(bool),
    SetData(bool),
    Window(Option<Win16HostWindow>),
    Data(Option<Win16HostClipboardData>),
    Count(u16),
    Format(u16),
    FormatName { copied: i16, bytes: Vec<u8> },
    PriorityFormat(i16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SystemParameterScalar {
    Border,
    KeyboardSpeed,
    IconHorizontalSpacing,
    ScreenSaverTimeout,
    ScreenSaverActive,
    GridGranularity,
    KeyboardDelay,
    IconVerticalSpacing,
    IconTitleWrap,
    MenuDropAlignment,
    DoubleClickWidth,
    DoubleClickHeight,
    MouseButtonSwap,
    FastTaskSwitch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16SystemParametersRequest {
    GetBool(u16),
    SetBool { action: u16, value: bool, flags: u16 },
    GetWord(u16),
    SetWord { action: u16, value: u16, flags: u16 },
    GetMouse,
    SetMouse { values: [i16; 3], flags: u16 },
    GetLanguageDriver { capacity: u16 },
    SetDesktopWallpaper { path: Vec<u8>, flags: u16 },
    SetDesktopPattern { flags: u16 },
    GetIconTitleLogFont,
    SetIconTitleLogFont { font: Win16HostLogFont, flags: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16SystemParametersValue {
    None,
    Bool(bool),
    Word(u16),
    Mouse([i16; 3]),
    LanguageDriver(Vec<u8>),
    LogFont(Win16HostLogFont),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostSystemParametersResult {
    pub succeeded: bool,
    pub value: Win16SystemParametersValue,
}

/// Generic session operations issued by Win16 USER through the native worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostSessionOperation {
    /// Original DWORD/WORD arguments, forwarded by position as NT WOW does.
    /// These are ExitWindows arguments, not ExitWindowsEx flags/reason.
    ExitWindows { return_code: u32, reserved: u16 },
    RunAfterWin16Restart { program: Vec<u8>, parameters: Option<Vec<u8>> },
}

/// Native API that rejected a Win16 USER session request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostSessionApiPhase {
    ExitWindowsEx,
}

impl Win16HostSessionApiPhase {
    pub const fn description(self) -> &'static str {
        match self {
            Self::ExitWindowsEx => "request the Windows session change",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostSessionApiFailure {
    pub phase: Win16HostSessionApiPhase,
    pub error_code: u32,
}

/// Native acceptance is not evidence that asynchronous logoff has completed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Win16HostSessionResult {
    pub accepted: bool,
    pub operation_failure: Option<Win16HostSessionApiFailure>,
}

/// Aggregate operation and result used as one nested USER worker variant.
/// Every variant is owned, pointer-free, and safe to retain while guest code
/// handles a synchronous window callback.
#[derive(Clone, Debug)]
pub enum Win16HostUserServiceOperation {
    Dialog(Win16HostDialogOperation),
    DialogControl(Win16HostDialogControlOperation),
    Clipboard(Win16HostClipboardOperation),
    SystemParameters(Win16SystemParametersRequest),
    Session(Win16HostSessionOperation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostUserServiceResult {
    Dialog(Win16HostDialogResult),
    DialogControl(Win16HostDialogControlResult),
    Clipboard(Win16HostClipboardResult),
    SystemParameters(Win16HostSystemParametersResult),
    Session(Win16HostSessionResult),
}
