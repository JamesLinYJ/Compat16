//! Owned, family-specific USER control messages shared with the Windows host.
//!
//! The protocol deliberately has no raw message/WPARAM/LPARAM tuple and no
//! guest address or native pointer. Runtime first queries the checked window
//! identity, then translates one family-specific operation to an owned value.
//! Host validates the actual dispatch target again before executing it.
//!
use crate::{Win16HostIcon, Win16HostProcedure, Win16HostRect, Win16HostWindow};

/// One complete Win16 Z string fits in a 64 KiB selector. Native unsized
/// GETTEXT staging uses this same bound as the guest ANSI string reader.
pub const WIN16_CONTROL_TEXT_CAPACITY: usize = 64 * 1024;

/// Standard native control family established from a checked HWND identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostControlFamily {
    Button,
    Edit,
    ListBox,
    ComboBox,
    Static,
}

/// Host-observed identity data used by runtime for Win16 style-sensitive
/// parameter decoding. Host rechecks the family and relevant style bits when
/// executing the subsequent message operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostControlIdentity {
    pub family: Win16HostControlFamily,
    pub style: u32,
}

/// Specifies the actual procedure that must receive a translated message.
/// `CallWindowProc` carries only an opaque token; no WNDPROC address crosses
/// the host boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostControlDispatch {
    Send,
    CallWindowProc { procedure: Win16HostProcedure },
}

/// Identity query request. Carrying dispatch through the query lets host
/// validate the exact procedure intended for the following call, including a
/// retained builtin procedure that a guest subclass replaced as current WndProc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostControlQuery {
    pub window: Win16HostWindow,
    pub dispatch: Win16HostControlDispatch,
}

/// Result of a checked control-family query. The dispatch is echoed so runtime
/// cannot reuse the identity for a different Send/CallWindowProc target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostControlQueryReply {
    pub window: Win16HostWindow,
    pub dispatch: Win16HostControlDispatch,
    pub identity: Option<Win16HostControlIdentity>,
}

/// An owned string or an opaque 32-bit owner-draw value supplied by a guest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostControlItem {
    /// ANSI bytes without the terminating NUL. Host builds native temporary
    /// NUL-terminated storage for string-mode control messages.
    Text(Vec<u8>),
    /// Arbitrary Win16 application data. Never decode or handle as a string,
    /// guest pointer, or native pointer.
    ItemData(u32),
}

/// Owned message request. There is intentionally no raw message number or
/// WPARAM/LPARAM; unknown and unresolved guest contracts have no request form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostControlMessage {
    Button(familytypes::Win16HostButtonMessage),
    Edit(familytypes::Win16HostEditMessage),
    ListBox(familytypes::Win16HostListBoxMessage),
    ComboBox(familytypes::Win16HostComboBoxMessage),
    Static(familytypes::Win16HostStaticMessage),
}

/// Synchronous operation after runtime has decoded and owned the guest inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostControlCall {
    pub window: Win16HostWindow,
    pub expected: Win16HostControlIdentity,
    pub dispatch: Win16HostControlDispatch,
    pub message: Win16HostControlMessage,
}

/// Win16 LRESULT value, or an opaque image result that runtime maps back to a
/// guest HICON16 through GuestImageHandles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostControlValue {
    /// Exact Win16 32-bit LRESULT bit pattern. Signed sentinels remain full
    /// DWORDs, for example -1 as 0xffff_ffff and -2 as 0xffff_fffe.
    Dword(u32),
    /// STATIC icon operation result; never put native HICON bits in a Dword.
    Icon(Option<Win16HostIcon>),
}

/// Owned message output. Guest output pointers and write ranges stay in the
/// runtime continuation and are not fields of this protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostControlOutput {
    None,
    /// Text result including its terminating NUL.
    AnsiZ(Vec<u8>),
    /// EM_GETLINE result bytes: exactly LRESULT count bytes, no terminating NUL.
    Bytes(Vec<u8>),
    /// Logical signed 32-bit coordinates. Runtime alone narrows to guest
    /// RECT16 and applies the existing zerocopy wire conversion.
    Rect(Win16HostRect),
    /// Checked host array converted to Win16 signed 16-bit elements.
    Int16s(Vec<i16>),
    /// Owner-draw/no-strings data, kept distinct from text output.
    ItemData(u32),
}

/// One synchronous native control response, bound to the queried target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostControlReply {
    pub window: Win16HostWindow,
    pub identity: Win16HostControlIdentity,
    pub value: Win16HostControlValue,
    pub output: Win16HostControlOutput,
}

/// Result of a synchronous family-specific control operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostControlResult {
    Reply(Win16HostControlReply),
    TargetUnavailable,
    IdentityChanged,
    /// Unsized LB/CB GETTEXT did not issue native GETTEXT because the checked
    /// selector write range is shorter than this full DWORD byte count.
    OutputDoesNotFit { actual: u32 },
    /// Unknown or unresolved Win16 contract. No native message was sent.
    Untranslated,
}

/// Family-specific semantic message variants. Guest WM_USER IDs are decoded
/// only in runtime; host maps these typed variants to native IDs and arguments.
pub mod familytypes {
    use super::Win16HostControlItem;
    use crate::{Win16HostGdiObject, Win16HostIcon, Win16HostRect};

    /// BUTTON messages (`BM_*`, Win16 offsets 0 through 4).
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Win16HostButtonMessage {
        GetCheck,
        SetCheck { state: u16 },
        GetState,
        SetState { state: u16 },
        SetStyle { style: u16, redraw: bool },
    }

    /// EDIT messages with a confirmed value/pointer contract. HLOCAL and
    /// word-break callback messages intentionally have no variant here.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Win16HostEditMessage {
        GetSelection,
        SetSelection { start: i16, end: i16, no_scroll: bool },
        GetRect,
        SetRect { rect: Win16HostRect },
        SetRectNoPaint { rect: Win16HostRect },
        Scroll { command: u16 },
        LineScroll { vertical: i16, horizontal: i16 },
        GetThumb,
        GetModify,
        SetModify { modified: bool },
        GetLineCount,
        LineIndex { line: i16 },
        LineLength { character: i16 },
        ReplaceSelection { text: Vec<u8> },
        SetFont { font: Option<Win16HostGdiObject>, redraw: bool },
        /// The guest capacity WORD is read from LPARAM before dispatch. Output
        /// starts at the same guest address and is not NUL-terminated.
        GetLine { line: u16, capacity: u16 },
        LimitText { maximum: u16 },
        CanUndo,
        Undo,
        FormatLines { add_eol: bool },
        LineFromCharacter { character: i16 },
        SetTabStops { positions: Vec<u16> },
        SetPasswordCharacter { character: u16 },
        EmptyUndoBuffer,
        GetFirstVisibleLine,
        SetReadOnly { read_only: bool },
        GetPasswordCharacter,
    }

    /// LISTBOX messages (`LB_*`). Strings and owner-draw item data share only
    /// the explicit `Win16HostControlItem` discriminant; item data is opaque.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Win16HostListBoxMessage {
        AddString { item: Win16HostControlItem },
        InsertString { index: i16, item: Win16HostControlItem },
        DeleteString { index: u16 },
        ResetContent,
        SetSelection { select: u16, index: i16 },
        SetCurrentSelection { index: i16 },
        GetSelection { index: u16 },
        GetCurrentSelection,
        GetText { index: u16, max_write_bytes: u32 },
        GetTextLength { index: u16 },
        GetCount,
        SelectString { start: i16, item: Win16HostControlItem },
        Directory { attributes: u16, filespec: Vec<u8> },
        GetTopIndex,
        FindString { start: i16, item: Win16HostControlItem },
        GetSelectionCount,
        GetSelectionItems { capacity: u16 },
        SetTabStops { positions: Vec<i16> },
        GetHorizontalExtent,
        SetHorizontalExtent { extent: u16 },
        SetColumnWidth { width: u16 },
        SetTopIndex { index: u16 },
        GetItemRect { index: u16 },
        GetItemData { index: u16 },
        SetItemData { index: u16, data: u32 },
        SelectItemRange { select: u16, first: u16, last: u16 },
        SetAnchorIndex { index: i16 },
        GetAnchorIndex,
        SetCaretIndex { index: u16, scroll: bool },
        GetCaretIndex,
        SetItemHeight { index: u16, height: u16 },
        GetItemHeight { index: u16 },
        FindStringExact { start: i16, item: Win16HostControlItem },
    }

    /// COMBOBOX messages (`CB_*`). Signed indices preserve -1 special cases.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Win16HostComboBoxMessage {
        GetEditSelection,
        LimitText { maximum: u16 },
        SetEditSelection { start: i16, end: i16 },
        AddString { item: Win16HostControlItem },
        DeleteString { index: u16 },
        Directory { attributes: u16, filespec: Vec<u8> },
        GetCount,
        GetCurrentSelection,
        GetText { index: u16, max_write_bytes: u32 },
        GetTextLength { index: u16 },
        InsertString { index: i16, item: Win16HostControlItem },
        ResetContent,
        FindString { start: i16, item: Win16HostControlItem },
        SelectString { start: i16, item: Win16HostControlItem },
        SetCurrentSelection { index: i16 },
        ShowDropdown { show: bool },
        GetItemData { index: u16 },
        SetItemData { index: u16, data: u32 },
        GetDroppedControlRect,
        SetItemHeight { index: i16, height: u16 },
        GetItemHeight { index: i16 },
        SetExtendedUi { extended: bool },
        GetExtendedUi,
        GetDroppedState,
        FindStringExact { start: i16, item: Win16HostControlItem },
    }

    /// STATIC icon messages. Resource-valued dialog-template initialization
    /// is not a message variant and must resolve in the guest module context.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Win16HostStaticMessage {
        GetIcon,
        SetIcon { icon: Option<Win16HostIcon> },
    }
}

pub use familytypes::{
    Win16HostButtonMessage, Win16HostComboBoxMessage, Win16HostEditMessage,
    Win16HostListBoxMessage, Win16HostStaticMessage,
};
