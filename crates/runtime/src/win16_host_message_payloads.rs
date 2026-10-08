//! Owned USER message payloads and results.

use super::{
    Win16GuestNotification, Win16HostClassName, Win16HostMinMaxInfo, Win16HostQueuedMessage,
    Win16ScalarMessage,
};
use crate::{Win16HostClass, Win16HostDc, Win16HostMenu, Win16HostWindow};

#[derive(Clone, Debug)]
pub struct Win16HostCreationData {
    pub class: Win16HostClass,
    pub guest_instance: u16,
    pub guest_class_name: Win16HostClassName,
    /// Original guest HMENU word (for child windows this is the control ID).
    pub guest_menu: u16,
    /// Copied default class RT_MENU for a top-level window whose caller did
    /// not supply an HMENU. The native window owner materializes and retires
    /// this menu with the actual HWND lifetime.
    pub class_menu_template: Option<crate::Win16MenuTemplate>,
    /// CreateWindow's guest lpParam. Dialog items instead use copied creation_data.
    pub create_parameter: u32,
    /// Win16 DLGITEMTEMPLATE bytes copied into a checked temporary guest block.
    pub creation_data: Option<Vec<u8>>,
    /// Checked CLIENTCREATESTRUCT16 fields for an exact MDIClient alias.
    pub mdi_client: Option<crate::Win16HostMdiClientCreate>,
    /// True only for the root HWND created by a custom dialog class.
    pub dialog_root: bool,
    /// Top-level window HMENU. Child controls use `child_id` instead.
    pub menu: Option<Win16HostMenu>,
    pub title: Option<Vec<u8>>,
    pub style: u32,
    pub ex_style: u32,
    pub x: i16,
    pub y: i16,
    pub width: i16,
    pub height: i16,
    pub parent: Option<Win16HostWindow>,
    pub child_id: Option<u16>,
}

/// Owned CREATESTRUCT16 and nested MDICREATESTRUCT16 inputs for a child
/// created by the native MDI client while a Win16 WM_MDICREATE is suspended.
#[derive(Clone, Debug)]
pub struct Win16HostMdiChildCreation {
    pub creation: Win16HostCreationData,
    pub mdi: crate::Win16HostMdiCreate,
}

/// Default processing receives only the fields used by USER. Application
/// creation data remains in the guest CREATESTRUCT for the guest WndProc.
#[derive(Clone, Debug)]
pub enum Win16HostMessage {
    /// Synchronous standard-control request, decoded using its checked family.
    Control(crate::Win16HostControlCall),
    OwnerDraw(crate::Win16OwnerDrawMessage),
    FindReplaceNotification(crate::Win16HostFindReplaceNotification),
    /// A verified native MakeDragList continuation copied out of the live
    /// child-subclass frame; its native DRAGLISTINFO pointer never crosses.
    DragListNotification(crate::Win16HostDragListNotification),
    /// Copied native HDROP contents in guest ANSI bytes. The native HDROP is
    /// finished by the host before this owned value crosses the boundary.
    DropFiles(crate::Win16HostDropFiles),
    /// A direct WndProc/DLGPROC delivery claimed the same exact native queue
    /// lease previously exposed by PeekMessage. Runtime reuses its HGLOBAL16
    /// generation and retires the native-pending pin exactly once.
    QueuedDropFiles(crate::Win16HostQueuedDropFiles),
    WindowInput(crate::Win16WindowInputMessage),
    ActivationApp(crate::Win16HostActivationApp),
    ParentNotification(crate::Win16HostParentNotification),
    ControlColor(crate::Win16HostControlColor),
    Scalar {
        kind: Win16ScalarMessage,
        w_param: u16,
        l_param: u32,
    },
    /// A Win16 MMSYSTEM MM_* notification outside an owned asynchronous
    /// receipt. This remains separate from the general scalar whitelist so
    /// its exact message range and FAR-bearing members can be handled safely.
    MultimediaNotification {
        message: u16,
        w_param: u16,
        l_param: u32,
    },
    /// WM_COMMAND's native control handle is carried as an opaque window
    /// identity. Guest WndProc packing is performed only after runtime lookup.
    Command {
        id: u16,
        notify: u16,
        control: Option<Win16HostWindow>,
        control_parent: Option<Win16HostWindow>,
    },
    ClipboardChainChange {
        removed: Option<Win16HostWindow>,
        next: Option<Win16HostWindow>,
    },
    /// WM_ERASEBKGND's HDC is an opaque token with a callback-scoped lease.
    EraseBackground {
        dc: Option<Win16HostDc>,
    },
    /// Win16 WM_PAINT permits a supplied HDC. It is a guest handle, never
    /// a scalar value suitable for passing directly to the native WNDPROC.
    Paint {
        dc: Option<Win16HostDc>,
    },
    /// User-range application messages are passed only to an explicitly
    /// registered guest window procedure; LPARAM contains guest 32-bit bits,
    /// never a host pointer.
    GuestOpaque {
        message: u16,
        w_param: u16,
        l_param: u32,
    },
    /// A private host sidecar carried an owned Win16 notification. It is
    /// checked before any native pointer-message classification.
    GuestNotification(Win16GuestNotification),
    Creation {
        non_client: bool,
        data: Win16HostCreationData,
    },
    /// A native DefFrameProc/MDI-client operation is synchronously creating a
    /// guest MDI child; `mdi.creation` binds this callback to that exact call.
    MdiChildCreation {
        non_client: bool,
        data: Win16HostMdiChildCreation,
    },
    /// A typed, copied Win16 MDI queue/callback message. Native HWND/HMENU
    /// identities remain opaque until the runtime validates and projects it.
    MdiQueued(crate::Win16HostMdiQueuedMessage),
    /// Synchronous Win16 WM_*MDI* default-procedure request.
    Mdi(crate::Win16HostMdiMessage),
    SetText(Option<Vec<u8>>),
    /// LPARAM nullness is observable to a Win16 window procedure even when
    /// the character capacity is zero; only the nullness crosses this boundary.
    GetText {
        capacity: u16,
        buffer_is_null: bool,
    },
    GetTextLength,
    /// HFONT16 is resolved by the runtime; only an opaque GDI identity crosses.
    SetFont {
        font: Option<crate::Win16HostGdiObject>,
        redraw: bool,
    },
    MinMaxInfo(Win16HostMinMaxInfo),
    /// w_param retains the guest BOOL16; the data shape must agree with zero
    /// versus nonzero. The nested position contains values, never a pointer.
    NonClientCalcSize {
        w_param: u16,
        data: crate::Win16HostNonClientCalcSize,
    },
    /// Windows 3.1 Programmer's Reference, volume 3, WM_NCPAINT (page 179):
    /// this notification has no parameters. Win32's update HRGN stays in its
    /// exact suspended native callback; it is not a Win16 GDI handle.
    NonClientPaint,
    /// WM_WINDOWPOSCHANGING permits structure output; WM_WINDOWPOSCHANGED
    /// is an input-only notification. Receiving-window identity is separate
    /// from the WINDOWPOS target field, which an application may change.
    WindowPosition {
        changing: bool,
        w_param: u16,
        data: crate::Win16HostWindowPos,
    },
    /// Win16 dialog initialization data for a private class WndProc. Focus is
    /// an opaque identity; the 32-bit init value remains guest data.
    InitDialog {
        focus: Option<Win16HostWindow>,
        focus_ancestry: Vec<(Win16HostWindow, Win16HostWindow)>,
        init_parameter: u32,
    },
    /// SDK 3.0 leaves both parameters unused. Native MSG arguments stay in
    /// the exact suspended callback and are never projected into the guest ABI.
    GetDlgCode,
}

/// Copied message inputs for a Win16 DLGPROC. Dialog callbacks are separate
/// from ordinary WndProc callbacks because WM_INITDIALOG has an HWND-valued
/// focus argument and WM_GETDLGCODE's native MSG pointer must be copied into
/// an owned Win16-compatible record before crossing the boundary.
#[derive(Clone, Debug)]
pub enum Win16HostDialogMessage {
    Init {
        focus: Option<Win16HostWindow>,
        /// Actual child/parent edges from the focus window to this dialog.
        /// Empty when native ancestry could not be established.
        focus_ancestry: Vec<(Win16HostWindow, Win16HostWindow)>,
        init_parameter: u32,
    },
    Message(Win16HostMessage),
    GetDlgCode {
        virtual_key: u16,
        message: Option<Win16HostQueuedMessage>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMessageOutput {
    Control(crate::Win16HostControlOutput),
    OwnerDrawMeasure {
        width: u16,
        height: u16,
    },
    FindReplace {
        request_id: u64,
        update: Option<crate::Win16HostFindReplaceUpdate>,
    },
    /// No bytes to copy. WndProc WM_GETTEXT uses this for return 0 with no
    /// supplied text or the documented CB_ERR; a DLGPROC may also be unhandled.
    None,
    /// Text includes its final NUL byte, or is empty for zero capacity.
    Text(Vec<u8>),
    MinMaxInfo(Win16HostMinMaxInfo),
    NonClientCalcSize(crate::Win16HostNonClientCalcSize),
    WindowPosition(crate::Win16HostWindowPos),
    /// Typed MDI results keep returned HWND/HMENU identities opaque.
    Mdi(crate::Win16HostMdiOutput),
    /// A Win16 HBRUSH result after guest-side handle classification. Native
    /// resolution still occurs in the host owner that owns the GDI table.
    ControlColor(crate::Win16HostControlColorBrush),
    /// Native USER retired exact HWND incarnations and menus while processing
    /// a message such as WM_CLOSE. Runtime validates the complete receipt set
    /// before retiring guest aliases and invalidating menu aliases.
    WindowRetirements(crate::Win16HostWindowRetirementBatch),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMessageResult {
    pub value: u32,
    pub output: Win16HostMessageOutput,
    /// DLGPROC's DWL_MSGRESULT is independent of its BOOL16 return in `value`.
    /// Ordinary WndProc/TIMERPROC replies do not carry dialog extra storage.
    pub dialog_result: Option<u32>,
}

/// Static-control icon messages, independent of guest/native message numbers.
#[derive(Clone, Copy, Debug)]
pub enum Win16HostStaticIconOperation {
    Get,
    Set { icon: Option<crate::Win16HostIcon> },
}

#[derive(Debug)]
pub enum Win16HostStaticIconResult {
    Icon(Option<crate::Win16HostIcon>),
    /// The target is a different native control family. No message was sent.
    Untranslated,
}
