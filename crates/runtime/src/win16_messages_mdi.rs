//! Typed Win16 MDI message boundaries and checked MDICREATESTRUCT16 wire data.
//!
//! This module is a child of `win16_runtime`. It contains only owned values at
//! the runtime/host boundary; native HWND, HMENU, HINSTANCE and pointer values
//! are never represented as guest scalar bits here.

use guest_core::memory::Memory;
use win16_abi::strings::read_ansi_z;
use win16_abi::{MAX_WIN16_STRING_BYTES, Win16ClassName};
use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_output_with_selectors},
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16CreationId, Win16HostClass,
    Win16HostClassName, Win16HostMenu, Win16HostSystemClass, Win16HostWindow,
};

#[path = "win16_messages_mdi_creation.rs"]
mod creation;
#[path = "win16_messages_mdi_queue.rs"]
mod queue;
pub(super) use queue::{
    project_queued_mdi_message_with, validate_mdi_endpoint_maps, validate_mdi_queued_children_maps,
};

pub const WM_MDICREATE16: u16 = 0x0220;
pub const WM_MDIDESTROY16: u16 = 0x0221;
pub const WM_MDIACTIVATE16: u16 = 0x0222;
pub const WM_MDIRESTORE16: u16 = 0x0223;
pub const WM_MDINEXT16: u16 = 0x0224;
pub const WM_MDIMAXIMIZE16: u16 = 0x0225;
pub const WM_MDITILE16: u16 = 0x0226;
pub const WM_MDICASCADE16: u16 = 0x0227;
pub const WM_MDIICONARRANGE16: u16 = 0x0228;
pub const WM_MDIGETACTIVE16: u16 = 0x0229;
pub const WM_MDISETMENU16: u16 = 0x0230;
/// Win32 USER's private/public MDI refresh notification has no Win16 message
/// number. Host-to-guest projection represents it as WM_MDISETMENU(TRUE).
pub const WM_MDIREFRESHMENU32: u32 = 0x0234;

pub(super) const fn is_mdi_message(message: u16) -> bool {
    matches!(
        message,
        WM_MDICREATE16
            | WM_MDIDESTROY16
            | WM_MDIACTIVATE16
            | WM_MDIRESTORE16
            | WM_MDINEXT16
            | WM_MDIMAXIMIZE16
            | WM_MDITILE16
            | WM_MDICASCADE16
            | WM_MDIICONARRANGE16
            | WM_MDIGETACTIVE16
            | WM_MDISETMENU16
    )
}

pub(super) const MDICREATESTRUCT16_SIZE: usize = 26;
const MDICREATESTRUCT16_COPYBACK_OFFSET: u16 = 8;
const MDICREATESTRUCT16_COPYBACK_SIZE: usize = 18;

pub(super) fn encode_mdi_create_wire(
    data: &Win16HostMdiCreate,
    class_far: u32,
    title_far: u32,
) -> [u8; MDICREATESTRUCT16_SIZE] {
    let wire = MdiCreateStruct16Wire {
        class_far: U32::new(class_far),
        title_far: U32::new(title_far),
        owner_instance: U16::new(data.owner_instance),
        x: I16::new(data.x),
        y: I16::new(data.y),
        cx: I16::new(data.cx),
        cy: I16::new(data.cy),
        style: U32::new(data.style),
        parameter: U32::new(data.parameter),
    };
    zerocopy::transmute!(wire)
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(super) struct MdiCreateStruct16Wire {
    pub(super) class_far: U32,
    pub(super) title_far: U32,
    pub(super) owner_instance: U16,
    pub(super) x: I16,
    pub(super) y: I16,
    pub(super) cx: I16,
    pub(super) cy: I16,
    pub(super) style: U32,
    pub(super) parameter: U32,
}

const _: () = {
    assert!(core::mem::size_of::<MdiCreateStruct16Wire>() == MDICREATESTRUCT16_SIZE);
    assert!(core::mem::align_of::<MdiCreateStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, class_far) == 0);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, title_far) == 4);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, owner_instance) == 8);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, x) == 10);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, y) == 12);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, cx) == 14);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, cy) == 16);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, style) == 18);
    assert!(core::mem::offset_of!(MdiCreateStruct16Wire, parameter) == 22);
};

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct MdiCreateCopyback16Wire {
    owner_instance: U16,
    x: I16,
    y: I16,
    cx: I16,
    cy: I16,
    style: U32,
    parameter: U32,
}

const _: () = {
    assert!(core::mem::size_of::<MdiCreateCopyback16Wire>() == MDICREATESTRUCT16_COPYBACK_SIZE);
    assert!(core::mem::align_of::<MdiCreateCopyback16Wire>() == 1);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, owner_instance) == 0);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, x) == 2);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, y) == 4);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, cx) == 6);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, cy) == 8);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, style) == 10);
    assert!(core::mem::offset_of!(MdiCreateCopyback16Wire, parameter) == 14);
};

/// Which Win16 window receives an MDI message. The child form is needed for
/// the distinct WM_MDIACTIVATE packing used by child windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MdiEndpoint {
    Client,
    Child(Win16HostWindow),
}

/// All WM_MDICREATE input fields after guest pointers/strings were validated
/// and copied. `owner_instance` remains the original guest HINSTANCE16 token;
/// the host resolves the class token to its own native module instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMdiCreate {
    /// Exact runtime creation identity shared with the native pending claim
    /// and each reentrant child-creation callback.
    pub creation: Win16CreationId,
    pub class: Win16HostClass,
    pub guest_class_name: Win16HostClassName,
    pub owner_instance: u16,
    pub title: Option<Vec<u8>>,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
    pub style: u32,
    pub parameter: u32,
}

/// Host-owned semantic form of Win16 WM_*MDI* messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMdiMessage {
    /// Child and client WM_MDIACTIVATE use different Win16 parameter forms.
    ActivateClient {
        activating: Option<Win16HostWindow>,
    },
    ActivateChild {
        child: Win16HostWindow,
        active: bool,
        activating: Option<Win16HostWindow>,
        deactivating: Option<Win16HostWindow>,
    },
    Create(Win16HostMdiCreate),
    Destroy {
        child: Option<Win16HostWindow>,
    },
    Restore {
        child: Option<Win16HostWindow>,
    },
    Next {
        child: Option<Win16HostWindow>,
        previous: bool,
    },
    Maximize {
        child: Option<Win16HostWindow>,
    },
    Tile {
        flags: u16,
    },
    Cascade {
        flags: u16,
    },
    IconArrange,
    GetActive,
    SetMenu {
        refresh: bool,
        frame_menu: Option<Win16HostMenu>,
        window_menu: Option<Win16HostMenu>,
    },
}

impl Win16HostMdiMessage {
    /// Guest message number for default-procedure callback validation.
    pub const fn message_id(&self) -> u16 {
        match self {
            Self::ActivateClient { .. } | Self::ActivateChild { .. } => WM_MDIACTIVATE16,
            Self::Create(_) => WM_MDICREATE16,
            Self::Destroy { .. } => WM_MDIDESTROY16,
            Self::Restore { .. } => WM_MDIRESTORE16,
            Self::Next { .. } => WM_MDINEXT16,
            Self::Maximize { .. } => WM_MDIMAXIMIZE16,
            Self::Tile { .. } => WM_MDITILE16,
            Self::Cascade { .. } => WM_MDICASCADE16,
            Self::IconArrange => WM_MDIICONARRANGE16,
            Self::GetActive => WM_MDIGETACTIVE16,
            Self::SetMenu { .. } => WM_MDISETMENU16,
        }
    }

    /// Native id observed by a live host callback. Win16 refresh requests
    /// become the native WM_MDIREFRESHMENU message during DefFrameProc.
    pub const fn native_message_id(&self) -> u32 {
        match self {
            Self::SetMenu { refresh: true, .. } => WM_MDIREFRESHMENU32,
            _ => self.message_id() as u32,
        }
    }
}

/// Typed MDI result. HWND/HMENU outputs have already been interned as opaque
/// host identities by the USER worker; the native pointer-sized result is not
/// present in this structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMdiCreateFields {
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
    pub style: u32,
    pub parameter: u32,
}

/// Exact identity token of a native HWND incarnation the host confirmed
/// retired. Host window tokens come from a checked monotonic sequence and are
/// never reused, so the token remains exact even after USER reuses the HWND.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWindowRetirementReceipt {
    pub window: Win16HostWindow,
}

/// Exact windows and menus invalidated by one native dispatch/close operation.
/// The entire receipt set is checked before runtime aliases are retired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostWindowRetirementBatch {
    pub receipts: Vec<Win16HostWindowRetirementReceipt>,
    pub invalidated_menus: Vec<Win16HostMenu>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMdiOutput {
    None,
    Created {
        child: Option<Win16HostWindow>,
        fields: Win16HostMdiCreateFields,
    },
    Active {
        child: Option<Win16HostWindow>,
        maximized: bool,
    },
    Destroyed {
        /// Present only when the requested MDI child itself was proven dead.
        receipt: Option<Win16HostWindowRetirementReceipt>,
        /// Other exact window incarnations proven dead during the same native
        /// MDI teardown, including descendants without runtime parent edges.
        additional_retirements: Vec<Win16HostWindowRetirementReceipt>,
        /// Guest HMENU aliases for menu tokens proven invalidated by USER.
        invalidated_menus: Vec<Win16HostMenu>,
    },
    ReplacedFrameMenu(Option<Win16HostMenu>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMdiMessageResult {
    /// Used only for scalar MDI message results. Created/destroyed HWNDs,
    /// active HWND, and replaced HMENU results are represented in `output`.
    pub value: u32,
    pub output: Win16HostMdiOutput,
}

/// An owned MDI message projected from a native queue/callback. The host has
/// converted native HWND/HMENU values to opaque identities before constructing
/// this type. WM_MDICREATE is deliberately not representable here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMdiQueuedMessage {
    pub endpoint: Win16MdiEndpoint,
    pub message: Win16HostMdiMessageQueuedKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMdiMessageQueuedKind {
    ActivateClient {
        activating: Option<Win16HostWindow>,
    },
    ActivateChild {
        activating: Option<Win16HostWindow>,
        deactivating: Option<Win16HostWindow>,
    },
    Destroy {
        child: Option<Win16HostWindow>,
    },
    Restore {
        child: Option<Win16HostWindow>,
    },
    Next {
        child: Option<Win16HostWindow>,
        previous: bool,
    },
    Maximize {
        child: Option<Win16HostWindow>,
    },
    Tile {
        flags: u16,
    },
    Cascade {
        flags: u16,
    },
    IconArrange,
    GetActive,
    SetMenu {
        refresh: bool,
        frame_menu: Option<Win16HostMenu>,
        window_menu: Option<Win16HostMenu>,
    },
}

impl Win16HostMdiQueuedMessage {
    /// Native message id that entered the callback/queue boundary. The
    /// Win32 MDI refresh notification projects to Win16 WM_MDISETMENU.
    pub const fn native_message_id(self) -> u32 {
        match self.message {
            Win16HostMdiMessageQueuedKind::ActivateClient { .. }
            | Win16HostMdiMessageQueuedKind::ActivateChild { .. } => WM_MDIACTIVATE16 as u32,
            Win16HostMdiMessageQueuedKind::Destroy { .. } => WM_MDIDESTROY16 as u32,
            Win16HostMdiMessageQueuedKind::Restore { .. } => WM_MDIRESTORE16 as u32,
            Win16HostMdiMessageQueuedKind::Next { .. } => WM_MDINEXT16 as u32,
            Win16HostMdiMessageQueuedKind::Maximize { .. } => WM_MDIMAXIMIZE16 as u32,
            Win16HostMdiMessageQueuedKind::Tile { .. } => WM_MDITILE16 as u32,
            Win16HostMdiMessageQueuedKind::Cascade { .. } => WM_MDICASCADE16 as u32,
            Win16HostMdiMessageQueuedKind::IconArrange => WM_MDIICONARRANGE16 as u32,
            Win16HostMdiMessageQueuedKind::GetActive => WM_MDIGETACTIVE16 as u32,
            Win16HostMdiMessageQueuedKind::SetMenu { refresh: true, .. } => WM_MDIREFRESHMENU32,
            Win16HostMdiMessageQueuedKind::SetMenu { refresh: false, .. } => WM_MDISETMENU16 as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16GuestMdiMessage {
    pub message: u16,
    pub w_param: u16,
    pub l_param: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MdiChildRetirementPlan {
    pub(super) guest: u16,
    pub(super) native: Win16HostWindow,
    pub(super) creation: Win16CreationId,
}

#[derive(Clone)]
pub(super) enum MdiOutputPlan {
    Create(MdiCreateOutputPlan),
    Destroy(MdiChildRetirementPlan),
}

/// Holds the output capability across host work/reentrant guest callbacks.
/// The captured range pins the exact selector generation and is revalidated
/// by `commit_guest_output_with_selectors` immediately before copyback.
#[derive(Clone)]
pub(super) struct MdiCreateOutputPlan {
    pub(super) range: GuestOutputRange,
    pub(super) owner_instance: u16,
    pub(super) creation: Win16CreationId,
    pub(super) mdi: Win16HostMdiCreate,
    pub(super) child_procedure: u32,
    pub(super) child_instance: u16,
    pub(super) system_kind: Option<Win16HostSystemClass>,
    pub(super) mdi_client_guest: u16,
    pub(super) mdi_client_native: Win16HostWindow,
}

impl MdiCreateOutputPlan {
    pub(super) fn commit(
        &self,
        state: &Win16State,
        memory: &mut Memory,
        fields: Win16HostMdiCreateFields,
    ) -> Result<(), RuntimeError> {
        self.commit_with_selectors(&state.selectors, memory, fields)
    }

    pub(super) fn commit_with_selectors(
        &self,
        selectors: &win16_abi::SelectorTable,
        memory: &mut Memory,
        fields: Win16HostMdiCreateFields,
    ) -> Result<(), RuntimeError> {
        let wire = MdiCreateCopyback16Wire {
            owner_instance: U16::new(self.owner_instance),
            x: I16::new(fields.x),
            y: I16::new(fields.y),
            cx: I16::new(fields.cx),
            cy: I16::new(fields.cy),
            style: U32::new(fields.style),
            parameter: U32::new(fields.parameter),
        };
        let bytes: [u8; MDICREATESTRUCT16_COPYBACK_SIZE] = zerocopy::transmute!(wire);
        commit_guest_output_with_selectors(selectors, memory, &self.range, &bytes)
    }

}

pub(super) struct PreparedMdiMessage {
    pub(super) message: Win16HostMdiMessage,
    pub(super) output: Option<MdiOutputPlan>,
}

impl Win16State {
    /// Convert a guest MDI message into a fully owned host request. `endpoint`
    /// tells the translator whether WM_MDIACTIVATE has client or child layout.
    /// An unmapped HWND/HMENU, malformed FAR string, invalid class owner, or
    /// unreadable MDICREATESTRUCT rejects the message before any host call.
    pub(super) fn prepare_mdi_message(
        &mut self,
        endpoint: Win16MdiEndpoint,
        mdi_client: Option<(u16, Win16HostWindow)>,
        message: u16,
        w_param: u16,
        l_param: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<PreparedMdiMessage>, RuntimeError> {
        let map_child = |state: &Self, guest: u16| -> Option<Option<Win16HostWindow>> {
            if guest == 0 {
                Some(None)
            } else {
                let native = *state.window_handles.get(&guest)?;
                (state.mdi_children.contains(&guest)
                    && state.mdi_endpoint_for_guest_window(guest)
                        == Some(Win16MdiEndpoint::Child(native)))
                .then_some(Some(native))
            }
        };
        let no_output = |message| {
            Some(PreparedMdiMessage {
                message,
                output: None,
            })
        };

        if message != WM_MDIACTIVATE16 && !matches!(endpoint, Win16MdiEndpoint::Client) {
            return Ok(None);
        }

        let prepared = match message {
            WM_MDIACTIVATE16 => match endpoint {
                Win16MdiEndpoint::Client => {
                    let Some(activating) = map_child(self, w_param) else {
                        return Ok(None);
                    };
                    no_output(Win16HostMdiMessage::ActivateClient { activating })
                }
                Win16MdiEndpoint::Child(child) => {
                    let Some(activating) = map_child(self, l_param as u16) else {
                        return Ok(None);
                    };
                    let Some(deactivating) = map_child(self, (l_param >> 16) as u16) else {
                        return Ok(None);
                    };
                    let active = w_param != 0;
                    let expected = if active { activating } else { deactivating };
                    if expected != Some(child) {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            "Win16 WM_MDIACTIVATE BOOL disagrees with its activated/deactivated child HWNDs"));
                        return Ok(None);
                    }
                    no_output(Win16HostMdiMessage::ActivateChild {
                        child,
                        active,
                        activating,
                        deactivating,
                    })
                }
            },
            WM_MDICREATE16 => {
                if w_param != 0 || l_param == 0 {
                    return Ok(None);
                }
                let Some((mdi_client_guest, mdi_client_native)) = mdi_client else {
                    return Ok(None);
                };
                if self.window_handles.get(&mdi_client_guest) != Some(&mdi_client_native)
                    || self.window_system_classes.get(&mdi_client_guest)
                        != Some(&Win16HostSystemClass::MdiClient)
                {
                    return Ok(None);
                }
                let pointer = self
                    .selectors
                    .pointer_from_far(l_param)
                    .map_err(crate::runtime_error)?;
                let mut bytes = [0_u8; MDICREATESTRUCT16_SIZE];
                self.selectors
                    .read(memory, pointer, &mut bytes)
                    .map_err(crate::runtime_error)?;
                let wire = MdiCreateStruct16Wire::read_from_bytes(&bytes).map_err(|_| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "checked MDICREATESTRUCT16 bytes failed their fixed wire decoder",
                    )
                })?;
                let class_pointer = wire.class_far.get();
                let class_name = if (class_pointer >> 16) == 0 {
                    let atom = class_pointer as u16;
                    if atom == 0 {
                        return Ok(None);
                    }
                    Win16ClassName::Atom(atom)
                } else {
                    Win16ClassName::Name(
                        read_ansi_z(
                            &self.selectors,
                            memory,
                            class_pointer,
                            MAX_WIN16_STRING_BYTES,
                        )
                        .map_err(crate::runtime_error)?,
                    )
                };
                let owner_instance = wire.owner_instance.get();
                if self.module_handle_for_instance(owner_instance).is_none() {
                    return Ok(None);
                }
                let Some(class) =
                    self.resolve_window_class_for_create(owner_instance, &class_name, host)?
                else {
                    return Ok(None);
                };
                let title_far = wire.title_far.get();
                let title = if title_far == 0 {
                    None
                } else {
                    Some(
                        read_ansi_z(&self.selectors, memory, title_far, MAX_WIN16_STRING_BYTES)
                            .map_err(crate::runtime_error)?,
                    )
                };
                // NTVDM copies back the tail beginning at hOwner. Keep hOwner
                // as the exact original guest token; the native HINSTANCE is
                // available only from the resolved host class identity.
                let output_pointer = self
                    .selectors
                    .add_bytes(pointer, u32::from(MDICREATESTRUCT16_COPYBACK_OFFSET))
                    .map_err(crate::runtime_error)?;
                let output_range = GuestOutputRange::capture(
                    self,
                    memory,
                    output_pointer,
                    MDICREATESTRUCT16_COPYBACK_SIZE,
                )?;
                let creation = self.allocate_window_creation_identity()?;
                let mdi = Win16HostMdiCreate {
                    creation,
                    class: class.host_class,
                    guest_class_name: match class_name {
                        Win16ClassName::Atom(atom) => Win16HostClassName::Atom(atom),
                        Win16ClassName::Name(bytes) => Win16HostClassName::Name(bytes),
                    },
                    owner_instance,
                    title,
                    x: wire.x.get(),
                    y: wire.y.get(),
                    cx: wire.cx.get(),
                    cy: wire.cy.get(),
                    style: wire.style.get(),
                    parameter: wire.parameter.get(),
                };
                Some(PreparedMdiMessage {
                    message: Win16HostMdiMessage::Create(mdi.clone()),
                    output: Some(MdiOutputPlan::Create(MdiCreateOutputPlan {
                        range: output_range,
                        owner_instance,
                        creation,
                        mdi,
                        child_procedure: class.wnd_proc,
                        child_instance: class.instance,
                        system_kind: class.system_kind,
                        mdi_client_guest,
                        mdi_client_native,
                    })),
                })
            }
            WM_MDIDESTROY16 => {
                let Some(child) = map_child(self, w_param) else {
                    return Ok(None);
                };
                let Some(native) = child else {
                    return Ok(None);
                };
                let Some(creation) = self.window_creations.get(&w_param).copied() else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "live Win16 MDI child has no exact creation generation",
                    ));
                };
                Some(PreparedMdiMessage {
                    message: Win16HostMdiMessage::Destroy { child },
                    output: Some(MdiOutputPlan::Destroy(MdiChildRetirementPlan {
                        guest: w_param,
                        native,
                        creation,
                    })),
                })
            }
            WM_MDIRESTORE16 => {
                let Some(child) = map_child(self, w_param) else {
                    return Ok(None);
                };
                no_output(Win16HostMdiMessage::Restore { child })
            }
            WM_MDINEXT16 => {
                let Some(child) = map_child(self, w_param) else {
                    return Ok(None);
                };
                no_output(Win16HostMdiMessage::Next {
                    child,
                    previous: l_param != 0,
                })
            }
            WM_MDIMAXIMIZE16 => {
                let Some(child) = map_child(self, w_param) else {
                    return Ok(None);
                };
                no_output(Win16HostMdiMessage::Maximize { child })
            }
            WM_MDITILE16 => no_output(Win16HostMdiMessage::Tile { flags: w_param }),
            WM_MDICASCADE16 => no_output(Win16HostMdiMessage::Cascade { flags: w_param }),
            WM_MDIICONARRANGE16 => no_output(Win16HostMdiMessage::IconArrange),
            WM_MDIGETACTIVE16 => no_output(Win16HostMdiMessage::GetActive),
            WM_MDISETMENU16 => {
                if w_param != 0 {
                    no_output(Win16HostMdiMessage::SetMenu {
                        refresh: true,
                        frame_menu: None,
                        window_menu: None,
                    })
                } else {
                    let frame = l_param as u16;
                    let window_menu = (l_param >> 16) as u16;
                    let frame_menu = if frame == 0 {
                        Some(None)
                    } else {
                        self.guest_menus.resolve(frame).map(Some)
                    };
                    let window_menu = if window_menu == 0 {
                        Some(None)
                    } else {
                        self.guest_menus.resolve(window_menu).map(Some)
                    };
                    let (Some(frame_menu), Some(window_menu)) = (frame_menu, window_menu) else {
                        return Ok(None);
                    };
                    no_output(Win16HostMdiMessage::SetMenu {
                        refresh: false,
                        frame_menu,
                        window_menu,
                    })
                }
            }
            _ => return Ok(None),
        };
        Ok(prepared)
    }
}
