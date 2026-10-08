//! Checked MDI endpoint validation and queue-message projection.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(in crate::win16_runtime) fn validate_mdi_endpoint_maps(
    guest_receiver: u16,
    native_receiver: Win16HostWindow,
    endpoint: Win16MdiEndpoint,
    window_handles: &BTreeMap<u16, Win16HostWindow>,
    window_parents: &BTreeMap<u16, u16>,
    window_system_classes: &BTreeMap<u16, Win16HostSystemClass>,
    mdi_children: &BTreeSet<u16>,
) -> Result<(), RuntimeError> {
    let valid = window_handles.get(&guest_receiver) == Some(&native_receiver)
        && match endpoint {
            Win16MdiEndpoint::Client => {
                window_system_classes.get(&guest_receiver) == Some(&Win16HostSystemClass::MdiClient)
            }
            Win16MdiEndpoint::Child(child) => {
                child == native_receiver
                    && is_claimed_mdi_child(
                        guest_receiver,
                        window_handles,
                        window_parents,
                        window_system_classes,
                        mdi_children,
                    )
            }
        };
    if !valid {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "typed MDI message endpoint is not a live MdiClient or claimed MDI child",
        ));
    }
    Ok(())
}

pub(in crate::win16_runtime) fn validate_mdi_queued_children_maps(
    queued: Win16HostMdiQueuedMessage,
    window_handles: &BTreeMap<u16, Win16HostWindow>,
    window_parents: &BTreeMap<u16, u16>,
    window_system_classes: &BTreeMap<u16, Win16HostSystemClass>,
    mdi_children: &BTreeSet<u16>,
) -> Result<(), RuntimeError> {
    let is_child = |native: Win16HostWindow| {
        window_handles.iter().any(|(guest, existing)| {
            *existing == native
                && is_claimed_mdi_child(
                    *guest,
                    window_handles,
                    window_parents,
                    window_system_classes,
                    mdi_children,
                )
        })
    };
    let child_is_live =
        |child: Option<Win16HostWindow>| child.is_none_or(|native| is_child(native));
    let endpoint_is_live = match queued.endpoint {
        Win16MdiEndpoint::Client => true,
        Win16MdiEndpoint::Child(child) => is_child(child),
    };
    let fields_are_live = match queued.message {
        Win16HostMdiMessageQueuedKind::ActivateClient { activating } => child_is_live(activating),
        Win16HostMdiMessageQueuedKind::ActivateChild {
            activating,
            deactivating,
        } => child_is_live(activating) && child_is_live(deactivating),
        Win16HostMdiMessageQueuedKind::Destroy { child }
        | Win16HostMdiMessageQueuedKind::Restore { child }
        | Win16HostMdiMessageQueuedKind::Next { child, .. }
        | Win16HostMdiMessageQueuedKind::Maximize { child } => child_is_live(child),
        Win16HostMdiMessageQueuedKind::Tile { .. }
        | Win16HostMdiMessageQueuedKind::Cascade { .. }
        | Win16HostMdiMessageQueuedKind::IconArrange
        | Win16HostMdiMessageQueuedKind::GetActive
        | Win16HostMdiMessageQueuedKind::SetMenu { .. } => true,
    };
    if !endpoint_is_live || !fields_are_live {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "typed MDI queue item names a window outside the exact MDI child set",
        ));
    }
    Ok(())
}

fn is_claimed_mdi_child(
    guest: u16,
    window_handles: &BTreeMap<u16, Win16HostWindow>,
    window_parents: &BTreeMap<u16, u16>,
    window_system_classes: &BTreeMap<u16, Win16HostSystemClass>,
    mdi_children: &BTreeSet<u16>,
) -> bool {
    if !mdi_children.contains(&guest) || !window_handles.contains_key(&guest) {
        return false;
    }
    window_parents.get(&guest).is_some_and(|parent| {
        window_system_classes.get(parent) == Some(&Win16HostSystemClass::MdiClient)
    })
}

impl Win16State {
    /// Resolve a receiving guest HWND only from the runtime's live identity
    /// tables. A normal child of an MDIClient is not an MDI child unless an
    /// exact MDI creation callback claimed it.
    pub(in crate::win16_runtime) fn mdi_endpoint_for_guest_window(
        &self,
        guest_window: u16,
    ) -> Option<Win16MdiEndpoint> {
        let native = *self.window_handles.get(&guest_window)?;
        if self.window_system_classes.get(&guest_window) == Some(&Win16HostSystemClass::MdiClient) {
            return Some(Win16MdiEndpoint::Client);
        }
        let parent = self.window_parents.get(&guest_window).copied()?;
        (self.mdi_children.contains(&guest_window)
            && self.window_creations.contains_key(&guest_window)
            && self.window_system_classes.get(&parent) == Some(&Win16HostSystemClass::MdiClient))
        .then_some(Win16MdiEndpoint::Child(native))
    }

    pub(in crate::win16_runtime) fn validate_mdi_endpoint(
        &self,
        guest_receiver: u16,
        native_receiver: Win16HostWindow,
        endpoint: Win16MdiEndpoint,
    ) -> Result<(), RuntimeError> {
        validate_mdi_endpoint_maps(
            guest_receiver,
            native_receiver,
            endpoint,
            &self.window_handles,
            &self.window_parents,
            &self.window_system_classes,
            &self.mdi_children,
        )
    }

    pub(in crate::win16_runtime) fn existing_mdi_child_guest_handle(
        &self,
        native: Win16HostWindow,
    ) -> Option<u16> {
        self.window_handles.iter().find_map(|(guest, existing)| {
            (*existing == native
                && self.mdi_children.contains(guest)
                && self.window_creations.contains_key(guest)
                && self.mdi_endpoint_for_guest_window(*guest)
                    == Some(Win16MdiEndpoint::Child(native)))
            .then_some(*guest)
        })
    }

    fn validate_queued_mdi_children(
        &self,
        queued: Win16HostMdiQueuedMessage,
    ) -> Result<(), RuntimeError> {
        validate_mdi_queued_children_maps(
            queued,
            &self.window_handles,
            &self.window_parents,
            &self.window_system_classes,
            &self.mdi_children,
        )
    }

    /// Convert a typed native MDI queue item to Win16's numeric MSG fields.
    /// Only pre-mapped identities may be named; no native handle bits are
    /// fabricated into guest handles. WM_MDICREATE has no queue projection.
    pub(in crate::win16_runtime) fn project_queued_mdi_message(
        &mut self,
        queued: Win16HostMdiQueuedMessage,
    ) -> Result<Win16GuestMdiMessage, RuntimeError> {
        self.validate_queued_mdi_children(queued)?;
        let Self {
            window_handles,
            owned_window_handles,
            next_window_handle,
            guest_menus,
            ..
        } = self;
        let mut map_window = |native| {
            map_mdi_window_handle(
                window_handles,
                owned_window_handles,
                next_window_handle,
                native,
            )
        };
        let mut map_menu = |native| {
            guest_menus.intern(native).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 guest HMENU namespace is full for a queued MDI message",
                )
            })
        };
        project_queued_mdi_message_with(queued, &mut map_window, &mut map_menu)
    }

    /// Guest message fields can be changed between GetMessage and
    /// DispatchMessage. This decoder accepts only registered MDIClient
    /// windows or HWNDs explicitly claimed by a live MDI create callback.
    pub(in crate::win16_runtime) fn prepare_guest_dispatch_mdi_message(
        &self,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    ) -> Result<Option<Win16HostMdiQueuedMessage>, RuntimeError> {
        if !is_mdi_message(message) || message == WM_MDICREATE16 {
            return Ok(None);
        }
        let Some(endpoint) = self.mdi_endpoint_for_guest_window(window) else {
            return Ok(None);
        };
        let map_guest_child = |guest: u16| -> Option<Option<Win16HostWindow>> {
            if guest == 0 {
                return Some(None);
            }
            let native = *self.window_handles.get(&guest)?;
            (self.mdi_endpoint_for_guest_window(guest) == Some(Win16MdiEndpoint::Child(native)))
                .then_some(Some(native))
        };
        let kind = match (endpoint, message) {
            (Win16MdiEndpoint::Client, WM_MDIACTIVATE16) => {
                if l_param != 0 {
                    return Ok(None);
                }
                let Some(activating) = map_guest_child(w_param) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::ActivateClient { activating }
            }
            (Win16MdiEndpoint::Child(child), WM_MDIACTIVATE16) => {
                let activating_guest = l_param as u16;
                let deactivating_guest = (l_param >> 16) as u16;
                let Some(activating) = map_guest_child(activating_guest) else {
                    return Ok(None);
                };
                let Some(deactivating) = map_guest_child(deactivating_guest) else {
                    return Ok(None);
                };
                if activating != Some(child) && deactivating != Some(child) {
                    return Ok(None);
                }
                if (w_param != 0) != (activating == Some(child)) {
                    return Ok(None);
                }
                Win16HostMdiMessageQueuedKind::ActivateChild {
                    activating,
                    deactivating,
                }
            }
            (Win16MdiEndpoint::Client, WM_MDIDESTROY16) => {
                let Some(child) = map_guest_child(w_param) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::Destroy { child }
            }
            (Win16MdiEndpoint::Client, WM_MDIRESTORE16) => {
                let Some(child) = map_guest_child(w_param) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::Restore { child }
            }
            (Win16MdiEndpoint::Client, WM_MDINEXT16) => {
                let Some(child) = map_guest_child(w_param) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::Next {
                    child,
                    previous: l_param != 0,
                }
            }
            (Win16MdiEndpoint::Client, WM_MDIMAXIMIZE16) => {
                let Some(child) = map_guest_child(w_param) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::Maximize { child }
            }
            (Win16MdiEndpoint::Client, WM_MDITILE16) => {
                Win16HostMdiMessageQueuedKind::Tile { flags: w_param }
            }
            (Win16MdiEndpoint::Client, WM_MDICASCADE16) => {
                Win16HostMdiMessageQueuedKind::Cascade { flags: w_param }
            }
            (Win16MdiEndpoint::Client, WM_MDIICONARRANGE16) => {
                Win16HostMdiMessageQueuedKind::IconArrange
            }
            (Win16MdiEndpoint::Client, WM_MDIGETACTIVE16) => {
                Win16HostMdiMessageQueuedKind::GetActive
            }
            (Win16MdiEndpoint::Client, WM_MDISETMENU16) if w_param != 0 => {
                Win16HostMdiMessageQueuedKind::SetMenu {
                    refresh: true,
                    frame_menu: None,
                    window_menu: None,
                }
            }
            (Win16MdiEndpoint::Client, WM_MDISETMENU16) => {
                let frame_guest = l_param as u16;
                let window_guest = (l_param >> 16) as u16;
                let frame_menu = if frame_guest == 0 {
                    Some(None)
                } else {
                    self.guest_menus.resolve(frame_guest).map(Some)
                };
                let window_menu = if window_guest == 0 {
                    Some(None)
                } else {
                    self.guest_menus.resolve(window_guest).map(Some)
                };
                let (Some(frame_menu), Some(window_menu)) = (frame_menu, window_menu) else {
                    return Ok(None);
                };
                Win16HostMdiMessageQueuedKind::SetMenu {
                    refresh: false,
                    frame_menu,
                    window_menu,
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(Win16HostMdiQueuedMessage {
            endpoint,
            message: kind,
        }))
    }
}

pub(in crate::win16_runtime) fn project_queued_mdi_message_with(
    queued: Win16HostMdiQueuedMessage,
    map_window: &mut impl FnMut(Win16HostWindow) -> Result<u16, RuntimeError>,
    map_menu: &mut impl FnMut(Win16HostMenu) -> Result<u16, RuntimeError>,
) -> Result<Win16GuestMdiMessage, RuntimeError> {
    let (message, w_param, l_param) = match queued.message {
        Win16HostMdiMessageQueuedKind::ActivateClient { activating } => (
            WM_MDIACTIVATE16,
            map_optional_window(activating, map_window)?,
            0,
        ),
        Win16HostMdiMessageQueuedKind::ActivateChild {
            activating,
            deactivating,
        } => {
            let child = match queued.endpoint {
                Win16MdiEndpoint::Child(child) => child,
                Win16MdiEndpoint::Client => {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "queued child WM_MDIACTIVATE has a client endpoint",
                    ));
                }
            };
            if activating != Some(child) && deactivating != Some(child) {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "queued WM_MDIACTIVATE names neither the activated nor deactivated child",
                ));
            }
            let active = activating == Some(child);
            let activating = map_optional_window(activating, map_window)?;
            let deactivating = map_optional_window(deactivating, map_window)?;
            (
                WM_MDIACTIVATE16,
                u16::from(active),
                u32::from(activating) | (u32::from(deactivating) << 16),
            )
        }
        Win16HostMdiMessageQueuedKind::Destroy { child } => {
            (WM_MDIDESTROY16, map_optional_window(child, map_window)?, 0)
        }
        Win16HostMdiMessageQueuedKind::Restore { child } => {
            (WM_MDIRESTORE16, map_optional_window(child, map_window)?, 0)
        }
        Win16HostMdiMessageQueuedKind::Next { child, previous } => (
            WM_MDINEXT16,
            map_optional_window(child, map_window)?,
            u32::from(previous),
        ),
        Win16HostMdiMessageQueuedKind::Maximize { child } => {
            (WM_MDIMAXIMIZE16, map_optional_window(child, map_window)?, 0)
        }
        Win16HostMdiMessageQueuedKind::Tile { flags } => (WM_MDITILE16, flags, 0),
        Win16HostMdiMessageQueuedKind::Cascade { flags } => (WM_MDICASCADE16, flags, 0),
        Win16HostMdiMessageQueuedKind::IconArrange => (WM_MDIICONARRANGE16, 0, 0),
        Win16HostMdiMessageQueuedKind::GetActive => (WM_MDIGETACTIVE16, 0, 0),
        Win16HostMdiMessageQueuedKind::SetMenu { refresh: true, .. } => (WM_MDISETMENU16, 1, 0),
        Win16HostMdiMessageQueuedKind::SetMenu {
            refresh: false,
            frame_menu,
            window_menu,
        } => {
            let frame_menu = map_optional_menu(frame_menu, map_menu)?;
            let window_menu = map_optional_menu(window_menu, map_menu)?;
            (
                WM_MDISETMENU16,
                0,
                u32::from(frame_menu) | (u32::from(window_menu) << 16),
            )
        }
    };
    Ok(Win16GuestMdiMessage {
        message,
        w_param,
        l_param,
    })
}

fn map_optional_window(
    token: Option<Win16HostWindow>,
    map: &mut impl FnMut(Win16HostWindow) -> Result<u16, RuntimeError>,
) -> Result<u16, RuntimeError> {
    token.map(map).transpose().map(|guest| guest.unwrap_or(0))
}

fn map_optional_menu(
    token: Option<Win16HostMenu>,
    map: &mut impl FnMut(Win16HostMenu) -> Result<u16, RuntimeError>,
) -> Result<u16, RuntimeError> {
    token.map(map).transpose().map(|guest| guest.unwrap_or(0))
}

fn map_mdi_window_handle(
    window_handles: &mut BTreeMap<u16, Win16HostWindow>,
    owned_window_handles: &mut BTreeSet<u16>,
    next_window_handle: &mut u16,
    native: Win16HostWindow,
) -> Result<u16, RuntimeError> {
    if let Some((&guest, _)) = window_handles
        .iter()
        .find(|(_, existing)| **existing == native)
    {
        return Ok(guest);
    }
    for _ in 0..u16::MAX {
        let guest = *next_window_handle;
        *next_window_handle = if guest >= 0xfffd { 2 } else { guest + 1 };
        if matches!(guest, 0 | 1 | 0xfffe | u16::MAX) || window_handles.contains_key(&guest) {
            continue;
        }
        window_handles.insert(guest, native);
        owned_window_handles.remove(&guest);
        return Ok(guest);
    }
    Err(RuntimeError::new(
        Kind::ResourceExhausted,
        "Win16 window handle table is full",
    ))
}
