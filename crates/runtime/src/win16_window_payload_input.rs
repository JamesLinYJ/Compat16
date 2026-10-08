//! Translate owned host callback messages into checked Win16 arguments.

use std::collections::BTreeMap;
use guest_core::memory::Memory;
use guest_core::OwnerId;
use zerocopy::byteorder::little_endian::{I16, U16};
use zerocopy::{IntoBytes, KnownLayout, Immutable, Unaligned};
use win16_abi::{CreateStruct16, Msg16, SelectorTable, Win16ClassName};

use super::{Win16State, windows::WindowCreateRequest};
use super::messages::WM_NCPAINT;
use super::window_payloads::{self, GuestWindowPayload};
use super::geometry::WM_GETMINMAXINFO;
use win16_abi::window_geometry::MinMaxInfo16;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCreationData, Win16HostMessage,
    Win16HostDialogMessage, Win16MessageSource,
};

const WM_CREATE: u16 = 0x0001;
const WM_SETTEXT: u16 = 0x000c;
const WM_GETTEXT: u16 = 0x000d;
const WM_GETTEXTLENGTH: u16 = 0x000e;
const WM_NCCREATE: u16 = 0x0081;
const WM_INITDIALOG: u16 = 0x0110;
const WM_GETDLGCODE: u16 = 0x0087;
const WM_CHANGECBCHAIN: u16 = 0x030d;
const WM_ACTIVATEAPP: u16 = 0x001c;
const WM_PARENTNOTIFY: u16 = 0x0210;
const WM_CTLCOLOR: u16 = 0x0019;
const GETTEXT_UNWRITTEN_FILL: u8 = u8::MAX;

pub(super) fn checked_activation_task_for_queue(
    queue: Option<crate::Win16HostTaskQueue>,
    binding: Option<(OwnerId, u16, u64, crate::Win16HostTaskQueue)>,
    current_owner: Option<OwnerId>,
    task_handles: &BTreeMap<OwnerId, u16>,
    selectors: &SelectorTable,
) -> Result<u16, RuntimeError> {
    let Some(queue) = queue else { return Ok(0); };
    let Some((owner, task, generation, bound_queue)) = binding else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "WM_ACTIVATEAPP queue has no current USER task binding"));
    };
    if queue != bound_queue || current_owner != Some(owner)
        || task_handles.get(&owner) != Some(&task)
        || !selectors.reference(guest_core::Selector(task))
            .is_ok_and(|reference| reference.generation() == generation)
    {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "WM_ACTIVATEAPP queue does not name the exact current Win16 task"));
    }
    Ok(task)
}

#[repr(C)]
#[derive(Clone, Copy, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DragListInfo16Wire {
    notification: U16,
    list_box: U16,
    cursor_x: I16,
    cursor_y: I16,
}

const _: () = assert!(core::mem::size_of::<DragListInfo16Wire>() == 8);

impl Win16State {
    pub(super) fn activation_task_for_queue(
        &self,
        queue: Option<crate::Win16HostTaskQueue>,
    ) -> Result<u16, RuntimeError> {
        checked_activation_task_for_queue(
            queue, self.user_task_queue, self.tasks.current(),
            &self.task_handles, &self.selectors,
        )
    }

    pub(super) fn activation_queue_for_task(
        &self,
        task: u16,
    ) -> Result<Option<crate::Win16HostTaskQueue>, RuntimeError> {
        if task == 0 { return Ok(None); }
        let Some((owner, current, generation, queue)) = self.user_task_queue else {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "WM_ACTIVATEAPP names a task without a current USER queue binding"));
        };
        if task != current || self.tasks.current() != Some(owner)
            || self.task_handles.get(&owner) != Some(&current)
            || !self.selectors.reference(guest_core::Selector(current))
                .is_ok_and(|reference| reference.generation() == generation)
        {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "WM_ACTIVATEAPP HTASK is not the exact current Win16 task"));
        }
        Ok(Some(queue))
    }

    pub(super) fn parent_notification_from_guest(
        &self,
        event: u16,
        l_param: u32,
    ) -> Result<crate::Win16HostParentNotification, RuntimeError> {
        let data = if matches!(event, 0x0001 | 0x0002) {
            let guest_child = l_param as u16;
            let child = if guest_child == 0 {
                None
            } else {
                Some(*self.window_handles.get(&guest_child).ok_or_else(||
                    RuntimeError::new(Kind::InvalidInput,
                        "WM_PARENTNOTIFY child HWND16 is not mapped"))?)
            };
            crate::Win16HostParentNotificationData::Child {
                child,
                id: (l_param >> 16) as u16,
            }
        } else if matches!(event, 0x0201 | 0x0204 | 0x0207) {
            crate::Win16HostParentNotificationData::Mouse { coordinates: l_param }
        } else {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "WM_PARENTNOTIFY event has no defined Win16 parameter layout"));
        };
        Ok(crate::Win16HostParentNotification { event, data })
    }

    /// Translate a copied host DLGPROC input to the Win16 argument layout.
    /// WM_GETDLGCODE keeps its virtual-key scalar and copies any supplied MSG
    /// into checked guest memory; native MSG pointers never enter the guest ABI.
    pub(super) fn prepare_dialog_callback_payload(
        &mut self,
        message: Win16HostDialogMessage,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<GuestWindowPayload, RuntimeError> {
        match message {
            Win16HostDialogMessage::Init { focus, init_parameter, .. } => {
                let focus = match focus {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                Ok(GuestWindowPayload {
                    message: WM_INITDIALOG,
                    w_param: focus,
                    l_param: init_parameter,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostDialogMessage::Message(message) => {
                let receiver = if matches!(
                    &message,
                    crate::Win16HostMessage::QueuedDropFiles(_),
                ) {
                    self.window_callbacks.last().and_then(|frame| match frame.continuation {
                        super::windows::WindowCallbackContinuation::HostDialog { window, .. } =>
                            Some(window),
                        _ => None,
                    })
                } else {
                    None
                };
                self.prepare_window_payload(message, receiver, None, memory, host)
            }
            Win16HostDialogMessage::GetDlgCode { virtual_key, message: None } => {
                Ok(GuestWindowPayload {
                    message: WM_GETDLGCODE,
                    w_param: virtual_key,
                    l_param: 0,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostDialogMessage::GetDlgCode {
                virtual_key,
                message: Some(message),
            } => {
                let source_is_owned_notification = match (message.source, message.l_param) {
                    (Win16MessageSource::GuestNotification,
                        crate::Win16MessageParam::GuestNotification { provenance, .. }) => {
                        provenance.source.id != 0
                            && provenance.source.generation != 0
                            && provenance.source.sequence != 0
                    }
                    (Win16MessageSource::NativeQueue, _) => true,
                    _ => false,
                };
                if !source_is_owned_notification {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WM_GETDLGCODE copied MSG has guest-message or mismatched notification provenance"));
                }
                let (allocation, pointer) = self.allocate_window_payload(
                    memory,
                    Msg16::SIZE,
                )?;
                if let Err(error) = self.write_queued_message(
                    pointer,
                    Some(message),
                    false,
                    memory,
                ) {
                    return Err(self.cleanup_after_error(allocation, error));
                }
                Ok(GuestWindowPayload {
                    message: WM_GETDLGCODE,
                    w_param: virtual_key,
                    l_param: pointer.far_value(),
                    allocation: Some(allocation),
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
        }
    }

    pub(super) fn prepare_window_payload(
        &mut self,
        message: Win16HostMessage,
        receiver_window: Option<u16>,
        creation: Option<&WindowCreateRequest>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<GuestWindowPayload, RuntimeError> {
        match message {
            Win16HostMessage::DropFiles(drop) => {
                let handle = self.prepare_drop_files_hglobal(drop, memory, host)?;
                Ok(GuestWindowPayload {
                    message: 0x0233,
                    w_param: handle,
                    l_param: 0,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::QueuedDropFiles(queued) => {
                let receiver = receiver_window.ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "direct queued WM_DROPFILES callback has no receiver HWND16",
                ))?;
                let window = self.window_handles.get(&receiver).copied().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "direct queued WM_DROPFILES receiver lost its exact HWND identity"))?;
                let handle = self.project_queued_drop_files_hglobal(
                    &queued, window, memory, host,
                )?;
                let (message, handle) = match handle {
                    Some(handle) => (0x0233, handle),
                    None => {
                        host.report_diagnostic(&crate::Diagnostic::warning(
                            Kind::CompatibilityGap,
                            "suppressed a queued WM_DROPFILES callback whose exact lease was already finished",
                        ));
                        (0, 0)
                    }
                };
                if let Some(allocation) = self.global_handles.get(&handle).copied() {
                    if let Some(frame) = self.window_callbacks.last_mut().filter(|frame|
                        frame.entry_phase == super::windows::WindowCallbackEntryPhase::Preparing)
                    {
                        frame.guest_drop_generation = Some(allocation);
                    }
                }
                Ok(GuestWindowPayload {
                    message,
                    w_param: handle,
                    l_param: 0,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::ActivationApp(input) => {
                let other_task = self.activation_task_for_queue(input.other_task_queue)?;
                Ok(GuestWindowPayload {
                    message: WM_ACTIVATEAPP,
                    w_param: u16::from(input.active != 0),
                    l_param: u32::from(other_task),
                    allocation: None, output: None, callback_dc: None,
                    command_control: None, command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::ParentNotification(input) => {
                let l_param = match input.data {
                    crate::Win16HostParentNotificationData::Child { child, id }
                        if matches!(input.event, 0x0001 | 0x0002) => {
                        let child = match child {
                            Some(native) => self.map_window_handle(native, false)?,
                            None => 0,
                        };
                        u32::from(child) | (u32::from(id) << 16)
                    }
                    crate::Win16HostParentNotificationData::Mouse { coordinates }
                        if matches!(input.event, 0x0201 | 0x0204 | 0x0207) => coordinates,
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WM_PARENTNOTIFY event and parameter layout disagree")),
                };
                Ok(GuestWindowPayload {
                    message: WM_PARENTNOTIFY,
                    w_param: input.event,
                    l_param,
                    allocation: None, output: None, callback_dc: None,
                    command_control: None, command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::ControlColor(input) => {
                if input.kind > 6 {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native control-color type is outside the seven Win16 classes"));
                }
                let control = match input.control {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                let callback_dc = match input.dc {
                    Some(native) => {
                        let guest = self.guest_gdi.allocate_dc(native).ok_or_else(||
                            RuntimeError::new(Kind::ResourceExhausted,
                                "Win16 control-color callback has no guest HDC alias"))?;
                        Some((guest, native))
                    }
                    None => None,
                };
                Ok(GuestWindowPayload {
                    message: WM_CTLCOLOR,
                    w_param: callback_dc.map_or(0, |(guest, _)| guest),
                    l_param: u32::from(control) | (u32::from(input.kind) << 16),
                    allocation: None, output: None, callback_dc,
                    command_control: None, command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::FindReplaceNotification(notification) => {
                let dispatched = self.prepare_find_replace_notification(memory, &notification)?
                    .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                        "filtered Find/Replace notification lost its runtime session"))?;
                Ok(GuestWindowPayload {
                    message: dispatched.message, w_param: dispatched.w_param,
                    l_param: dispatched.l_param, allocation: None, output: None,
                    callback_dc: None, command_control: None, command_parent: None,
                    common_dialog_request: Some(dispatched.request_id),
                })
            }
            Win16HostMessage::DragListNotification(notification) => {
                if self.window_handles.get(&notification.guest_list_box)
                    != Some(&notification.list_box)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "MakeDragList callback no longer matches its captured HWND16 alias"));
                }
                let list_box = notification.guest_list_box;
                // Win31API.TXT (Microsoft, 1992) defines LB_MSGMAX as
                // WM_USER+33; WFW 3.1 COMMCTRL.H defines DL_* as +100..+103.
                let notification_code = match notification.kind {
                    crate::Win16HostDragListKind::BeginDrag => 0x0485,
                    crate::Win16HostDragListKind::Dragging => 0x0486,
                    crate::Win16HostDragListKind::Dropped => 0x0487,
                    crate::Win16HostDragListKind::CancelDrag => 0x0488,
                };
                let wire = DragListInfo16Wire {
                    notification: U16::new(notification_code),
                    list_box: U16::new(list_box),
                    cursor_x: I16::new(notification.cursor_x),
                    cursor_y: I16::new(notification.cursor_y),
                };
                let (allocation, pointer) = self.allocate_window_payload(memory, 8)?;
                if let Err(error) = self.write_text_bytes(memory, pointer, wire.as_bytes()) {
                    return Err(self.cleanup_after_error(allocation, error));
                }
                Ok(GuestWindowPayload {
                    message: notification.message,
                    w_param: notification.control_id,
                    l_param: pointer.far_value(),
                    allocation: Some(allocation),
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::WindowInput(input) => {
                let (message, w_param, l_param) = self.window_input_to_guest(input)?;
                Ok(GuestWindowPayload {
                    message,
                    w_param,
                    l_param,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::InitDialog {
                focus,
                focus_ancestry,
                init_parameter,
            } => {
                let focus = match focus {
                    Some(focus) => self.map_window_handle(focus, false)?,
                    None => 0,
                };
                for (child, parent) in focus_ancestry {
                    let child = self.map_window_handle(child, false)?;
                    let parent = self.map_window_handle(parent, false)?;
                    self.set_window_parent_from_host(child, parent)?;
                }
                Ok(GuestWindowPayload {
                    message: WM_INITDIALOG,
                    w_param: focus,
                    l_param: init_parameter,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::GetDlgCode => Ok(GuestWindowPayload {
                message: WM_GETDLGCODE,
                w_param: 0,
                l_param: 0,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            }),
            Win16HostMessage::Scalar { kind, w_param, l_param } => Ok(GuestWindowPayload {
                message: kind as u16,
                w_param,
                l_param,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            }),
            Win16HostMessage::MultimediaNotification { message, w_param, l_param } => {
                if !crate::is_multimedia_notification_message(message) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed Win16 multimedia callback is outside the MM_* range"));
                }
                Ok(GuestWindowPayload {
                    message,
                    w_param,
                    l_param,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::GuestOpaque { message, w_param, l_param } => {
                if message < 0x0400 {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 opaque WndProc message is outside the application-defined range"));
                }
                Ok(GuestWindowPayload {
                    message,
                    w_param,
                    l_param,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::GuestNotification(notification) => {
                let (window, guest_hwnd) = match notification.target {
                    crate::Win16GuestNotificationTarget::Window { window, guest_hwnd } =>
                        (window, guest_hwnd),
                    crate::Win16GuestNotificationTarget::Task { .. } => {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "task notification entered a native window callback"));
                    }
                };
                if self.window_handles.get(&guest_hwnd) != Some(&window) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "guest notification alias changed before native callback dispatch"));
                }
                Ok(GuestWindowPayload {
                    message: notification.message,
                    w_param: notification.w_param,
                    l_param: notification.l_param,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::NonClientPaint => Ok(GuestWindowPayload {
                // Windows 3.1 Programmer's Reference, Vol. 3, p. 179:
                // WM_NCPAINT has no parameters. Native Win32 HRGN state stays
                // with the suspended host callback and is never a guest handle.
                message: WM_NCPAINT,
                w_param: 0,
                l_param: 0,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            }),
            Win16HostMessage::Command { id, notify, control, control_parent } => {
                let guest_control = match control {
                    // Dialog-manager controls are native child HWNDs that may
                    // not have crossed the guest boundary before WM_COMMAND.
                    // Allocate a checked opaque Win16 alias instead of
                    // truncating the native handle into LPARAM.
                    Some(control) => self.map_window_handle(control, false)?,
                    None => 0,
                };
                let (w_param, l_param) = super::messages::pack_win16_command(
                    id, notify, guest_control);
                Ok(GuestWindowPayload {
                    message: 0x0111,
                    w_param,
                    l_param,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: control,
                    command_parent: control_parent,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::ClipboardChainChange { removed, next } => {
                let removed = match removed {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                let next = match next {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                Ok(GuestWindowPayload {
                    message: WM_CHANGECBCHAIN,
                    w_param: removed,
                    l_param: u32::from(next),
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::Control(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "synchronous control request cannot be a guest callback payload")),
            Win16HostMessage::OwnerDraw(item) => self.prepare_owner_draw_payload(item, memory),
            payload @ (Win16HostMessage::EraseBackground { dc: Some(_) }
                | Win16HostMessage::Paint { dc: Some(_) }) => {
                let (message, dc) = match payload {
                    Win16HostMessage::EraseBackground { dc: Some(dc) } => (0x0014, dc),
                    Win16HostMessage::Paint { dc: Some(dc) } => (0x000f, dc),
                    _ => unreachable!(),
                };
                let guest_dc = self.guest_gdi.allocate_dc(dc).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 callback HDC handle table is full"))?;
                Ok(GuestWindowPayload {
                    message,
                    w_param: guest_dc,
                    l_param: 0,
                    allocation: None,
                    output: None,
                    callback_dc: Some((guest_dc, dc)),
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::EraseBackground { dc: None } => Ok(GuestWindowPayload {
                message: 0x0014,
                w_param: 0,
                l_param: 0,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            }),
            Win16HostMessage::Paint { dc: None } => Ok(GuestWindowPayload {
                message: 0x000f, w_param: 0, l_param: 0,
                allocation: None, output: None, callback_dc: None,
                command_control: None, command_parent: None, common_dialog_request: None,
            }),
            Win16HostMessage::Creation { non_client, data } => {
                let request = if let Some(request) = creation {
                    request.clone()
                } else {
                    let parent = match data.parent {
                        Some(parent) => self.map_window_handle(parent, false)?,
                        None => 0,
                    };
                    let menu = match data.menu {
                        Some(menu) => self.guest_menus.intern(menu).ok_or_else(|| {
                            RuntimeError::new(
                                Kind::ResourceExhausted,
                                "guest menu handle table filled during CREATESTRUCT16 projection",
                            )
                        })?,
                        None => data.guest_menu,
                    };
                    WindowCreateRequest {
                        class_name: match &data.guest_class_name {
                            crate::Win16HostClassName::Name(name) => Win16ClassName::Name(name.clone()),
                            crate::Win16HostClassName::Atom(atom) => Win16ClassName::Atom(*atom),
                        },
                        window_name: data.title.clone(),
                        ex_style: data.ex_style,
                        style: data.style,
                        x: data.x,
                        y: data.y,
                        width: data.width,
                        height: data.height,
                        parent,
                        menu,
                        instance: data.guest_instance,
                        parameter: data.create_parameter,
                    }
                };
                self.prepare_creation_payload(non_client, data, &request, memory)
            }
            Win16HostMessage::MdiChildCreation { non_client, data } => {
                let Some(callback_id) = self.preparing_window_callback_id() else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 MDI child payload has no Preparing callback owner"));
                };
                let Some(receiver_window) = receiver_window else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 MDI child callback has no receiving guest HWND"));
                };
                let frame = self.window_callbacks.last().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 MDI child callback owner disappeared before payload creation",
                ))?;
                let (native_window, callback_window) = match frame.continuation {
                    super::windows::WindowCallbackContinuation::Host {
                        native_window, window, ..
                    } => (native_window, window),
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 MDI child payload is not owned by a native WndProc callback")),
                };
                let retained = frame.mdi_child_creation.as_ref().ok_or_else(|| {
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 MDI child callback lost its typed creation provenance")
                })?;
                if frame.callback_id != callback_id
                    || callback_window != receiver_window
                    || self.window_handles.get(&receiver_window) != Some(&native_window)
                    || !self.mdi_children.contains(&receiver_window)
                    || retained.mdi.creation != data.mdi.creation
                    || retained.mdi.class != data.mdi.class
                    || retained.mdi.guest_class_name != data.mdi.guest_class_name
                    || retained.mdi.owner_instance != data.mdi.owner_instance
                    || retained.creation.parent != data.creation.parent
                    || retained.creation.guest_instance != data.creation.guest_instance
                    || data.creation.ex_style & 0x0000_0040 == 0
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 MDI child payload differs from its retained exact callback owner"));
                }
                self.validate_mdi_endpoint(
                    receiver_window,
                    native_window,
                    crate::Win16MdiEndpoint::Child(native_window),
                )?;
                self.prepare_mdi_child_creation_payload(non_client, &data, memory)
            }
            Win16HostMessage::MdiQueued(queued) => {
                let Some(receiver_window) = receiver_window else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed Win16 MDI callback has no receiving guest HWND"));
                };
                let native = *self.window_handles.get(&receiver_window).ok_or_else(|| {
                    RuntimeError::new(Kind::InternalInvariant,
                        "typed Win16 MDI callback receiver has no live native HWND alias")
                })?;
                self.validate_mdi_endpoint(receiver_window, native, queued.endpoint)?;
                let projected = self.project_queued_mdi_message(queued)?;
                Ok(GuestWindowPayload {
                    message: projected.message,
                    w_param: projected.w_param,
                    l_param: projected.l_param,
                    allocation: None,
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::Mdi(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "synchronous Win16 MDI request was routed through callback payload preparation")),
            Win16HostMessage::SetText(bytes) => {
                let Some(bytes) = bytes else {
                    return Ok(GuestWindowPayload {
                        message: WM_SETTEXT,
                        w_param: 0,
                        l_param: 0,
                        allocation: None,
                        output: None,
                        callback_dc: None,
                        command_control: None,
                        command_parent: None,
                        common_dialog_request: None,
                    });
                };
                validate_ansi_bytes(&bytes, "Win16 WM_SETTEXT")?;
                let allocation_size = terminated_size(bytes.len(), "Win16 WM_SETTEXT")?;
                let (allocation, pointer) =
                    self.allocate_window_payload(memory, allocation_size)?;
                if let Err(error) = self.selectors.write(memory, pointer, &bytes) {
                    return Err(self.cleanup_after_error(allocation, crate::runtime_error(error)));
                }
                Ok(GuestWindowPayload {
                    message: WM_SETTEXT,
                    w_param: 0,
                    l_param: pointer.far_value(),
                    allocation: Some(allocation),
                    output: None,
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::GetText { capacity, buffer_is_null } => {
                if buffer_is_null {
                    return Ok(GuestWindowPayload {
                        message: WM_GETTEXT,
                        w_param: capacity,
                        l_param: 0,
                        allocation: None,
                        output: None,
                        callback_dc: None,
                        command_control: None,
                        command_parent: None,
                        common_dialog_request: None,
                    });
                }
                // LPARAM remains observable to a Win16 procedure when wParam
                // is zero. A checked one-byte guest block represents a
                // non-NULL buffer, but no output is read or copied back.
                let (allocation, pointer) = self.allocate_window_payload(
                    memory,
                    usize::from(capacity).max(1),
                )?;
                if capacity != 0 {
                    let fill_size = usize::from(capacity);
                    let mut fill = Vec::new();
                    if let Err(error) = fill.try_reserve_exact(fill_size) {
                        let error = RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "cannot initialize the Win16 WM_GETTEXT callback buffer",
                            error,
                        );
                        return Err(self.cleanup_after_error(allocation, error));
                    }
                    fill.resize(fill_size, GETTEXT_UNWRITTEN_FILL);
                    if let Err(error) = self.selectors.write(memory, pointer, &fill) {
                        return Err(self.cleanup_after_error(
                            allocation,
                            crate::runtime_error(error),
                        ));
                    }
                }
                Ok(GuestWindowPayload {
                    message: WM_GETTEXT,
                    w_param: capacity,
                    l_param: pointer.far_value(),
                    allocation: Some(allocation),
                    output: (capacity != 0).then_some((pointer, capacity)),
                    callback_dc: None,
                    command_control: None,
                    command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::SetFont { font, redraw } => {
                let w_param = match font {
                    None => 0,
                    Some(font) => match self.guest_gdi.existing_object(font) {
                        Some(handle) => handle,
                        None => self.guest_gdi.allocate_object(font).ok_or_else(||
                            RuntimeError::new(Kind::ResourceExhausted,
                                "Win16 font callback cannot allocate a guest GDI handle"))?,
                    },
                };
                Ok(GuestWindowPayload {
                    message: super::messages::WM_SETFONT,
                    w_param, l_param: u32::from(redraw), allocation: None, output: None,
                    callback_dc: None, command_control: None, command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::GetTextLength => Ok(GuestWindowPayload {
                message: WM_GETTEXTLENGTH,
                w_param: 0,
                l_param: 0,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            }),
            Win16HostMessage::MinMaxInfo(data) => {
                let (allocation, pointer) = self.allocate_window_payload(memory, MinMaxInfo16::SIZE)?;
                let bytes = super::geometry::guest_minmax_info(data).encode();
                if let Err(error) = self.selectors.write(memory, pointer, &bytes) {
                    return Err(self.cleanup_after_error(allocation, crate::runtime_error(error)));
                }
                Ok(GuestWindowPayload {
                    message: WM_GETMINMAXINFO, w_param: 0, l_param: pointer.far_value(),
                    allocation: Some(allocation), output: Some((pointer, MinMaxInfo16::SIZE as u16)),
                    callback_dc: None, command_control: None, command_parent: None,
                    common_dialog_request: None,
                })
            }
            Win16HostMessage::NonClientCalcSize { w_param, data } => {
                super::window_payloads::nonclient_payloads::prepare_callback_payload(
                    self, w_param, data, memory,
                )
            }
            Win16HostMessage::WindowPosition { changing, w_param, data } => {
                super::window_payloads::window_position_payloads::prepare_callback_payload(
                    self, changing, w_param, data, memory,
                )
            }
        }
    }

    fn prepare_creation_payload(
        &mut self,
        non_client: bool,
        data: Win16HostCreationData,
        request: &WindowCreateRequest,
        memory: &mut Memory,
    ) -> Result<GuestWindowPayload, RuntimeError> {
        let class_bytes = match &request.class_name {
            Win16ClassName::Name(bytes) => Some(bytes.as_slice()),
            Win16ClassName::Atom(_) => None,
        };
        if let Some(bytes) = class_bytes {
            validate_ansi_bytes(bytes, "Win16 CREATESTRUCT16 class name")?;
        }
        if let Some(bytes) = data.title.as_deref() {
            validate_ansi_bytes(bytes, "Win16 CREATESTRUCT16 title")?;
        }

        let class_storage = class_bytes
            .map_or(Ok(0), |bytes| terminated_size(bytes.len(), "Win16 class name"))?;
        let title_storage = data
            .title
            .as_deref()
            .map_or(Ok(0), |bytes| terminated_size(bytes.len(), "Win16 title"))?;
        let creation_data_offset = CreateStruct16::SIZE
            .checked_add(class_storage)
            .and_then(|offset| offset.checked_add(title_storage))
            .ok_or_else(|| window_payloads::payload_size_error("Win16 creation-data offset overflow"))?;
        let title_offset = CreateStruct16::SIZE
            .checked_add(class_storage)
            .ok_or_else(|| window_payloads::payload_size_error("Win16 CREATESTRUCT16 size overflow"))?;
        let allocation_size = title_offset
            .checked_add(title_storage)
            .and_then(|size| size.checked_add(data.creation_data.as_ref().map_or(0, Vec::len)))
            .filter(|size| *size <= usize::from(u16::MAX))
            .ok_or_else(|| window_payloads::payload_size_error(
                "Win16 CREATESTRUCT16 payload exceeds one guest segment"))?;

        let (allocation, pointer) = self.allocate_window_payload(memory, allocation_size)?;
        let prepared = (|| {
            let class_pointer = match &request.class_name {
                Win16ClassName::Atom(atom) => u32::from(*atom),
                Win16ClassName::Name(_) => self
                    .selectors
                    .add_bytes(pointer, CreateStruct16::SIZE as u32)
                    .map_err(crate::runtime_error)?
                    .far_value(),
            };
            let title_pointer = if data.title.is_some() {
                let offset = u32::try_from(title_offset)
                    .map_err(|_| window_payloads::payload_size_error("Win16 title offset is not representable"))?;
                self.selectors
                    .add_bytes(pointer, offset)
                    .map_err(crate::runtime_error)?
                    .far_value()
            } else {
                0
            };
            let creation_data_pointer = if data.creation_data.as_ref().is_some_and(|bytes| !bytes.is_empty()) {
                let offset = u32::try_from(creation_data_offset)
                    .map_err(|_| window_payloads::payload_size_error("Win16 creation-data offset is not representable"))?;
                self.selectors.add_bytes(pointer, offset)
                    .map_err(crate::runtime_error)?.far_value()
            } else {
                0
            };

            CreateStruct16 {
                lp_create_params: if data.creation_data.is_some() {
                    creation_data_pointer
                } else {
                    request.parameter
                },
                h_instance: request.instance,
                h_menu: request.menu,
                hwnd_parent: request.parent,
                cy: data.height,
                cx: data.width,
                y: data.y,
                x: data.x,
                style: data.style,
                lpsz_name: title_pointer,
                lpsz_class: class_pointer,
                dw_ex_style: data.ex_style,
            }
            .write_to(&self.selectors, memory, pointer)
            .map_err(crate::runtime_error)?;

            if let Some(bytes) = class_bytes {
                let target = self
                    .selectors
                    .add_bytes(pointer, CreateStruct16::SIZE as u32)
                    .map_err(crate::runtime_error)?;
                self.selectors.write(memory, target, bytes)
                    .map_err(crate::runtime_error)?;
            }
            if let Some(bytes) = data.title.as_deref() {
                let offset = u32::try_from(title_offset)
                    .map_err(|_| window_payloads::payload_size_error("Win16 title offset is not representable"))?;
                let target = self.selectors
                    .add_bytes(pointer, offset)
                    .map_err(crate::runtime_error)?;
                self.selectors.write(memory, target, bytes)
                    .map_err(crate::runtime_error)?;
            }
            if let Some(bytes) = data.creation_data.as_deref() {
                let offset = u32::try_from(creation_data_offset)
                    .map_err(|_| window_payloads::payload_size_error("Win16 creation-data offset is not representable"))?;
                let target = self.selectors.add_bytes(pointer, offset)
                    .map_err(crate::runtime_error)?;
                self.selectors.write(memory, target, bytes)
                    .map_err(crate::runtime_error)?;
            }
            Ok(())
        })();
        if let Err(error) = prepared {
            return Err(self.cleanup_after_error(allocation, error));
        }

        Ok(GuestWindowPayload {
            message: if non_client { WM_NCCREATE } else { WM_CREATE },
            w_param: 0,
            l_param: pointer.far_value(),
            allocation: Some(allocation),
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        })
    }
}

fn validate_ansi_bytes(bytes: &[u8], field: &str) -> Result<(), RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{field} contains an embedded NUL byte"),
        ));
    }
    Ok(())
}

fn terminated_size(length: usize, field: &str) -> Result<usize, RuntimeError> {
    length
        .checked_add(1)
        .filter(|size| *size <= usize::from(u16::MAX))
        .ok_or_else(|| window_payloads::payload_size_error(
            format!("{field} exceeds one Win16 segment")))
}
