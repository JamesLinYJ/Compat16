use crate::handle::{HandleError, HandleTable};
use crate::surface::Rect;
use crate::WindowHandle;
use std::collections::VecDeque;
use std::fmt;

pub const WM_PAINT: u16 = 0x000f;
pub const WM_CLOSE: u16 = 0x0010;
pub const WM_KEYDOWN: u16 = 0x0100;
pub const WM_KEYUP: u16 = 0x0101;
pub const WM_CHAR: u16 = 0x0102;
pub const WM_MOUSEMOVE: u16 = 0x0200;
pub const WM_LBUTTONDOWN: u16 = 0x0201;
pub const WM_LBUTTONUP: u16 = 0x0202;
pub const WM_RBUTTONDOWN: u16 = 0x0204;
pub const WM_RBUTTONUP: u16 = 0x0205;
pub const WM_MBUTTONDOWN: u16 = 0x0207;
pub const WM_MBUTTONUP: u16 = 0x0208;

pub const MAX_QUEUED_MESSAGES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowDescription {
    pub class_name: String,
    pub title: String,
    pub parent: Option<WindowHandle>,
    pub rect: Rect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowInfo {
    pub handle: WindowHandle,
    pub class_name: String,
    pub title: String,
    pub parent: Option<WindowHandle>,
    pub rect: Rect,
    pub visible: bool,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Window {
    class_name: String,
    title: String,
    parent: Option<WindowHandle>,
    rect: Rect,
    visible: bool,
    enabled: bool,
}

impl Window {
    fn info(&self, handle: WindowHandle) -> WindowInfo {
        WindowInfo {
            handle,
            class_name: self.class_name.clone(),
            title: self.title.clone(),
            parent: self.parent,
            rect: self.rect,
            visible: self.visible,
            enabled: self.enabled,
        }
    }
}

/// Commands for the Windows host adapter. Producing a command is not evidence
/// that the corresponding native window operation has completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostAction {
    CreateWindow {
        handle: WindowHandle,
        class_name: String,
        title: String,
        parent: Option<WindowHandle>,
        rect: Rect,
    },
    SetWindowVisible { handle: WindowHandle, visible: bool },
    SetWindowEnabled { handle: WindowHandle, enabled: bool },
    MoveWindow { handle: WindowHandle, rect: Rect },
    DestroyWindow { handle: WindowHandle },
    InvalidateWindow { handle: WindowHandle, rect: Rect },
}

/// Events sent by the host adapter into the portable USER queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEvent {
    Close { window: WindowHandle },
    Paint { window: WindowHandle, damage: Rect },
    KeyDown { window: WindowHandle, key: u16, repeat_count: u16 },
    KeyUp { window: WindowHandle, key: u16, repeat_count: u16 },
    Character {
        window: WindowHandle,
        character: u16,
        scan: u8,
        repeat_count: u16,
    },
    MouseMove { window: WindowHandle, x: i16, y: i16 },
    MouseButton {
        window: WindowHandle,
        button: MouseButton,
        down: bool,
        x: i16,
        y: i16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowMessage {
    pub window: Option<WindowHandle>,
    pub message: u16,
    pub w_param: u32,
    pub l_param: u32,
    /// Present only for host paint notifications; a USER adapter can preserve
    /// the damage region while translating it to the guest paint lifecycle.
    pub damage: Option<Rect>,
}

impl WindowMessage {
    pub fn new(window: Option<WindowHandle>, message: u16, w_param: u32, l_param: u32) -> Self {
        Self { window, message, w_param, l_param, damage: None }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserError {
    InvalidWindow(WindowHandle),
    InvalidParent(WindowHandle),
    InvalidRectangle,
    HandleExhausted,
    QueueFull,
    AllocationFailed,
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow(window) => write!(
                f,
                "Window handle 0x{:04X} is invalid or no longer exists.",
                window.raw()
            ),
            Self::InvalidParent(parent) => write!(
                f,
                "Parent window handle 0x{:04X} is invalid or no longer exists.",
                parent.raw()
            ),
            Self::InvalidRectangle => f.write_str(
                "Window rectangle has its right edge before its left edge or its bottom before its top.",
            ),
            Self::HandleExhausted => {
                f.write_str("No free 16-bit guest window handles remain.")
            }
            Self::QueueFull => f.write_str("Guest window message queue is full."),
            Self::AllocationFailed => {
                f.write_str("Could not allocate guest window state or message queue storage.")
            }
        }
    }
}

static HANDLE_EXHAUSTED_SOURCE: HandleError = HandleError::Exhausted;

impl std::error::Error for UserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HandleExhausted => Some(&HANDLE_EXHAUSTED_SOURCE),
            _ => None,
        }
    }
}

impl From<HandleError> for UserError {
    fn from(_: HandleError) -> Self { Self::HandleExhausted }
}

/// A bounded FIFO queue. Empty reads report no message instead of fabricating
/// a quit/message result or blocking a portable runtime thread.
#[derive(Debug)]
pub struct MessageQueue {
    messages: VecDeque<WindowMessage>,
    limit: usize,
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self { messages: VecDeque::new(), limit: MAX_QUEUED_MESSAGES }
    }
}

impl MessageQueue {
    pub fn new() -> Self { Self::default() }

    /// Reserve a guest-visible queue size before it is used for new messages.
    /// An invalid or too-small request leaves this queue intact.
    pub fn configure_limit(&mut self, limit: usize) -> Result<bool, UserError> {
        if limit == 0 || limit > MAX_QUEUED_MESSAGES || limit < self.messages.len() {
            return Ok(false);
        }
        self.messages.try_reserve(limit - self.messages.len())
            .map_err(|_| UserError::AllocationFailed)?;
        self.limit = limit;
        Ok(true)
    }

    pub fn post(&mut self, message: WindowMessage) -> Result<(), UserError> {
        if self.messages.len() >= self.limit {
            return Err(UserError::QueueFull);
        }
        self.messages.try_reserve(1).map_err(|_| UserError::AllocationFailed)?;
        self.messages.push_back(message);
        Ok(())
    }

    pub fn try_pop(&mut self) -> Option<WindowMessage> {
        self.messages.pop_front()
    }

    pub fn len(&self) -> usize { self.messages.len() }

    pub fn is_empty(&self) -> bool { self.messages.is_empty() }

    fn remove_window(&mut self, handle: WindowHandle) {
        self.messages.retain(|message| message.window != Some(handle));
    }
}

/// Portable window state plus a FIFO guest-message queue.
#[derive(Debug, Default)]
pub struct WindowSystem {
    windows: HandleTable<WindowHandle, Window>,
    queue: MessageQueue,
}

impl WindowSystem {
    pub fn new() -> Self { Self::default() }

    pub fn create_window(
        &mut self,
        description: WindowDescription,
    ) -> Result<(WindowHandle, HostAction), UserError> {
        validate_rect(description.rect)?;
        if let Some(parent) = description.parent {
            if !self.windows.contains(parent) {
                return Err(UserError::InvalidParent(parent));
            }
        }

        let window = Window {
            class_name: description.class_name.clone(),
            title: description.title.clone(),
            parent: description.parent,
            rect: description.rect,
            visible: false,
            enabled: true,
        };
        let handle = self.windows.insert(window)?;
        let action = HostAction::CreateWindow {
            handle,
            class_name: description.class_name,
            title: description.title,
            parent: description.parent,
            rect: description.rect,
        };
        Ok((handle, action))
    }

    pub fn window(&self, handle: WindowHandle) -> Result<WindowInfo, UserError> {
        self.windows
            .get(handle)
            .map(|window| window.info(handle))
            .ok_or(UserError::InvalidWindow(handle))
    }

    pub fn window_count(&self) -> usize { self.windows.len() }

    pub fn show_window(
        &mut self,
        handle: WindowHandle,
        visible: bool,
    ) -> Result<(bool, HostAction), UserError> {
        let window = self.windows.get_mut(handle).ok_or(UserError::InvalidWindow(handle))?;
        let previous = window.visible;
        window.visible = visible;
        Ok((previous, HostAction::SetWindowVisible { handle, visible }))
    }

    pub fn enable_window(
        &mut self,
        handle: WindowHandle,
        enabled: bool,
    ) -> Result<(bool, HostAction), UserError> {
        let window = self.windows.get_mut(handle).ok_or(UserError::InvalidWindow(handle))?;
        let previous = window.enabled;
        window.enabled = enabled;
        Ok((previous, HostAction::SetWindowEnabled { handle, enabled }))
    }

    pub fn move_window(
        &mut self,
        handle: WindowHandle,
        rect: Rect,
    ) -> Result<HostAction, UserError> {
        validate_rect(rect)?;
        let window = self.windows.get_mut(handle).ok_or(UserError::InvalidWindow(handle))?;
        window.rect = rect;
        Ok(HostAction::MoveWindow { handle, rect })
    }

    pub fn invalidate(
        &self,
        handle: WindowHandle,
        rect: Rect,
    ) -> Result<HostAction, UserError> {
        if !self.windows.contains(handle) {
            return Err(UserError::InvalidWindow(handle));
        }
        Ok(HostAction::InvalidateWindow { handle, rect })
    }

    /// Destroys the window and all descendants, child-first, and removes their
    /// queued messages before returning host destruction commands.
    pub fn destroy_window(&mut self, handle: WindowHandle) -> Result<Vec<HostAction>, UserError> {
        if !self.windows.contains(handle) {
            return Err(UserError::InvalidWindow(handle));
        }

        let mut stack = Vec::new();
        stack.try_reserve(1).map_err(|_| UserError::AllocationFailed)?;
        stack.push((handle, false));
        let mut order = Vec::new();
        while let Some((current, expanded)) = stack.pop() {
            if expanded {
                order.try_reserve(1).map_err(|_| UserError::AllocationFailed)?;
                order.push(current);
                continue;
            }
            stack.try_reserve(1).map_err(|_| UserError::AllocationFailed)?;
            stack.push((current, true));
            for (candidate, window) in self.windows.iter() {
                if window.parent == Some(current) {
                    stack.try_reserve(1).map_err(|_| UserError::AllocationFailed)?;
                    stack.push((candidate, false));
                }
            }
        }

        let mut actions = Vec::new();
        actions.try_reserve_exact(order.len()).map_err(|_| UserError::AllocationFailed)?;
        for current in order {
            self.windows.remove(current).ok_or(UserError::InvalidWindow(current))?;
            self.queue.remove_window(current);
            actions.push(HostAction::DestroyWindow { handle: current });
        }
        Ok(actions)
    }

    pub fn post_message(&mut self, message: WindowMessage) -> Result<(), UserError> {
        if let Some(handle) = message.window {
            if !self.windows.contains(handle) {
                return Err(UserError::InvalidWindow(handle));
            }
        }
        self.queue.post(message)
    }

    pub fn dispatch_host_event(&mut self, event: HostEvent) -> Result<(), UserError> {
        let message = match event {
            HostEvent::Close { window } => WindowMessage::new(Some(window), WM_CLOSE, 0, 0),
            HostEvent::Paint { window, damage } => {
                let mut message = WindowMessage::new(Some(window), WM_PAINT, 0, 0);
                message.damage = Some(damage);
                message
            }
            HostEvent::KeyDown { window, key, repeat_count } => {
                WindowMessage::new(Some(window), WM_KEYDOWN, u32::from(key), u32::from(repeat_count))
            }
            HostEvent::KeyUp { window, key, repeat_count } => {
                WindowMessage::new(Some(window), WM_KEYUP, u32::from(key), u32::from(repeat_count))
            }
            HostEvent::Character {
                window,
                character,
                scan,
                repeat_count,
            } => WindowMessage::new(
                Some(window),
                WM_CHAR,
                u32::from(character),
                u32::from(repeat_count) | (u32::from(scan) << 16),
            ),
            HostEvent::MouseMove { window, x, y } => {
                WindowMessage::new(Some(window), WM_MOUSEMOVE, 0, pack_point(x, y))
            }
            HostEvent::MouseButton { window, button, down, x, y } => {
                let (message, w_param) = match (button, down) {
                    (MouseButton::Left, true) => (WM_LBUTTONDOWN, 1),
                    (MouseButton::Left, false) => (WM_LBUTTONUP, 0),
                    (MouseButton::Middle, true) => (WM_MBUTTONDOWN, 16),
                    (MouseButton::Middle, false) => (WM_MBUTTONUP, 0),
                    (MouseButton::Right, true) => (WM_RBUTTONDOWN, 2),
                    (MouseButton::Right, false) => (WM_RBUTTONUP, 0),
                };
                WindowMessage::new(Some(window), message, w_param, pack_point(x, y))
            }
        };
        self.post_message(message)
    }

    pub fn get_message(&mut self) -> Option<WindowMessage> {
        self.queue.try_pop()
    }

    pub fn pending_message_count(&self) -> usize { self.queue.len() }
}

fn validate_rect(rect: Rect) -> Result<(), UserError> {
    if rect.right < rect.left || rect.bottom < rect.top {
        Err(UserError::InvalidRectangle)
    } else {
        Ok(())
    }
}

fn pack_point(x: i16, y: i16) -> u32 {
    u32::from(x as u16) | (u32::from(y as u16) << 16)
}

#[cfg(test)]
mod tests;
