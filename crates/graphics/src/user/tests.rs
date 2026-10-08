use super::{
    HostAction, HostEvent, MessageQueue, MouseButton, UserError, WindowDescription,
    WindowMessage, WindowSystem, WM_CHAR, WM_CLOSE, WM_KEYDOWN, WM_LBUTTONDOWN, WM_PAINT,
};
use crate::{Rect, WindowHandle};

fn description(title: &str, parent: Option<WindowHandle>) -> WindowDescription {
    WindowDescription {
        class_name: "TEST".to_owned(),
        title: title.to_owned(),
        parent,
        rect: Rect::new(0, 0, 100, 50),
    }
}

#[test]
fn creates_shows_moves_and_destroys_with_host_actions() {
    let mut user = WindowSystem::new();
    let (parent, action) = user.create_window(description("parent", None)).unwrap();
    assert_eq!(action, HostAction::CreateWindow {
        handle: parent,
        class_name: "TEST".to_owned(),
        title: "parent".to_owned(),
        parent: None,
        rect: Rect::new(0, 0, 100, 50),
    });
    assert_eq!(user.show_window(parent, true).unwrap().0, false);
    assert!(user.window(parent).unwrap().visible);
    assert_eq!(user.enable_window(parent, false).unwrap().0, true);
    assert!(!user.window(parent).unwrap().enabled);
    user.move_window(parent, Rect::new(5, 6, 20, 30)).unwrap();
    let (child, _) = user.create_window(description("child", Some(parent))).unwrap();
    user.post_message(WindowMessage::new(Some(child), WM_CLOSE, 0, 0)).unwrap();
    let actions = user.destroy_window(parent).unwrap();

    assert_eq!(actions, vec![
        HostAction::DestroyWindow { handle: child },
        HostAction::DestroyWindow { handle: parent },
    ]);
    assert_eq!(user.window(parent), Err(UserError::InvalidWindow(parent)));
    assert_eq!(user.window(child), Err(UserError::InvalidWindow(child)));
    assert_eq!(user.pending_message_count(), 0);
    let (next, _) = user.create_window(description("next", None)).unwrap();
    assert_ne!(next, parent);
    assert_ne!(next, child);
}

#[test]
fn translates_host_input_and_preserves_paint_damage_fifo() {
    let mut user = WindowSystem::new();
    let (window, _) = user.create_window(description("input", None)).unwrap();
    let damage = Rect::new(1, 2, 30, 40);
    user.dispatch_host_event(HostEvent::Paint { window, damage }).unwrap();
    user.dispatch_host_event(HostEvent::KeyDown { window, key: 65, repeat_count: 3 }).unwrap();
    user.dispatch_host_event(HostEvent::Character {
        window,
        character: 0x4e2d,
        scan: 0x32,
        repeat_count: 2,
    }).unwrap();
    user.dispatch_host_event(HostEvent::MouseButton {
        window, button: MouseButton::Left, down: true, x: -2, y: 4,
    }).unwrap();

    let paint = user.get_message().unwrap();
    assert_eq!(paint.message, WM_PAINT);
    assert_eq!(paint.damage, Some(damage));
    let key = user.get_message().unwrap();
    assert_eq!((key.message, key.w_param, key.l_param), (WM_KEYDOWN, 65, 3));
    let character = user.get_message().unwrap();
    assert_eq!(
        (character.message, character.w_param, character.l_param),
        (WM_CHAR, 0x4e2d, 2 | (0x32 << 16)),
    );
    let button = user.get_message().unwrap();
    assert_eq!(button.message, WM_LBUTTONDOWN);
    assert_eq!(button.w_param, 1);
    assert_eq!(button.l_param, u32::from((-2i16) as u16) | (4u32 << 16));
    assert!(user.get_message().is_none());
}

#[test]
fn invalid_windows_and_rectangles_are_explicit_errors() {
    let mut user = WindowSystem::new();
    let stale = WindowHandle::from_raw(9).unwrap();
    assert_eq!(user.post_message(WindowMessage::new(Some(stale), 1, 0, 0)), Err(UserError::InvalidWindow(stale)));
    let bad = WindowDescription {
        rect: Rect::new(2, 0, 1, 1),
        ..description("bad", None)
    };
    assert_eq!(user.create_window(bad), Err(UserError::InvalidRectangle));
}

#[test]
fn message_queue_is_fifo_and_empty_pop_is_not_fabricated() {
    let mut queue = MessageQueue::new();
    assert!(queue.is_empty());
    assert_eq!(queue.try_pop(), None);
    queue.post(WindowMessage::new(None, 1, 2, 3)).unwrap();
    queue.post(WindowMessage::new(None, 4, 5, 6)).unwrap();
    assert_eq!(queue.try_pop().unwrap().message, 1);
    assert_eq!(queue.try_pop().unwrap().message, 4);
    assert!(queue.is_empty());
}

#[test]
fn user_error_text_keeps_window_handle_and_exhaustion_cause() {
    let window = WindowHandle::from_raw(0x1234).unwrap();
    assert_eq!(
        UserError::InvalidWindow(window).to_string(),
        "Window handle 0x1234 is invalid or no longer exists."
    );
    assert_eq!(
        std::error::Error::source(&UserError::HandleExhausted)
            .unwrap()
            .to_string(),
        "No unused 16-bit object handles remain; valid handles range from 1 through 65,535."
    );
}
