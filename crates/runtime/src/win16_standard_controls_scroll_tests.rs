//! Windows 3.1 EDIT IDs remain distinct from their Win32 IDs and pointer slots.

use super::*;
use crate::Runtime;
use crate::win16_runtime::test_support::{NoHost, tiny_ne_executable};

#[test]
fn edit_scroll_win31_messages_ignore_unused_pointer_bits() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SCROLL.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let native = crate::Win16HostWindow(1);
    state.window_handles.insert(7, native);
    let identity = Win16HostControlIdentity {
        family: Family::Edit,
        style: 0x0004, // ES_MULTILINE
    };
    for (id, command, expected) in [
        (0x0405, 0, Edit::Scroll { command: 0 }),
        (0x0405, 1, Edit::Scroll { command: 1 }),
        (0x0405, 2, Edit::Scroll { command: 2 }),
        (0x0405, 3, Edit::Scroll { command: 3 }),
        (0x0405, u16::MAX, Edit::Scroll { command: u16::MAX }),
        (0x040e, u16::MAX, Edit::GetThumb),
    ] {
        // Unused LPARAM must not be decoded as a guest far pointer. Invalid
        // scroll commands stay intact for native USER to reject honestly.
        let (message, output) = state
            .prepare_control_message(
                7,
                id,
                command,
                u32::MAX,
                None,
                identity,
                &runtime.memory,
                &mut NoHost,
            )
            .unwrap()
            .unwrap();
        assert!(matches!(output, MessageOutput::None));
        let Win16HostMessage::Control(call) = message else {
            panic!("EDIT scroll must use the checked control-family route");
        };
        assert_eq!(
            call,
            Win16HostControlCall {
                window: native,
                expected: identity,
                dispatch: Dispatch::Send,
                message: Message::Edit(expected),
            }
        );
    }
}
