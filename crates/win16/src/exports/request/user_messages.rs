//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserMessagesRequest {
    /// Invoke USER.107 with the Win16 window/message parameters. `l_param`
    /// remains raw guest bits because its meaning depends on the message.
    DefWindowProc {
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    /// Queue a thread-level WM_QUIT with its raw Win16 exit code.
    PostQuitMessage {
        exit_code: u16,
    },

    /// Retrieve a queue message into a guest MSG16 output buffer. The pointer
    /// remains raw so the runtime can validate all 18 writable bytes before
    /// modifying guest memory; the decoder never reads the output structure.
    GetMessage {
        output: u32,
        window: u16,
        min_message: u16,
        max_message: u16,
    },

    /// Peek a queue message with the same checked-output contract as GetMessage.
    /// Raw Win16 flags preserve PM_REMOVE and PM_NOYIELD semantics.
    PeekMessage {
        output: u32,
        window: u16,
        min_message: u16,
        max_message: u16,
        flags: u16,
    },

    /// Translate a checked copy of a guest MSG16 for keyboard-to-character
    /// translation. Pointer-bearing LPARAM fields remain guest values.
    TranslateMessage {
        message: Msg16,
    },

    /// Dispatch a checked copy of a guest MSG16 through the Win16 message path.
    DispatchMessage {
        message: Msg16,
    },

    /// Register a checked nullable ANSI window-message name and return its
    /// Win16 WORD message identifier.
    RegisterWindowMessage {
        name: Option<Vec<u8>>,
    },

    /// Win16 message LPARAM is raw guest data and is interpreted by the message path.
    PostMessage {
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    SendMessage {
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    /// The signed Win16 item ID remains its original 16-bit wire pattern.
    SendDlgItemMessage {
        dialog: u16,
        id: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    WaitMessage,

    PostAppMessage {
        task: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    GetMessagePos,

    GetMessageTime,

    /// Read the current USER queue's opaque, scalar LONG extra information.
    GetMessageExtraInfo,

    /// Query the SendMessage state on the native USER worker servicing the
    /// current guest window callback.
    InSendMessage,

    CallWindowProc {
        procedure: u32,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    GetKeyboardState {
        output: u32,
    },

    SetKeyboardState {
        state: [u8; 256],
    },

    GetQueueStatus {
        flags: u16,
    },

    GetInputState,

    /// Resize the Win16 message queue before windows or messages are created.
    /// The documented `int` count is signed 16-bit, while the BOOL result
    /// remains a 16-bit word in AX.
    SetMessageQueue {
        message_count: i16,
    },
}
