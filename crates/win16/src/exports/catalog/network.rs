//! Complete ABI parameter arrays for the selected Winsock, DDEML, NDDEAPI,
//! and NETAPI exports. Names are positional labels; widths and pointer roles
//! are copied from this crate's export inventory declarations.

use super::*;

macro_rules! params {
    ($name:ident: [$($arg:ident: $kind:ident / $role:expr),* $(,)?]) => {
        pub(super) const $name: &[Win16Parameter] = &[
            $(Win16Parameter { name: stringify!($arg), kind: ArgumentKind::$kind, parameter_type: $role },)*
        ];
    };
}

macro_rules! w { ($($args:tt)*) => { params!($($args)*); } }
macro_rules! d { ($($args:tt)*) => { params!($($args)*); } }
macro_rules! p { ($($args:tt)*) => { params!($($args)*); } }

// Winsock 1.x (all 49 known signatures).
w!(WS_ACCEPT: [s: Word / SCALAR_WORD, address: Dword / FAR_OUTPUT_BUFFER, address_length: Dword / FAR_OUTPUT_BUFFER]);
w!(WS_BIND_CONNECT: [s: Word / SCALAR_WORD, address: Dword / FAR_BUFFER, address_length: Word / SCALAR_WORD]);
w!(WS_CLOSE: [s: Word / SCALAR_WORD]);
w!(WS_PEER_NAME: [s: Word / SCALAR_WORD, address: Dword / FAR_OUTPUT_BUFFER, address_length: Dword / FAR_OUTPUT_BUFFER]);
w!(WS_GETSOCKOPT: [s: Word / SCALAR_WORD, level: Word / SCALAR_WORD, option: Word / SCALAR_WORD, value: Dword / FAR_OUTPUT_BUFFER, value_length: Dword / FAR_OUTPUT_BUFFER]);
w!(WS_LONG: [value: Dword / SCALAR_DWORD]);
w!(WS_WORD: [value: Word / SCALAR_WORD]);
w!(WS_INET_ADDR: [address: Dword / FAR_STRING]);
w!(WS_IOCTL: [s: Word / SCALAR_WORD, command: Dword / SCALAR_DWORD, value: Dword / FAR_BUFFER]);
w!(WS_TWO_WORDS: [a0: Word / SCALAR_WORD, a1: Word / SCALAR_WORD]);
w!(WS_RECV: [s: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, length: Word / SCALAR_WORD, flags: Word / SCALAR_WORD]);
w!(WS_RECVFROM: [s: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, length: Word / SCALAR_WORD, flags: Word / SCALAR_WORD, address: Dword / FAR_OUTPUT_BUFFER, address_length: Dword / FAR_OUTPUT_BUFFER]);
w!(WS_SELECT: [nfds: Word / SCALAR_WORD, read_set: Dword / FAR_BUFFER, write_set: Dword / FAR_BUFFER, except_set: Dword / FAR_BUFFER, timeout: Dword / FAR_BUFFER]);
w!(WS_SEND: [s: Word / SCALAR_WORD, buffer: Dword / FAR_BUFFER, length: Word / SCALAR_WORD, flags: Word / SCALAR_WORD]);
w!(WS_SENDTO: [s: Word / SCALAR_WORD, buffer: Dword / FAR_BUFFER, length: Word / SCALAR_WORD, flags: Word / SCALAR_WORD, address: Dword / FAR_BUFFER, address_length: Word / SCALAR_WORD]);
w!(WS_SETSOCKOPT: [s: Word / SCALAR_WORD, level: Word / SCALAR_WORD, option: Word / SCALAR_WORD, value: Dword / FAR_BUFFER, value_length: Word / SCALAR_WORD]);
w!(WS_SOCKET: [address_family: Word / SCALAR_WORD, socket_type: Word / SCALAR_WORD, protocol: Word / SCALAR_WORD]);
w!(WS_GETHOSTBYADDR: [address: Dword / FAR_BUFFER, address_length: Word / SCALAR_WORD, address_type: Word / SCALAR_WORD]);
w!(WS_POINTER: [value: Dword / FAR_STRING]);
w!(WS_PROTOCOL_NUMBER: [protocol: Word / SCALAR_WORD]);
w!(WS_TWO_POINTERS: [a0: Dword / FAR_STRING, a1: Dword / FAR_STRING]);
w!(WS_SERVICE_BY_PORT: [port: Word / SCALAR_WORD, protocol: Dword / FAR_STRING]);
w!(WS_GETHOSTNAME: [name: Dword / FAR_OUTPUT_BUFFER, length: Word / SCALAR_WORD]);
w!(WS_ASYNC_SELECT: [s: Word / SCALAR_WORD, window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, events: Dword / SCALAR_DWORD]);
w!(WS_ASYNC_HOST_BY_ADDR: [window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, address: Dword / FAR_BUFFER, address_length: Word / SCALAR_WORD, address_type: Word / SCALAR_WORD, output: Dword / FAR_OUTPUT_BUFFER, output_length: Word / SCALAR_WORD]);
w!(WS_ASYNC_HOST_BY_NAME: [window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, name: Dword / FAR_STRING, output: Dword / FAR_OUTPUT_BUFFER, output_length: Word / SCALAR_WORD]);
w!(WS_ASYNC_PROTO_BY_NUMBER: [window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, protocol: Word / SCALAR_WORD, output: Dword / FAR_OUTPUT_BUFFER, output_length: Word / SCALAR_WORD]);
w!(WS_ASYNC_PROTO_BY_NAME: [window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, name: Dword / FAR_STRING, output: Dword / FAR_OUTPUT_BUFFER, output_length: Word / SCALAR_WORD]);
w!(WS_ASYNC_SERVICE_BY_PORT: [window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, port: Word / SCALAR_WORD, protocol: Dword / FAR_STRING, output: Dword / FAR_OUTPUT_BUFFER, output_length: Word / SCALAR_WORD]);
w!(WS_ASYNC_SERVICE_BY_NAME: [window: Word / SCALAR_WORD, message: Word / SCALAR_WORD, name: Dword / FAR_STRING, protocol: Dword / FAR_STRING, output: Dword / FAR_OUTPUT_BUFFER, output_length: Word / SCALAR_WORD]);
w!(WS_SET_BLOCKING_HOOK: [callback: Dword / Win16ParameterType::FarPointer]);
w!(WS_STARTUP: [version: Word / SCALAR_WORD, data: Dword / FAR_OUTPUT_BUFFER]);
w!(WS_FD_IS_SET: [s: Word / SCALAR_WORD, set: Dword / FAR_BUFFER]);
w!(WS_RECVEX: [s: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, length: Word / SCALAR_WORD, flags: Dword / FAR_OUTPUT_BUFFER]);

// DDEML (all 27 known signatures).
d!(DDE_INITIALIZE: [instance: Dword / FAR_OUTPUT_BUFFER, callback: Dword / Win16ParameterType::FarPointer, flags: Dword / SCALAR_DWORD, reserved: Dword / SCALAR_DWORD]);
d!(DDE_ONE_DWORD: [a0: Dword / SCALAR_DWORD]);
d!(DDE_CONNECT_LIST: [instance: Dword / SCALAR_DWORD, service: Dword / SCALAR_DWORD, topic: Dword / SCALAR_DWORD, list: Dword / SCALAR_DWORD, context: Dword / FAR_BUFFER]);
d!(DDE_TWO_DWORDS: [a0: Dword / SCALAR_DWORD, a1: Dword / SCALAR_DWORD]);
d!(DDE_CONNECT: [instance: Dword / SCALAR_DWORD, service: Dword / SCALAR_DWORD, topic: Dword / SCALAR_DWORD, context: Dword / FAR_BUFFER]);
d!(DDE_QUERY_CONV_INFO: [conversation: Dword / SCALAR_DWORD, transaction: Dword / SCALAR_DWORD, info: Dword / FAR_OUTPUT_BUFFER]);
d!(DDE_THREE_DWORDS: [a0: Dword / SCALAR_DWORD, a1: Dword / SCALAR_DWORD, a2: Dword / SCALAR_DWORD]);
d!(DDE_CLIENT_TRANSACTION: [data: Dword / FAR_BUFFER, data_length: Dword / SCALAR_DWORD, conversation: Dword / SCALAR_DWORD, item: Dword / SCALAR_DWORD, format: Word / SCALAR_WORD, transaction_type: Word / SCALAR_WORD, timeout: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
d!(DDE_CREATE_DATA: [instance: Dword / SCALAR_DWORD, data: Dword / FAR_BUFFER, data_length: Dword / SCALAR_DWORD, offset: Dword / SCALAR_DWORD, item: Dword / SCALAR_DWORD, format: Word / SCALAR_WORD, flags: Word / SCALAR_WORD]);
d!(DDE_ADD_DATA: [data: Dword / SCALAR_DWORD, source: Dword / FAR_BUFFER, data_length: Dword / SCALAR_DWORD, offset: Dword / SCALAR_DWORD]);
d!(DDE_GET_DATA: [data: Dword / SCALAR_DWORD, output: Dword / FAR_OUTPUT_BUFFER, capacity: Dword / SCALAR_DWORD, offset: Dword / SCALAR_DWORD]);
d!(DDE_ACCESS_DATA: [data: Dword / SCALAR_DWORD, size: Dword / FAR_OUTPUT_BUFFER]);
d!(DDE_CREATE_STRING: [instance: Dword / SCALAR_DWORD, value: Dword / FAR_STRING, code_page: Word / SIGNED_SCALAR]);
d!(DDE_QUERY_STRING: [instance: Dword / SCALAR_DWORD, string: Dword / SCALAR_DWORD, output: Dword / FAR_OUTPUT_BUFFER, capacity: Dword / SCALAR_DWORD, code_page: Word / SIGNED_SCALAR]);
d!(DDE_ENABLE_CALLBACK: [instance: Dword / SCALAR_DWORD, conversation: Dword / SCALAR_DWORD, command: Word / SCALAR_WORD]);
d!(DDE_NAME_SERVICE: [instance: Dword / SCALAR_DWORD, service: Dword / SCALAR_DWORD, reserved: Dword / SCALAR_DWORD, command: Word / SCALAR_WORD]);

// NDDEAPI and NETAPI calls with known signatures (unknown NDDE stubs are not
// represented here and therefore cannot be dispatched as calls).
p!(NDDE_SHARE_ADD: [server: Dword / FAR_STRING, level: Word / SCALAR_WORD, info: Dword / FAR_BUFFER, size: Dword / SCALAR_DWORD]);
p!(NDDE_SHARE_DELETE: [server: Dword / FAR_STRING, share: Dword / FAR_STRING, reserved: Word / SCALAR_WORD]);
p!(NDDE_SHARE_ENUM: [server: Dword / FAR_STRING, level: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, size: Dword / SCALAR_DWORD, entries_read: Dword / FAR_OUTPUT_BUFFER, total_entries: Dword / FAR_OUTPUT_BUFFER]);
p!(NDDE_SHARE_GET_INFO: [server: Dword / FAR_STRING, share: Dword / FAR_STRING, level: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, size: Dword / SCALAR_DWORD, entries_read: Dword / FAR_OUTPUT_BUFFER, total_entries: Dword / FAR_OUTPUT_BUFFER]);
p!(NDDE_SHARE_SET_INFO: [server: Dword / FAR_STRING, share: Dword / FAR_STRING, level: Word / SCALAR_WORD, buffer: Dword / FAR_BUFFER, size: Dword / SCALAR_DWORD, reserved: Word / SCALAR_WORD]);
p!(NDDE_GET_CLIENT_INFO: [level: Word / SCALAR_WORD, client_name: Dword / FAR_OUTPUT_BUFFER, client_size: Dword / SCALAR_DWORD, user_name: Dword / FAR_OUTPUT_BUFFER, user_size: Dword / SCALAR_DWORD]);
p!(NDDE_SESSION_ENUM: [server: Dword / FAR_STRING, level: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, size: Dword / SCALAR_DWORD, entries_read: Dword / FAR_OUTPUT_BUFFER, total_entries: Dword / FAR_OUTPUT_BUFFER]);
p!(NDDE_GET_NODE_NAME: [name: Dword / FAR_OUTPUT_BUFFER, size: Dword / SCALAR_DWORD]);
p!(NDDE_GET_ERROR_STRING: [error: Word / SCALAR_WORD, output: Dword / FAR_OUTPUT_BUFFER, capacity: Dword / SCALAR_DWORD]);
p!(NDDE_CONNECTION_ENUM: [server: Dword / FAR_STRING, share: Dword / FAR_STRING, user: Dword / SCALAR_DWORD, level: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, size: Dword / SCALAR_DWORD, entries_read: Dword / FAR_OUTPUT_BUFFER, total_entries: Dword / FAR_OUTPUT_BUFFER]);
p!(NDDE_SESSION_CLOSE: [server: Dword / FAR_STRING, client: Dword / FAR_STRING, session: Dword / SCALAR_DWORD]);
p!(NDDE_ONE_STRING: [value: Dword / FAR_STRING]);
p!(NETAPI_WKSTA_GET_INFO: [server: Dword / Win16ParameterType::NullableFarString, level: Word / SCALAR_WORD, buffer: Dword / FAR_OUTPUT_BUFFER, capacity: Word / SCALAR_WORD, bytes_read: Dword / FAR_OUTPUT_BUFFER]);

