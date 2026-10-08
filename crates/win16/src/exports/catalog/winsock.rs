//! Win16 Winsock 1.x parameter layouts only.
//!
//! This file stays separate from `network.rs`, whose records also describe
//! DDEML and network-administration exports with distinct request owners.

use super::*;

macro_rules! params {
    ($name:ident: [$($arg:ident: $kind:ident / $role:expr),* $(,)?]) => {
        pub(super) const $name: &[Win16Parameter] = &[
            $(Win16Parameter {
                name: stringify!($arg),
                kind: ArgumentKind::$kind,
                parameter_type: $role,
            },)*
        ];
    };
}

const W: Win16ParameterType = Win16ParameterType::Scalar;
const S: Win16ParameterType = Win16ParameterType::SignedScalar;
const P: Win16ParameterType = Win16ParameterType::FarPointer;
const IN: Win16ParameterType = Win16ParameterType::FarBuffer;
const OUT: Win16ParameterType = Win16ParameterType::FarOutputBuffer;
const STR: Win16ParameterType = Win16ParameterType::FarString;

params!(ACCEPT: [socket: Word / W, address: Dword / OUT, address_length: Dword / OUT]);
params!(ADDRESS: [socket: Word / W, address: Dword / IN, length: Word / S]);
params!(SOCKET: [socket: Word / W]);
params!(ADDRESS_OUT: [socket: Word / W, address: Dword / OUT, length: Dword / OUT]);
params!(GET_OPTION: [socket: Word / W, level: Word / S, option: Word / S, value: Dword / OUT, value_length: Dword / OUT]);
params!(LONG: [value: Dword / W]);
params!(WORD: [value: Word / W]);
params!(INET_ADDRESS: [address: Dword / STR]);
params!(IOCTL: [socket: Word / W, command: Dword / S, value: Dword / OUT]);
params!(TWO_SIGNED: [first: Word / S, second: Word / S]);
params!(RECEIVE: [socket: Word / W, buffer: Dword / OUT, length: Word / S, flags: Word / S]);
params!(RECEIVE_FROM: [socket: Word / W, buffer: Dword / OUT, length: Word / S, flags: Word / S, address: Dword / OUT, address_length: Dword / OUT]);
params!(SELECT: [nfds: Word / S, read_set: Dword / IN, write_set: Dword / IN, except_set: Dword / IN, timeout: Dword / IN]);
params!(SEND: [socket: Word / W, buffer: Dword / IN, length: Word / S, flags: Word / S]);
params!(SEND_TO: [socket: Word / W, buffer: Dword / IN, length: Word / S, flags: Word / S, address: Dword / IN, address_length: Word / S]);
params!(SET_OPTION: [socket: Word / W, level: Word / S, option: Word / S, value: Dword / IN, value_length: Word / S]);
params!(SOCKET_CREATE: [address_family: Word / S, socket_type: Word / S, protocol: Word / S]);
params!(HOST_BY_ADDRESS: [address: Dword / IN, length: Word / S, address_type: Word / S]);
params!(STRING: [value: Dword / STR]);
params!(PROTOCOL_NUMBER: [protocol: Word / S]);
params!(TWO_STRINGS: [first: Dword / STR, second: Dword / STR]);
params!(SERVICE_BY_PORT: [port: Word / W, protocol: Dword / STR]);
params!(GET_HOST_NAME: [buffer: Dword / OUT, length: Word / S]);
params!(ASYNC_SELECT: [socket: Word / W, window: Word / W, message: Word / W, events: Dword / W]);
params!(ASYNC_HOST_BY_ADDRESS: [window: Word / W, message: Word / W, address: Dword / IN, address_length: Word / S, address_type: Word / S, output: Dword / OUT, output_length: Word / S]);
params!(ASYNC_HOST_BY_NAME: [window: Word / W, message: Word / W, name: Dword / STR, output: Dword / OUT, output_length: Word / S]);
params!(ASYNC_PROTOCOL_NUMBER: [window: Word / W, message: Word / W, protocol: Word / S, output: Dword / OUT, output_length: Word / S]);
params!(ASYNC_PROTOCOL_NAME: [window: Word / W, message: Word / W, name: Dword / STR, output: Dword / OUT, output_length: Word / S]);
params!(ASYNC_SERVICE_PORT: [window: Word / W, message: Word / W, port: Word / W, protocol: Dword / STR, output: Dword / OUT, output_length: Word / S]);
params!(ASYNC_SERVICE_NAME: [window: Word / W, message: Word / W, name: Dword / STR, protocol: Dword / STR, output: Dword / OUT, output_length: Word / S]);
params!(BLOCKING_HOOK: [callback: Dword / P]);
params!(STARTUP: [version: Word / W, data: Dword / OUT]);
params!(FD_IS_SET: [socket: Word / W, set: Dword / IN]);
params!(RECEIVE_EX: [socket: Word / W, buffer: Dword / OUT, length: Word / S, flags: Dword / OUT]);
