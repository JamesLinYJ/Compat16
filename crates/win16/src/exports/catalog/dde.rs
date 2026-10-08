//! DDEML Win16 stack parameter layouts.

use super::*;

macro_rules! params {
    ($name:ident: [$($arg:ident: $kind:ident / $role:expr),* $(,)?]) => {
        pub(super) const $name: &[Win16Parameter] = &[
            $(Win16Parameter { name: stringify!($arg), kind: ArgumentKind::$kind, parameter_type: $role },)*
        ];
    };
}

params!(INITIALIZE: [instance: Dword / FAR_OUTPUT_BUFFER, callback: Dword / Win16ParameterType::FarPointer, flags: Dword / SCALAR_DWORD, reserved: Dword / SCALAR_DWORD]);
params!(ONE_DWORD: [value: Dword / SCALAR_DWORD]);
params!(CONNECT_LIST: [instance: Dword / SCALAR_DWORD, service: Dword / SCALAR_DWORD, topic: Dword / SCALAR_DWORD, list: Dword / SCALAR_DWORD, context: Dword / FAR_BUFFER]);
params!(TWO_DWORDS: [first: Dword / SCALAR_DWORD, second: Dword / SCALAR_DWORD]);
params!(CONNECT: [instance: Dword / SCALAR_DWORD, service: Dword / SCALAR_DWORD, topic: Dword / SCALAR_DWORD, context: Dword / FAR_BUFFER]);
params!(QUERY_CONVERSATION_INFO: [conversation: Dword / SCALAR_DWORD, transaction: Dword / SCALAR_DWORD, info: Dword / FAR_OUTPUT_BUFFER]);
params!(THREE_DWORDS: [first: Dword / SCALAR_DWORD, second: Dword / SCALAR_DWORD, third: Dword / SCALAR_DWORD]);
params!(CLIENT_TRANSACTION: [data: Dword / FAR_BUFFER, data_length: Dword / SCALAR_DWORD, conversation: Dword / SCALAR_DWORD, item: Dword / SCALAR_DWORD, format: Word / SCALAR_WORD, transaction_type: Word / SCALAR_WORD, timeout: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
params!(CREATE_DATA: [instance: Dword / SCALAR_DWORD, data: Dword / FAR_BUFFER, data_length: Dword / SCALAR_DWORD, offset: Dword / SCALAR_DWORD, item: Dword / SCALAR_DWORD, format: Word / SCALAR_WORD, flags: Word / SCALAR_WORD]);
params!(ADD_DATA: [data: Dword / SCALAR_DWORD, source: Dword / FAR_BUFFER, data_length: Dword / SCALAR_DWORD, offset: Dword / SCALAR_DWORD]);
params!(GET_DATA: [data: Dword / SCALAR_DWORD, output: Dword / FAR_OUTPUT_BUFFER, capacity: Dword / SCALAR_DWORD, offset: Dword / SCALAR_DWORD]);
params!(ACCESS_DATA: [data: Dword / SCALAR_DWORD, size: Dword / FAR_OUTPUT_BUFFER]);
params!(CREATE_STRING: [instance: Dword / SCALAR_DWORD, value: Dword / FAR_STRING, code_page: Word / SIGNED_SCALAR]);
params!(QUERY_STRING: [instance: Dword / SCALAR_DWORD, string: Dword / SCALAR_DWORD, output: Dword / FAR_OUTPUT_BUFFER, capacity: Dword / SCALAR_DWORD, code_page: Word / SIGNED_SCALAR]);
params!(ENABLE_CALLBACK: [instance: Dword / SCALAR_DWORD, conversation: Dword / SCALAR_DWORD, command: Word / SCALAR_WORD]);
params!(NAME_SERVICE: [instance: Dword / SCALAR_DWORD, service: Dword / SCALAR_DWORD, reserved: Dword / SCALAR_DWORD, command: Word / SCALAR_WORD]);
