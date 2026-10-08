//! Owned DDEML call descriptions. Handle fields are guest tokens; callbacks
//! remain guest FARPROC values for runtime-owned callback scheduling.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16DdeBuffer {
    pub far_pointer: u32,
    pub capacity: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16DdeTransactionData {
    None,
    /// Bytes copied from guest memory before a host DDE call.
    Bytes(Vec<u8>),
    /// The `pData` argument is a DDE data-handle token when `cbData == -1`.
    /// This value must be resolved by the runtime before a host call.
    DataHandle(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16DdeRequest {
    Initialize { instance_output: u32, initial_instance: u32, callback: u32, flags: u32, reserved: u32 },
    Uninitialize { instance: u32 },
    ConnectList { instance: u32, service: u32, topic: u32, list: u32, context: Option<Vec<u8>> },
    QueryNextServer { list: u32, previous: u32 },
    DisconnectList { list: u32 },
    Connect { instance: u32, service: Option<u32>, topic: Option<u32>, context: Option<Vec<u8>> },
    Disconnect { conversation: u32 },
    QueryConversationInfo { conversation: u32, transaction: u32, output: u32, guest_size: u32 },
    SetUserHandle { conversation: u32, transaction: u32, user_data: u32 },
    ClientTransaction {
        data: Win16DdeTransactionData,
        conversation: u32,
        item: u32,
        format: u16,
        transaction_type: u16,
        timeout: u32,
        result_output: u32,
    },
    AbandonTransaction { instance: u32, conversation: Option<u32>, transaction: u32 },
    PostAdvise { instance: u32, topic: Option<u32>, item: Option<u32> },
    CreateData { instance: u32, data: Option<Vec<u8>>, count: u32, offset: u32, item: u32, format: u16, flags: u16 },
    AddData { data: u32, bytes: Vec<u8>, offset: u32 },
    GetData { data: u32, output: Win16DdeBuffer, offset: u32 },
    AccessData { data: u32, size_output: u32 },
    UnaccessData { data: u32 },
    FreeData { data: u32 },
    GetLastError { instance: u32 },
    CreateString { instance: u32, value: Vec<u8>, code_page: i16 },
    FreeString { instance: u32, string: u32 },
    QueryString { instance: u32, string: u32, output: Win16DdeBuffer, code_page: i16 },
    KeepString { instance: u32, string: u32 },
    EnableCallback { instance: u32, conversation: u32, command: u16 },
    NameService { instance: u32, service: u32, reserved: u32, command: u16 },
    CompareStrings { left: u32, right: u32 },
    Reconnect { conversation: u32 },
}
