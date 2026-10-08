// Typed bindings for the complete known DDEML export surface.
macro_rules! export_catalog_with_dde {
    ($($existing:tt)*) => {
        export_catalog_with_user_cursor_accelerators! {
            $($existing)*
            DdeInitialize => DDEML_INITIALIZE: ("DDEML", 2u16, Stack, dde::INITIALIZE, Word);
            DdeUninitialize => DDEML_UNINITIALIZE: ("DDEML", 3u16, Stack, dde::ONE_DWORD, Word);
            DdeConnectList => DDEML_CONNECT_LIST: ("DDEML", 4u16, Stack, dde::CONNECT_LIST, Dword);
            DdeQueryNextServer => DDEML_QUERY_NEXT_SERVER: ("DDEML", 5u16, Stack, dde::TWO_DWORDS, Dword);
            DdeDisconnectList => DDEML_DISCONNECT_LIST: ("DDEML", 6u16, Stack, dde::ONE_DWORD, Word);
            DdeConnect => DDEML_CONNECT: ("DDEML", 7u16, Stack, dde::CONNECT, Dword);
            DdeDisconnect => DDEML_DISCONNECT: ("DDEML", 8u16, Stack, dde::ONE_DWORD, Word);
            DdeQueryConvInfo => DDEML_QUERY_CONV_INFO: ("DDEML", 9u16, Stack, dde::QUERY_CONVERSATION_INFO, Word);
            DdeSetUserHandle => DDEML_SET_USER_HANDLE: ("DDEML", 10u16, Stack, dde::THREE_DWORDS, Word);
            DdeClientTransaction => DDEML_CLIENT_TRANSACTION: ("DDEML", 11u16, Stack, dde::CLIENT_TRANSACTION, Dword);
            DdeAbandonTransaction => DDEML_ABANDON_TRANSACTION: ("DDEML", 12u16, Stack, dde::THREE_DWORDS, Word);
            DdePostAdvise => DDEML_POST_ADVISE: ("DDEML", 13u16, Stack, dde::THREE_DWORDS, Word);
            DdeCreateDataHandle => DDEML_CREATE_DATA_HANDLE: ("DDEML", 14u16, Stack, dde::CREATE_DATA, Dword);
            DdeAddData => DDEML_ADD_DATA: ("DDEML", 15u16, Stack, dde::ADD_DATA, Dword);
            DdeGetData => DDEML_GET_DATA: ("DDEML", 16u16, Stack, dde::GET_DATA, Dword);
            DdeAccessData => DDEML_ACCESS_DATA: ("DDEML", 17u16, Stack, dde::ACCESS_DATA, FarPointer);
            DdeUnaccessData => DDEML_UNACCESS_DATA: ("DDEML", 18u16, Stack, dde::ONE_DWORD, Word);
            DdeFreeDataHandle => DDEML_FREE_DATA_HANDLE: ("DDEML", 19u16, Stack, dde::ONE_DWORD, Word);
            DdeGetLastError => DDEML_GET_LAST_ERROR: ("DDEML", 20u16, Stack, dde::ONE_DWORD, Word);
            DdeCreateStringHandle => DDEML_CREATE_STRING_HANDLE: ("DDEML", 21u16, Stack, dde::CREATE_STRING, Dword);
            DdeFreeStringHandle => DDEML_FREE_STRING_HANDLE: ("DDEML", 22u16, Stack, dde::TWO_DWORDS, Word);
            DdeQueryString => DDEML_QUERY_STRING: ("DDEML", 23u16, Stack, dde::QUERY_STRING, Dword);
            DdeKeepStringHandle => DDEML_KEEP_STRING_HANDLE: ("DDEML", 24u16, Stack, dde::TWO_DWORDS, Word);
            DdeEnableCallback => DDEML_ENABLE_CALLBACK: ("DDEML", 26u16, Stack, dde::ENABLE_CALLBACK, Word);
            DdeNameService => DDEML_NAME_SERVICE: ("DDEML", 27u16, Stack, dde::NAME_SERVICE, Dword);
            DdeCmpStringHandles => DDEML_CMP_STRING_HANDLES: ("DDEML", 36u16, Stack, dde::TWO_DWORDS, Word);
            DdeReconnect => DDEML_RECONNECT: ("DDEML", 37u16, Stack, dde::ONE_DWORD, Dword);
        }
    };
}
