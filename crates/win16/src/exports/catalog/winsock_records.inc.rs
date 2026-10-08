// The 49 declared WINSOCK ordinals are bound independently of DDEML and
// network-administration exports, whose ABI owners remain separate.
macro_rules! export_catalog_with_winsock {
    ($($existing:tt)*) => {
        export_catalog_with_ole2nls! {
            $($existing)*
            WinsockAccept => WINSOCK_ACCEPT: ("WINSOCK", 1u16, Stack, winsock::ACCEPT, Word);
            WinsockBind => WINSOCK_BIND: ("WINSOCK", 2u16, Stack, winsock::ADDRESS, Word);
            WinsockCloseSocket => WINSOCK_CLOSE_SOCKET: ("WINSOCK", 3u16, Stack, winsock::SOCKET, Word);
            WinsockConnect => WINSOCK_CONNECT: ("WINSOCK", 4u16, Stack, winsock::ADDRESS, Word);
            WinsockGetPeerName => WINSOCK_GET_PEER_NAME: ("WINSOCK", 5u16, Stack, winsock::ADDRESS_OUT, Word);
            WinsockGetSocketName => WINSOCK_GET_SOCKET_NAME: ("WINSOCK", 6u16, Stack, winsock::ADDRESS_OUT, Word);
            WinsockGetSocketOption => WINSOCK_GET_SOCKET_OPTION: ("WINSOCK", 7u16, Stack, winsock::GET_OPTION, Word);
            WinsockHostToNetworkLong => WINSOCK_HOST_TO_NETWORK_LONG: ("WINSOCK", 8u16, Stack, winsock::LONG, Dword);
            WinsockHostToNetworkShort => WINSOCK_HOST_TO_NETWORK_SHORT: ("WINSOCK", 9u16, Stack, winsock::WORD, Word);
            WinsockInetAddress => WINSOCK_INET_ADDRESS: ("WINSOCK", 10u16, Stack, winsock::INET_ADDRESS, Dword);
            WinsockInetName => WINSOCK_INET_NAME: ("WINSOCK", 11u16, Stack, winsock::LONG, FarPointer);
            WinsockIoctlSocket => WINSOCK_IOCTL_SOCKET: ("WINSOCK", 12u16, Stack, winsock::IOCTL, Word);
            WinsockListen => WINSOCK_LISTEN: ("WINSOCK", 13u16, Stack, winsock::TWO_SIGNED, Word);
            WinsockNetworkToHostLong => WINSOCK_NETWORK_TO_HOST_LONG: ("WINSOCK", 14u16, Stack, winsock::LONG, Dword);
            WinsockNetworkToHostShort => WINSOCK_NETWORK_TO_HOST_SHORT: ("WINSOCK", 15u16, Stack, winsock::WORD, Word);
            WinsockReceive => WINSOCK_RECEIVE: ("WINSOCK", 16u16, Stack, winsock::RECEIVE, Word);
            WinsockReceiveFrom => WINSOCK_RECEIVE_FROM: ("WINSOCK", 17u16, Stack, winsock::RECEIVE_FROM, Word);
            WinsockSelect => WINSOCK_SELECT: ("WINSOCK", 18u16, Stack, winsock::SELECT, Word);
            WinsockSend => WINSOCK_SEND: ("WINSOCK", 19u16, Stack, winsock::SEND, Word);
            WinsockSendTo => WINSOCK_SEND_TO: ("WINSOCK", 20u16, Stack, winsock::SEND_TO, Word);
            WinsockSetSocketOption => WINSOCK_SET_SOCKET_OPTION: ("WINSOCK", 21u16, Stack, winsock::SET_OPTION, Word);
            WinsockShutdown => WINSOCK_SHUTDOWN: ("WINSOCK", 22u16, Stack, winsock::TWO_SIGNED, Word);
            WinsockCreateSocket => WINSOCK_CREATE_SOCKET: ("WINSOCK", 23u16, Stack, winsock::SOCKET_CREATE, Word);
            WinsockGetHostByAddress => WINSOCK_GET_HOST_BY_ADDRESS: ("WINSOCK", 51u16, Stack, winsock::HOST_BY_ADDRESS, FarPointer);
            WinsockGetHostByName => WINSOCK_GET_HOST_BY_NAME: ("WINSOCK", 52u16, Stack, winsock::STRING, FarPointer);
            WinsockGetProtocolByName => WINSOCK_GET_PROTOCOL_BY_NAME: ("WINSOCK", 53u16, Stack, winsock::STRING, FarPointer);
            WinsockGetProtocolByNumber => WINSOCK_GET_PROTOCOL_BY_NUMBER: ("WINSOCK", 54u16, Stack, winsock::PROTOCOL_NUMBER, FarPointer);
            WinsockGetServiceByName => WINSOCK_GET_SERVICE_BY_NAME: ("WINSOCK", 55u16, Stack, winsock::TWO_STRINGS, FarPointer);
            WinsockGetServiceByPort => WINSOCK_GET_SERVICE_BY_PORT: ("WINSOCK", 56u16, Stack, winsock::SERVICE_BY_PORT, FarPointer);
            WinsockGetHostName => WINSOCK_GET_HOST_NAME: ("WINSOCK", 57u16, Stack, winsock::GET_HOST_NAME, Word);
            WinsockAsyncSelect => WINSOCK_ASYNC_SELECT: ("WINSOCK", 101u16, Stack, winsock::ASYNC_SELECT, Word);
            WinsockAsyncGetHostByAddress => WINSOCK_ASYNC_GET_HOST_BY_ADDRESS: ("WINSOCK", 102u16, Stack, winsock::ASYNC_HOST_BY_ADDRESS, Word);
            WinsockAsyncGetHostByName => WINSOCK_ASYNC_GET_HOST_BY_NAME: ("WINSOCK", 103u16, Stack, winsock::ASYNC_HOST_BY_NAME, Word);
            WinsockAsyncGetProtocolByNumber => WINSOCK_ASYNC_GET_PROTOCOL_BY_NUMBER: ("WINSOCK", 104u16, Stack, winsock::ASYNC_PROTOCOL_NUMBER, Word);
            WinsockAsyncGetProtocolByName => WINSOCK_ASYNC_GET_PROTOCOL_BY_NAME: ("WINSOCK", 105u16, Stack, winsock::ASYNC_PROTOCOL_NAME, Word);
            WinsockAsyncGetServiceByPort => WINSOCK_ASYNC_GET_SERVICE_BY_PORT: ("WINSOCK", 106u16, Stack, winsock::ASYNC_SERVICE_PORT, Word);
            WinsockAsyncGetServiceByName => WINSOCK_ASYNC_GET_SERVICE_BY_NAME: ("WINSOCK", 107u16, Stack, winsock::ASYNC_SERVICE_NAME, Word);
            WinsockCancelAsyncRequest => WINSOCK_CANCEL_ASYNC_REQUEST: ("WINSOCK", 108u16, Stack, winsock::WORD, Word);
            WinsockSetBlockingHook => WINSOCK_SET_BLOCKING_HOOK: ("WINSOCK", 109u16, Stack, winsock::BLOCKING_HOOK, FarPointer);
            WinsockUnhookBlockingHook => WINSOCK_UNHOOK_BLOCKING_HOOK: ("WINSOCK", 110u16, Stack, &[], Word);
            WinsockGetLastError => WINSOCK_GET_LAST_ERROR: ("WINSOCK", 111u16, Stack, &[], Word);
            WinsockSetLastError => WINSOCK_SET_LAST_ERROR: ("WINSOCK", 112u16, Stack, winsock::WORD, Void);
            WinsockCancelBlockingCall => WINSOCK_CANCEL_BLOCKING_CALL: ("WINSOCK", 113u16, Stack, &[], Word);
            WinsockIsBlocking => WINSOCK_IS_BLOCKING: ("WINSOCK", 114u16, Stack, &[], Word);
            WinsockStartup => WINSOCK_STARTUP: ("WINSOCK", 115u16, Stack, winsock::STARTUP, Word);
            WinsockCleanup => WINSOCK_CLEANUP: ("WINSOCK", 116u16, Stack, &[], Word);
            WinsockFdIsSet => WINSOCK_FD_IS_SET: ("WINSOCK", 151u16, Stack, winsock::FD_IS_SET, Word);
            WinsockReceiveEx => WINSOCK_RECEIVE_EX: ("WINSOCK", 1107u16, Stack, winsock::RECEIVE_EX, Word);
            WinsockDefaultHook => WINSOCK_DEFAULT_HOOK: ("WINSOCK", 2000u16, Stack, &[], Word);
        }
    };
}
