use std::ptr;

use runtime::{
    Win16HostNetworkResult, Win16HostNetworkValue,
    Win16HostSocket, Win16HostSocketOptionEncoding,
};
use windows_sys::Win32::Networking::WinSock::*;

use super::{Win16NetworkHost, fail, nonnegative_length, ok, socket_option_empty};

impl Win16NetworkHost {
    pub(super) fn get_socket_option(
        &mut self,
        socket: Win16HostSocket,
        level: i16,
        option: i16,
        capacity: i16,
        encoding: Win16HostSocketOptionEncoding,
    ) -> Win16HostNetworkResult {
        let Some(raw) = self.socket(socket) else {
            return fail(WSAENOTSOCK, socket_option_empty());
        };
        let Some(capacity) = nonnegative_length(capacity) else {
            return fail(WSAEINVAL, socket_option_empty());
        };
        if level as u16 == SOL_SOCKET as u16 && option as u16 == SO_ERROR as u16 {
            if encoding != Win16HostSocketOptionEncoding::Win16SignedInt {
                return fail(WSAEINVAL, socket_option_empty());
            }
            if capacity < 2 { return fail(WSAEFAULT, socket_option_empty()); }
            // The WinSock 1.1 SDK's FAR `int *` is a 16-bit guest int; the
            // Win32 provider's native `int` is 32 bits. Stage the native result
            // and let Runtime commit the narrowed guest value before ACK.
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(4).is_err() {
                return fail(WSAENOBUFS, socket_option_empty());
            }
            return match self.async_state.read_socket_error(socket, raw) {
                Ok((value, token)) => {
                    bytes.extend_from_slice(&value.to_ne_bytes());
                    ok(Win16HostNetworkValue::SocketOptionPendingRead { bytes, required: 4, token })
                }
                Err(error) => fail(error, socket_option_empty()),
            };
        }

        let (mut bytes, mut length) = match encoding {
            Win16HostSocketOptionEncoding::Win16SignedInt => {
                if capacity < 2 { return fail(WSAEFAULT, socket_option_empty()); }
                (vec![0u8; 4], 4i32)
            }
            Win16HostSocketOptionEncoding::Opaque =>
                (vec![0u8; capacity as usize], capacity),
        };
        let output = if bytes.is_empty() { ptr::null_mut() } else { bytes.as_mut_ptr().cast() };
        let result = unsafe {
            getsockopt(raw, i32::from(level as u16), i32::from(option), output, &mut length)
        };
        if result == SOCKET_ERROR { return fail(unsafe { WSAGetLastError() }, socket_option_empty()); }
        let written = match encoding {
            Win16HostSocketOptionEncoding::Win16SignedInt => {
                if length != 4 { return fail(WSAEINVAL, socket_option_empty()); }
                4
            }
            Win16HostSocketOptionEncoding::Opaque => length.clamp(0, capacity) as usize,
        };
        bytes.truncate(written);
        ok(Win16HostNetworkValue::SocketOption { bytes, required: length.max(0) })
    }

    pub(super) fn acknowledge_socket_error(
        &mut self,
        token: runtime::Win16HostSocketErrorReadToken,
    ) -> Win16HostNetworkResult {
        self.async_state.acknowledge_socket_error(token)
    }
}
