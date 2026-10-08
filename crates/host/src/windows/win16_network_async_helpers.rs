//! Low-level identities and nonblocking socket probes for the async owner.

use std::sync::atomic::{AtomicU64, Ordering};

use runtime::{
    DiagnosticKind, RuntimeError, Win16GuestNotificationSource,
    Win16HostNetworkEvent, Win16HostNetworkValue,
};
use windows_sys::Win32::Networking::WinSock::*;

#[derive(Debug)]
pub(super) struct SocketProbeError(pub i32);

impl std::fmt::Display for SocketProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Winsock error {} while reading SO_ERROR", self.0)
    }
}

impl std::error::Error for SocketProbeError {}

pub(super) fn allocate_source_id(identity_source: &AtomicU64) -> Option<u64> {
    loop {
        let current = identity_source.load(Ordering::Acquire);
        if current == 0 || current == u64::MAX { return None; }
        let next = current.checked_add(1)?;
        if next == 0 { return None; }
        if identity_source.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return Some(current);
        }
    }
}

pub(super) fn event_source(event: &Win16HostNetworkEvent) -> Win16GuestNotificationSource {
    match event {
        Win16HostNetworkEvent::SocketReady { source, .. }
        | Win16HostNetworkEvent::AsyncQueryComplete { source, .. } => *source,
    }
}

pub(super) fn socket_error(raw: SOCKET) -> Result<i32, i32> {
    let mut error = 0i32;
    let mut length = std::mem::size_of::<i32>() as i32;
    let result = unsafe {
        getsockopt(raw, SOL_SOCKET, SO_ERROR, (&mut error as *mut i32).cast(), &mut length)
    };
    if result == SOCKET_ERROR { Err(unsafe { WSAGetLastError() }) }
    else { Ok(error) }
}

pub(super) fn socket_peek_status(raw: SOCKET) -> Result<Option<usize>, i32> {
    let mut byte = 0u8;
    let result = unsafe { recv(raw, (&mut byte as *mut u8).cast(), 1, MSG_PEEK) };
    if result >= 0 { Ok(Some(result as usize)) }
    else {
        let error = unsafe { WSAGetLastError() };
        if error == WSAEWOULDBLOCK { Ok(None) } else { Err(error) }
    }
}

pub(super) fn signed_error() -> Win16HostNetworkValue {
    Win16HostNetworkValue::Signed(SOCKET_ERROR)
}

pub(super) fn network_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(DiagnosticKind::InternalInvariant, message)
}
