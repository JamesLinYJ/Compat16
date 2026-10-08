//! Guest socket handle creation and close lifetime.

use compat_services::win16_network::{WSAENOBUFS, WSAENOTSOCK};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostNetworkCall, Win16HostNetworkValue, Win16NetworkTaskIdentity,
};
use super::Win16State;

impl Win16State {
    pub(super) fn winsock_create_socket(
        &mut self,
        task: u16,
        task_identity: Win16NetworkTaskIdentity,
        address_family: i16,
        socket_type: i16,
        protocol: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if !self.network.has_free_guest_socket()
            || self.network.reserve_orphan_sockets(1).is_err()
        {
            return Ok(self.fail_int(task, WSAENOBUFS));
        }
        let result = host.win16_network(Win16HostNetworkCall::CreateSocket {
            task: task_identity, address_family, socket_type, protocol,
        })?;
        if result.wsa_error != 0 {
            return Ok(self.result_error(task, result.wsa_error, super::SOCKET_ERROR_WORD));
        }
        let Win16HostNetworkValue::Socket(Some(socket)) = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock socket creation succeeded without a socket token"));
        };
        if let Some(guest) = self.network.add_socket(socket, task_identity) {
            return Ok(u32::from(guest));
        }
        if !self.retire_unpublished_socket(task_identity, socket, host) {
            host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                "WinSock created a socket without a guest handle and native rollback remains owned for teardown"));
        }
        Ok(self.fail_int(task, WSAENOBUFS))
    }

    pub(super) fn winsock_close_socket(
        &mut self,
        task: u16,
        guest_socket: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let Some(owner) = self.network.socket_owner(guest_socket) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock guest socket lost its captured task identity"));
        };
        if self.network.async_select_route(guest_socket).is_some()
            && self.network.reserve_retired_async_selects(1).is_err()
        {
            return Ok(self.fail_int(task, WSAENOBUFS));
        }
        let result = host.win16_network(Win16HostNetworkCall::CloseSocket { socket, owner })?;
        if result.wsa_error != 0 {
            return Ok(self.result_error(task, result.wsa_error, super::SOCKET_ERROR_WORD));
        }
        let value = Self::expect_signed(result.value)?;
        if value == -1 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock close returned SOCKET_ERROR without an error code"));
        }
        if self.network.close_socket(guest_socket)? != Some(socket) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock guest socket identity changed during close"));
        }
        Ok(Self::int_return(value))
    }
}
