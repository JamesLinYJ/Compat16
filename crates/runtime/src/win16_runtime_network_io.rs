//! Socket data transfer and select helpers for the synchronous WinSock bridge.

use compat_services::win16_network::{FdSet16, WSAEFAULT, WSAEINVAL, WSAENOTSOCK};
use guest_core::memory::Memory;
use win16_abi::{Win16GuestInOutBuffer, Win16SelectInput, Win16SocketSetInput};

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostNetworkCall,
    Win16HostNetworkValue, Win16HostSocket,
};
use super::{PreparedFdSet, SetPrepareError, Win16State};
use super::super::guest_ranges::GuestOutputRange;

impl Win16State {
    pub(super) fn rearm_async_events(
        &self,
        guest_socket: u16,
        socket: Win16HostSocket,
        requested_events: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(route) = self.network.async_select_route(guest_socket) else {
            return Ok(());
        };
        if route.socket != socket || self.network.host_socket(guest_socket) != Some(socket) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock rearm no longer matches the captured socket incarnation"));
        }
        let events = route.events & requested_events;
        if events == 0 { return Ok(()); }
        let result = host.win16_network(Win16HostNetworkCall::RearmAsyncEvent {
            socket,
            source_id: route.source_id,
            registration_generation: route.registration_generation,
            events,
        })?;
        if result.wsa_error != 0 {
            return Err(RuntimeError::with_source(Kind::HostFailure,
                "WinSock reenabling call could not restore its exact async registration",
                WinsockRearmError(result.wsa_error)));
        }
        if !matches!(result.value, Win16HostNetworkValue::Signed(0)) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock async rearm returned an unexpected value"));
        }
        Ok(())
    }

    pub(super) fn winsock_receive(
        &mut self,
        task: u16,
        guest_socket: u16,
        output_far: u32,
        raw_capacity: u16,
        flags: i16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let (capacity, output) = match self.capture_buffer(memory, output_far, raw_capacity) {
            Ok(value) => value,
            Err(error) => {
                let wsa_error = Self::map_range_error(error)?;
                if let Err(rearm) = self.rearm_async_events(
                    guest_socket, socket, 0x0001 | 0x0004, host,
                ) { host.report_diagnostic(rearm.diagnostic()); }
                return Ok(self.fail_int(task, wsa_error));
            }
        };
        let result = self.win16_network_call_with_blocking(
            task,
            Win16HostNetworkCall::Receive { socket, capacity, flags },
            host,
        )?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32)); }
        let Win16HostNetworkValue::Bytes { bytes, count } = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock receive returned an unexpected host result"));
        };
        if count < 0 || usize::try_from(count).ok() != Some(bytes.len()) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock receive byte count disagrees with its copied buffer"));
        }
        if let Some(output) = output {
            if let Err(error) = self.commit_outputs(memory, vec![(output, bytes)]) {
                return Ok(self.fail_int(task, Self::map_range_error(error)?));
            }
        }
        Ok(Self::int_return(count))
    }

    pub(super) fn winsock_receive_from(
        &mut self,
        task: u16,
        guest_socket: u16,
        output_far: u32,
        raw_capacity: u16,
        flags: i16,
        address: Option<Win16GuestInOutBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let (capacity, output) = match self.capture_buffer(memory, output_far, raw_capacity) {
            Ok(value) => value,
            Err(error) => {
                let wsa_error = Self::map_range_error(error)?;
                if let Err(rearm) = self.rearm_async_events(
                    guest_socket, socket, 0x0001 | 0x0004, host,
                ) { host.report_diagnostic(rearm.diagnostic()); }
                return Ok(self.fail_int(task, wsa_error));
            }
        };
        let prepared = match address {
            Some(value) => match self.capture_inout(memory, value.buffer_far, value.length_pointer) {
                Ok(value) => Some(value),
                Err(error) => {
                    let wsa_error = Self::map_range_error(error)?;
                    if let Err(rearm) = self.rearm_async_events(
                        guest_socket, socket, 0x0001 | 0x0004, host,
                    ) { host.report_diagnostic(rearm.diagnostic()); }
                    return Ok(self.fail_int(task, wsa_error));
                }
            },
            None => None,
        };
        let result = self.win16_network_call_with_blocking(
            task,
            Win16HostNetworkCall::ReceiveFrom {
                socket, capacity, flags,
                address_capacity: prepared.as_ref().map(|value| value.capacity),
            },
            host,
        )?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32)); }
        let Win16HostNetworkValue::ReceivedFrom { bytes, count, address, required } = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock recvfrom returned an unexpected host result"));
        };
        if count < 0 || usize::try_from(count).ok() != Some(bytes.len()) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock recvfrom count disagrees with its copied buffer"));
        }
        let mut writes = Vec::new();
        if let Some(output) = output { writes.push((output, bytes)); }
        if let Some(prepared) = prepared { writes.extend(Self::inout_writes(prepared, address, required)?); }
        if let Err(error) = self.commit_outputs(memory, writes) {
            return Ok(self.fail_int(task, Self::map_range_error(error)?));
        }
        Ok(Self::int_return(count))
    }

    pub(super) fn winsock_receive_ex(
        &mut self,
        task: u16,
        guest_socket: u16,
        output_far: u32,
        raw_capacity: u16,
        flags_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let (capacity, output) = match self.capture_buffer(memory, output_far, raw_capacity) {
            Ok(value) => value,
            Err(error) => {
                let wsa_error = Self::map_range_error(error)?;
                if let Err(rearm) = self.rearm_async_events(
                    guest_socket, socket, 0x0001 | 0x0004, host,
                ) { host.report_diagnostic(rearm.diagnostic()); }
                return Ok(self.fail_int(task, wsa_error));
            }
        };
        let flags = match self.capture_network_output(memory, flags_far, 2) {
            Ok(Some(value)) => value,
            Ok(None) => {
                if let Err(rearm) = self.rearm_async_events(
                    guest_socket, socket, 0x0001 | 0x0004, host,
                ) { host.report_diagnostic(rearm.diagnostic()); }
                return Ok(self.fail_int(task, WSAEFAULT));
            }
            Err(error) => {
                let wsa_error = Self::map_range_error(error)?;
                if let Err(rearm) = self.rearm_async_events(
                    guest_socket, socket, 0x0001 | 0x0004, host,
                ) { host.report_diagnostic(rearm.diagnostic()); }
                return Ok(self.fail_int(task, wsa_error));
            }
        };
        let result = self.win16_network_call_with_blocking(
            task,
            Win16HostNetworkCall::ReceiveEx { socket, capacity },
            host,
        )?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32)); }
        let Win16HostNetworkValue::ReceiveEx { bytes, count, flags: output_flags } = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock receive-ex returned an unexpected host result"));
        };
        if count < 0 || usize::try_from(count).ok() != Some(bytes.len()) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock receive-ex count disagrees with its copied buffer"));
        }
        let mut writes = vec![(flags, output_flags.to_le_bytes().to_vec())];
        if let Some(output) = output { writes.push((output, bytes)); }
        if let Err(error) = self.commit_outputs(memory, writes) {
            return Ok(self.fail_int(task, Self::map_range_error(error)?));
        }
        Ok(Self::int_return(count))
    }

    pub(super) fn winsock_hostname(
        &mut self,
        task: u16,
        output_far: u32,
        raw_capacity: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let (capacity, output) = match self.capture_buffer(memory, output_far, raw_capacity) {
            Ok(value) => value,
            Err(error) => return Ok(self.fail_int(task, Self::map_range_error(error)?)),
        };
        let result = host.win16_network(Win16HostNetworkCall::GetHostName { capacity })?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32)); }
        let Win16HostNetworkValue::HostName(bytes) = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock gethostname returned an unexpected host result"));
        };
        if bytes.len() > usize::try_from(capacity).unwrap_or(0) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock gethostname exceeded the captured guest capacity"));
        }
        if let Some(output) = output {
            if let Err(error) = self.commit_outputs(memory, vec![(output, bytes)]) {
                return Ok(self.fail_int(task, Self::map_range_error(error)?));
            }
        }
        Ok(0)
    }

    fn prepare_fd_set(
        &self,
        memory: &Memory,
        input: Win16SocketSetInput,
    ) -> Result<PreparedFdSet, SetPrepareError> {
        let Win16SocketSetInput::Encoded { far_pointer, bytes } = input else {
            return Ok(PreparedFdSet { range: None, sockets: None });
        };
        let range = self.capture_network_output(memory, far_pointer, bytes.len())
            .map_err(|error| match Self::map_range_error(error) {
                Ok(code) => SetPrepareError::Winsock(code),
                Err(error) => SetPrepareError::Runtime(error),
            })?
            .ok_or(SetPrepareError::Winsock(WSAEFAULT))?;
        let decoded = FdSet16::decode(&bytes).map_err(|_| SetPrepareError::Winsock(WSAEINVAL))?;
        let mut sockets = Vec::new();
        sockets.try_reserve_exact(decoded.0.len()).map_err(|error| SetPrepareError::Runtime(
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve mapped WinSock fd_set", error)))?;
        for guest in decoded.0 {
            let Some(socket) = self.network.host_socket(guest) else {
                return Err(SetPrepareError::Winsock(WSAENOTSOCK));
            };
            sockets.push(socket);
        }
        Ok(PreparedFdSet { range: Some(range), sockets: Some(sockets) })
    }

    pub(super) fn winsock_select(
        &mut self,
        task: u16,
        input: Win16SelectInput,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // Winsock ignores the BSD nfds argument, but its Win16 signed width is
        // retained in the decoded request.
        let _nfds = input.nfds;
        let read = match self.prepare_fd_set(memory, input.read) {
            Ok(value) => value,
            Err(SetPrepareError::Winsock(error)) => return Ok(self.fail_int(task, error)),
            Err(SetPrepareError::Runtime(error)) => return Err(error),
        };
        let write = match self.prepare_fd_set(memory, input.write) {
            Ok(value) => value,
            Err(SetPrepareError::Winsock(error)) => return Ok(self.fail_int(task, error)),
            Err(SetPrepareError::Runtime(error)) => return Err(error),
        };
        let except = match self.prepare_fd_set(memory, input.except) {
            Ok(value) => value,
            Err(SetPrepareError::Winsock(error)) => return Ok(self.fail_int(task, error)),
            Err(SetPrepareError::Runtime(error)) => return Err(error),
        };
        let result = self.win16_network_call_with_blocking(
            task,
            Win16HostNetworkCall::Select {
                read: read.sockets.clone(), write: write.sockets.clone(),
                except: except.sockets.clone(), timeout: input.timeout,
            },
            host,
        )?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32)); }
        let Win16HostNetworkValue::Selected {
            ready_count, read: selected_read, write: selected_write, except: selected_except,
        } = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock select returned an unexpected host result"));
        };
        let mut writes = Vec::new();
        Self::append_fd_set_write(self, &mut writes, read.range, selected_read)?;
        Self::append_fd_set_write(self, &mut writes, write.range, selected_write)?;
        Self::append_fd_set_write(self, &mut writes, except.range, selected_except)?;
        if let Err(error) = self.commit_outputs(memory, writes) {
            return Ok(self.fail_int(task, Self::map_range_error(error)?));
        }
        Ok(Self::int_return(ready_count))
    }

    fn append_fd_set_write(
        &self,
        writes: &mut Vec<(GuestOutputRange, Vec<u8>)>,
        range: Option<GuestOutputRange>,
        selected: Option<Vec<Win16HostSocket>>,
    ) -> Result<(), RuntimeError> {
        let (range, selected) = match (range, selected) {
            (None, None) => return Ok(()),
            (Some(range), Some(selected)) => (range, selected),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock select changed a null fd_set identity")),
        };
        let mut guests = Vec::new();
        guests.try_reserve_exact(selected.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve returned WinSock fd_set", error))?;
        for socket in selected {
            let Some(guest) = self.network.guest_socket(socket) else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock select returned an unknown native socket token"));
            };
            guests.push(guest);
        }
        let bytes = FdSet16(guests).encode(range.length()).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "WinSock select result does not fit captured fd_set", error))?;
        writes.push((range, bytes));
        Ok(())
    }

    pub(super) fn winsock_is_set(&mut self, _task: u16, guest_socket: u16, bytes: &[u8]) -> u32 {
        match FdSet16::decode(bytes) {
            Ok(set) => u32::from(set.0.contains(&guest_socket)),
            Err(_) => 0,
        }
    }
}

#[derive(Debug)]
struct WinsockRearmError(i32);

impl std::fmt::Display for WinsockRearmError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Winsock error {} while rearming an async event", self.0)
    }
}

impl std::error::Error for WinsockRearmError {}
