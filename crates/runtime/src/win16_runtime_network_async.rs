//! Runtime ownership for Winsock asynchronous notifications and lookups.

use compat_services::win16_network::{WSAEFAULT, WSAEINVAL, WSAENOBUFS};
use guest_core::{memory::Memory, Selector};
use win16_abi::{Win16AsyncLookup, Win16GuestBuffer};

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostNetworkCall,
    Win16HostNetworkNameQuery, Win16HostNetworkValue, Win16NetworkTaskIdentity,
};
use super::Win16State;

impl Win16State {
    pub(super) fn winsock_async_select(
        &mut self,
        task: u16,
        guest_socket: u16,
        window: u16,
        message: u16,
        events: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let task_identity = self.winsock_task_identity(task)?;
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, compat_services::win16_network::WSAENOTSOCK));
        };
        const LEGACY_EVENTS: u32 = 0x003f;
        if events & !LEGACY_EVENTS != 0 {
            return Ok(self.fail_int(task, WSAEINVAL));
        }
        let mapped_window = self.window_handles.get(&window).copied();
        let old_route = self.network.async_select_route(guest_socket);
        let (host_window, guest_hwnd) = if events == 0 {
            match (mapped_window, old_route) {
                (Some(host_window), Some(route)) if route.host_window == host_window
                    && route.window == window => (host_window, window),
                (_, Some(route)) => (route.host_window, route.window),
                (Some(host_window), None) => (host_window, window),
                (None, None) => return Ok(self.fail_int(task, WSAEINVAL)),
            }
        } else {
            let Some(host_window) = mapped_window else {
                return Ok(self.fail_int(task, WSAEINVAL));
            };
            (host_window, window)
        };
        let generation = if events == 0 {
            old_route.map_or(0, |route| route.registration_generation)
        } else {
            let Some(generation) = self.network.reserve_async_generation() else {
                return Ok(self.fail_int(task, WSAENOBUFS));
            };
            generation
        };
        if events != 0 {
            if self.network.reserve_async_select().is_err() {
                return Ok(self.fail_int(task, WSAENOBUFS));
            }
        }
        if old_route.is_some()
            && self.network.reserve_retired_async_selects(1).is_err()
        {
            return Ok(self.fail_int(task, WSAENOBUFS));
        }
        let result = host.win16_network(Win16HostNetworkCall::AsyncSelect {
            socket,
            task: task_identity,
            window: host_window,
            guest_hwnd,
            message,
            events,
            registration_generation: generation,
            expected_source_id: if events == 0 {
                old_route.map(|route| route.source_id)
            } else {
                None
            },
        })?;
        if result.wsa_error != 0 {
            return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32));
        }
        if !self.network.set_socket_nonblocking(guest_socket, true) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock guest socket disappeared after successful WSAAsyncSelect"));
        }
        let source_id = match result.value {
            Win16HostNetworkValue::AsyncRegistration { source_id, generation: returned }
                if returned == generation && (events == 0 && source_id == 0
                    || events != 0 && source_id != 0 && source_id != u64::MAX) => source_id,
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock WSAAsyncSelect returned an invalid registration identity")),
        };
        if result.wsa_error == 0 && events != 0 && source_id == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock WSAAsyncSelect omitted its notification source identity"));
        }
        let route = (events != 0).then_some(crate::win16_network::Win16AsyncSelectRoute {
            socket,
            window: guest_hwnd,
            host_window,
            message,
            events,
            task: task_identity,
            registration_generation: generation,
            source_id,
            last_event_sequence: 0,
        });
        if !self.network.set_async_select(guest_socket, route) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock socket route disappeared after WSAAsyncSelect succeeded"));
        }
        Ok(0)
    }

    pub(super) fn winsock_async_query(
        &mut self,
        task: u16,
        window: u16,
        message: u16,
        lookup: Win16AsyncLookup,
        output: Win16GuestBuffer,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let task_identity = self.winsock_task_identity(task)?;
        let Some(host_window) = self.window_handles.get(&window).copied() else {
            return Ok(self.fail_pointer(task, WSAEINVAL));
        };
        let (capacity, output_range) = match self.capture_buffer(
            memory, output.far_pointer, output.capacity,
        ) {
            Ok(value) if value.0 > 0 => value,
            Ok(_) => return Ok(self.fail_pointer(task, WSAEINVAL)),
            Err(error) => return Ok(self.fail_pointer(task, Self::map_range_error(error)?)),
        };
        let Some(output_range) = output_range else {
            return Ok(self.fail_pointer(task, WSAEFAULT));
        };
        let Some(request_generation) = self.network.reserve_async_generation() else {
            return Ok(self.fail_pointer(task, WSAENOBUFS));
        };
        let query = host_query(lookup.clone());
        let route = crate::win16_network::Win16AsyncGuestRoute {
            window,
            host_window,
            message,
            task: task_identity,
            lookup,
            output: output_range,
            output_capacity: output.capacity,
            request_generation,
            source_id: None,
        };
        let Some(guest_task) = self.network.reserve_async_task(route)? else {
            return Ok(self.fail_pointer(task, WSAENOBUFS));
        };
        let result = host.win16_network(Win16HostNetworkCall::AsyncQuery {
            task: task_identity,
            window: host_window,
            guest_hwnd: window,
            message,
            query,
            capacity,
            request_generation,
        });
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.network.remove_async_task_reservation(guest_task);
                return Err(error);
            }
        };
        if result.wsa_error != 0 {
            self.network.remove_async_task_reservation(guest_task);
            return Ok(self.result_error(task, result.wsa_error, 0));
        }
        let Win16HostNetworkValue::AsyncTask(Some(host_request)) = result.value else {
            // A successful host return may already own asynchronous work. Keep
            // the guest route reserved until the host's exact task identity is
            // available instead of silently dropping a possible completion.
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock asynchronous resolver omitted its accepted task identity"));
        };
        if host_request.generation != request_generation
            || host_request.source_id == 0
            || host_request.source_id == u64::MAX
            || !self.network.bind_async_task(guest_task, host_request)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock asynchronous task reservation changed after host acceptance"));
        }
        Ok(u32::from(guest_task))
    }

    pub(super) fn winsock_cancel_async_request(
        &mut self,
        task: u16,
        guest_task: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some((Some(host_request), route)) = self.network.async_task_record(guest_task) else {
            return Ok(self.fail_int(task, WSAEINVAL));
        };
        let result = host.win16_network(Win16HostNetworkCall::CancelAsyncRequest {
            request: host_request,
            owner: route.task,
        })?;
        if result.wsa_error != 0 {
            // WSAEALREADY means completion is already retained for guest
            // delivery. The request owner remains until that event is ACKed.
            return Ok(self.result_error(task, result.wsa_error, u16::MAX as u32));
        }
        if !matches!(result.value, Win16HostNetworkValue::Signed(0)) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock WSACancelAsyncRequest returned an unexpected success value"));
        }
        if self.network.take_async_task(guest_task) != Some(host_request) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock asynchronous task owner changed after exact cancellation"));
        }
        Ok(0)
    }
}

impl Win16State {
    pub(super) fn winsock_task_identity(&self, expected_handle: u16)
        -> Result<Win16NetworkTaskIdentity, RuntimeError> {
        let owner = self.tasks.current().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WinSock has no current Win16 task owner"))?;
        let guest_htask = self.task_handles.get(&owner).copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WinSock current task has no guest HTASK"))?;
        if guest_htask != expected_handle {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock task handle changed during request capture"));
        }
        let selector = self.selectors.reference(Selector(guest_htask)).map_err(crate::runtime_error)?;
        Ok(Win16NetworkTaskIdentity {
            owner,
            guest_htask,
            selector_generation: selector.generation(),
        })
    }
}

fn host_query(query: Win16AsyncLookup) -> Win16HostNetworkNameQuery {
    match query {
        Win16AsyncLookup::HostByAddress { address, address_type } =>
            Win16HostNetworkNameQuery::HostByAddress { address, address_type },
        Win16AsyncLookup::HostByName(name) => Win16HostNetworkNameQuery::HostByName(name),
        Win16AsyncLookup::ProtocolByName(name) => Win16HostNetworkNameQuery::ProtocolByName(name),
        Win16AsyncLookup::ProtocolByNumber(number) => Win16HostNetworkNameQuery::ProtocolByNumber(number),
        Win16AsyncLookup::ServiceByName { name, protocol } =>
            Win16HostNetworkNameQuery::ServiceByName { name, protocol },
        Win16AsyncLookup::ServiceByPort { port_network_order, protocol } =>
            Win16HostNetworkNameQuery::ServiceByPort { port_network_order, protocol },
    }
}
