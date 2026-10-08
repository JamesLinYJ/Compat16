//! Resolver result staging and task-owned WinSock static globals.

use compat_services::win16_network::{
    encode_host_entry_16, encode_protocol_entry_16, encode_service_entry_16, GuestFarBase16,
    WSAEINVAL, WSAENOBUFS,
};
use guest_core::memory::Memory;
use win16_abi::Win16HostQuery;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostNetworkCall,
    Win16HostNetworkNameQuery, Win16HostNetworkNameResult, Win16HostNetworkValue,
};
use crate::win16_runtime::global_memory::GlobalTeardownResult;
use super::{GLOBAL_MOVEABLE_ZEROINIT, Win16State};

impl Win16State {
    pub(super) fn winsock_inet_name(
        &mut self,
        task: u16,
        address: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let result = host.win16_network(Win16HostNetworkCall::InetName(address))?;
        if result.wsa_error != 0 {
            self.network.record_host_error(task, result.wsa_error);
            return Ok(0);
        }
        let Win16HostNetworkValue::InetText(mut bytes) = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock inet_ntoa returned an unexpected host result"));
        };
        bytes.push(0);
        self.store_static_result(task, memory, host, |_| Ok(bytes.clone()))
    }

    pub(super) fn winsock_query(
        &mut self,
        task: u16,
        query: Win16HostQuery,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let expected = match &query {
            Win16HostQuery::HostByAddress { .. } | Win16HostQuery::HostByName(_) => 0,
            Win16HostQuery::ProtocolByName(_) | Win16HostQuery::ProtocolByNumber(_) => 1,
            Win16HostQuery::ServiceByName { .. } | Win16HostQuery::ServiceByPort { .. } => 2,
        };
        let query = match query {
            Win16HostQuery::HostByAddress { address, address_type } => {
                if address.len() > i16::MAX as usize { return Ok(self.fail_pointer(task, WSAEINVAL)); }
                Win16HostNetworkNameQuery::HostByAddress { address, address_type }
            }
            Win16HostQuery::HostByName(name) => Win16HostNetworkNameQuery::HostByName(name),
            Win16HostQuery::ProtocolByName(name) => Win16HostNetworkNameQuery::ProtocolByName(name),
            Win16HostQuery::ProtocolByNumber(number) => Win16HostNetworkNameQuery::ProtocolByNumber(number),
            Win16HostQuery::ServiceByName { name, protocol } =>
                Win16HostNetworkNameQuery::ServiceByName { name, protocol },
            Win16HostQuery::ServiceByPort { port_network_order, protocol } =>
                Win16HostNetworkNameQuery::ServiceByPort { port_network_order, protocol },
        };
        let result = self.win16_network_call_with_blocking(
            task,
            Win16HostNetworkCall::Query(query),
            host,
        )?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, 0)); }
        let entry = match result.value {
            Win16HostNetworkValue::NameQuery(Some(entry)) => entry,
            Win16HostNetworkValue::NameQuery(None) => return Err(RuntimeError::new(
                Kind::InternalInvariant, "WinSock query returned no entry without a WSA error")),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock query returned a mismatched host result kind")),
        };
        let matches_expected = matches!((expected, &entry),
            (0, Win16HostNetworkNameResult::Host(_))
            | (1, Win16HostNetworkNameResult::Protocol(_))
            | (2, Win16HostNetworkNameResult::Service(_)));
        if !matches_expected {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock query returned a result from the wrong resolver family"));
        }
        self.store_static_result(task, memory, host, |base| encode_name_result_at(&entry, base))
    }

    fn store_static_result<F>(
        &mut self,
        task: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        encode: F,
    ) -> Result<u32, RuntimeError>
    where
        F: Fn(GuestFarBase16) -> Result<Vec<u8>, compat_services::win16_network::GuestNetworkLayoutError>,
    {
        let probe = match encode(GuestFarBase16 { selector: 1, offset: 0 }) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(self.fail_pointer(task, WSAENOBUFS)),
        };
        if probe.is_empty() || probe.len() > 65_536 { return Ok(self.fail_pointer(task, WSAENOBUFS)); }
        let previous = self.network.try_result_blocks_for_task(task).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve prior WinSock resolver owner snapshot", error))?;
        self.network.reserve_result_block(task).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock resolver owner record before guest allocation", error))?;
        let block = self.global_alloc(GLOBAL_MOVEABLE_ZEROINIT,
            u32::try_from(probe.len()).unwrap_or(u32::MAX), memory, host)?;
        if block == 0 { return Ok(self.fail_pointer(task, WSAENOBUFS)); }
        let identity = self.global_handles.get(&block).copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WinSock static result allocation has no GlobalHandle identity"))?;
        let current = crate::win16_network::StaticResultBlock::new(block, identity);
        self.network.track_result_block(task, current.clone());
        let far = match self.global_lock(block, memory) {
            Ok(far) => far,
            Err(error) => return Err(self.preserve_failed_static_result(task, &current, error)),
        };
        if far == 0 {
            self.retire_failed_static_result(task, &current)?;
            return Ok(self.fail_pointer(task, WSAENOBUFS));
        }
        let encoded = match encode(GuestFarBase16 { selector: (far >> 16) as u16, offset: far as u16 }) {
            Ok(value) => value,
            Err(_) => {
                if let Err(error) = self.global_unlock(block) {
                    return Err(self.preserve_failed_static_result(task, &current, error));
                }
                self.retire_failed_static_result(task, &current)?;
                return Ok(self.fail_pointer(task, WSAENOBUFS));
            }
        };
        let pointer = match self.selectors.pointer_from_far(far) {
            Ok(pointer) => pointer,
            Err(error) => {
                let mut primary = crate::runtime_error(error);
                if let Err(cleanup) = self.global_unlock(block) {
                    primary = primary.with_cleanup(
                        "unlocking an invalid WinSock static result pointer", cleanup,
                    );
                }
                return Err(self.preserve_failed_static_result(task, &current, primary));
            }
        };
        if encoded.len() != probe.len() {
            let mut primary = RuntimeError::new(Kind::InternalInvariant,
                "WinSock static result changed size when assigning its guest selector");
            if let Err(cleanup) = self.global_unlock(block) {
                primary = primary.with_cleanup(
                    "unlocking a malformed WinSock static result", cleanup,
                );
            }
            return Err(self.preserve_failed_static_result(task, &current, primary));
        }
        let write_result = self.selectors.write(memory, pointer, &encoded).map_err(crate::runtime_error);
        let unlock_result = self.global_unlock(block);
        if let Err(error) = write_result {
            let primary = match unlock_result {
                Ok(_) => error,
                Err(cleanup) => error.with_cleanup("unlocking failed WinSock static result", cleanup),
            };
            return Err(self.preserve_failed_static_result(task, &current, primary));
        }
        if let Err(error) = unlock_result {
            return Err(self.preserve_failed_static_result(task, &current, error));
        }
        for old in previous {
            match self.free_result_owner(&old) {
                Ok(GlobalTeardownResult::Freed) => self.network.remove_result_block(
                    task, old.guest_handle, old.identity,
                ),
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    let error = retained.retained_error("WinSock resolver result")
                        .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "WinSock resolver lost a retained result diagnostic"));
                    return Err(self.network.record_result_block_failure(
                        task, old.guest_handle, old.identity, error,
                    ));
                }
                Err(error) => {
                    let error = error.with_context("retiring previous WinSock static resolver result");
                    return Err(self.network.record_result_block_failure(
                        task, old.guest_handle, old.identity, error,
                    ));
                }
            }
        }
        Ok(far)
    }

    fn preserve_failed_static_result(
        &mut self,
        task: u16,
        current: &crate::win16_network::StaticResultBlock,
        primary: RuntimeError,
    ) -> RuntimeError {
        match self.retire_failed_static_result(task, current) {
            Ok(()) => primary,
            Err(cleanup) => primary.with_cleanup(
                "retiring failed WinSock static result while retaining its owner record",
                cleanup,
            ),
        }
    }

    fn retire_failed_static_result(
        &mut self,
        task: u16,
        current: &crate::win16_network::StaticResultBlock,
    ) -> Result<(), RuntimeError> {
        match self.free_result_owner(current) {
            Ok(GlobalTeardownResult::Freed) => {
                self.network.remove_result_block(task, current.guest_handle, current.identity);
                Ok(())
            }
            Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                let error = retained.retained_error("failed WinSock static result")
                    .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "failed WinSock result lost its retained diagnostic"));
                Err(self.network.record_result_block_failure(
                    task, current.guest_handle, current.identity, error,
                ))
            }
            Err(error) => Err(self.network.record_result_block_failure(
                task, current.guest_handle, current.identity, error,
            )),
        }
    }
}

pub(super) fn encode_name_result_at(
    entry: &Win16HostNetworkNameResult,
    base: GuestFarBase16,
) -> Result<Vec<u8>, compat_services::win16_network::GuestNetworkLayoutError> {
    match entry {
        Win16HostNetworkNameResult::Host(value) => encode_host_entry_16(base, value),
        Win16HostNetworkNameResult::Protocol(value) => encode_protocol_entry_16(base, value),
        Win16HostNetworkNameResult::Service(value) => encode_service_entry_16(base, value),
        Win16HostNetworkNameResult::HostName(value) => {
            let mut bytes = value.clone();
            bytes.push(0);
            Ok(bytes)
        }
        Win16HostNetworkNameResult::NotFound => Ok(Vec::new()),
    }
}
