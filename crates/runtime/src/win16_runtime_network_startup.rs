use super::*;

impl Win16State {
    pub(super) fn winsock_startup(
        &mut self,
        task: u16,
        task_identity: Win16NetworkTaskIdentity,
        version: u16,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if !self.network.can_note_startup(task_identity) {
            return Ok(u32::from(compat_services::win16_network::WSAENOBUFS as u16));
        }
        if self.network.reserve_orphan_sockets(
            self.network.socket_count_for_task(task_identity),
        ).is_err() {
            return Ok(u32::from(WSAENOBUFS as u16));
        }
        let output = match self.capture_network_output(memory, output_far, WSADATA16_SIZE) {
            Ok(Some(range)) => range,
            Ok(None) => return Ok(u32::from(WSAEFAULT as u16)),
            Err(error) => return Ok(u32::from(Self::map_range_error(error)? as u16)),
        };
        let mut staged = Vec::new();
        staged.try_reserve_exact(WSADATA16_SIZE).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve WinSock startup guest output staging", error))?;
        let mut writes = Vec::new();
        writes.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve WinSock startup output transaction", error))?;
        let result = host.win16_network(Win16HostNetworkCall::Startup { task: task_identity, version })?;
        if result.wsa_error != 0 { return Ok(result.wsa_error as u16 as u32); }
        let Win16HostNetworkValue::Startup(data) = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock Startup returned an unexpected host result"));
        };
        // Account for the native reference before the guest output commit so
        // teardown can retry cleanup if that commit or its compensating call
        // fails.
        if !self.network.note_startup(task_identity) {
            match host.win16_network(Win16HostNetworkCall::Cleanup { task: task_identity, task_final: false }) {
                Ok(cleanup) if cleanup.wsa_error == 0 => {
                    let (release, failures) = Self::cleanup_retirement_errors(cleanup.value)?;
                    if release.owner != task_identity || release.task_final || !failures.is_empty() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "WinSock Startup compensation returned an unexpected release receipt"));
                    }
                    return Ok(u32::from(compat_services::win16_network::WSAENOBUFS as u16));
                }
                Ok(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock startup accounting overflow could not be compensated")),
                Err(error) => return Err(error.with_context(
                    "compensating untracked WinSock startup reference")),
            }
        }
        staged.extend_from_slice(&data.encode());
        writes.push((output, staged));
        if let Err(error) = self.commit_outputs(memory, writes) {
            let task_final = self.network.startup_references_for_task(task_identity) == 1;
            let cleanup = host.win16_network(Win16HostNetworkCall::Cleanup { task: task_identity, task_final });
            match cleanup {
                Ok(result) if result.wsa_error == 0 => {
                    let (release, failures) = Self::cleanup_retirement_errors(result.value)?;
                    if release.owner != task_identity || release.task_final != task_final {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "WinSock startup rollback released a different task reference"));
                    }
                    if !self.network.note_cleanup(task_identity) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "WinSock startup rollback lost its runtime reference owner"));
                    }
                    let retention = self.retain_cleanup_failures(task_identity, &failures);
                    Self::report_retirement_errors(host, &failures);
                    if task_final && retention.is_ok() {
                        self.network.retire_task_sockets(task_identity)?;
                        self.free_result_blocks_for_task(task)?;
                    }
                    if self.network.startup_references() == 0 && retention.is_ok() {
                        self.network.clear_sockets()?;
                    }
                    retention?;
                }
                _ => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                        "WinSock startup succeeded but cleanup after a guest output failure did not complete; teardown will retry"));
                }
            }
            return Ok(u32::from(Self::map_range_error(error)? as u16));
        }
        Ok(0)
    }
}
