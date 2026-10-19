//! Startup-reference and exact socket-owner transitions for Winsock.

use super::*;

impl Win16NetworkHost {
    pub(super) fn startup(
        &mut self,
        task: Win16NetworkTaskIdentity,
        version: u16,
    ) -> Win16HostNetworkResult {
        if task.selector_generation == 0 {
            return fail(WSAEINVAL, unit());
        }
        let Some(next_guest_references) = self.guest_startup_references.checked_add(1) else {
            return fail(WSAENOBUFS, unit());
        };
        let current_task_references = self
            .startup_references_by_task
            .get(&task)
            .copied()
            .unwrap_or(0);
        let Some(next_task_references) = current_task_references.checked_add(1) else {
            return fail(WSAENOBUFS, unit());
        };
        // Insert exact task rows before WSAStartup so successful native refs
        // never need an owner allocation after the effect.
        self.startup_references_by_task.entry(task).or_insert(0);
        self.startup_release_failures.entry(task).or_insert(None);
        let opened_anchor = !self.host_anchor_reference;
        if opened_anchor {
            let mut anchor_data = MaybeUninit::<WSADATA>::zeroed();
            // SAFETY: WSAStartup writes into a caller-owned WSADATA that outlives the call.
            let status = unsafe { WSAStartup(0x0202, anchor_data.as_mut_ptr()) };
            if status != 0 {
                if current_task_references == 0 {
                    self.startup_references_by_task.remove(&task);
                    self.startup_release_failures.remove(&task);
                }
                return fail(status, unit());
            }
            self.host_anchor_reference = true;
        }
        let mut data = MaybeUninit::<WSADATA>::zeroed();
        // SAFETY: WSAStartup writes into a caller-owned WSADATA that outlives the call.
        let status = unsafe { WSAStartup(version, data.as_mut_ptr()) };
        if status != 0 {
            if opened_anchor {
                // SAFETY: WSACleanup balances one WSAStartup on this process and takes no pointers.
                if unsafe { WSACleanup() } == 0 {
                    self.host_anchor_reference = false;
                    self.host_anchor_first_cause = None;
                    self.host_anchor_last_wsa_error = None;
                } else {
                    let error = crate::windows::win32_safe::wsa_last_error();
                    self.host_anchor_last_wsa_error = Some(error);
                    self.host_anchor_first_cause.get_or_insert_with(|| Arc::new(
                        RuntimeError::new(DiagnosticKind::HostFailure, format!(
                            "balancing WinSock host anchor after startup failure returned WSA error {error}"
                        )),
                    ));
                }
            }
            if current_task_references == 0 {
                self.startup_references_by_task.remove(&task);
                self.startup_release_failures.remove(&task);
            }
            return fail(status, unit());
        }
        self.guest_startup_references = next_guest_references;
        if let Some(count) = self.startup_references_by_task.get_mut(&task) {
            *count = next_task_references;
        }
        // SAFETY: The preceding successful call initialized every field of this value.
        let data = unsafe { data.assume_init() };
        ok(Win16HostNetworkValue::Startup(WsaData16 {
            version: data.wVersion,
            high_version: data.wHighVersion,
            description: array_string(&data.szDescription),
            system_status: array_string(&data.szSystemStatus),
            max_sockets: data.iMaxSockets,
            max_udp_datagram: data.iMaxUdpDg,
        }))
    }

    pub(super) fn cleanup(
        &mut self,
        task: Win16NetworkTaskIdentity,
        task_final: bool,
    ) -> Win16HostNetworkResult {
        let Some(task_references) = self.startup_references_by_task.get(&task).copied() else {
            return fail(
                WSANOTINITIALISED,
                Win16HostNetworkValue::Signed(SOCKET_ERROR),
            );
        };
        if self.guest_startup_references == 0
            || task_references == 0
            || task_final != (task_references == 1)
        {
            return fail(WSAEINVAL, Win16HostNetworkValue::Signed(SOCKET_ERROR));
        }
        let owned_sockets = if task_final {
            self.socket_owners
                .values()
                .filter(|owner| **owner == task)
                .count()
        } else {
            0
        };
        let mut socket_retire_failures = Vec::new();
        if socket_retire_failures
            .try_reserve_exact(owned_sockets)
            .is_err()
            || self
                .socket_retirement_failures
                .try_reserve(owned_sockets)
                .is_err()
        {
            return fail(WSAENOBUFS, Win16HostNetworkValue::Signed(SOCKET_ERROR));
        }
        // SAFETY: WSACleanup balances one WSAStartup on this process and takes no pointers.
        let result = unsafe { WSACleanup() };
        if result == SOCKET_ERROR {
            let error = crate::windows::win32_safe::wsa_last_error();
            let failure = self.startup_release_failures.entry(task).or_insert(None);
            let failure = failure.get_or_insert_with(|| NetworkReferenceFailure {
                current_wsa_error: error,
                first_cause: Arc::new(RuntimeError::new(
                    DiagnosticKind::HostFailure,
                    format!(
                        "WinSock Cleanup for task {:?} first failed with WSA error {error}",
                        task
                    ),
                )),
            });
            failure.current_wsa_error = error;
            fail(error, Win16HostNetworkValue::Signed(result))
        } else {
            self.guest_startup_references -= 1;
            if task_final {
                self.startup_references_by_task.remove(&task);
                self.startup_release_failures.remove(&task);
            } else {
                if let Some(count) = self.startup_references_by_task.get_mut(&task) {
                    *count -= 1;
                }
                if let Some(failure) = self.startup_release_failures.get_mut(&task) {
                    *failure = None;
                }
            }
            let reference_release = Win16HostNetworkReferenceRelease {
                owner: task,
                task_final,
            };
            if task_final {
                self.retire_task_sockets(task, &mut socket_retire_failures);
            }
            ok(Win16HostNetworkValue::Cleanup {
                reference_release,
                socket_retire_failures,
            })
        }
    }

    fn retire_task_sockets(
        &mut self,
        task: Win16NetworkTaskIdentity,
        failures: &mut Vec<Win16HostSocketRetirementFailure>,
    ) {
        let mut last = None;
        loop {
            let token = self.sockets.keys().copied().find(|token| {
                last.map_or(true, |previous| *token > previous)
                    && self.socket_owners.get(token) == Some(&task)
            });
            let Some(token) = token else {
                break;
            };
            last = Some(token);
            let Some(raw) = self.sockets.get(&token).copied() else {
                continue;
            };
            if let Err(failure) = self.retire_socket(
                token,
                raw,
                task,
                Win16HostSocketRetirementPhase::GuestCleanupReferenceReleased,
            ) {
                failures.push(failure);
            }
        }
    }

    pub(super) fn can_allocate_socket_token(&self) -> bool {
        self.next_socket != 0
            && self.next_socket != u64::MAX
            && self.next_socket.checked_add(1).is_some()
            && !self
                .sockets
                .contains_key(&Win16HostSocket(self.next_socket))
    }

    pub(super) fn startup_owner_live(&self, owner: Win16NetworkTaskIdentity) -> bool {
        owner.selector_generation != 0
            && self
                .startup_references_by_task
                .get(&owner)
                .is_some_and(|count| *count != 0)
    }

    pub(super) fn reserve_socket_owner_capacity(&mut self) -> Result<(), RuntimeError> {
        let desired = self.sockets.len().checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "WinSock socket retirement owner count overflowed",
            )
        })?;
        let additional = desired.saturating_sub(self.socket_retirement_failures.len());
        self.socket_retirement_failures
            .try_reserve(additional)
            .map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve retained WinSock close-cause capacity before native socket creation",
                    error,
                )
            })
    }

    pub(super) fn insert_socket(
        &mut self,
        raw: SOCKET,
        owner_task: Win16NetworkTaskIdentity,
        socket_type: i32,
        connected: bool,
    ) -> Option<Win16HostSocket> {
        if !self.can_allocate_socket_token() {
            return None;
        }
        let id = self.next_socket;
        self.next_socket = id.checked_add(1)?;
        let token = Win16HostSocket(id);
        self.sockets.insert(token, raw);
        self.socket_tokens.insert(raw, token);
        self.socket_owners.insert(token, owner_task);
        self.socket_types.insert(token, socket_type);
        self.async_state
            .register_socket(token, socket_type, connected);
        Some(token)
    }

    pub(super) fn remove_socket(&mut self, token: Win16HostSocket) {
        if let Some(raw) = self.sockets.remove(&token) {
            self.socket_tokens.remove(&raw);
        }
        self.socket_owners.remove(&token);
        self.socket_types.remove(&token);
        self.socket_retirement_failures.remove(&token);
        self.listening_sockets.remove(&token);
        self.async_state.remove_socket(token);
    }

    pub(super) fn retire_socket(
        &mut self,
        token: Win16HostSocket,
        raw: SOCKET,
        owner: Win16NetworkTaskIdentity,
        phase: Win16HostSocketRetirementPhase,
    ) -> Result<(), Win16HostSocketRetirementFailure> {
        let Some(socket_type) = self.socket_types.get(&token).copied() else {
            return Err(self.record_socket_retirement_failure(token, owner, phase, WSAENOTSOCK));
        };
        match abortive_close_socket(raw, socket_type) {
            Ok(()) => {
                self.remove_socket(token);
                Ok(())
            }
            Err(error) => Err(self.record_socket_retirement_failure(token, owner, phase, error)),
        }
    }

    pub(super) fn record_socket_retirement_failure(
        &mut self,
        token: Win16HostSocket,
        owner: Win16NetworkTaskIdentity,
        phase: Win16HostSocketRetirementPhase,
        wsa_error: i32,
    ) -> Win16HostSocketRetirementFailure {
        let failure = self.socket_retirement_failures.entry(token).or_insert_with(|| {
            Win16HostSocketRetirementFailure {
                socket: token,
                owner,
                phase,
                wsa_error,
                first_cause: Arc::new(RuntimeError::new(DiagnosticKind::HostFailure, format!(
                    "WinSock socket token {} for task {:?} first failed retirement in phase {:?} with WSA error {wsa_error}",
                    token.0, owner, phase
                ))),
            }
        });
        failure.phase = phase;
        failure.wsa_error = wsa_error;
        failure.clone()
    }
}
