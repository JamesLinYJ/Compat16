//! Process-lifetime owner for native Winsock objects that outlive WindowsHost.
//!
//! A reserved slot exists before the first WSAStartup/socket effect. Failed
//! closes and cleanup calls move into that exact slot and are retried at a
//! fixed interval; their raw SOCKETs, task identities, first causes, and
//! resolver/source receipts stay together until native retirement is proven.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use runtime::{DiagnosticKind, RuntimeError, Win16HostSocket, Win16NetworkTaskIdentity};
use windows_sys::Win32::Networking::WinSock::{SOCKET, WSACleanup};

use super::async_ops::AsyncShutdownReceipt;

const RETRY_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub(super) struct NetworkRetirementOwner {
    pub sockets: BTreeMap<Win16HostSocket, SOCKET>,
    pub socket_owners: BTreeMap<Win16HostSocket, Win16NetworkTaskIdentity>,
    pub socket_types: BTreeMap<Win16HostSocket, i32>,
    pub socket_retirement_failures:
        HashMap<Win16HostSocket, runtime::Win16HostSocketRetirementFailure>,
    pub startup_references: BTreeMap<Win16NetworkTaskIdentity, u32>,
    pub startup_release_failures:
        BTreeMap<Win16NetworkTaskIdentity, Option<super::NetworkReferenceFailure>>,
    pub host_anchor_reference: bool,
    pub host_anchor_first_cause: Option<Arc<RuntimeError>>,
    pub host_anchor_last_wsa_error: Option<i32>,
    pub resolver_sources: AsyncShutdownReceipt,
    pub(super) socket_retry_cursor: Option<Win16HostSocket>,
    pub(super) startup_retry_cursor: Option<Win16NetworkTaskIdentity>,
    pub(super) invariant_failure: Option<Arc<RuntimeError>>,
}

impl NetworkRetirementOwner {
    pub(super) fn progress_once(&mut self) -> bool {
        let token = self
            .socket_retry_cursor
            .and_then(|cursor| self.sockets.keys().copied().find(|token| *token > cursor))
            .or_else(|| self.sockets.keys().next().copied());
        if let Some(token) = token
            && let Some(raw) = self.sockets.get(&token).copied()
        {
            self.socket_retry_cursor = Some(token);
            let Some(owner) = self.socket_owners.get(&token).copied() else {
                self.invariant_failure.get_or_insert_with(|| {
                    Arc::new(RuntimeError::new(
                        DiagnosticKind::InternalInvariant,
                        "retained WinSock SOCKET lost its exact task identity",
                    ))
                });
                return false;
            };
            let Some(socket_type) = self.socket_types.get(&token).copied() else {
                let failure = self
                    .socket_retirement_failures
                    .entry(token)
                    .or_insert_with(|| runtime::Win16HostSocketRetirementFailure {
                        socket: token,
                        owner,
                        phase: runtime::Win16HostSocketRetirementPhase::FinalHostShutdown,
                        wsa_error: windows_sys::Win32::Networking::WinSock::WSAEINVAL,
                        first_cause: Arc::new(RuntimeError::new(
                            DiagnosticKind::InternalInvariant,
                            "retained WinSock SOCKET lost its native type",
                        )),
                    });
                failure.wsa_error = windows_sys::Win32::Networking::WinSock::WSAEINVAL;
                return false;
            };
            // Keep one retry per owner per wake interval. A failed close does
            // not remove any identity or cause; only a successful native close
            // releases this slot's SOCKET ownership.
            match super::abortive_close_socket(raw, socket_type) {
                Ok(()) => {
                    self.sockets.remove(&token);
                    self.socket_owners.remove(&token);
                    self.socket_types.remove(&token);
                    self.socket_retirement_failures.remove(&token);
                    self.resolver_sources.retire_socket(token);
                }
                Err(code) => {
                    let first_failure = !self.socket_retirement_failures.contains_key(&token);
                    let failure = self.socket_retirement_failures.entry(token).or_insert_with(|| {
                        runtime::Win16HostSocketRetirementFailure {
                            socket: token,
                            owner,
                            phase: runtime::Win16HostSocketRetirementPhase::FinalHostShutdown,
                            wsa_error: code,
                            first_cause: Arc::new(RuntimeError::new(DiagnosticKind::HostFailure, format!(
                                "final WinSock socket retirement for token {} failed with WSA error {code}", token.0
                            ))),
                        }
                    });
                    failure.phase = runtime::Win16HostSocketRetirementPhase::FinalHostShutdown;
                    failure.wsa_error = code;
                    if first_failure {
                        eprintln!("runtime: {}", failure.first_cause);
                    }
                }
            }
            return false;
        }

        let identity = self
            .startup_retry_cursor
            .and_then(|cursor| {
                self.startup_references
                    .keys()
                    .copied()
                    .find(|task| *task > cursor)
            })
            .or_else(|| self.startup_references.keys().next().copied());
        if let Some(identity) = identity
            && let Some(count) = self.startup_references.get(&identity).copied()
        {
            self.startup_retry_cursor = Some(identity);
            // SAFETY: WSACleanup balances one WSAStartup on this process and takes no pointers.
            if unsafe { WSACleanup() } == 0 {
                if count <= 1 {
                    self.startup_references.remove(&identity);
                } else {
                    self.startup_references.insert(identity, count - 1);
                }
                if let Some(failure) = self.startup_release_failures.get_mut(&identity) {
                    *failure = None;
                }
            } else {
                let code = crate::windows::win32_safe::wsa_last_error();
                let first_failure = self
                    .startup_release_failures
                    .get(&identity)
                    .is_none_or(|failure| failure.is_none());
                let failure = self
                    .startup_release_failures
                    .entry(identity)
                    .or_insert(None);
                let failure = failure.get_or_insert_with(|| super::NetworkReferenceFailure {
                    current_wsa_error: code,
                    first_cause: Arc::new(RuntimeError::new(DiagnosticKind::HostFailure, format!(
                        "final WinSock reference release for task {:?} first failed with WSA error {code}", identity
                    ))),
                });
                failure.current_wsa_error = code;
                if first_failure {
                    eprintln!("runtime: {}", failure.first_cause);
                }
            }
            return false;
        }

        if self.host_anchor_reference {
            // SAFETY: WSACleanup balances one WSAStartup on this process and takes no pointers.
            if unsafe { WSACleanup() } == 0 {
                self.host_anchor_reference = false;
                self.host_anchor_first_cause = None;
                self.host_anchor_last_wsa_error = None;
            } else {
                let code = crate::windows::win32_safe::wsa_last_error();
                let first_failure = self.host_anchor_first_cause.is_none();
                self.host_anchor_last_wsa_error = Some(code);
                let failure = self.host_anchor_first_cause.get_or_insert_with(|| {
                    Arc::new(RuntimeError::new(
                        DiagnosticKind::HostFailure,
                        format!("final WinSock host-anchor release failed with WSA error {code}"),
                    ))
                });
                if first_failure {
                    eprintln!("runtime: {failure}");
                }
            }
            return false;
        }

        self.resolver_sources.is_quiescent() && self.invariant_failure.is_none()
    }
}

#[derive(Debug)]
struct SlotState {
    generation: u64,
    // `reserved` belongs to a live ticket even before it has native owners.
    reserved: bool,
    // `handed_off` belongs to the process worker until its exact owner retires.
    handed_off: bool,
    owners: Vec<NetworkRetirementOwner>,
}

#[derive(Debug)]
struct Slot {
    state: Mutex<SlotState>,
}

#[derive(Debug, Default)]
struct State {
    slots: Vec<Arc<Slot>>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug)]
pub(super) struct NetworkRetirementTicket {
    inner: Arc<Inner>,
    slot: Arc<Slot>,
    generation: u64,
    resolved: bool,
}

static SERVICE: OnceLock<Mutex<Option<Arc<Inner>>>> = OnceLock::new();

// Winsock provides no owner that can retry a failed closesocket/WSACleanup
// after this host object is destroyed. Reserve a process-lifetime typed owner
// before any native effect; a failed retry keeps the same token, task identity,
// phase, and first cause in this service until native retirement succeeds.
impl NetworkRetirementTicket {
    pub(super) fn reserve() -> Result<Self, RuntimeError> {
        let service = SERVICE.get_or_init(|| Mutex::new(None));
        let mut service = service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let inner = if let Some(inner) = service.as_ref() {
            Arc::clone(inner)
        } else {
            let inner = Arc::new(Inner {
                state: Mutex::new(State::default()),
                changed: Condvar::new(),
            });
            let worker = Arc::clone(&inner);
            std::thread::Builder::new()
                .name("win16-winsock-retirement".into())
                .spawn(move || retirement_worker(worker))
                .map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::HostFailure,
                        "start process-lifetime WinSock retirement service",
                        error,
                    )
                })?;
            *service = Some(Arc::clone(&inner));
            inner
        };

        let mut state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for slot in &state.slots {
            let mut slot_state = slot
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot_state.reserved || slot_state.handed_off || !slot_state.owners.is_empty() {
                continue;
            }
            let Some(generation) = slot_state
                .generation
                .checked_add(1)
                .filter(|value| *value != 0)
            else {
                return Err(RuntimeError::new(
                    DiagnosticKind::ResourceExhausted,
                    "WinSock retirement slot generation space is exhausted",
                ));
            };
            slot_state.owners.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve exact WinSock retirement owner before native effects",
                    error,
                )
            })?;
            slot_state.generation = generation;
            slot_state.reserved = true;
            return Ok(Self {
                inner: Arc::clone(&inner),
                slot: Arc::clone(slot),
                generation,
                resolved: false,
            });
        }
        state.slots.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "reserve process-lifetime WinSock retirement slot before native effects",
                error,
            )
        })?;
        let slot = Arc::new(Slot {
            state: Mutex::new(SlotState {
                generation: 1,
                reserved: true,
                handed_off: false,
                owners: Vec::new(),
            }),
        });
        slot.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owners
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve exact WinSock retirement owner before native effects",
                    error,
                )
            })?;
        state.slots.push(Arc::clone(&slot));
        Ok(Self {
            inner: Arc::clone(&inner),
            slot,
            generation: 1,
            resolved: false,
        })
    }

    pub(super) fn retain(&mut self, mut owner: NetworkRetirementOwner) {
        let mut slot = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.generation != self.generation || !slot.reserved {
            owner.invariant_failure.get_or_insert_with(|| {
                Arc::new(RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "WinSock retirement ticket changed its reserved slot generation",
                ))
            });
        }
        // Capacity for this exact owner was reserved before native effects.
        // Keep it even if a slot invariant is reported; never drop raw handles.
        slot.owners.push(owner);
        slot.reserved = false;
        slot.handed_off = true;
        self.resolved = true;
        self.inner.changed.notify_one();
    }

    pub(super) fn release(&mut self) {
        self.resolve_empty();
    }

    fn resolve_empty(&mut self) {
        if self.resolved {
            return;
        }
        let mut slot = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only this generation's live ticket may release an empty slot. The
        // 250 ms worker must not infer ticket release from an empty owner Vec.
        if slot.generation == self.generation
            && slot.reserved
            && !slot.handed_off
            && slot.owners.is_empty()
        {
            slot.reserved = false;
        }
        self.resolved = true;
    }
}

impl Drop for NetworkRetirementTicket {
    fn drop(&mut self) {
        self.resolve_empty();
    }
}

fn retirement_worker(inner: Arc<Inner>) {
    loop {
        let state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, _) = inner
            .changed
            .wait_timeout(state, RETRY_INTERVAL)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for slot in &state.slots {
            let mut slot_state = slot
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut index = 0usize;
            while index < slot_state.owners.len() {
                if slot_state.owners[index].progress_once() {
                    slot_state.owners.remove(index);
                } else {
                    index += 1;
                }
            }
            // A live ticket owns its slot before handoff, including the empty
            // interval between construction and Drop. Reopen only after the
            // exact handed-off owner completed its real native retirement.
            if slot_state.handed_off && slot_state.owners.is_empty() {
                slot_state.handed_off = false;
            }
        }
    }
}
