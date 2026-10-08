//! Direct Win16 MSACM export dispatch and runtime-owned object identities.

use std::collections::{BTreeSet, HashMap, HashSet};

use guest_core::{GuestMemory, Registers, memory::Memory};
use win16_abi::{SegmentedPointer, Win16MultimediaArgument, Win16MultimediaCall,
    Win16ReturnKind};
use super::{CallbackKind, Win16State};
use super::global_memory::GlobalTeardownResult;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAcmNativeFailure,
    Win16HostAcmNativeOperation, Win16HostAcmOperation, Win16HostAcmResult,
    Win16HostAcmEnumerationRecord, Win16HostIcon,
};
use super::guest_ranges::{GuestOutputRange, commit_guest_writes};

#[path = "win16_acm_driver.rs"]
mod driver;
#[path = "win16_acm_format.rs"]
mod format;
#[path = "win16_acm_stream.rs"]
mod stream;
#[path = "win16_acm_enumeration.rs"]
mod enumeration;
#[path = "win16_acm_owner.rs"]
mod owner;

use crate::{Win16HostAcmHandle, Win16HostAcmObjectKind};
use owner::OrphanAcmAllocation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeAcmHandle {
    kind: Win16HostAcmObjectKind,
    host: Win16HostAcmHandle,
}

enum AcmHeaderCleanup {
    NativePrepared { token: u64 },
    CancelPendingGuestPublication { unprepare_flags: u32, native_result: u32 },
}

#[derive(Default)]
pub(super) struct Win16AcmState {
    next_handle: u32,
    next_header_token: u64,
    handles: HashMap<u16, RuntimeAcmHandle>,
    added_driver_ids: HashSet<u16>,
    prepared_headers: HashMap<(u16, u32), stream::PreparedAcmHeader>,
    enumerations: Vec<enumeration::AcmEnumerationFrame>,
    orphaned_enumeration: Option<Vec<Win16HostAcmEnumerationRecord>>,
    orphan_callback_allocations: Vec<OrphanAcmAllocation>,
    orphaned_icons: Vec<Win16HostIcon>,
    warned_unsupported: BTreeSet<u16>,
}

impl Win16AcmState {
    pub(super) fn callback_frames_are_empty(&self) -> bool {
        self.enumerations.is_empty()
    }

    pub(super) fn new() -> Self {
        Self { next_handle: 1, next_header_token: 1,
            handles: HashMap::new(), added_driver_ids: HashSet::new(),
            prepared_headers: HashMap::new(),
            enumerations: Vec::new(), orphaned_enumeration: None,
            orphan_callback_allocations: Vec::new(), orphaned_icons: Vec::new(),
            warned_unsupported: BTreeSet::new() }
    }

    pub(super) fn native_sources_quiescent(&self) -> bool {
        self.handles.is_empty() && self.prepared_headers.is_empty()
            && self.enumerations.is_empty() && self.orphaned_enumeration.is_none()
            && self.orphaned_icons.is_empty()
    }

    pub(super) fn reserve_orphan_icon_slot(&mut self) -> Result<(), RuntimeError> {
        self.orphaned_icons.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve retry owner for copied ACM driver icon", error))
    }

    fn reserve_owner_slots(&mut self, count: usize) -> Result<(), RuntimeError> {
        self.handles.try_reserve(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 ACM handle entries", error))?;
        self.added_driver_ids.try_reserve(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 ACM driver ownership entries", error))?;
        Ok(())
    }

    fn handle(
        &self,
        guest: u16,
        expected: Win16HostAcmObjectKind,
    ) -> Option<Win16HostAcmHandle> {
        let record = self.handles.get(&guest)?;
        (record.kind == expected).then_some(record.host)
    }

    pub(super) fn code_references(&self) -> Vec<u32> {
        let mut references = Vec::new();
        for frame in &self.enumerations {
            references.push(frame.callback);
            references.push(guest_code_reference(frame.saved.cs, frame.saved.ip()));
            references.push(guest_code_reference(frame.return_to.0, frame.return_to.1));
        }
        references
    }

    fn object(
        &self,
        guest: u16,
    ) -> Option<(Win16HostAcmObjectKind, Win16HostAcmHandle)> {
        let record = self.handles.get(&guest)?;
        Some((record.kind, record.host))
    }

    fn next_header_token(&mut self) -> Result<u64, RuntimeError> {
        let token = self.next_header_token;
        self.next_header_token = token.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 ACM stream-header identities exhausted"))?;
        Ok(token)
    }

    fn store_handle(&mut self, kind: Win16HostAcmObjectKind,
        host: Win16HostAcmHandle) -> Result<u16, RuntimeError> {
        if kind == Win16HostAcmObjectKind::DriverId {
            if let Some((guest, _)) = self.handles.iter()
                .find(|(_, record)| record.kind == kind && record.host == host)
            {
                return Ok(*guest);
            }
        }
        let Some(alias) = self.reserve_handle_alias()? else {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "all nonzero Win16 ACM WORD handles are currently owned"));
        };
        self.store_reserved_handle(kind, host, alias)
    }

    fn reserve_handle_alias(&mut self) -> Result<Option<u16>, RuntimeError> {
        self.reserve_owner_slots(1)?;
        let mut candidate = self.next_handle.clamp(1, u16::MAX as u32) as u16;
        let start = candidate;
        loop {
            if !self.handles.contains_key(&candidate) { break; }
            candidate = if candidate == u16::MAX { 1 } else { candidate + 1 };
            if candidate == start { return Ok(None); }
        }
        Ok(Some(candidate))
    }

    fn store_reserved_handle(
        &mut self,
        kind: Win16HostAcmObjectKind,
        host: Win16HostAcmHandle,
        candidate: u16,
    ) -> Result<u16, RuntimeError> {
        if kind == Win16HostAcmObjectKind::DriverId {
            if let Some((guest, _)) = self.handles.iter()
                .find(|(_, record)| record.kind == kind && record.host == host)
            {
                return Ok(*guest);
            }
        }
        if candidate == 0 || self.handles.contains_key(&candidate) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "reserved Win16 ACM WORD alias is no longer available"));
        }
        self.next_handle = if candidate == u16::MAX { 1 } else { u32::from(candidate + 1) };
        self.handles.insert(candidate, RuntimeAcmHandle { kind, host });
        Ok(candidate)
    }

    pub(super) fn retire_all(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failure = None;
        // Reserve every snapshot before the first host-side close/remove.
        // Allocation failure therefore cannot leave a partially retired set.
        let mut prepared = Vec::new();
        prepared.try_reserve_exact(self.prepared_headers.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM prepared-header cleanup snapshot", error))?;
        for (key, value) in &self.prepared_headers {
            let cleanup = match &value.phase {
                stream::PreparedAcmHeaderPhase::NativePrepared { token } =>
                    AcmHeaderCleanup::NativePrepared { token: *token },
                stream::PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(receipt) =>
                    AcmHeaderCleanup::CancelPendingGuestPublication {
                        unprepare_flags: receipt.unprepare_flags,
                        native_result: receipt.native_result,
                    },
            };
            prepared.push((*key, cleanup));
        }
        let mut streams = Vec::new();
        streams.try_reserve_exact(self.handles.values().filter(|record|
            record.kind == Win16HostAcmObjectKind::Stream).count()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM stream cleanup snapshot", error))?;
        streams.extend(self.handles.iter().filter_map(|(guest, record)|
            (record.kind == Win16HostAcmObjectKind::Stream).then_some((*guest, record.host))));
        let mut drivers = Vec::new();
        drivers.try_reserve_exact(self.handles.values().filter(|record|
            record.kind == Win16HostAcmObjectKind::Driver).count()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM driver cleanup snapshot", error))?;
        drivers.extend(self.handles.iter().filter_map(|(guest, record)|
            (record.kind == Win16HostAcmObjectKind::Driver).then_some((*guest, record.host))));
        let mut added_ids = Vec::new();
        added_ids.try_reserve_exact(self.added_driver_ids.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM added-driver cleanup snapshot", error))?;
        added_ids.extend(self.added_driver_ids.iter().copied());
        let mut borrowed_ids = Vec::new();
        borrowed_ids.try_reserve_exact(self.handles.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM borrowed-driver cleanup snapshot", error))?;
        borrowed_ids.extend(self.handles.iter().filter_map(|(guest, record)|
            (record.kind == Win16HostAcmObjectKind::DriverId
                && !self.added_driver_ids.contains(guest)).then_some((*guest, record.host))));
        for ((guest_stream, header_far), cleanup) in prepared {
            match cleanup {
                AcmHeaderCleanup::CancelPendingGuestPublication {
                    unprepare_flags, native_result,
                } => {
                    // Task retirement is terminal: discard the unpublished guest
                    // record explicitly and never claim it was written or acknowledged.
                    self.prepared_headers.remove(&(guest_stream, header_far));
                    remember_acm_cleanup_failure(&mut failure,
                        acm_publication_cancelled(unprepare_flags, native_result));
                }
                AcmHeaderCleanup::NativePrepared { token } => {
                    let Some(stream) = self.handle(guest_stream,
                        Win16HostAcmObjectKind::Stream) else {
                        remember_acm_cleanup_failure(&mut failure, acm_invariant(
                            "prepared ACM header lost its runtime stream handle"));
                        continue;
                    };
                    match host.win16_acm(Win16HostAcmOperation::StreamUnprepareHeader {
                        stream, header_token: token, flags: 0,
                    }) {
                        Ok(Win16HostAcmResult::StreamHeader {
                            result, status, header_retired, ..
                        }) => {
                            let prepared = status & ACMSTREAMHEADER_STATUSF_PREPARED != 0;
                            if header_retired {
                                // This terminal path intentionally cancels guest
                                // publication. The native retirement receipt still
                                // consumes the token, including a contradictory status.
                                self.prepared_headers.remove(&(guest_stream, header_far));
                                if prepared {
                                    remember_acm_cleanup_failure(&mut failure, acm_invariant(
                                        "native ACM unprepare retirement receipt retained PREPARED status"));
                                }
                                if result != 0 {
                                    remember_acm_cleanup_failure(&mut failure,
                                        acm_native_result_error(
                                            Win16HostAcmNativeOperation::StreamUnprepareHeader,
                                            result));
                                }
                            } else if result == 0 {
                                remember_acm_cleanup_failure(&mut failure, acm_invariant(
                                    "native ACM unprepare succeeded without a retirement receipt"));
                            } else {
                                remember_acm_cleanup_failure(&mut failure, acm_native_result_error(
                                    Win16HostAcmNativeOperation::StreamUnprepareHeader, result));
                            }
                        }
                        Ok(_) => remember_acm_cleanup_failure(&mut failure,
                            acm_invariant("ACM header cleanup returned the wrong host result")),
                        Err(error) => remember_acm_cleanup_failure(&mut failure, error),
                    }
                }
            }
        }

        for (guest, stream) in streams {
            if self.prepared_headers.keys().any(|(owner, _)| *owner == guest) {
                // Failed unprepare retains both the guest retry record and the
                // native stream/header owners. Closing cannot retire them.
                continue;
            }
            match host.win16_acm(Win16HostAcmOperation::StreamClose { stream, flags: 0 }) {
                Ok(Win16HostAcmResult::Scalar(0)) => {
                    self.handles.remove(&guest);
                }
                Ok(Win16HostAcmResult::Scalar(result)) => remember_acm_cleanup_failure(
                    &mut failure, acm_native_result_error(
                        Win16HostAcmNativeOperation::StreamClose, result)),
                Ok(_) => remember_acm_cleanup_failure(&mut failure,
                    acm_invariant("ACM stream cleanup returned the wrong host result")),
                Err(error) => remember_acm_cleanup_failure(&mut failure, error),
            }
        }

        for (guest, driver) in drivers {
            match host.win16_acm(Win16HostAcmOperation::DriverClose { driver, flags: 0 }) {
                Ok(Win16HostAcmResult::Scalar(0)) => { self.handles.remove(&guest); }
                Ok(Win16HostAcmResult::Scalar(result)) => remember_acm_cleanup_failure(
                    &mut failure, acm_native_result_error(
                        Win16HostAcmNativeOperation::DriverClose, result)),
                Ok(_) => remember_acm_cleanup_failure(&mut failure,
                    acm_invariant("ACM driver cleanup returned the wrong host result")),
                Err(error) => remember_acm_cleanup_failure(&mut failure, error),
            }
        }

        for guest in added_ids {
            let Some(driver_id) = self.handle(guest, Win16HostAcmObjectKind::DriverId) else {
                self.added_driver_ids.remove(&guest);
                continue;
            };
            match host.win16_acm(Win16HostAcmOperation::DriverRemove { driver_id, flags: 0 }) {
                Ok(Win16HostAcmResult::Scalar(0)) => {
                    self.handles.remove(&guest);
                    self.added_driver_ids.remove(&guest);
                }
                Ok(Win16HostAcmResult::Scalar(result)) => remember_acm_cleanup_failure(
                    &mut failure, acm_native_result_error(
                        Win16HostAcmNativeOperation::DriverRemove, result)),
                Ok(_) => remember_acm_cleanup_failure(&mut failure,
                    acm_invariant("ACM driver-remove cleanup returned the wrong host result")),
                Err(error) => remember_acm_cleanup_failure(&mut failure, error),
            }
        }
        for (guest, driver_id) in borrowed_ids {
            match host.win16_acm(Win16HostAcmOperation::DriverIdRelease { driver_id }) {
                Ok(Win16HostAcmResult::Scalar(0)) => { self.handles.remove(&guest); }
                Ok(Win16HostAcmResult::Scalar(result)) => remember_acm_cleanup_failure(
                    &mut failure, acm_native_result_error(
                        Win16HostAcmNativeOperation::DriverIdRelease, result)),
                Ok(_) => remember_acm_cleanup_failure(&mut failure,
                    acm_invariant("ACM borrowed-driver cleanup returned the wrong host result")),
                Err(error) => remember_acm_cleanup_failure(&mut failure, error),
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn remember_acm_cleanup_failure(
    first: &mut Option<RuntimeError>,
    error: RuntimeError,
) {
    *first = Some(match first.take() {
        None => error,
        Some(primary) => combine_acm_failures(primary, error,
            "multiple Win16 ACM cleanup operations failed"),
    });
}

fn acm_publication_cancelled(unprepare_flags: u32, native_result: u32) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure,
        "terminal ACM cleanup cancelled an unpublished guest header record",
        AcmGuestPublicationCancelled { unprepare_flags, native_result })
}

#[derive(Debug)]
struct AcmGuestPublicationCancelled { unprepare_flags: u32, native_result: u32 }

impl std::fmt::Display for AcmGuestPublicationCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter,
            "guest writeback was cancelled after unprepare flags {:#010X} and native MMRESULT {:#010X}; no guest publication, source acknowledgement, or producer-quiescence proof was recorded",
            self.unprepare_flags, self.native_result)
    }
}

impl std::error::Error for AcmGuestPublicationCancelled {}

pub(super) fn combine_acm_failures(
    primary: RuntimeError,
    additional: RuntimeError,
    message: &'static str,
) -> RuntimeError {
    primary.with_cleanup(message, additional)
}

pub(super) fn acm_native_result_error(
    operation: Win16HostAcmNativeOperation,
    result: u32,
) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure,
        "native ACM cleanup operation returned an error result",
        Win16HostAcmNativeFailure::new(operation, result))
}

impl super::Win16State {
    pub(super) fn acm_compat_api(
        &mut self,
        call: Win16MultimediaCall,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        if !call.module.eq_ignore_ascii_case("MSACM") {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "non-MSACM multimedia request reached direct ACM dispatch"));
        }
        self.retry_orphaned_acm_icons(host)?;
        self.retry_orphaned_acm_enumeration(host)?;
        match call.ordinal {
            3 => {
                // The local Win16 compatibility reference's DllEntryPoint16
                // is a stateless TRUE initializer; do not treat it as a
                // general driver callback or forward its Win16 frame to host.
                self.finish_acm(&mut cpu.regs, return_to, 1, return_kind)
            }
            7 => {
                let reply = host.win16_acm(crate::Win16HostAcmOperation::GetVersion)?;
                let value = match reply {
                    crate::Win16HostAcmResult::Scalar(value) => value,
                    _ => return Err(acm_invariant("acmGetVersion returned the wrong result")),
                };
                self.finish_acm(&mut cpu.regs, return_to, value, return_kind)
            }
            8 | 10..=18 => self.acm_driver_api(
                call, cpu, dos, memory, host, return_to, return_kind),
            30 | 31 | 40..=45 | 50 | 51 | 60..=62 => self.acm_format_api(
                call, cpu, dos, memory, host, return_to, return_kind),
            70..=78 => self.acm_stream_api(
                call, &mut cpu.regs, memory, host, return_to, return_kind),
            _ => Err(RuntimeError::new(Kind::CompatibilityGap, format!(
                "Win16 MSACM ordinal {} has no known-signature runtime operation", call.ordinal))),
        }
    }

    fn acm_driver_api(
        &mut self, call: Win16MultimediaCall, cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel, memory: &mut Memory,
        host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.acm_driver_export(call, cpu, dos, memory, host, return_to, return_kind)
    }

    fn acm_format_api(
        &mut self, call: Win16MultimediaCall, cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel, memory: &mut Memory,
        host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.acm_format_export(call, cpu, dos, memory, host, return_to, return_kind)
    }

    fn acm_stream_api(
        &mut self, call: Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.acm_stream_export(call, registers, memory, host, return_to, return_kind)
    }

    fn finish_acm(
        &mut self, registers: &mut Registers, return_to: (u16, u16, u32),
        value: u32, kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(registers, return_to.0, return_to.1, return_to.2, value, kind)
    }

    pub(super) fn finish_acm_input_error(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
        error: RuntimeError,
        guest_result: u32,
        kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        if error.kind() == Kind::InvalidInput {
            self.finish_acm(registers, return_to, guest_result, kind)
        } else {
            Err(error)
        }
    }
}

pub(super) const MMSYSERR_INVALHANDLE: u32 = 5;
pub(super) const MMSYSERR_NOMEM: u32 = 7;
pub(super) const MMSYSERR_NOTSUPPORTED: u32 = 8;
pub(super) const MMSYSERR_INVALFLAG: u32 = 10;
pub(super) const MMSYSERR_INVALPARAM: u32 = 11;
pub(super) const ACMERR_NOTPOSSIBLE: u32 = 512;
// ACMERR_UNPREPARED from the Windows ACM error definitions (514).
pub(super) const ACMERR_UNPREPARED: u32 = 514;
pub(super) const ACM_STREAMOPENF_ASYNC: u32 = 2;
pub(super) const ACMSTREAMHEADER_STATUSF_PREPARED: u32 = 0x0002_0000;

impl super::Win16State {
    pub(super) fn retire_all_acm(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failure = None;
        if !self.acm.enumerations.is_empty() {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "MSACM enumeration frames must be canceled in callback-stack order before task cleanup"));
        }
        if let Err(error) = self.retry_orphaned_acm_enumeration(host) {
            remember_acm_cleanup_failure(&mut failure, error);
        }
        if let Err(error) = self.retry_orphaned_acm_icons(host) {
            remember_acm_cleanup_failure(&mut failure, error);
        }
        if let Err(error) = self.retire_acm_orphan_allocations() {
            remember_acm_cleanup_failure(&mut failure, error);
        }
        if let Err(error) = self.acm.retire_all(host) {
            remember_acm_cleanup_failure(&mut failure, error);
        }
        failure.map_or(Ok(()), Err)
    }

    pub(super) fn retry_orphaned_acm_icons(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failure = None;
        let mut index = 0;
        while index < self.acm.orphaned_icons.len() {
            let icon = self.acm.orphaned_icons[index];
            match host.win16_release_icon(icon) {
                Ok(()) => { self.acm.orphaned_icons.remove(index); }
                Err(error) => {
                    remember_acm_cleanup_failure(&mut failure,
                        error.with_context("retrying unpublished ACM driver icon release"));
                    index += 1;
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn retire_acm_orphan_allocations(&mut self) -> Result<(), RuntimeError> {
        let mut failure = None;
        let mut index = 0;
        while index < self.acm.orphan_callback_allocations.len() {
            let allocation = self.acm.orphan_callback_allocations[index].identity;
            match self.free_runtime_global_on_teardown(allocation) {
                Ok(GlobalTeardownResult::Freed) => {
                    self.acm.orphan_callback_allocations.remove(index);
                }
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    let error = retained.retained_error("MSACM callback buffer")
                        .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "MSACM orphan cleanup lost its retained cause"));
                    let error = self.acm.orphan_callback_allocations[index]
                        .remember_failure(error);
                    remember_acm_cleanup_failure(&mut failure, error);
                    index += 1;
                }
                Err(error) => {
                    let error = self.acm.orphan_callback_allocations[index]
                        .remember_failure(error);
                    remember_acm_cleanup_failure(&mut failure, error);
                    index += 1;
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn guest_code_reference(selector: u16, offset: u16) -> u32 {
    (u32::from(selector) << 16) | u32::from(offset)
}

pub(super) fn acm_output_range(
    state: &super::Win16State,
    far: u32,
    length: usize,
    memory: &Memory,
) -> Result<GuestOutputRange, RuntimeError> {
    if far == 0 { return Err(RuntimeError::new(Kind::InvalidInput,
        "Win16 MSACM required output far pointer is null")); }
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, length)
}

pub(super) fn acm_commit_output(
    state: &super::Win16State,
    memory: &mut Memory,
    range: GuestOutputRange,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    let mut writes = Vec::new();
    writes.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 ACM output transaction", error))?;
    writes.push((range, bytes));
    commit_guest_writes(state, memory, writes)
}

pub(super) struct AcmU16Write {
    range: GuestOutputRange,
    bytes: Vec<u8>,
    writes: Vec<(GuestOutputRange, Vec<u8>)>,
}

impl AcmU16Write {
    pub(super) fn reserve(range: GuestOutputRange) -> Result<Self, RuntimeError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 ACM WORD output bytes", error))?;
        let mut writes = Vec::new();
        writes.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 ACM WORD output transaction", error))?;
        Ok(Self { range, bytes, writes })
    }

    pub(super) fn commit(
        mut self,
        state: &super::Win16State,
        memory: &mut Memory,
        value: u16,
    ) -> Result<(), RuntimeError> {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.writes.push((self.range, self.bytes));
        commit_guest_writes(state, memory, self.writes)
    }
}

pub(super) fn acm_wire_size(
    state: &super::Win16State,
    far: u32,
    minimum: usize,
    memory: &Memory,
) -> Result<(SegmentedPointer, usize), RuntimeError> {
    let pointer = acm_pointer(state, far, 4, memory)?;
    let header = acm_read(state, pointer, 4, memory)?;
    let size = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let size = usize::try_from(size).map_err(|error| RuntimeError::with_source(
        Kind::InvalidInput, "Win16 ACM structure size exceeds host address width", error))?;
    if size < minimum {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 ACM structure is smaller than its required fixed prefix"));
    }
    acm_pointer(state, far, size, memory)?;
    Ok((pointer, size))
}

pub(super) fn acm_read_ansi_z(
    state: &super::Win16State,
    far: u32,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 MSACM required string far pointer is null"));
    }
    win16_abi::strings::read_ansi_z(&state.selectors, memory, far,
        win16_abi::MAX_WIN16_STRING_BYTES).map_err(crate::runtime_error)
}

pub(super) fn acm_validate_callback(
    state: &super::Win16State,
    callback: u32,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    if callback == 0 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 MSACM callback pointer is null"));
    }
    let pointer = state.selectors.pointer_from_far(callback).map_err(crate::runtime_error)?;
    state.selectors.translate(pointer, win16_abi::Access::Execute, 1, memory)
        .map_err(crate::runtime_error)?;
    Ok(())
}

pub(super) fn acm_warn_unsupported(
    state: &mut super::Win16State,
    host: &mut impl RuntimeHost,
    ordinal: u16,
    message: &'static str,
) {
    if state.acm.warned_unsupported.insert(ordinal) {
        host.report_diagnostic(&crate::Diagnostic::warning(Kind::CompatibilityGap,
            format!("MSACM ordinal {ordinal}: {message}")));
    }
}

pub(super) fn acm_word(call: &Win16MultimediaCall, index: usize) -> Result<u16, RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::Word(value)) => Ok(*value),
        _ => Err(bad_acm_argument(call, index)),
    }
}

pub(super) fn acm_dword(call: &Win16MultimediaCall, index: usize) -> Result<u32, RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::Dword(value)) => Ok(*value),
        _ => Err(bad_acm_argument(call, index)),
    }
}

pub(super) fn acm_far(call: &Win16MultimediaCall, index: usize) -> Result<u32, RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::GuestFarPointer(value)) => Ok(*value),
        _ => Err(bad_acm_argument(call, index)),
    }
}

pub(super) fn acm_pointer(
    state: &super::Win16State, far: u32, bytes: usize, memory: &Memory,
) -> Result<SegmentedPointer, RuntimeError> {
    if far == 0 { return Err(RuntimeError::new(Kind::InvalidInput,
        "Win16 MSACM required far pointer is null")); }
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    let mut consumed = 0usize;
    while consumed < bytes {
        let displacement = u32::try_from(consumed).map_err(|error|
            RuntimeError::with_source(Kind::GuestFault,
                "Win16 ACM read range exceeds DWORD address extent", error))?;
        let chunk = state.selectors.add_bytes(pointer, displacement)
            .map_err(crate::runtime_error)?;
        let descriptor = state.selectors.describe(chunk.selector())
            .map_err(crate::runtime_error)?;
        let available = descriptor.limit.checked_sub(u32::from(chunk.offset()))
            .and_then(|remaining| remaining.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 ACM range starts beyond selector limit"))? as usize;
        let length = available.min(bytes - consumed);
        state.selectors.translate(chunk, win16_abi::Access::Read, length, memory)
            .map_err(crate::runtime_error)?;
        consumed = consumed.checked_add(length).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 ACM read range length overflow"))?;
    }
    Ok(pointer)
}

pub(super) fn acm_read(
    state: &super::Win16State, pointer: SegmentedPointer, bytes: usize,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(bytes).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve full Win16 ACM guest range", error))?;
    output.resize(bytes, 0);
    let mut consumed = 0usize;
    while consumed < bytes {
        let displacement = u32::try_from(consumed).map_err(|error|
            RuntimeError::with_source(Kind::GuestFault,
                "Win16 ACM read range exceeds DWORD address extent", error))?;
        let chunk = state.selectors.add_bytes(pointer, displacement)
            .map_err(crate::runtime_error)?;
        let descriptor = state.selectors.describe(chunk.selector())
            .map_err(crate::runtime_error)?;
        let available = descriptor.limit.checked_sub(u32::from(chunk.offset()))
            .and_then(|remaining| remaining.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 ACM range starts beyond selector limit"))? as usize;
        let length = available.min(bytes - consumed);
        let address = state.selectors.translate(chunk, win16_abi::Access::Read,
            length, memory).map_err(crate::runtime_error)?;
        memory.read(address, &mut output[consumed..consumed + length])
            .map_err(crate::runtime_error)?;
        consumed = consumed.checked_add(length).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 ACM read range length overflow"))?;
    }
    Ok(output)
}

pub(super) fn acm_copy(source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(source.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy Win16 ACM input bytes", error))?;
    output.extend_from_slice(source);
    Ok(output)
}

pub(super) fn acm_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn bad_acm_argument(call: &Win16MultimediaCall, index: usize) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, format!(
        "Win16 MSACM decoder returned the wrong argument kind for ordinal {} argument {}",
        call.ordinal, index))
}
