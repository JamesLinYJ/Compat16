//! Stream close and prepared-header retirement share one native unprepare path.

use std::{error::Error, fmt};

use guest_core::{Registers, memory::Memory};
use win16_abi::Win16ReturnKind;

use super::{
    Kind, PreparedAcmHeader, PreparedAcmHeaderPhase, PendingAcmHeaderPublication,
    GuestOutputRange, RuntimeError, RuntimeHost, Win16HostAcmHandle, Win16HostAcmObjectKind,
    Win16HostAcmOperation, Win16HostAcmResult, Win16State, acm_dword, acm_far,
    acm_invariant, acm_word, scalar_result, try_clone_header_bytes,
    ACMERR_UNPREPARED, ACMSTREAMHEADER_STATUSF_PREPARED, MMSYSERR_INVALHANDLE,
    MMSYSERR_INVALPARAM,
};

impl Win16State {
    pub(super) fn acm_stream_close(
        &mut self,
        call: &win16_abi::Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest = acm_word(call, 0)?;
        let Some(stream) = self.acm.handle(guest, Win16HostAcmObjectKind::Stream) else {
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let flags = acm_dword(call, 1)?;
        let mut headers = Vec::new();
        let count = self.acm.prepared_headers.keys()
            .filter(|(owner, _)| *owner == guest).count();
        headers.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve ACM stream-close unprepare snapshot", error))?;
        for ((owner, far), prepared) in &self.acm.prepared_headers {
            if *owner == guest {
                let clone = prepared.try_clone().map_err(|error| {
                    match &prepared.phase {
                        PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(receipt) =>
                            pending_publication_error(*owner, *far, receipt.unprepare_flags,
                                receipt.native_result, error),
                        PreparedAcmHeaderPhase::NativePrepared { .. } => error,
                    }
                });
                headers.push((*far, clone));
            }
        }

        let mut unprepare_failure = None;
        let mut native_failures = None;
        let mut publication_failures = None;
        let mut all_headers_published = true;
        for (header_far, prepared) in headers {
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    all_headers_published = false;
                    remember_close_failure(&mut publication_failures, error);
                    continue;
                }
            };
            let current = if prepared.is_native_prepared() {
                match self.live_prepared_header(guest, header_far, memory) {
                    Ok((live, _)) => match live.header_output.read(self, memory) {
                        Ok(bytes) => Some(bytes),
                        Err(error) if error.kind() == Kind::GuestFault => None,
                        Err(error) => {
                            all_headers_published = false;
                            remember_close_failure(&mut publication_failures, error);
                            continue;
                        }
                    },
                    Err(error) if error.kind() == Kind::GuestFault => None,
                    Err(error) if error.kind() == Kind::InvalidInput => {
                        all_headers_published = false;
                        unprepare_failure.get_or_insert(u32::from(MMSYSERR_INVALPARAM));
                        continue;
                    }
                    Err(error) => {
                        all_headers_published = false;
                        remember_close_failure(&mut publication_failures, error);
                        continue;
                    }
                }
            } else {
                None
            };
            let outcome = match unprepare_prepared_header(self, guest, header_far,
                stream, prepared, current, 0, memory, host)
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    all_headers_published = false;
                    remember_close_failure(&mut publication_failures, error);
                    continue;
                }
            };
            if outcome.result != 0 {
                unprepare_failure.get_or_insert(outcome.result);
                if outcome.publication_failure.is_none() {
                    remember_close_failure(&mut native_failures,
                        super::super::acm_native_result_error(
                            super::super::Win16HostAcmNativeOperation::StreamUnprepareHeader,
                            outcome.result));
                }
            }
            if !outcome.publication_complete {
                all_headers_published = false;
            }
            if let Some(error) = outcome.publication_failure {
                remember_close_failure(&mut publication_failures, error);
            }
        }

        if !all_headers_published {
            if let Some(mut failure) = publication_failures {
                if let Some(native) = native_failures {
                    failure = super::super::combine_acm_failures(failure, native,
                        "ACM header publication and native unprepare both failed");
                }
                return Err(failure);
            }
            if let Some(result) = unprepare_failure {
                return self.finish_acm(registers, return_to, result, return_kind);
            }
            return Err(acm_invariant(
                "ACM stream close retained a header without an unprepare result"));
        }
        if self.acm.prepared_headers.keys().any(|(owner, _)| *owner == guest) {
            return Err(acm_invariant(
                "ACM stream close reached native close with an unpublished guest header"));
        }

        let result = scalar_result(host.win16_acm(Win16HostAcmOperation::StreamClose {
            stream, flags,
        })?)?;
        if result == 0 {
            self.acm.handles.remove(&guest);
            return self.finish_acm(registers, return_to,
                unprepare_failure.unwrap_or(0), return_kind);
        }
        if let Some(unprepare_errors) = native_failures {
            return Err(super::super::combine_acm_failures(unprepare_errors,
                super::super::acm_native_result_error(
                    super::super::Win16HostAcmNativeOperation::StreamClose, result),
                "ACM stream close and header unprepare both failed"));
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    pub(super) fn acm_stream_unprepare(
        &mut self,
        call: &win16_abi::Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest_stream = acm_word(call, 0)?;
        let Some(stream) = self.acm.handle(guest_stream, Win16HostAcmObjectKind::Stream) else {
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let header_far = acm_far(call, 1)?;
        let flags = acm_dword(call, 2)?;
        let Some(saved) = self.acm.prepared_headers.get(&(guest_stream, header_far)) else {
            return self.finish_acm(registers, return_to, ACMERR_UNPREPARED, return_kind);
        };
        let prepared = saved.try_clone().map_err(|error| match &saved.phase {
            PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(receipt) =>
                pending_publication_error(guest_stream, header_far,
                    receipt.unprepare_flags, receipt.native_result, error),
            PreparedAcmHeaderPhase::NativePrepared { .. } => error,
        })?;
        let current = if prepared.is_native_prepared() {
            let (live, _) = match self.live_prepared_header(guest_stream, header_far, memory) {
                Ok(value) => value,
                Err(error) => return self.finish_acm_input_error(registers, return_to, error,
                    u32::from(MMSYSERR_INVALPARAM), return_kind),
            };
            match live.header_output.read(self, memory) {
                Ok(bytes) => Some(bytes),
                Err(error) => return self.finish_acm_input_error(registers, return_to, error,
                    u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        } else {
            None
        };
        let outcome = unprepare_prepared_header(self, guest_stream, header_far,
            stream, prepared, current, flags, memory, host)?;
        if let Some(error) = outcome.publication_failure { return Err(error); }
        self.finish_acm(registers, return_to, outcome.result, return_kind)
    }
}

struct UnprepareOutcome {
    result: u32,
    publication_complete: bool,
    publication_failure: Option<RuntimeError>,
}

fn unprepare_prepared_header(
    state: &mut Win16State,
    guest_stream: u16,
    header_far: u32,
    stream: Win16HostAcmHandle,
    prepared: PreparedAcmHeader,
    current: Option<Vec<u8>>,
    flags: u32,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<UnprepareOutcome, RuntimeError> {
    let key = (guest_stream, header_far);
    if let PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(pending) = &prepared.phase {
        let result = pending.native_result;
        let saved_flags = pending.unprepare_flags;
        let mut writes = Vec::new();
        let publication_failure = match writes.try_reserve(1) {
            Ok(()) => publish_retired_header(state, key, memory, writes).err()
                .map(|error| pending_publication_error(
                    guest_stream, header_far, saved_flags, result, error)),
            Err(error) => Some(pending_publication_error(guest_stream, header_far,
                saved_flags, result,
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve pending ACM header publication transaction", error))),
        };
        return Ok(UnprepareOutcome {
            result,
            publication_complete: publication_failure.is_none(),
            publication_failure,
        });
    }

    let PreparedAcmHeaderPhase::NativePrepared { token } = prepared.phase else {
        return Err(acm_invariant("unknown ACM prepared-header phase"));
    };
    // The key, selector identity, output range, capacity and guest snapshot
    // already have owned storage. Reserve the transaction container before
    // native unprepare can retire its header owner.
    let mut writes = Vec::new();
    writes.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve ACM unprepare guest commit", error))?;
    let reply = host.win16_acm(Win16HostAcmOperation::StreamUnprepareHeader {
        stream, header_token: token, flags,
    })?;
    let (result, status, header_retired, source_used, destination_used, reserved) = match reply {
        Win16HostAcmResult::StreamHeader { result, status, header_retired,
            source_used, destination_used, reserved, .. } =>
            (result, status, header_retired, source_used, destination_used, reserved),
        _ => return Err(acm_invariant("acmStreamUnprepareHeader returned the wrong host result")),
    };
    let status_prepared = status & ACMSTREAMHEADER_STATUSF_PREPARED != 0;
    if header_retired {
        retain_pending_publication(state, key, PendingAcmHeaderPublication {
            native_result: result,
            unprepare_flags: flags,
            status,
            source_used,
            destination_used,
            reserved,
            header_bytes: current,
        })?;
        if status_prepared {
            return Err(acm_invariant(
                "native ACM unprepare retirement receipt retained PREPARED status"));
        }
    }
    if result == 0 && !header_retired {
        return Err(acm_invariant("native ACM unprepare succeeded without a retirement receipt"));
    }
    if !header_retired {
        return Ok(UnprepareOutcome {
            result,
            publication_complete: false,
            publication_failure: None,
        });
    }

    let publication_failure = publish_retired_header(state, key, memory, writes)
        .err().map(|error| pending_publication_error(
            guest_stream, header_far, flags, result, error));
    Ok(UnprepareOutcome {
        result,
        publication_complete: publication_failure.is_none(),
        publication_failure,
    })
}

fn retain_pending_publication(
    state: &mut Win16State,
    key: (u16, u32),
    pending: PendingAcmHeaderPublication,
) -> Result<(), RuntimeError> {
    let Some(prepared) = state.acm.prepared_headers.get_mut(&key) else {
        return Err(acm_invariant("retired ACM header lost its guest identity reservation"));
    };
    if !prepared.is_native_prepared() {
        return Err(acm_invariant("ACM header retirement changed a non-native phase"));
    }
    prepared.phase = PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(pending);
    Ok(())
}

fn publish_retired_header(
    state: &mut Win16State,
    key: (u16, u32),
    memory: &mut Memory,
    mut writes: Vec<(GuestOutputRange, Vec<u8>)>,
) -> Result<(), RuntimeError> {
    let snapshot = state.acm.prepared_headers.get(&key)
        .ok_or_else(|| acm_invariant("pending ACM header lost its guest publication owner"))?
        .try_clone()?;
    let PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(pending) = snapshot.phase else {
        return Err(acm_invariant("native ACM unprepare retry lacks a retired publication receipt"));
    };
    if pending.status & ACMSTREAMHEADER_STATUSF_PREPARED != 0 {
        return Err(acm_invariant(
            "retired ACM publication receipt contains PREPARED status"));
    }

    let mut bytes = match pending.header_bytes {
        Some(bytes) => bytes,
        None => {
            let bytes = snapshot.header_output.read(state, memory)?;
            let fields = super::decode_stream_header(&bytes)?;
            if fields.signature != snapshot.signature
                || fields.source_bytes > snapshot.source_capacity
                || fields.destination_bytes > snapshot.destination_capacity
            {
                return Err(RuntimeError::new(Kind::InvalidInput,
                    "pending ACM header identity or capacities changed before publication"));
            }
            bytes
        }
    };
    super::patch_stream_header(&mut bytes, pending.status, pending.source_used,
        pending.destination_used, pending.reserved)?;
    super::restore_header_capacities(
        &mut bytes, snapshot.source_capacity, snapshot.destination_capacity,
    )?;
    let commit_bytes = try_clone_header_bytes(&bytes)?;
    let output = snapshot.header_output.try_clone()?;

    let Some(live) = state.acm.prepared_headers.get_mut(&key) else {
        return Err(acm_invariant("pending ACM header disappeared before guest publication"));
    };
    match &mut live.phase {
        PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(receipt)
            if receipt.native_result == pending.native_result =>
        {
            // Keep the exact full guest record, including extension bytes, for
            // another attempt if any later allocation or guest write fails.
            receipt.header_bytes = Some(bytes);
        }
        _ => return Err(acm_invariant(
            "pending ACM header identity changed before guest publication")),
    }
    if writes.capacity() == 0 {
        writes.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve pending ACM guest publication transaction", error))?;
    }
    writes.push((output, commit_bytes));
    super::commit_guest_writes(state, memory, writes)?;
    state.acm.prepared_headers.remove(&key);
    Ok(())
}

fn pending_publication_error(
    guest_stream: u16,
    header_far: u32,
    unprepare_flags: u32,
    native_result: u32,
    cause: RuntimeError,
) -> RuntimeError {
    RuntimeError::with_source(cause.kind(),
        "Win16 ACM header publication remains pending after native unprepare retirement",
        PendingGuestPublicationFailure {
            guest_stream, header_far, unprepare_flags, native_result, cause,
        })
}

#[derive(Debug)]
struct PendingGuestPublicationFailure {
    guest_stream: u16,
    header_far: u32,
    unprepare_flags: u32,
    native_result: u32,
    cause: RuntimeError,
}

impl fmt::Display for PendingGuestPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter,
            "stream {:#06X} header {:#010X}, original flags {:#010X}, native MMRESULT {:#010X}: {}",
            self.guest_stream, self.header_far, self.unprepare_flags,
            self.native_result, self.cause)
    }
}

impl Error for PendingGuestPublicationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.cause) }
}

fn remember_close_failure(first: &mut Option<RuntimeError>, error: RuntimeError) {
    *first = Some(match first.take() {
        None => error,
        Some(primary) => super::super::combine_acm_failures(primary, error,
            "multiple ACM stream-close operations failed"),
    });
}
