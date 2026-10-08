//! Direct synchronous Win16 ACM stream calls and checked buffer ownership.
//!
//! Guest ACMSTREAMHEADER records are decoded field by field. Native stream
//! objects and prepared header storage stay behind the host token boundary;
//! the guest's reserved words never carry a host pointer or native handle.

use guest_core::{Registers, memory::Memory};
use win16_abi::{SegmentedPointer, Win16ReturnKind};
use zerocopy::FromBytes;

use super::{
    Win16State, acm_dword, acm_far, acm_invariant, acm_output_range, acm_pointer,
    acm_read, acm_warn_unsupported, acm_wire_size, AcmU16Write,
    acm_word,
    ACM_STREAMOPENF_ASYNC, MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM,
    MMSYSERR_NOMEM, MMSYSERR_NOTSUPPORTED, ACMERR_UNPREPARED,
    ACMSTREAMHEADER_STATUSF_PREPARED,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAcmHandle,
    Win16HostAcmObjectKind, Win16HostAcmOperation, Win16HostAcmResult,
};
use super::super::guest_ranges::{GuestInputRange, GuestOutputRange, commit_guest_writes};

#[path = "win16_acm_stream_close.rs"]
mod close;

const STREAM_HEADER_BYTES: usize = win16_abi::msacm_abi::ACMSTREAMHEADER16_BYTES;
const STREAM_HEADER_PREFIX_BYTES: usize =
    win16_abi::msacm_abi::ACMSTREAMHEADER16_PREFIX_BYTES;
const WAVEFORMATEX_FIXED_BYTES: usize = win16_abi::msacm_abi::WAVEFORMATEX16_FIXED_BYTES;
const WAVEFILTER_FIXED_BYTES: usize = win16_abi::msacm_abi::WAVEFILTER16_BYTES;
const ACM_STREAMOPENF_QUERY: u32 = 1;

pub(super) struct PreparedAcmHeader {
    pub(super) phase: PreparedAcmHeaderPhase,
    header_pointer: SegmentedPointer,
    header_output: GuestOutputRange,
    signature: StreamHeaderSignature,
    source_capacity: u32,
    destination_capacity: u32,
    source_range: Option<GuestInputRange>,
    destination_range: Option<GuestOutputRange>,
}

// The map value is reserved before native prepare. Retirement replaces this
// inline phase and moves in the captured record when readable; its guest range
// identity remains present even if that read was unavailable. Retaining a
// native receipt therefore does not allocate after the host consumes its token.
pub(super) enum PreparedAcmHeaderPhase {
    NativePrepared { token: u64 },
    NativeRetiredPendingGuestPublication(PendingAcmHeaderPublication),
}

pub(super) struct PendingAcmHeaderPublication {
    pub(super) native_result: u32,
    pub(super) unprepare_flags: u32,
    pub(super) status: u32,
    pub(super) source_used: u32,
    pub(super) destination_used: u32,
    pub(super) reserved: [u32; 10],
    pub(super) header_bytes: Option<Vec<u8>>,
}

impl PreparedAcmHeader {
    fn try_clone(&self) -> Result<Self, RuntimeError> {
        let phase = match &self.phase {
            PreparedAcmHeaderPhase::NativePrepared { token } =>
                PreparedAcmHeaderPhase::NativePrepared { token: *token },
            PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(pending) =>
                PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(
                    PendingAcmHeaderPublication {
                        native_result: pending.native_result,
                        unprepare_flags: pending.unprepare_flags,
                        status: pending.status,
                        source_used: pending.source_used,
                        destination_used: pending.destination_used,
                        reserved: pending.reserved,
                        header_bytes: pending.header_bytes.as_deref()
                            .map(try_clone_header_bytes).transpose()?,
                    }),
        };
        Ok(Self {
            phase,
            header_pointer: self.header_pointer,
            header_output: self.header_output.try_clone()?,
            signature: self.signature,
            source_capacity: self.source_capacity,
            destination_capacity: self.destination_capacity,
            source_range: self.source_range.as_ref().map(GuestInputRange::try_clone)
                .transpose()?,
            destination_range: self.destination_range.as_ref().map(GuestOutputRange::try_clone)
                .transpose()?,
        })
    }

    fn is_native_prepared(&self) -> bool {
        matches!(&self.phase, PreparedAcmHeaderPhase::NativePrepared { .. })
    }

    fn native_token(&self) -> Option<u64> {
        match &self.phase {
            PreparedAcmHeaderPhase::NativePrepared { token } => Some(*token),
            PreparedAcmHeaderPhase::NativeRetiredPendingGuestPublication(_) => None,
        }
    }
}

fn try_clone_header_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut clone = Vec::new();
    clone.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        crate::DiagnosticKind::ResourceExhausted,
        "reserve retained ACM stream-header publication bytes", error))?;
    clone.extend_from_slice(bytes);
    Ok(clone)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StreamHeaderSignature {
    structure_bytes: u32,
    user: u32,
    source_far: u32,
    source_user: u32,
    destination_far: u32,
    destination_user: u32,
}

struct StreamHeaderFields {
    signature: StreamHeaderSignature,
    source_bytes: u32,
    destination_bytes: u32,
    status: u32,
    reserved: [u32; 10],
}

impl Win16State {
    pub(super) fn acm_stream_export(
        &mut self,
        call: win16_abi::Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match call.ordinal {
            70 => self.acm_stream_open(&call, registers, memory, host, return_to, return_kind),
            71 => self.acm_stream_close(&call, registers, memory, host, return_to, return_kind),
            72 => self.acm_stream_size(&call, registers, memory, host, return_to, return_kind),
            75 => self.acm_stream_convert(&call, registers, memory, host, return_to, return_kind),
            76 => self.acm_stream_reset(&call, registers, host, return_to, return_kind),
            77 => self.acm_stream_prepare(&call, registers, memory, host, return_to, return_kind),
            78 => self.acm_stream_unprepare(&call, registers, memory, host, return_to, return_kind),
            _ => Err(acm_invariant("non-stream export reached MSACM stream dispatcher")),
        }
    }

    fn acm_stream_open(
        &mut self,
        call: &win16_abi::Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let output_far = acm_far(call, 0)?;
        let driver_word = acm_word(call, 1)?;
        let driver = match self.acm_driver_for_stream(driver_word) {
            Ok(driver) => driver,
            Err(code) => return self.finish_acm(registers, return_to, code, return_kind),
        };
        let source_far = acm_far(call, 2)?;
        let destination_far = acm_far(call, 3)?;
        let filter_far = acm_far(call, 4)?;
        let callback = acm_dword(call, 5)?;
        let instance = acm_dword(call, 6)?;
        let flags = acm_dword(call, 7)?;
        if flags & ACM_STREAMOPENF_ASYNC != 0 {
            acm_warn_unsupported(self, host, 70,
                "asynchronous stream completion needs the shared guest callback/message router");
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_NOTSUPPORTED), return_kind);
        }
        if callback != 0 || instance != 0 {
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind);
        }
        let query_only = flags & ACM_STREAMOPENF_QUERY != 0;
        let output = if query_only {
            if output_far != 0 {
                return self.finish_acm(registers, return_to,
                    u32::from(MMSYSERR_INVALPARAM), return_kind);
            }
            None
        } else {
            match acm_output_range(self, output_far, 2, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let output_write = output.map(AcmU16Write::reserve).transpose()?;
        let source = match read_waveformat(self, source_far, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let destination = match read_waveformat(self, destination_far, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let filter = if filter_far == 0 { None } else {
            match read_wavefilter(self, filter_far, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let alias = if query_only { None } else {
            match self.acm.reserve_handle_alias()? {
                Some(alias) => Some(alias),
                None => return self.finish_acm(registers, return_to,
                    u32::from(MMSYSERR_NOMEM), return_kind),
            }
        };
        let reply = host.win16_acm(Win16HostAcmOperation::StreamOpen {
            driver, source, destination, filter, flags, query_only,
        })?;
        let (result, stream) = match reply {
            Win16HostAcmResult::StreamOpened { result, stream } => (result, stream),
            _ => return Err(acm_invariant("acmStreamOpen returned the wrong host result")),
        };
        if result != 0 {
            if let Some(stream) = stream {
                close_untracked_stream(host, stream)?;
            }
            return self.finish_acm(registers, return_to, result, return_kind);
        }
        if query_only {
            if let Some(opened) = stream {
                let cleanup = host.win16_acm(Win16HostAcmOperation::StreamClose {
                    stream: opened, flags: 0,
                })?;
                if !matches!(cleanup, Win16HostAcmResult::Scalar(0)) {
                    return Err(acm_invariant("query-only ACM stream unexpectedly opened a native stream"));
                }
                return Err(acm_invariant("query-only ACM stream returned a native stream"));
            }
            return self.finish_acm(registers, return_to, result, return_kind);
        }
        let Some(stream) = stream else {
            return Err(acm_invariant("successful acmStreamOpen returned no native stream"));
        };
        let alias = alias.ok_or_else(|| acm_invariant(
            "non-query ACM stream has no reserved guest handle alias"))?;
        let guest = self.acm.store_reserved_handle(
            Win16HostAcmObjectKind::Stream, stream, alias)?;
        let Some(output) = output_write else {
            return Err(acm_invariant("non-query ACM stream has no guest output range"));
        };
        if let Err(error) = output.commit(self, memory, guest) {
            // Native open already succeeded; keep the owner mapped so task
            // teardown can retry even when guest writeback failed.
            return Err(error);
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_stream_size(
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
        let input_bytes = acm_dword(call, 1)?;
        let output_far = acm_far(call, 2)?;
        let flags = acm_dword(call, 3)?;
        let output = match acm_output_range(self, output_far, 4, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let mut wire_output = Vec::new();
        wire_output.try_reserve_exact(4).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve ACM stream-size guest output", error))?;
        let mut writes = Vec::new();
        writes.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve ACM stream-size output transaction", error))?;
        let reply = host.win16_acm(Win16HostAcmOperation::StreamSize {
            stream, input_bytes, flags,
        })?;
        let (result, output_bytes) = match reply {
            Win16HostAcmResult::StreamSize { result, output_bytes } => (result, output_bytes),
            _ => return Err(acm_invariant("acmStreamSize returned the wrong host result")),
        };
        if result == 0 {
            wire_output.extend_from_slice(&output_bytes.to_le_bytes());
            writes.push((output, wire_output));
            commit_guest_writes(self, memory, writes)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_stream_prepare(
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
        if self.acm.prepared_headers.contains_key(&(guest_stream, header_far)) {
            // ACM documents repeated prepare as a no-op. Still validate that
            // the same guest selector generation and header signature remain
            // live before accepting the no-op.
            if self.acm.prepared_headers.get(&(guest_stream, header_far))
                .is_some_and(|prepared| !prepared.is_native_prepared())
            {
                return self.finish_acm(registers, return_to, ACMERR_UNPREPARED, return_kind);
            }
            if let Err(error) = self.live_prepared_header(guest_stream, header_far, memory) {
                return self.finish_acm_input_error(registers, return_to, error,
                    u32::from(MMSYSERR_INVALPARAM), return_kind);
            }
            return self.finish_acm(registers, return_to, 0, return_kind);
        }
        let (pointer, output, mut full_header, fields) = match read_guest_header(self, header_far, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let source_capacity = fields.source_bytes;
        let destination_capacity = fields.destination_bytes;
        let source_range = if source_capacity == 0 { None } else {
            match acm_input_range(self, fields.signature.source_far,
                source_capacity as usize, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let source = match &source_range {
            Some(range) => match range.read_prefix(self, memory, source_capacity as usize) {
                Ok(value) => value,
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            },
            None => Vec::new(),
        };
        let destination_output = if destination_capacity == 0 { None } else {
            match acm_output_range(self, fields.signature.destination_far,
                destination_capacity as usize, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let destination = match &destination_output {
            Some(range) => match range.read_prefix(self, memory, destination_capacity as usize) {
                Ok(value) => value,
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            },
            None => Vec::new(),
        };
        self.acm.prepared_headers.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve prepared Win16 ACM header owner before native prepare", error))?;
        let mut writes = Vec::new();
        writes.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve prepared-header guest commit", error))?;
        let retained_output = output.try_clone()?;
        let token = self.acm.next_header_token()?;
        let reply = host.win16_acm(Win16HostAcmOperation::StreamPrepareHeader {
            stream, header_token: token, flags, status: fields.status,
            user: fields.signature.user, source_user: fields.signature.source_user,
            destination_user: fields.signature.destination_user,
            source, destination,
            reserved: fields.reserved,
        })?;
        let (result, status, source_used, destination_used, destination, reserved) =
            match reply {
                Win16HostAcmResult::StreamHeader { result, status, source_used,
                    destination_used, destination, reserved, .. } =>
                    (result, status, source_used, destination_used, destination, reserved),
                _ => return Err(acm_invariant("acmStreamPrepareHeader returned the wrong host result")),
            };
        let native_prepared = status & ACMSTREAMHEADER_STATUSF_PREPARED != 0;
        if native_prepared {
            let prepared = PreparedAcmHeader {
                phase: PreparedAcmHeaderPhase::NativePrepared { token },
                header_pointer: pointer, header_output: retained_output,
                signature: fields.signature, source_capacity, destination_capacity,
                source_range, destination_range: destination_output,
            };
            self.acm.prepared_headers.insert((guest_stream, header_far), prepared);
        }
        if result != 0 {
            patch_stream_header(&mut full_header, status, source_used,
                destination_used, reserved)?;
            writes.push((output, full_header));
            commit_guest_writes(self, memory, writes)?;
            return self.finish_acm(registers, return_to, result, return_kind);
        }
        if !native_prepared {
            return Err(acm_invariant("successful native ACM prepare omitted PREPARED status"));
        }
        if source_used > source_capacity || destination_used > destination_capacity
            || destination.len() != destination_capacity as usize
        {
            // Keep both runtime and host owners: native ACM may have marked
            // the header prepared even though its receipt violated bounds.
            return Err(acm_invariant("native ACM prepare returned invalid buffer lengths"));
        }
        patch_stream_header(&mut full_header, status, source_used, destination_used, reserved)?;
        writes.push((output, full_header));
        commit_guest_writes(self, memory, writes)?;
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_stream_convert(
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
        if !self.acm.prepared_headers.contains_key(&(guest_stream, header_far)) {
            return self.finish_acm(registers, return_to, ACMERR_UNPREPARED, return_kind);
        }
        if self.acm.prepared_headers.get(&(guest_stream, header_far))
            .is_some_and(|prepared| !prepared.is_native_prepared())
        {
            // The owner is retained only to retry publication of a native
            // unprepare result; it no longer denotes a native-prepared header.
            // Leave that receipt untouched and report the ordinary guest state.
            return self.finish_acm(registers, return_to, ACMERR_UNPREPARED, return_kind);
        }
        let (prepared, fields) = match self.live_prepared_header(guest_stream, header_far, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to, error,
                u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let mut current = match prepared.header_output.read(self, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        if fields.source_bytes > prepared.source_capacity
            || fields.destination_bytes > prepared.destination_capacity
        {
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind);
        }
        let source = match &prepared.source_range {
            Some(range) => match range.read_prefix(self, memory, fields.source_bytes as usize) {
                Ok(value) => value,
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            },
            None if fields.source_bytes == 0 => Vec::new(),
            None => return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let destination_output = if fields.destination_bytes == 0 { None } else {
            match prepared.destination_range.as_ref() {
                Some(range) => match range.try_clone() {
                    Ok(range) => Some(range),
                    Err(error) => return Err(error),
                },
                None => return self.finish_acm(registers, return_to,
                    u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let destination = match &destination_output {
            Some(range) => match range.read_prefix(self, memory,
                fields.destination_bytes as usize) {
                Ok(value) => value,
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            },
            None => Vec::new(),
        };
        let mut writes = Vec::new();
        writes.try_reserve(2).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve ACM convert guest commit", error))?;
        let mut destination_write = Vec::new();
        destination_write.try_reserve_exact(fields.destination_bytes as usize)
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM convert output before native conversion", error))?;
        let reply = host.win16_acm(Win16HostAcmOperation::StreamConvert {
            stream, header_token: prepared.native_token().ok_or_else(||
                acm_invariant("retired ACM header reached native conversion"))?,
            source, destination, flags,
        })?;
        let (result, status, source_used, destination_used, destination, reserved) = match reply {
            Win16HostAcmResult::StreamHeader { result, status, source_used,
                destination_used, destination, reserved, .. } =>
                (result, status, source_used, destination_used, destination, reserved),
            _ => return Err(acm_invariant("acmStreamConvert returned the wrong host result")),
        };
        let destination_shape_invalid = result == 0
            && destination.len() != fields.destination_bytes as usize;
        let failed_result_has_partial_payload = result != 0 && !destination.is_empty()
            && destination.len() != fields.destination_bytes as usize;
        if source_used > fields.source_bytes
            || destination_used > fields.destination_bytes
            || (destination.is_empty() && destination_used != 0)
            || destination_shape_invalid
            || failed_result_has_partial_payload
        {
            return Err(acm_invariant("native ACM conversion returned invalid used lengths"));
        }
        patch_stream_header(&mut current, status, source_used, destination_used, reserved)?;
        if destination_used != 0 {
            let range = destination_output.ok_or_else(||
                acm_invariant("native ACM used a zero-length destination buffer"))?;
            destination_write.extend_from_slice(&destination[..destination_used as usize]);
            writes.push((range, destination_write));
        }
        writes.push((prepared.header_output, current));
        commit_guest_writes(self, memory, writes)?;
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_stream_reset(
        &mut self,
        call: &win16_abi::Win16MultimediaCall,
        registers: &mut Registers,
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
        let result = scalar_result(host.win16_acm(Win16HostAcmOperation::StreamReset {
            stream, flags,
        })?)?;
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_for_stream(
        &self,
        guest: u16,
    ) -> Result<Option<Win16HostAcmHandle>, u32> {
        if guest == 0 { return Ok(None); }
        self.acm.handle(guest, Win16HostAcmObjectKind::Driver)
            .map(Some).ok_or(u32::from(MMSYSERR_INVALHANDLE))
    }

    fn live_prepared_header(
        &self,
        guest_stream: u16,
        header_far: u32,
        memory: &Memory,
    ) -> Result<(PreparedAcmHeader, StreamHeaderFields), RuntimeError> {
        let Some(saved) = self.acm.prepared_headers.get(&(guest_stream, header_far)) else {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "Win16 ACM stream header is not prepared"));
        };
        if !saved.is_native_prepared() {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "Win16 ACM stream header awaits unprepare result publication"));
        }
        let prepared = saved.try_clone()?;
        let current_pointer = self.selectors.pointer_from_far(header_far)
            .map_err(crate::runtime_error)?;
        if current_pointer != prepared.header_pointer {
            return Err(RuntimeError::new(Kind::GuestFault,
                "prepared ACM header selector identity changed"));
        }
        prepared.header_output.is_live(self, memory)?;
        if let Some(source) = &prepared.source_range { source.is_live(self, memory)?; }
        if let Some(destination) = &prepared.destination_range {
            destination.is_live(self, memory)?;
        }
        let bytes = prepared.header_output.read(self, memory)
            ?;
        let fields = decode_stream_header(&bytes)?;
        if fields.signature != prepared.signature
            || fields.source_bytes > prepared.source_capacity
            || fields.destination_bytes > prepared.destination_capacity
        {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "prepared ACM stream header fields changed beyond retained capacities"));
        }
        Ok((prepared, fields))
    }
}

fn acm_input_range(
    state: &Win16State,
    far: u32,
    length: usize,
    memory: &Memory,
) -> Result<GuestInputRange, RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 ACM stream source buffer is null"));
    }
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    GuestInputRange::capture(state, memory, pointer, length)
}

fn read_guest_header(
    state: &Win16State,
    far: u32,
    memory: &Memory,
) -> Result<(SegmentedPointer, GuestOutputRange, Vec<u8>, StreamHeaderFields), RuntimeError> {
    let (pointer, size) = acm_wire_size(state, far, STREAM_HEADER_BYTES, memory)?;
    let output = acm_output_range(state, far, size, memory)?;
    let bytes = output.read(state, memory)?;
    let fields = decode_stream_header(&bytes)?;
    if u64::from(fields.signature.structure_bytes) != size as u64 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 ACM stream header size is invalid"));
    }
    Ok((pointer, output, bytes, fields))
}

fn decode_stream_header(bytes: &[u8]) -> Result<StreamHeaderFields, RuntimeError> {
    if bytes.len() < STREAM_HEADER_BYTES {
        return Err(acm_invariant("Win16 ACM stream header is shorter than its fixed record"));
    }
    let wire = win16_abi::msacm_abi::AcmStreamHeader16Wire::read_from_bytes(
        &bytes[..STREAM_HEADER_BYTES])
        .map_err(|_| RuntimeError::new(Kind::InvalidInput,
            "invalid Win16 ACM stream-header wire record"))?;
    let signature = StreamHeaderSignature {
        structure_bytes: wire.structure_bytes.get(), user: wire.user.get(),
        source_far: wire.source_far.get(),
        source_user: wire.source_user.get(), destination_far: wire.destination_far.get(),
        destination_user: wire.destination_user.get(),
    };
    let mut reserved = [0; 10];
    for (target, value) in reserved.iter_mut().zip(wire.reserved) {
        *target = value.get();
    }
    Ok(StreamHeaderFields {
        signature, source_bytes: wire.source_bytes.get(),
        destination_bytes: wire.destination_bytes.get(),
        status: wire.status.get(), reserved,
    })
}

fn patch_stream_header(
    bytes: &mut [u8],
    status: u32,
    source_used: u32,
    destination_used: u32,
    reserved: [u32; 10],
) -> Result<(), RuntimeError> {
    if bytes.len() < STREAM_HEADER_BYTES {
        return Err(acm_invariant("cannot update a truncated Win16 ACM stream header"));
    }
    write_dword(bytes, 4, status)?;
    write_dword(bytes, 20, source_used)?;
    write_dword(bytes, 36, destination_used)?;
    for (index, value) in reserved.into_iter().enumerate() {
        write_dword(bytes, STREAM_HEADER_PREFIX_BYTES + index * 4, value)?;
    }
    Ok(())
}

fn write_dword(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), RuntimeError> {
    let destination = bytes.get_mut(offset..offset + 4)
        .ok_or_else(|| acm_invariant("Win16 ACM field lies outside its wire record"))?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn restore_header_capacities(
    bytes: &mut [u8],
    source_capacity: u32,
    destination_capacity: u32,
) -> Result<(), RuntimeError> {
    // Win16 ACMSTREAMHEADER keeps current lengths at offsets 16 and 32;
    // Convert may shorten them, while Unprepare restores the capacities that
    // were presented to Prepare.
    write_dword(bytes, 16, source_capacity)?;
    write_dword(bytes, 32, destination_capacity)
}

fn read_waveformat(
    state: &Win16State,
    far: u32,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let prefix_pointer = acm_pointer(state, far, 16, memory)?;
    let pcwfx = acm_read(state, prefix_pointer, 16, memory)?;
    if u16::from_le_bytes([pcwfx[0], pcwfx[1]]) == 1 {
        // Win16 PCMFORMAT carries 16 bytes; the host adapter adds cbSize to
        // owned WAVEFORMATEX storage without extending the guest buffer.
        return Ok(pcwfx);
    }
    let pointer = acm_pointer(state, far, WAVEFORMATEX_FIXED_BYTES, memory)?;
    let fixed = acm_read(state, pointer, WAVEFORMATEX_FIXED_BYTES, memory)?;
    let extra = u16::from_le_bytes([fixed[16], fixed[17]]) as usize;
    let size = WAVEFORMATEX_FIXED_BYTES.checked_add(extra).ok_or_else(||
        RuntimeError::new(Kind::GuestFault, "Win16 WAVEFORMATEX size overflow"))?;
    acm_read(state, pointer, size, memory)
}

fn read_wavefilter(
    state: &Win16State,
    far: u32,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let pointer = acm_pointer(state, far, WAVEFILTER_FIXED_BYTES, memory)?;
    let fixed = acm_read(state, pointer, WAVEFILTER_FIXED_BYTES, memory)?;
    let declared = u32::from_le_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
    let size = usize::try_from(declared).map_err(|error| RuntimeError::with_source(
        Kind::InvalidInput, "Win16 WAVEFILTER size exceeds host address width", error))?;
    if size < WAVEFILTER_FIXED_BYTES {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 WAVEFILTER is smaller than its fixed prefix"));
    }
    acm_read(state, pointer, size, memory)
}

fn scalar_result(result: Win16HostAcmResult) -> Result<u32, RuntimeError> {
    match result {
        Win16HostAcmResult::Scalar(value) => Ok(value),
        _ => Err(acm_invariant("ACM scalar operation returned the wrong host result")),
    }
}

fn close_untracked_stream(
    host: &mut impl RuntimeHost,
    stream: Win16HostAcmHandle,
) -> Result<(), RuntimeError> {
    match host.win16_acm(Win16HostAcmOperation::StreamClose { stream, flags: 0 })? {
        Win16HostAcmResult::Scalar(0) => Ok(()),
        _ => Err(acm_invariant("could not close an ACM stream whose guest handle allocation failed")),
    }
}
