//! Win16 NetBIOS calls forwarded through the Windows NCB API.
//!
//! The guest NCB is decoded by the runtime. This module accepts only owned
//! fields and buffers; a guest FAR pointer, the Win16 `ncb_post` value, and the
//! Win16 reserve bytes are never passed to Windows. Commands whose buffer is
//! itself a structure or contains a nested pointer need a typed projection
//! before they can use this adapter.

use super::*;
use windows_sys::Win32::NetworkManagement::NetBios::{
    ADAPTER_STATUS, FIND_NAME_BUFFER, FIND_NAME_HEADER, LANA_ENUM, NAME_BUFFER, NCB, Netbios,
    SESSION_BUFFER, SESSION_HEADER,
};

#[path = "win16_netbios_async.rs"]
mod asynchronous;
pub(in crate::windows) use asynchronous::HostState;
#[path = "win16_netbios_contract.rs"]
mod command_contract;
use command_contract::{has_flat_payload_contract, payload_access_matches_command};

const ASYNCH: u8 = 0x80;
const NCBASTAT: u8 = 0x33;
const NCBSSTAT: u8 = 0x34;
const NCBLISTEN: u8 = 0x11;
const NCBDGRECV: u8 = 0x21;
const NCBDGRECVBC: u8 = 0x23;
const NRC_GOODRET: u8 = 0;
const NRC_INCOMP: u8 = 0x06;
const NCBFINDNAME: u8 = 0x78;
const NCBENUM: u8 = 0x37;
const NCBACTION: u8 = 0x77;

/// Execute a synchronous command whose buffer is one flat, owned byte range.
///
/// The Windows NCB is constructed field by field. The `Vec` remains alive and
/// mutable for the entire synchronous call, including the empty-but-non-null
/// guest-buffer case. Native status and output fields are returned verbatim.
pub(super) fn execute(
    call: runtime::Win16HostNetbiosCall,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    if call.asynchronous {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "synchronous Windows NetBIOS adapter received an asynchronous NCB",
        ));
    }
    match call.command {
        NCBASTAT => execute_adapter_status(call),
        NCBSSTAT => execute_session_status(call),
        NCBFINDNAME => execute_find_name(call),
        NCBENUM => execute_lana_enum(call),
        // NCBACTION is a Windows extension. The runtime keeps ACTION_HEADER
        // and optional trailing action data opaque, so this adapter can pass
        // one owned flat buffer without interpreting transport-specific bytes.
        NCBACTION => execute_flat_payload(call),
        command if has_flat_payload_contract(command) => execute_flat_payload(call),
        _ => Ok(invoke_native(
            NativeCallFields::from(&call),
            std::ptr::null_mut(),
        )
        .into_guest_result(runtime::Win16HostNetbiosOutput::None)),
    }
}

fn execute_flat_payload(
    call: runtime::Win16HostNetbiosCall,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    let fields = NativeCallFields::from(&call);
    let buffer = match call.payload {
        runtime::Win16HostNetbiosPayload::None => None,
        runtime::Win16HostNetbiosPayload::Bytes { bytes, access } => {
            if bytes.len() != usize::from(call.native_length) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 NetBIOS buffer length does not match its NCB length",
                ));
            }
            if !payload_access_matches_command(call.command, access) {
                return Err(payload_command_mismatch());
            }
            Some((bytes, access))
        }
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 NetBIOS payload does not match its command",
            ));
        }
    };
    let mut native_buffer = match buffer.as_ref() {
        Some((bytes, _)) => Some(NativeBuffer::from_bytes(bytes)?),
        None => None,
    };
    let mut output_bytes = match buffer.as_ref() {
        Some((_, access)) if !matches!(access, runtime::Win16HostNetbiosBufferAccess::Read) => {
            Some(output_buffer(
                usize::from(call.native_length),
                "unable to allocate Win16 NetBIOS output buffer",
            )?)
        }
        _ => None,
    };
    let buffer_pointer = native_buffer
        .as_mut()
        .map_or(std::ptr::null_mut(), NativeBuffer::as_mut_ptr);

    let native_result = invoke_native(fields, buffer_pointer);

    let output = if let (Some((_, access)), Some(native_buffer)) =
        (buffer.as_ref(), native_buffer.as_ref())
    {
        native_buffer.check_overrun()?;
        if matches!(access, runtime::Win16HostNetbiosBufferAccess::Read)
            || !has_buffer_completion(native_result)
        {
            runtime::Win16HostNetbiosOutput::None
        } else {
            let returned_length = usize::from(native_result.length);
            if returned_length > usize::from(call.native_length)
                || returned_length > native_buffer.as_bytes().len()
            {
                return Err(native_buffer_overrun());
            }
            let mut output = output_bytes.take().ok_or_else(payload_command_mismatch)?;
            output.extend_from_slice(&native_buffer.as_bytes()[..returned_length]);
            runtime::Win16HostNetbiosOutput::Bytes { bytes: output }
        }
    } else {
        runtime::Win16HostNetbiosOutput::None
    };

    let mut native_result = native_result;
    if call.native_length != call.length {
        // Chain-send is flattened to one native SEND buffer; the Win16 NCB's
        // first-buffer length remains its completion value.
        native_result.length = call.length;
    }
    Ok(native_result.into_guest_result(output))
}

fn execute_find_name(
    call: runtime::Win16HostNetbiosCall,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    let capacity = match &call.payload {
        runtime::Win16HostNetbiosPayload::FindName { capacity } => usize::from(*capacity),
        _ => return Err(payload_command_mismatch()),
    };
    require_capacity_matches_ncb_length(capacity, call.native_length)?;
    require_find_name_layout()?;
    let mut native_buffer = NativeBuffer::zeroed(capacity)?;
    let mut outcome = invoke_native(
        NativeCallFields::from(&call),
        native_buffer.as_mut_ptr(),
    );
    native_buffer.check_overrun()?;
    let payload = if has_successful_completion(outcome) {
        let bytes = native_buffer.as_bytes();
        if bytes.len() < std::mem::size_of::<FIND_NAME_HEADER>() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "NCBFINDNAME success omitted its native result header",
            ));
        }
        let node_count = usize::from(read_u16(bytes, 0)?);
        let extent = node_count
            .checked_mul(std::mem::size_of::<FIND_NAME_BUFFER>())
            .and_then(|length| length.checked_add(std::mem::size_of::<FIND_NAME_HEADER>()))
            .ok_or_else(native_buffer_overrun)?;
        if extent > bytes.len() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "NCBFINDNAME node count exceeds its native buffer capacity",
            ));
        }
        let mut output = output_buffer(extent, "unable to retain NCBFINDNAME results")?;
        output.extend_from_slice(&bytes[..extent]);
        runtime::Win16HostNetbiosOutput::FindName { bytes: output }
    } else {
        runtime::Win16HostNetbiosOutput::None
    };
    // NCBFINDNAME uses ncb_length as the supplied buffer capacity. Keep the
    // provider's required-length report on NRC_BUFLEN, but never rewrite it
    // from the number of projected entries on success.
    if outcome.retcode == 0 && outcome.cmd_cplt == 0 {
        outcome.length = call.length;
    }
    Ok(outcome.into_guest_result(payload))
}

fn execute_lana_enum(
    call: runtime::Win16HostNetbiosCall,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    let capacity = match &call.payload {
        runtime::Win16HostNetbiosPayload::LanaEnum { capacity } => usize::from(*capacity),
        _ => return Err(payload_command_mismatch()),
    };
    require_capacity_matches_ncb_length(capacity, call.native_length)?;
    require_lana_enum_layout()?;
    let mut native_buffer = NativeBuffer::zeroed(capacity)?;
    let outcome = invoke_native(
        NativeCallFields::from(&call),
        native_buffer.as_mut_ptr(),
    );
    native_buffer.check_overrun()?;
    let payload = if has_successful_completion(outcome) {
        let extent = std::mem::size_of::<LANA_ENUM>();
        if capacity < extent {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "NCBENUM succeeded without enough room for its native LANA_ENUM",
            ));
        }
        let mut bytes = output_buffer(extent, "unable to retain Windows LANA_ENUM output")?;
        bytes.extend_from_slice(&native_buffer.as_bytes()[..extent]);
        runtime::Win16HostNetbiosOutput::LanaEnum { bytes }
    } else {
        runtime::Win16HostNetbiosOutput::None
    };
    Ok(outcome.into_guest_result(payload))
}

fn execute_adapter_status(
    call: runtime::Win16HostNetbiosCall,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    let capacity = match &call.payload {
        runtime::Win16HostNetbiosPayload::None => {
            return Ok(
                invoke_native(NativeCallFields::from(&call), std::ptr::null_mut())
                    .into_guest_result(runtime::Win16HostNetbiosOutput::None),
            );
        }
        runtime::Win16HostNetbiosPayload::AdapterStatus { capacity } => usize::from(*capacity),
        _ => return Err(payload_command_mismatch()),
    };
    require_capacity_matches_ncb_length(capacity, call.length)?;
    require_adapter_layout()?;

    let output_bytes = output_buffer(capacity, "unable to allocate Win16 adapter status output")?;
    let mut native_buffer = NativeBuffer::zeroed(capacity)?;
    let outcome = invoke_native(NativeCallFields::from(&call), native_buffer.as_mut_ptr());
    native_buffer.check_overrun()?;
    let output = if has_successful_completion(outcome) {
        if outcome.length > call.length {
            return Err(native_buffer_overrun());
        }
        let native_bytes = native_buffer.as_bytes();
        runtime::Win16HostNetbiosOutput::AdapterStatus {
            bytes: project_adapter_status(native_bytes, output_bytes)?,
        }
    } else {
        runtime::Win16HostNetbiosOutput::None
    };
    Ok(outcome.into_guest_result(output))
}

fn execute_session_status(
    call: runtime::Win16HostNetbiosCall,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    let capacity = match &call.payload {
        runtime::Win16HostNetbiosPayload::None => {
            return Ok(
                invoke_native(NativeCallFields::from(&call), std::ptr::null_mut())
                    .into_guest_result(runtime::Win16HostNetbiosOutput::None),
            );
        }
        runtime::Win16HostNetbiosPayload::SessionStatus { capacity } => usize::from(*capacity),
        _ => return Err(payload_command_mismatch()),
    };
    require_capacity_matches_ncb_length(capacity, call.length)?;
    require_session_layout()?;

    let output_bytes = output_buffer(capacity, "unable to allocate Win16 session status output")?;
    let mut native_buffer = NativeBuffer::zeroed(capacity)?;
    let outcome = invoke_native(NativeCallFields::from(&call), native_buffer.as_mut_ptr());
    native_buffer.check_overrun()?;
    let output = if has_successful_completion(outcome) {
        if outcome.length > call.length {
            return Err(native_buffer_overrun());
        }
        let native_bytes = native_buffer.as_bytes();
        runtime::Win16HostNetbiosOutput::SessionStatus {
            bytes: project_session_status(
                native_bytes,
                output_bytes,
                usize::from(outcome.length),
                false,
            )?,
        }
    } else if outcome.function_return == NRC_INCOMP
        && outcome.retcode == NRC_INCOMP
        && outcome.cmd_cplt == NRC_INCOMP
        && usize::from(outcome.length) >= 4
    {
        if outcome.length > call.length {
            return Err(native_buffer_overrun());
        }
        // NCBSSTAT may complete with NRC_INCOMP while still returning its
        // four-byte header and every complete record that fits. Its header
        // retains the total session count; it is not the copied-record count.
        runtime::Win16HostNetbiosOutput::SessionStatus {
            bytes: project_session_status(
                native_buffer.as_bytes(),
                output_bytes,
                usize::from(outcome.length),
                true,
            )?,
        }
    } else {
        runtime::Win16HostNetbiosOutput::None
    };
    Ok(outcome.into_guest_result(output))
}

#[derive(Clone, Copy)]
struct NativeCallFields {
    command: u8,
    lsn: u8,
    num: u8,
    length: u16,
    callname: [u8; 16],
    name: [u8; 16],
    rto: u8,
    sto: u8,
    lana_num: u8,
}

impl From<&runtime::Win16HostNetbiosCall> for NativeCallFields {
    fn from(call: &runtime::Win16HostNetbiosCall) -> Self {
        Self {
            command: call.command,
            lsn: call.lsn,
            num: call.num,
            length: call.native_length,
            callname: call.call_name,
            name: call.name,
            rto: call.receive_timeout,
            sto: call.send_timeout,
            lana_num: call.lana_num,
        }
    }
}

#[derive(Clone, Copy)]
struct NativeCallResult {
    command: u8,
    function_return: u8,
    retcode: u8,
    cmd_cplt: u8,
    lsn: u8,
    num: u8,
    length: u16,
    call_name: [u8; 16],
}

impl NativeCallResult {
    fn into_guest_result(
        self,
        payload: runtime::Win16HostNetbiosOutput,
    ) -> runtime::Win16HostNetbiosResult {
        let call_name = match self.command {
            NCBLISTEN if self.function_return == NRC_GOODRET && self.retcode == NRC_GOODRET => {
                Some(self.call_name)
            }
            NCBDGRECV | NCBDGRECVBC
                if matches!(self.retcode, NRC_GOODRET | NRC_INCOMP)
                    && self.function_return == self.retcode =>
            {
                Some(self.call_name)
            }
            _ => None,
        };
        runtime::Win16HostNetbiosResult {
            function_return: self.function_return,
            retcode: self.retcode,
            cmd_cplt: self.cmd_cplt,
            lsn: self.lsn,
            num: self.num,
            length: self.length,
            call_name,
            payload,
        }
    }
}

fn has_buffer_completion(result: NativeCallResult) -> bool {
    result.function_return == result.retcode && matches!(result.retcode, NRC_GOODRET | NRC_INCOMP)
}

fn has_successful_completion(result: NativeCallResult) -> bool {
    result.function_return == NRC_GOODRET && result.retcode == NRC_GOODRET
}

fn invoke_native(fields: NativeCallFields, buffer: *mut u8) -> NativeCallResult {
    let mut native = NCB::default();
    native.ncb_command = fields.command;
    native.ncb_lsn = fields.lsn;
    native.ncb_num = fields.num;
    native.ncb_buffer = buffer;
    native.ncb_length = fields.length;
    native.ncb_callname = fields.callname;
    native.ncb_name = fields.name;
    native.ncb_rto = fields.rto;
    native.ncb_sto = fields.sto;
    // Win16 ncb_post is an opaque DWORD notification value, not a native
    // function pointer. Synchronous calls never install a native callback.
    native.ncb_post = 0;
    native.ncb_lana_num = fields.lana_num;
    native.ncb_event = std::ptr::null_mut();
    // `NCB::default()` zeroes native-only reserved bytes; never copy the
    // different-sized Win16 reserve area into the Windows structure.

    // SAFETY: callers keep `native` and any non-null owned output/input buffer
    // alive until the synchronous function returns. No guest pointer is used.
    // Native callback and event paths are disabled.
    let function_return = unsafe { Netbios(&mut native) };
    NativeCallResult {
        command: fields.command,
        function_return,
        retcode: native.ncb_retcode,
        cmd_cplt: native.ncb_cmd_cplt,
        lsn: native.ncb_lsn,
        num: native.ncb_num,
        length: native.ncb_length,
        call_name: native.ncb_callname,
    }
}

// This owned byte buffer preserves NULL versus non-NULL/zero-length NCB data
// while giving native status records their required alignment. The typed
// NativeOutputBuffer is for worker protocol records and cannot express that
// NCB distinction. The trailing canary detects a native length-contract breach;
// it is not memory isolation from a misbehaving system provider.
struct NativeBuffer {
    words: Vec<u64>,
    length: usize,
}

impl NativeBuffer {
    fn from_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        let mut buffer = Self::zeroed(bytes.len())?;
        buffer.as_bytes_mut().copy_from_slice(bytes);
        Ok(buffer)
    }

    fn zeroed(length: usize) -> Result<Self, RuntimeError> {
        let word_count = length.div_ceil(std::mem::size_of::<u64>()) + 1;
        let mut words = Vec::new();
        words.try_reserve_exact(word_count).map_err(|error| {
            allocation_error("unable to allocate aligned Windows NetBIOS buffer", error)
        })?;
        words.resize(word_count, u64::from_ne_bytes([0xa5; 8]));
        let mut buffer = Self { words, length };
        buffer.as_bytes_mut().fill(0);
        Ok(buffer)
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast::<u8>()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the word allocation is initialized and has at least `length`
        // bytes. The native API is called only while this owner remains live.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.length) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the word allocation is initialized and has at least `length`
        // bytes. This exclusive borrow prevents native access while editing.
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.length) }
    }

    fn check_overrun(&self) -> Result<(), RuntimeError> {
        let allocated = self.words.len() * std::mem::size_of::<u64>();
        // SAFETY: `allocated` is exactly the size of the initialized word
        // allocation, including the trailing canary word.
        let all =
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), allocated) };
        if all[self.length..].iter().all(|byte| *byte == 0xa5) {
            Ok(())
        } else {
            Err(native_buffer_overrun())
        }
    }
}

fn allocation_error(
    message: &'static str,
    error: std::collections::TryReserveError,
) -> RuntimeError {
    RuntimeError::with_source(Kind::ResourceExhausted, message, error)
}

fn output_buffer(length: usize, message: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|error| allocation_error(message, error))?;
    Ok(output)
}

fn require_adapter_layout() -> Result<(), RuntimeError> {
    let valid = std::mem::size_of::<ADAPTER_STATUS>() == 60
        && std::mem::offset_of!(ADAPTER_STATUS, adapter_address) == 0
        && std::mem::offset_of!(ADAPTER_STATUS, rev_major) == 6
        && std::mem::offset_of!(ADAPTER_STATUS, reserved0) == 7
        && std::mem::offset_of!(ADAPTER_STATUS, adapter_type) == 8
        && std::mem::offset_of!(ADAPTER_STATUS, rev_minor) == 9
        && std::mem::offset_of!(ADAPTER_STATUS, duration) == 10
        && std::mem::offset_of!(ADAPTER_STATUS, frmr_recv) == 12
        && std::mem::offset_of!(ADAPTER_STATUS, frmr_xmit) == 14
        && std::mem::offset_of!(ADAPTER_STATUS, iframe_recv_err) == 16
        && std::mem::offset_of!(ADAPTER_STATUS, xmit_aborts) == 18
        && std::mem::offset_of!(ADAPTER_STATUS, xmit_success) == 20
        && std::mem::offset_of!(ADAPTER_STATUS, recv_success) == 24
        && std::mem::offset_of!(ADAPTER_STATUS, iframe_xmit_err) == 28
        && std::mem::offset_of!(ADAPTER_STATUS, recv_buff_unavail) == 30
        && std::mem::offset_of!(ADAPTER_STATUS, t1_timeouts) == 32
        && std::mem::offset_of!(ADAPTER_STATUS, ti_timeouts) == 34
        && std::mem::offset_of!(ADAPTER_STATUS, reserved1) == 36
        && std::mem::offset_of!(ADAPTER_STATUS, free_ncbs) == 40
        && std::mem::offset_of!(ADAPTER_STATUS, max_cfg_ncbs) == 42
        && std::mem::offset_of!(ADAPTER_STATUS, max_ncbs) == 44
        && std::mem::offset_of!(ADAPTER_STATUS, xmit_buf_unavail) == 46
        && std::mem::offset_of!(ADAPTER_STATUS, max_dgram_size) == 48
        && std::mem::offset_of!(ADAPTER_STATUS, pending_sess) == 50
        && std::mem::offset_of!(ADAPTER_STATUS, max_cfg_sess) == 52
        && std::mem::offset_of!(ADAPTER_STATUS, max_sess) == 54
        && std::mem::offset_of!(ADAPTER_STATUS, max_sess_pkt_size) == 56
        && std::mem::offset_of!(ADAPTER_STATUS, name_count) == 58
        && std::mem::size_of::<NAME_BUFFER>() == 18
        && std::mem::offset_of!(NAME_BUFFER, name) == 0
        && std::mem::offset_of!(NAME_BUFFER, name_num) == 16
        && std::mem::offset_of!(NAME_BUFFER, name_flags) == 17;
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows adapter status structure does not match its documented layout",
        ))
    }
}

fn require_session_layout() -> Result<(), RuntimeError> {
    let valid = std::mem::size_of::<SESSION_HEADER>() == 4
        && std::mem::offset_of!(SESSION_HEADER, sess_name) == 0
        && std::mem::offset_of!(SESSION_HEADER, num_sess) == 1
        && std::mem::offset_of!(SESSION_HEADER, rcv_dg_outstanding) == 2
        && std::mem::offset_of!(SESSION_HEADER, rcv_any_outstanding) == 3
        && std::mem::size_of::<SESSION_BUFFER>() == 36
        && std::mem::offset_of!(SESSION_BUFFER, lsn) == 0
        && std::mem::offset_of!(SESSION_BUFFER, state) == 1
        && std::mem::offset_of!(SESSION_BUFFER, local_name) == 2
        && std::mem::offset_of!(SESSION_BUFFER, remote_name) == 18
        && std::mem::offset_of!(SESSION_BUFFER, rcvs_outstanding) == 34
        && std::mem::offset_of!(SESSION_BUFFER, sends_outstanding) == 35;
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows session status structures do not match their documented layout",
        ))
    }
}

fn require_find_name_layout() -> Result<(), RuntimeError> {
    let valid = std::mem::size_of::<FIND_NAME_HEADER>() == 4
        && std::mem::offset_of!(FIND_NAME_HEADER, node_count) == 0
        && std::mem::offset_of!(FIND_NAME_HEADER, reserved) == 2
        && std::mem::offset_of!(FIND_NAME_HEADER, unique_group) == 3
        && std::mem::size_of::<FIND_NAME_BUFFER>() == 33
        && std::mem::offset_of!(FIND_NAME_BUFFER, length) == 0
        && std::mem::offset_of!(FIND_NAME_BUFFER, access_control) == 1
        && std::mem::offset_of!(FIND_NAME_BUFFER, frame_control) == 2
        && std::mem::offset_of!(FIND_NAME_BUFFER, destination_addr) == 3
        && std::mem::offset_of!(FIND_NAME_BUFFER, source_addr) == 9
        && std::mem::offset_of!(FIND_NAME_BUFFER, routing_info) == 15;
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows FIND_NAME structures do not match the Win16 wire layout",
        ))
    }
}

fn require_lana_enum_layout() -> Result<(), RuntimeError> {
    let valid = std::mem::size_of::<LANA_ENUM>() == 256
        && std::mem::offset_of!(LANA_ENUM, length) == 0
        && std::mem::offset_of!(LANA_ENUM, lana) == 1;
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows LANA_ENUM does not match its documented fixed layout",
        ))
    }
}

// The SDK records contain only unsigned byte arrays, UCHAR, WORD and ULONG
// fields. Decode WORD/ULONG values explicitly and never materialize a Rust
// struct from native bytes, so every possible source byte pattern is valid.
fn project_adapter_status(native: &[u8], mut output: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
    const STATUS_SIZE: usize = 60;
    const NAME_SIZE: usize = 18;
    if native.len() < STATUS_SIZE {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBASTAT capacity cannot hold its status header",
        ));
    }
    let name_count = read_u16(native, 58)?;
    let names_length = usize::from(name_count)
        .checked_mul(NAME_SIZE)
        .ok_or_else(native_buffer_overrun)?;
    let output_length = STATUS_SIZE
        .checked_add(names_length)
        .ok_or_else(native_buffer_overrun)?;
    if output_length > native.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBASTAT name count exceeds its returned native buffer capacity",
        ));
    }
    if output_length > output.capacity() {
        return Err(native_buffer_overrun());
    }
    output.extend_from_slice(native_field(native, 0, 6)?);
    for offset in 6..10 {
        output.extend_from_slice(native_field(native, offset, 1)?);
    }
    push_u16(&mut output, read_u16(native, 10)?);
    push_u16(&mut output, read_u16(native, 12)?);
    push_u16(&mut output, read_u16(native, 14)?);
    push_u16(&mut output, read_u16(native, 16)?);
    push_u16(&mut output, read_u16(native, 18)?);
    push_u32(&mut output, read_u32(native, 20)?);
    push_u32(&mut output, read_u32(native, 24)?);
    push_u16(&mut output, read_u16(native, 28)?);
    push_u16(&mut output, read_u16(native, 30)?);
    push_u16(&mut output, read_u16(native, 32)?);
    push_u16(&mut output, read_u16(native, 34)?);
    push_u32(&mut output, read_u32(native, 36)?);
    push_u16(&mut output, read_u16(native, 40)?);
    push_u16(&mut output, read_u16(native, 42)?);
    push_u16(&mut output, read_u16(native, 44)?);
    push_u16(&mut output, read_u16(native, 46)?);
    push_u16(&mut output, read_u16(native, 48)?);
    push_u16(&mut output, read_u16(native, 50)?);
    push_u16(&mut output, read_u16(native, 52)?);
    push_u16(&mut output, read_u16(native, 54)?);
    push_u16(&mut output, read_u16(native, 56)?);
    push_u16(&mut output, name_count);
    for offset in (STATUS_SIZE..output_length).step_by(NAME_SIZE) {
        output.extend_from_slice(native_field(native, offset, 16)?);
        output.extend_from_slice(native_field(native, offset + 16, 1)?);
        output.extend_from_slice(native_field(native, offset + 17, 1)?);
    }
    Ok(output)
}

fn project_session_status(
    native: &[u8],
    mut output: Vec<u8>,
    valid_extent: usize,
    allow_partial: bool,
) -> Result<Vec<u8>, RuntimeError> {
    const HEADER_SIZE: usize = 4;
    const SESSION_SIZE: usize = 36;
    if valid_extent < HEADER_SIZE || valid_extent > native.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT returned extent cannot hold its session header",
        ));
    }
    let header = native_field(native, 0, HEADER_SIZE)?;
    let advertised_sessions = usize::from(header[1]);
    let available_sessions = (valid_extent - HEADER_SIZE) / SESSION_SIZE;
    if !allow_partial && advertised_sessions > available_sessions {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT session count exceeds its returned native buffer extent",
        ));
    }
    let copied_sessions = advertised_sessions.min(available_sessions);
    let sessions_length = copied_sessions
        .checked_mul(SESSION_SIZE)
        .ok_or_else(native_buffer_overrun)?;
    let output_length = HEADER_SIZE
        .checked_add(sessions_length)
        .ok_or_else(native_buffer_overrun)?;
    if output_length > valid_extent {
        return Err(native_buffer_overrun());
    }
    if output_length > output.capacity() {
        return Err(native_buffer_overrun());
    }
    for offset in 0..HEADER_SIZE {
        output.extend_from_slice(native_field(native, offset, 1)?);
    }
    for offset in (HEADER_SIZE..output_length).step_by(SESSION_SIZE) {
        output.extend_from_slice(native_field(native, offset, 1)?);
        output.extend_from_slice(native_field(native, offset + 1, 1)?);
        output.extend_from_slice(native_field(native, offset + 2, 16)?);
        output.extend_from_slice(native_field(native, offset + 18, 16)?);
        output.extend_from_slice(native_field(native, offset + 34, 1)?);
        output.extend_from_slice(native_field(native, offset + 35, 1)?);
    }
    Ok(output)
}

fn native_field(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], RuntimeError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(native_buffer_overrun)?;
    bytes.get(offset..end).ok_or_else(partial_native_record)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RuntimeError> {
    let field = native_field(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RuntimeError> {
    let field = native_field(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn partial_native_record() -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        "Windows NetBIOS returned a partial native status record",
    )
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn native_buffer_overrun() -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        "Windows NetBIOS returned a length larger than its owned buffer",
    )
}

fn require_capacity_matches_ncb_length(
    capacity: usize,
    ncb_length: u16,
) -> Result<(), RuntimeError> {
    if capacity == usize::from(ncb_length) {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "typed Win16 NetBIOS output capacity does not match NCB length",
        ))
    }
}

fn payload_command_mismatch() -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        "Win16 NetBIOS payload does not match its command",
    )
}
