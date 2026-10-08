//! Synchronous MMIO calls with guest HMMIO aliases and checked FAR data.

use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{
    Access, Win16MediaIoRequest, Win16MmckInfo16, MAX_WIN16_STRING_BYTES,
    MMCKINFO16_SIZE, MMIOINFO16_ERROR_OFFSET,
    MMIOINFO16_SIZE,
};

use super::{Win16State, guest_ranges::{GuestOutputRange, commit_guest_writes}};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMediaIoOperation as Operation, Win16HostMediaOpenResult as OpenResult,
    Win16HostMmckInfo,
    Win16HostMediaIoResult as ResultValue};

const MMIOERR_CANNOTOPEN: u32 = 259;
const MMIOERR_FILENOTFOUND: u32 = 257;
const MMIOERR_CANNOTCLOSE: u32 = 260;
const MMIOERR_CANNOTWRITE: u32 = 262;
const MMIOERR_CANNOTSEEK: u32 = 263;
const MMIOERR_CHUNKNOTFOUND: u32 = 265;
const MMIO_PARSE: u32 = 0x0000_0100;
const MMIO_DELETE: u32 = 0x0000_0200;
const MMIO_EXIST: u32 = 0x0000_4000;
const MMIO_GETTEMP: u32 = 0x0002_0000;
const MMIO_PATH_OUTPUT_FLAGS: u32 = MMIO_PARSE | MMIO_EXIST | MMIO_GETTEMP;
const MMIO_BOOLEAN_RESULT_FLAGS: u32 = MMIO_DELETE | MMIO_EXIST | MMIO_PARSE;
const MMIO_NO_HANDLE_FLAGS: u32 = MMIO_BOOLEAN_RESULT_FLAGS | MMIO_GETTEMP;
const MMIO_OPEN_PATH_BUFFER_SIZE: usize = 128;

impl Win16State {
    pub(in crate::win16_runtime) fn media_io_api(
        &mut self,
        request: Win16MediaIoRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16MediaIoRequest::Open { path_far, info, flags } =>
                self.open(path_far, info, flags, memory, host),
            Win16MediaIoRequest::Close { handle, flags } => {
                let Some(native) = self.media_services.mmio_handle(handle) else {
                    return Ok(MMIOERR_CANNOTCLOSE);
                };
                match host.win16_media_io(Operation::Close { handle: native, flags })? {
                    ResultValue::Scalar(result) => {
                        if result == 0 { self.media_services.remove_mmio(handle); }
                        Ok(u32::from(result as u16))
                    }
                    _ => Err(invariant("mmioClose returned the wrong host result shape")),
                }
            }
            Win16MediaIoRequest::Read { handle, buffer, count } => {
                if count < 0 { return Ok(u32::MAX); }
                let Some(native) = self.media_services.mmio_handle(handle) else {
                    return Ok(u32::MAX);
                };
                let capacity = count as usize;
                let output = if capacity == 0 { None } else {
                    match capture_huge_output(self, memory, buffer, capacity) {
                        Ok(range) => Some(range),
                        Err(error) if is_guest_api_failure(&error) => return Ok(u32::MAX),
                        Err(error) => return Err(error),
                    }
                };
                let reply = host.win16_media_io(Operation::Read { handle: native, count })?;
                let ResultValue::Transfer { result, bytes } = reply else {
                    return Err(invariant("mmioRead returned the wrong host result shape"));
                };
                if result <= 0 {
                    if result < -1 {
                        return Err(invariant("mmioRead returned an undocumented negative count"));
                    }
                    if !bytes.is_empty() {
                        return Err(invariant("failed mmioRead returned output bytes"));
                    }
                    return Ok(result as u32);
                }
                let written = result as usize;
                if written > capacity || written != bytes.len() {
                    return Err(invariant("native mmioRead result did not match its output bytes"));
                }
                let output = output.ok_or_else(|| invariant(
                    "mmioRead returned bytes without a captured guest destination"))?;
                match commit_guest_writes(self, memory,
                    vec![(output, bytes[..written].to_vec())])
                {
                    Ok(()) => Ok(result as u32),
                    Err(error) if is_guest_api_failure(&error) => Ok(u32::MAX),
                    Err(error) => Err(error),
                }
            }
            Win16MediaIoRequest::Write { handle, buffer, count } => {
                if count < 0 { return Ok(u32::MAX); }
                let Some(native) = self.media_services.mmio_handle(handle) else {
                    return Ok(u32::MAX);
                };
                let data = if count == 0 { Vec::new() } else {
                    let pointer = match self.selectors.pointer_from_far(buffer) {
                        Ok(pointer) => pointer,
                        Err(error) => {
                            let error = crate::runtime_error(error);
                            if is_guest_api_failure(&error) { return Ok(u32::MAX); }
                            return Err(error);
                        }
                    };
                    match self.read_text_bytes(memory, pointer, count as usize) {
                        Ok(bytes) => bytes,
                        Err(error) if is_guest_api_failure(&error) => return Ok(u32::MAX),
                        Err(error) => return Err(error),
                    }
                };
                match host.win16_media_io(Operation::Write { handle: native, data })? {
                    ResultValue::Transfer { result, bytes }
                        if bytes.is_empty() && result >= -1 && result <= count as i32 =>
                    {
                        Ok(result as u32)
                    }
                    ResultValue::Transfer { .. } => Err(invariant(
                        "mmioWrite returned an invalid count or unexpected host output bytes")),
                    _ => Err(invariant("mmioWrite returned the wrong host result shape")),
                }
            }
            Win16MediaIoRequest::Seek { handle, offset, origin } => {
                let Some(native) = self.media_services.mmio_handle(handle) else {
                    return Ok(u32::MAX);
                };
                match host.win16_media_io(Operation::Seek { handle: native, offset, origin })? {
                    ResultValue::Transfer { result, bytes } if bytes.is_empty() => Ok(result as u32),
                    ResultValue::Transfer { .. } => Err(invariant(
                        "mmioSeek returned unexpected host output bytes")),
                    _ => Err(invariant("mmioSeek returned the wrong host result shape")),
                }
            }
            Win16MediaIoRequest::Flush { handle, flags } => {
                let Some(native) = self.media_services.mmio_handle(handle) else {
                    return Ok(MMIOERR_CANNOTWRITE);
                };
                match host.win16_media_io(Operation::Flush { handle: native, flags })? {
                    ResultValue::Scalar(result) => Ok(u32::from(result as u16)),
                    _ => Err(invariant("mmioFlush returned the wrong host result shape")),
                }
            }
            Win16MediaIoRequest::StringToFourCc { text, flags } => {
                let Some(text) = text else { return Ok(0); };
                match host.win16_media_io(Operation::StringToFourCc { text, flags })? {
                    ResultValue::FourCc(value) => Ok(value),
                    _ => Err(invariant("mmioStringToFOURCC returned the wrong host result shape")),
                }
            }
            Win16MediaIoRequest::Descend { handle, chunk, parent, flags } =>
                self.descend(handle, chunk, parent, flags, memory, host),
            Win16MediaIoRequest::Ascend { handle, chunk, flags } =>
                self.finish_chunk_request(handle, chunk, flags, false, memory, host),
            Win16MediaIoRequest::CreateChunk { handle, chunk, flags } =>
                self.finish_chunk_request(handle, chunk, flags, true, memory, host),
            Win16MediaIoRequest::Rename { old_path, new_path, info, flags } => {
                if info != 0 {
                    return unsupported_info(self, memory, info, MMIOERR_CANNOTWRITE, host,
                        "mmioRename with caller-owned MMIOINFO callbacks/buffers");
                }
                match host.win16_media_io(Operation::Rename { old_path, new_path, flags })? {
                    ResultValue::Scalar(result) => Ok(u32::from(result as u16)),
                    _ => Err(invariant("mmioRename returned the wrong host result shape")),
                }
            }
        }
    }

    fn open(
        &mut self,
        path_far: u32,
        info: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if info != 0 {
            unsupported_info(self, memory, info, MMIOERR_CANNOTOPEN, host,
                "mmioOpen with caller-owned MMIOINFO callbacks/buffers")?;
            return Ok(open_guest_failure(flags));
        }
        if path_far == 0 { return Ok(open_guest_failure(flags)); }
        let path = match read_open_path(self, memory, path_far) {
            Ok(path) => path,
            Err(error) if is_guest_api_failure(&error) => return Ok(open_guest_failure(flags)),
            Err(error) => return Err(error),
        };
        if path.len() >= MMIO_OPEN_PATH_BUFFER_SIZE { return Ok(open_guest_failure(flags)); }
        let output = if flags & MMIO_PATH_OUTPUT_FLAGS != 0 {
            match capture_open_path_output(self, memory, path_far) {
                Ok(output) => Some(output),
                Err(error) if is_guest_api_failure(&error) => return Ok(open_guest_failure(flags)),
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let path_buffer = match output.as_ref().map(|range| range.read(self, memory)).transpose() {
            Ok(path_buffer) => path_buffer,
            Err(error) if is_guest_api_failure(&error) => return Ok(open_guest_failure(flags)),
            Err(error) => return Err(error),
        };
        let reply = host.win16_media_io(Operation::Open { path, path_buffer, flags })?;
        let ResultValue::Open { result, path_buffer } = reply else {
            return Err(invariant("mmioOpen returned the wrong host result shape"));
        };
        match (output, path_buffer) {
            (Some(output), Some(bytes)) if bytes.len() == MMIO_OPEN_PATH_BUFFER_SIZE => {
                match commit_guest_writes(self, memory, vec![(output, bytes)]) {
                    Ok(()) => {}
                    Err(error) if is_guest_api_failure(&error) => return Ok(open_guest_failure(flags)),
                    Err(error) => return Err(error),
                }
            }
            (None, None) => {}
            _ => return Err(invariant("mmioOpen path buffer result did not match its request")),
        }
        match result {
            OpenResult::File(None) if flags & MMIO_NO_HANDLE_FLAGS == 0 => Ok(0),
            OpenResult::File(Some(handle)) if flags & MMIO_NO_HANDLE_FLAGS == 0 && handle.0 != 0 => {
                if let Some(alias) = self.media_services.insert_mmio(handle) {
                    return Ok(u32::from(alias));
                }
                let error = match host.win16_media_io(Operation::Close { handle, flags: 0 }) {
                    Ok(ResultValue::Scalar(0)) => RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 MMIO alias table is full"),
                    Ok(ResultValue::Scalar(code)) => RuntimeError::new(Kind::ResourceExhausted,
                        format!("MMIO alias table is full and native close failed (0x{code:08X})")),
                    Ok(_) => invariant("MMIO rollback close returned the wrong result shape"),
                    Err(error) => error.with_context(
                        "closing an MMIO handle that could not receive a Win16 alias"),
                };
                Err(error)
            }
            OpenResult::Boolean(value) if flags & MMIO_BOOLEAN_RESULT_FLAGS != 0
                && flags & MMIO_GETTEMP == 0 => Ok(u32::from(value)),
            OpenResult::Status(value) if flags & MMIO_GETTEMP != 0 => Ok(u32::from(value as u16)),
            _ => Err(invariant("mmioOpen native result kind did not match its mode flags")),
        }
    }

    fn descend(
        &self,
        guest: u16,
        chunk_far: u32,
        parent_far: u32,
        flags: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(handle) = self.media_services.mmio_handle(guest) else {
            return Ok(MMIOERR_CHUNKNOTFOUND);
        };
        let (chunk_range, chunk) = match capture_chunk(self, memory, chunk_far) {
            Ok(value) => value,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMIOERR_CHUNKNOTFOUND),
            Err(error) => return Err(error),
        };
        let parent = if parent_far == 0 { None } else {
            match read_chunk(self, memory, parent_far) {
                Ok(value) => Some(value),
                Err(error) if is_guest_api_failure(&error) => return Ok(MMIOERR_CHUNKNOTFOUND),
                Err(error) => return Err(error),
            }
        };
        let result = host.win16_media_io(Operation::Descend {
            handle, chunk: host_chunk(chunk), parent: parent.map(host_chunk), flags,
        })?;
        let ResultValue::Chunk { result, chunk } = result else {
            return Err(invariant("mmioDescend returned the wrong host result shape"));
        };
        if result == 0 {
            match commit_guest_writes(self, memory,
                vec![(chunk_range, Win16MmckInfo16::from(chunk).encode().to_vec())])
            {
                Ok(()) => {}
                Err(error) if is_guest_api_failure(&error) => return Ok(MMIOERR_CHUNKNOTFOUND),
                Err(error) => return Err(error),
            }
        }
        Ok(u32::from(result as u16))
    }

    fn finish_chunk_request(
        &self,
        guest: u16,
        chunk_far: u32,
        flags: u16,
        create: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(handle) = self.media_services.mmio_handle(guest) else {
            return Ok(if create { MMIOERR_CANNOTWRITE } else { MMIOERR_CHUNKNOTFOUND });
        };
        let (chunk_range, chunk) = match capture_chunk(self, memory, chunk_far) {
            Ok(value) => value,
            Err(error) if is_guest_api_failure(&error) => {
                return Ok(if create { MMIOERR_CANNOTWRITE } else { MMIOERR_CHUNKNOTFOUND });
            }
            Err(error) => return Err(error),
        };
        let operation = if create {
            Operation::CreateChunk { handle, chunk: host_chunk(chunk), flags }
        } else {
            Operation::Ascend { handle, chunk: host_chunk(chunk), flags }
        };
        match host.win16_media_io(operation)? {
            ResultValue::Chunk { result, chunk } => {
                if result == 0 {
                    let bytes = Win16MmckInfo16::from(chunk).encode().to_vec();
                    match commit_guest_writes(self, memory, vec![(chunk_range, bytes)]) {
                        Ok(()) => {}
                        Err(error) if is_guest_api_failure(&error) => return Ok(if create {
                            MMIOERR_CANNOTWRITE
                        } else {
                            MMIOERR_CANNOTSEEK
                        }),
                        Err(error) => return Err(error),
                    }
                }
                Ok(u32::from(result as u16))
            }
            _ => Err(invariant("MMCKINFO operation returned the wrong host result shape")),
        }
    }
}

fn capture_open_path_output(
    state: &Win16State,
    memory: &Memory,
    far: u32,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    // MMIO_PARSE, MMIO_EXIST and MMIO_GETTEMP may expand a path in place;
    // the SDK contract requires a 128-byte ordinary FAR buffer.
    state.selectors.translate(pointer, Access::Write, MMIO_OPEN_PATH_BUFFER_SIZE, memory)
        .map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, MMIO_OPEN_PATH_BUFFER_SIZE)
}

fn read_open_path(
    state: &Win16State,
    memory: &Memory,
    far: u32,
) -> Result<Vec<u8>, RuntimeError> {
    // SDK 3.1 declares pszFileName as LPSTR/FAR, so stop at this descriptor
    // instead of following the HPSTR huge-selector chain used by Read/Write.
    let start = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    let descriptor = state.selectors.describe(start.selector()).map_err(crate::runtime_error)?;
    let available = descriptor.limit.checked_sub(u32::from(start.offset()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
            "mmioOpen filename starts beyond its ordinary FAR descriptor"))?;
    let bound = available.min(MAX_WIN16_STRING_BYTES);
    let mut path = Vec::new();
    path.try_reserve(bound.min(128)).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve mmioOpen filename", error))?;
    for offset in 0..bound {
        let pointer = state.selectors.add_bytes(start,
            u32::try_from(offset).map_err(|error| RuntimeError::with_source(
                Kind::GuestFault, "mmioOpen filename offset exceeds DWORD", error))?)
            .map_err(crate::runtime_error)?;
        let mut byte = [0_u8; 1];
        state.selectors.read(memory, pointer, &mut byte).map_err(crate::runtime_error)?;
        if byte[0] == 0 { return Ok(path); }
        path.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "grow mmioOpen filename", error))?;
        path.push(byte[0]);
    }
    Err(RuntimeError::new(Kind::GuestFault,
        "mmioOpen filename is not terminated within its ordinary FAR descriptor"))
}

fn open_guest_failure(flags: u32) -> u32 {
    if flags & MMIO_GETTEMP != 0 { MMIOERR_FILENOTFOUND } else { 0 }
}

fn capture_huge_output(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, size)
}

fn capture_chunk(
    state: &Win16State,
    memory: &Memory,
    far: u32,
) -> Result<(GuestOutputRange, Win16MmckInfo16), RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    // MMCKINFO is a fixed ordinary FAR record, unlike MMIORead/Write HPSTR.
    state.selectors.translate(pointer, Access::Write, MMCKINFO16_SIZE, memory)
        .map_err(crate::runtime_error)?;
    let range = GuestOutputRange::capture(state, memory, pointer, MMCKINFO16_SIZE)?;
    let bytes = range.read(state, memory)?;
    let record: [u8; MMCKINFO16_SIZE] = bytes.try_into().map_err(|_| invariant(
        "captured MMCKINFO length changed"))?;
    Ok((range, Win16MmckInfo16::decode(&record)))
}

fn read_chunk(
    state: &Win16State,
    memory: &Memory,
    far: u32,
) -> Result<Win16MmckInfo16, RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    let address = state.selectors.translate(pointer, Access::Read, MMCKINFO16_SIZE, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = [0_u8; MMCKINFO16_SIZE];
    memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
    Ok(Win16MmckInfo16::decode(&bytes))
}

fn unsupported_info(
    state: &Win16State,
    memory: &mut Memory,
    far: u32,
    failure: u32,
    host: &mut impl RuntimeHost,
    detail: &str,
) -> Result<u32, RuntimeError> {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        format!("Win16 {detail} is unsupported; reporting its MMIO failure code")));
    let pointer = match state.selectors.pointer_from_far(far) {
        Ok(pointer) => pointer,
        Err(error) => {
            let error = crate::runtime_error(error);
            if is_guest_api_failure(&error) { return Ok(failure); }
            return Err(error);
        }
    };
    if let Err(error) = state.selectors.translate(pointer, Access::Write, MMIOINFO16_SIZE, memory) {
        let error = crate::runtime_error(error);
        if is_guest_api_failure(&error) { return Ok(failure); }
        return Err(error);
    }
    let error_pointer = state.selectors.add_bytes(pointer, MMIOINFO16_ERROR_OFFSET as u32)
        .map_err(crate::runtime_error)?;
    let output = match GuestOutputRange::capture(state, memory, error_pointer, 2) {
        Ok(output) => output,
        Err(error) if is_guest_api_failure(&error) => return Ok(failure),
        Err(error) => return Err(error),
    };
    match commit_guest_writes(state, memory, vec![(output, (failure as u16).to_le_bytes().to_vec())]) {
        Ok(()) => Ok(failure),
        Err(error) if is_guest_api_failure(&error) => Ok(failure),
        Err(error) => Err(error),
    }
}

fn host_chunk(info: Win16MmckInfo16) -> Win16HostMmckInfo {
    Win16HostMmckInfo {
        chunk_id: info.chunk_id,
        chunk_size: info.chunk_size,
        form_type: info.form_type,
        data_offset: info.data_offset,
        flags: info.flags,
    }
}

impl From<Win16HostMmckInfo> for Win16MmckInfo16 {
    fn from(info: Win16HostMmckInfo) -> Self {
        Self {
            chunk_id: info.chunk_id,
            chunk_size: info.chunk_size,
            form_type: info.form_type,
            data_offset: info.data_offset,
            flags: info.flags,
        }
    }
}

fn is_guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn invariant(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
