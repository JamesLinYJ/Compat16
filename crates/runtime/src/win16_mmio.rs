//! Checked Win16 MMIO file operations.

use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::{Win16MultimediaCall, Win16ReturnKind};

use super::multimedia::{
    dword, pointer, scalar, string, word, Win16HostMultimediaOperation,
    Win16HostMultimediaHandle, Win16HostMultimediaResult, Win16MultimediaHandleKind,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

pub(super) fn is_mmio_export(name: &str) -> bool {
    ["mmioOpen", "mmioClose", "mmioRead", "mmioWrite", "mmioSeek",
        "mmioFlush", "mmioRename", "mmioGetInfo", "mmioSetInfo", "mmioSetBuffer",
        "mmioAdvance", "mmioInstallIOProc", "mmioSendMessage", "mmioDescend",
        "mmioAscend", "mmioCreateChunk"]
        .iter().any(|candidate| name.eq_ignore_ascii_case(candidate))
}

impl super::Win16State {
    pub(super) fn mmio_compat_api(
        &mut self,
        call: &Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let name = call.name.unwrap_or("");
        let value = if name.eq_ignore_ascii_case("mmioOpen") {
            let path = string(call, 0)?.to_vec();
            if pointer(call, 1)? != 0 {
                return Err(structure_gap(call, "MMIOINFO16 open callbacks and buffers"));
            }
            let flags = dword(call, 2)?;
            match host.win16_multimedia(Win16HostMultimediaOperation::MmioOpen { path, flags })? {
                Win16HostMultimediaResult::Handle(Some(file)) => {
                    match self.multimedia.add_handle(Win16MultimediaHandleKind::Mmio, file) {
                        Some(guest) => u32::from(guest),
                        None => {
                            // The native handle was created but could not be
                            // assigned a guest alias. Attempt to release it.
                            let _ = host.win16_multimedia(
                                Win16HostMultimediaOperation::MmioClose { file, flags: 0 },
                            );
                            return Err(RuntimeError::new(Kind::ResourceExhausted,
                                "Win16 multimedia guest handle table is full"));
                        }
                    }
                }
                Win16HostMultimediaResult::Handle(None) => 0,
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "mmioOpen returned an unexpected multimedia result")),
            }
        } else if name.eq_ignore_ascii_case("mmioClose") {
            let guest = word(call, 0)?;
            let flags = word(call, 1)?;
            let file = host_file(self, call, guest)?;
            let result = scalar(host.win16_multimedia(
                Win16HostMultimediaOperation::MmioClose { file, flags },
            )?)?;
            if result == 0 {
                self.multimedia.remove_handle(guest, Win16MultimediaHandleKind::Mmio);
            }
            result
        } else if name.eq_ignore_ascii_case("mmioRead") {
            let guest = word(call, 0)?;
            let output_pointer = pointer(call, 1)?;
            let count = dword(call, 2)? as i32;
            if count < 0 {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 mmioRead length is negative"));
            }
            let file = host_file(self, call, guest)?;
            let capacity = count as usize;
            let output = self.prepare_multimedia_output(memory, output_pointer, capacity)?;
            let reply = host.win16_multimedia(Win16HostMultimediaOperation::MmioRead {
                file, count: count as u32,
            })?;
            let (result, bytes) = transfer_result(reply)?;
            if result > 0 {
                let actual = result as usize;
                if actual > capacity || actual > bytes.len() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "mmioRead returned more bytes than its owned output"));
                }
                let Some(output) = output else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "mmioRead produced bytes without a prepared guest destination"));
                };
                output.commit(memory, &bytes[..actual])?;
            }
            result as u32
        } else if name.eq_ignore_ascii_case("mmioWrite") {
            let guest = word(call, 0)?;
            let input_pointer = pointer(call, 1)?;
            let count = dword(call, 2)? as i32;
            if count < 0 {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 mmioWrite length is negative"));
            }
            let file = host_file(self, call, guest)?;
            let pointer = self.selectors.pointer_from_far(input_pointer)
                .map_err(crate::runtime_error)?;
            let bytes = self.read_text_bytes(memory, pointer, count as usize)?;
            let reply = host.win16_multimedia(Win16HostMultimediaOperation::MmioWrite {
                file, data: bytes,
            })?;
            transfer_result(reply)?.0 as u32
        } else if name.eq_ignore_ascii_case("mmioSeek") {
            let guest = word(call, 0)?;
            let offset = dword(call, 1)? as i32;
            let origin = word(call, 2)? as i16;
            let file = host_file(self, call, guest)?;
            match host.win16_multimedia(Win16HostMultimediaOperation::MmioSeek {
                file, offset, origin,
            })? {
                Win16HostMultimediaResult::Transfer { result, bytes } if bytes.is_empty() => result as u32,
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "mmioSeek returned an unexpected multimedia result")),
            }
        } else if name.eq_ignore_ascii_case("mmioFlush") {
            let guest = word(call, 0)?;
            let flags = word(call, 1)?;
            let file = host_file(self, call, guest)?;
            scalar(host.win16_multimedia(Win16HostMultimediaOperation::MmioFlush {
                file, flags,
            })?)?
        } else if name.eq_ignore_ascii_case("mmioRename") {
            let old_path = string(call, 0)?.to_vec();
            let new_path = string(call, 1)?.to_vec();
            if pointer(call, 2)? != 0 {
                return Err(structure_gap(call, "MMIOINFO16 rename callbacks"));
            }
            let flags = dword(call, 3)?;
            scalar(host.win16_multimedia(Win16HostMultimediaOperation::MmioRename {
                old_path, new_path, flags,
            })?)?
        } else {
            return Err(structure_gap(call, "MMIO chunk or procedure structures"));
        };
        self.finish_multimedia(registers, return_to, value, return_kind)
    }
}

fn host_file(
    state: &super::Win16State,
    call: &Win16MultimediaCall,
    guest: u16,
) -> Result<Win16HostMultimediaHandle, RuntimeError> {
    state.multimedia.host_handle(guest, Win16MultimediaHandleKind::Mmio)
        .ok_or_else(|| RuntimeError::new(Kind::CompatibilityGap, format!(
            "Win16 MMSYSTEM.{} received unmapped HMMIO16 0x{guest:04X}", call.ordinal,
        )))
}

fn structure_gap(call: &Win16MultimediaCall, structure: &str) -> RuntimeError {
    RuntimeError::new(Kind::CompatibilityGap, format!(
        "Win16 MMSYSTEM.{} requires unsupported {structure}", call.ordinal,
    ))
}

fn transfer_result(reply: Win16HostMultimediaResult) -> Result<(i32, Vec<u8>), RuntimeError> {
    match reply {
        Win16HostMultimediaResult::Transfer { result, bytes } => Ok((result, bytes)),
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 multimedia host service returned the wrong transfer result kind")),
    }
}
