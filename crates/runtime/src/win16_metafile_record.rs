//! PlayMetaFileRecord: checked guest buffers, reserved handles, and void ABI.

use super::Win16State;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMetafileOperation as Operation, Win16HostMetafileResult as ResultValue,
};
use guest_core::memory::Memory;

impl Win16State {
    pub(super) fn play_metafile_record(
        &mut self,
        dc: u16,
        table: u32,
        record: u32,
        count: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(());
        };
        let record_pointer = self
            .selectors
            .pointer_from_far(record)
            .map_err(crate::runtime_error)?;
        let header = self.read_text_bytes(memory, record_pointer, 6)?;
        let words = u32::from_le_bytes(header[..4].try_into().expect("checked DWORD"));
        let Some(bytes) = words.checked_mul(2).filter(|_| words >= 3) else {
            return Ok(());
        };
        if bytes > memory.size_bytes() {
            return Ok(());
        }
        let record = self.read_text_bytes(memory, record_pointer, bytes as usize)?;
        let shape = match formats::validate_wmf_record_playback(&record, usize::from(count)) {
            Ok(shape) => shape,
            Err(formats::WmfPlaybackError::Invalid) => return Ok(()),
            Err(formats::WmfPlaybackError::Unsupported(function)) => {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!("WMF record 0x{function:04x} has no checked playback translation"),
                ));
                return Ok(());
            }
        };
        let table_pointer = if count == 0 {
            None
        } else {
            let pointer = self
                .selectors
                .pointer_from_far(table)
                .map_err(crate::runtime_error)?;
            // No callback occurs during this operation. Validate the complete
            // output before native drawing or object creation takes effect.
            self.prepare_text_write(memory, pointer, usize::from(count) * 2)?;
            Some(pointer)
        };
        let table_bytes = match table_pointer {
            Some(pointer) => self.read_text_bytes(memory, pointer, usize::from(count) * 2)?,
            None => Vec::new(),
        };
        let mut objects = Vec::with_capacity(usize::from(count));
        for bytes in table_bytes.chunks_exact(2) {
            let handle = u16::from_le_bytes([bytes[0], bytes[1]]);
            // WOW's handle thunk maps an absent HGDIOBJ16 to NULL. Unused
            // stale slots must not suppress an unrelated drawing record.
            let token = if handle == 0 {
                None
            } else {
                self.guest_gdi.object(handle)
            };
            objects.push(token);
        }
        if shape.creates_object && !objects.contains(&None) {
            return Ok(());
        }
        let mut reserved = if shape.creates_object {
            let Some(handle) = self.guest_gdi.reserve_object() else {
                return Ok(());
            };
            Some(handle)
        } else {
            None
        };
        let callback = self.metafile_callback_for_table(table, count);
        let result = (|| {
            let result = host.win16_metafile(Operation::PlayRecord {
                dc,
                callback,
                record,
                objects,
            })?;
            let ResultValue::Record {
                objects, retired, ..
            } = result
            else {
                return Err(invariant(
                    "WMF record playback returned another result kind",
                ));
            };
            if objects.len() != usize::from(count) {
                return Err(invariant("WMF record playback changed its table extent"));
            }
            for token in retired {
                self.guest_gdi.retire_object_aliases(token);
            }
            let mut output = Vec::with_capacity(table_bytes.len());
            for token in objects {
                let word =
                    match token {
                        None => 0,
                        Some(token) => match self.guest_gdi.existing_object(token) {
                            Some(handle) => handle,
                            None => {
                                let handle = reserved.take().ok_or_else(|| invariant(
                                "WMF record created more objects than its reserved contract"))?;
                                if !self.guest_gdi.bind_object(handle, token) {
                                    return Err(invariant(
                                        "WMF object lost its unpublished reservation",
                                    ));
                                }
                                handle
                            }
                        },
                    };
                output.extend_from_slice(&word.to_le_bytes());
            }
            if let Some(pointer) = table_pointer {
                self.write_text_bytes(memory, pointer, &output)?;
            }
            Ok(())
        })();
        if let Some(handle) = reserved {
            if !self.guest_gdi.cancel_object(handle) {
                return Err(invariant("WMF playback lost its unused object reservation"));
            }
        }
        result
    }
}
fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
