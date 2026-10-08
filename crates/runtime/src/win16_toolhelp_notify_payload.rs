//! Zerocopy guest payload encoding and owner cleanup for ToolHelp notifications.

use guest_core::memory::Memory;
use win16_abi::toolhelp_abi::{
    NfyLoadSeg16Wire, NfyRip16Wire, NfyStartDll16Wire, NFYLOADSEG16_SIZE,
    NFYRIP16_SIZE, NFYSTARTDLL16_SIZE,
};
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U16, U32};

use super::toolhelp_notify::Win16ToolhelpNotifyData;
use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn toolhelp_notify_guest_data(
        &mut self,
        data: &Win16ToolhelpNotifyData,
        memory: &mut Memory,
        buffers: &mut Vec<super::callback_scheduler::CallbackBuffer>,
    ) -> Result<u32, RuntimeError> {
        match data {
            Win16ToolhelpNotifyData::Scalar(value) => Ok(*value),
            Win16ToolhelpNotifyData::LoadSegment {
                selector,
                segment_number,
                segment_type,
                instance_count,
                module_name,
                ..
            } => {
                let mut terminated_name = Vec::new();
                terminated_name.try_reserve_exact(module_name.len().saturating_add(1)).map_err(
                    |error| RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "build Win16 ToolHelp module-name payload",
                        error,
                    ),
                )?;
                terminated_name.extend_from_slice(module_name);
                terminated_name.push(0);
                let name_far = self.allocate_toolhelp_notify_buffer(
                    memory, &terminated_name, buffers,
                )?;
                let wire = NfyLoadSeg16Wire {
                    dw_size: U32::new(NFYLOADSEG16_SIZE as u32),
                    selector: U16::new(*selector),
                    segment_number: U16::new(*segment_number),
                    segment_type: U16::new(*segment_type),
                    instance_count: U16::new(*instance_count),
                    module_name: U32::new(name_far),
                };
                self.allocate_toolhelp_notify_buffer(memory, wire.as_bytes(), buffers)
            }
            Win16ToolhelpNotifyData::FreeSegment { selector, .. } => {
                Ok(u32::from(*selector))
            }
            Win16ToolhelpNotifyData::DeleteModule { module_handle, .. } => {
                Ok(u32::from(*module_handle))
            }
            Win16ToolhelpNotifyData::StartDll {
                module, code_segment, instruction_pointer, ..
            } => {
                let wire = NfyStartDll16Wire {
                    dw_size: U32::new(NFYSTARTDLL16_SIZE as u32),
                    module: U16::new(*module),
                    code_segment: U16::new(*code_segment),
                    instruction_pointer: U16::new(*instruction_pointer),
                };
                self.allocate_toolhelp_notify_buffer(memory, wire.as_bytes(), buffers)
            }
            Win16ToolhelpNotifyData::Rip {
                instruction_pointer,
                code_segment,
                stack_segment,
                base_pointer,
                exit_code,
            } => {
                let wire = NfyRip16Wire {
                    dw_size: U32::new(NFYRIP16_SIZE as u32),
                    instruction_pointer: U16::new(*instruction_pointer),
                    code_segment: U16::new(*code_segment),
                    stack_segment: U16::new(*stack_segment),
                    base_pointer: U16::new(*base_pointer),
                    exit_code: U16::new(*exit_code),
                };
                self.allocate_toolhelp_notify_buffer(memory, wire.as_bytes(), buffers)
            }
        }
    }

    pub(super) fn allocate_toolhelp_notify_buffer(
        &mut self,
        memory: &mut Memory,
        bytes: &[u8],
        buffers: &mut Vec<super::callback_scheduler::CallbackBuffer>,
    ) -> Result<u32, RuntimeError> {
        match self.allocate_callback_buffer(memory, bytes) {
            Ok((owner, far, _)) => {
                buffers.push(owner);
                Ok(far)
            }
            Err((error, partial)) => {
                if let Some(partial) = partial { buffers.push(partial); }
                Err(error)
            }
        }
    }

    pub(super) fn finish_toolhelp_notify_payload_setup_failure(
        &mut self,
        primary: RuntimeError,
        mut buffers: Vec<super::callback_scheduler::CallbackBuffer>,
    ) -> RuntimeError {
        match self.release_callback_buffers(&mut buffers) {
            Ok(()) => primary,
            Err(cleanup) => primary.with_cleanup(
                "ToolHelp notification setup retained its primary failure and payload cleanup failure",
                cleanup,
            ),
        }
    }

}
