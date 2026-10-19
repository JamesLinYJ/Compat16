//! Win3.1 truncation and Win32 optional-pointer registry query contracts.
use guest_core::memory::Memory;
use win16_abi::Win16ShellRegistryRequest;

use super::{Win16State, wrong_registry_result};
use crate::{
    DiagnosticKind, RuntimeError, RuntimeHost, Win16HostRegistryOperation, Win16HostRegistryResult,
    Win16RegistryQueryOutput as Output,
};

impl Win16State {
    pub(super) fn shell_registry_query_value(
        &mut self,
        request: Win16ShellRegistryRequest,
        win31: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Win16ShellRegistryRequest::QueryValue {
            key,
            subkey,
            output,
            byte_count: capacity,
            byte_count_output: size_output,
        } = request
        else {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "registry query received another request variant",
            ));
        };
        if win31 && size_output == 0 {
            return Ok(87);
        }
        let Ok(key) = self.registry_key_for_api(key, win31, true) else {
            return Ok(6);
        };
        let size_pointer = if size_output == 0 {
            None
        } else {
            Some(self.preflight_registry_output(memory, size_output, 4)?)
        };
        let policy = if size_pointer.is_none() {
            Output::WithoutLength {
                data_present: output != 0,
            }
        } else if output == 0 {
            Output::SizeOnly
        } else if win31 {
            Output::Complete
        } else {
            Output::Bounded(capacity)
        };
        let result = host.win16_registry(Win16HostRegistryOperation::QueryValue {
            key,
            subkey,
            output: policy,
            view: if win31 { crate::Win16RegistryQueryView::Win31Strings }
                else { crate::Win16RegistryQueryView::Native },
        })?;
        let Win16HostRegistryResult::QueryValue {
            status,
            mut required_bytes,
            mut bytes,
            ..
        } = result
        else {
            return Err(wrong_registry_result("RegQueryValue"));
        };
        if status == 0 {
            match policy {
                Output::SizeOnly | Output::WithoutLength { .. } => {
                    if !bytes.is_empty() {
                        return Err(invalid_output());
                    }
                }
                Output::Complete | Output::Bounded(_) => {
                    if bytes.len() != required_bytes as usize {
                        return Err(invalid_output());
                    }
                    if let Output::Bounded(capacity) = policy {
                        if required_bytes > capacity {
                            return Err(invalid_output());
                        }
                    } else if required_bytes > capacity {
                        // WOW WS32RegQueryValue retries into owned storage and
                        // copies only the original low-WORD byte capacity. It
                        // neither appends NUL nor repairs a split DBCS character.
                        required_bytes = capacity & 0xffff;
                        bytes.truncate(required_bytes as usize);
                    }
                    // Check exactly the bytes that will be written, rather
                    // than faulting on an oversized advertised capacity.
                    if !bytes.is_empty() {
                        self.write_registry_output(memory, output, &bytes)?;
                    }
                }
            }
        }
        // Native query failures leave lpcbData unchanged. Only success and
        // MORE_DATA return a size; optional length pointers are never written.
        if matches!(status, 0 | 234) {
            if let Some(pointer) = size_pointer {
                self.selectors
                    .write(memory, pointer, &required_bytes.to_le_bytes())
                    .map_err(crate::runtime_error)?;
            }
        }
        Ok(status)
    }
}

fn invalid_output() -> RuntimeError {
    RuntimeError::new(
        DiagnosticKind::InternalInvariant,
        "host RegQueryValue result violates the requested output contract",
    )
}
