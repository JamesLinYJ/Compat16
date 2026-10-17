//! Runtime for KERNEL exports that were declaration-only.
//!
//! Guest selectors and far pointers stay guest values. A call the host cannot
//! perform returns the documented failure value and does not report success.

use guest_core::memory::Memory;
use win16_abi::local_heap::LocalHeap;
use win16_abi::task_database::TASK_DATABASE_ERROR_MODE_OFFSET;
use win16_abi::{
    Access, Win16Argument, Win16KernelRemainderRequest, Win16ReturnKind, Win16ShellRegistryRequest,
};
use x86_cpu::Cpu;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const HFILE_ERROR: u32 = 0xFFFF;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const MAX_REGISTRY_BYTES: u32 = 64 * 1024;
const MAX_ANSI_BYTES: usize = 64 * 1024;

pub(super) enum KernelRemainderOutcome {
    Value(u32),
    /// `ExitKernel` ends the guest task. The word is the exit status.
    Terminate(u16),
}

impl Win16State {
    pub(super) fn execute_kernel_remainder(
        &mut self,
        request: Win16KernelRemainderRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<KernelRemainderOutcome, RuntimeError> {
        let Win16KernelRemainderRequest::Stack { ordinal, arguments } = request else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "register-context KERNEL remainder reached the stack executor",
            ));
        };
        if ordinal == 2 {
            return Ok(KernelRemainderOutcome::Terminate(0));
        }
        Ok(KernelRemainderOutcome::Value(self.kernel_remainder_value(
            ordinal, &arguments, memory, host,
        )?))
    }

    /// Register-context glue has no 32-bit callee. AX and DX return zero.
    pub(super) fn fail_kernel_register_remainder(
        &mut self,
        cpu: &mut Cpu,
        memory: &Memory,
    ) -> Result<Option<u8>, RuntimeError> {
        let (return_selector, return_offset, return_sp) = self.far_return(&cpu.regs, memory, 0)?;
        self.complete_return(
            &mut cpu.regs,
            return_selector,
            return_offset,
            return_sp,
            0,
            Win16ReturnKind::Dword,
        )
    }

    fn kernel_remainder_value(
        &mut self,
        ordinal: u16,
        arguments: &[Win16Argument],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match ordinal {
            75 | 360 => Ok(HFILE_ERROR),
            99 => self.kernel_error_mode_pointer(),
            138 => self.kernel_heap_spaces(arg_word(arguments, 0)?, memory),
            216 | 217 | 218 | 219 | 220 | 221 | 224 => {
                self.kernel_registry(ordinal, arguments, memory, host)
            }
            222 | 223 | 225 | 226 | 227 | 232 | 233 | 234 => Ok(ERROR_CALL_NOT_IMPLEMENTED),
            316 => self.kernel_get_free_space(0),
            434 => self.kernel_unicode_to_ansi(arguments, memory, host),
            460 | 461 | 495 => Ok(WAIT_FAILED),
            462 => Ok(u32::from(self.current_task_handle()?)),
            471 => Ok(self.kernel_get_current_pdb()),
            627 => self.kernel_is_bad_flat(arguments, memory),
            652 => {
                let id = arg_dword(arguments, 0)?;
                Ok(u32::from(id == u32::from(self.current_task_handle()?)))
            }
            _ => Ok(0),
        }
    }

    /// Far pointer to the task database error-mode word `SetErrorMode` stores.
    fn kernel_error_mode_pointer(&self) -> Result<u32, RuntimeError> {
        let task = self.current_task_handle()?;
        let offset = u16::try_from(TASK_DATABASE_ERROR_MODE_OFFSET).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 error-mode offset exceeds a word",
            )
        })?;
        Ok((u32::from(task) << 16) | u32::from(offset))
    }

    /// High word: global free bytes, saturated. Low word: local `count_free`
    /// for the module selector, or for the current instance when the module is 0.
    fn kernel_heap_spaces(&self, module: u16, memory: &Memory) -> Result<u32, RuntimeError> {
        let global = self.kernel_get_free_space(0)?.min(u32::from(u16::MAX)) as u16;
        let selector = if module == 0 {
            self.instance_selector.raw().0
        } else {
            module
        };
        let local = self.local_heap_free_bytes(selector, memory);
        Ok((u32::from(global) << 16) | u32::from(local))
    }

    fn local_heap_free_bytes(&self, selector: u16, memory: &Memory) -> u16 {
        let Ok((_, mut bytes)) = self.local_segment(selector, false, memory) else {
            return 0;
        };
        let Ok(heap) = LocalHeap::open(&mut bytes) else {
            return 0;
        };
        heap.count_free().unwrap_or(0)
    }

    fn kernel_is_bad_flat(
        &self,
        arguments: &[Win16Argument],
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        let pointer = arg_dword(arguments, 0)?;
        let length = arg_dword(arguments, 1)?;
        let _mode = arg_word(arguments, 2)?;
        let read = self.kernel_is_bad_memory_pointer(pointer, length, Access::Read, memory)?;
        let write = self.kernel_is_bad_memory_pointer(pointer, length, Access::Write, memory)?;
        Ok(u32::from(u16::from(read != 0 || write != 0)))
    }

    /// `UnicodeToAnsi(destination, source, capacity)`. Unrepresentable text and
    /// a short buffer return 0 and leave the destination unchanged.
    fn kernel_unicode_to_ansi(
        &self,
        arguments: &[Win16Argument],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let destination = arg_dword(arguments, 0)?;
        let source = arg_dword(arguments, 1)?;
        let capacity = arg_word(arguments, 2)?;
        if destination == 0 || source == 0 || capacity == 0 {
            return Ok(0);
        }
        let Some(units) = self.read_utf16_z(source, memory) else {
            return Ok(0);
        };
        let Ok(text) = String::from_utf16(&units) else {
            return Ok(0);
        };
        let Ok(encoded) = host.encode_win16_ansi(&text) else {
            return Ok(0);
        };
        let width = encoded.len().saturating_add(1);
        if width > usize::from(capacity) {
            return Ok(0);
        }
        let Ok(pointer) = self.selectors.pointer_from_far(destination) else {
            return Ok(0);
        };
        if self
            .selectors
            .translate(pointer, Access::Write, width, memory)
            .is_err()
        {
            return Ok(0);
        }
        let mut bytes = encoded;
        bytes.push(0);
        self.selectors
            .write(memory, pointer, &bytes)
            .map_err(crate::runtime_error)?;
        u32::try_from(bytes.len() - 1).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 UnicodeToAnsi length exceeds a dword",
            )
        })
    }

    fn read_utf16_z(&self, far: u32, memory: &Memory) -> Option<Vec<u16>> {
        let mut pointer = self.selectors.pointer_from_far(far).ok()?;
        let mut units = Vec::new();
        loop {
            if self
                .selectors
                .translate(pointer, Access::Read, 2, memory)
                .is_err()
            {
                return None;
            }
            let mut bytes = [0_u8; 2];
            self.selectors.read(memory, pointer, &mut bytes).ok()?;
            let unit = u16::from_le_bytes(bytes);
            if unit == 0 {
                return Some(units);
            }
            if units.len() == 32_767 {
                return None;
            }
            units.push(unit);
            pointer = self.selectors.add_bytes(pointer, 2).ok()?;
        }
    }

    fn kernel_registry(
        &mut self,
        ordinal: u16,
        arguments: &[Win16Argument],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let request = match ordinal {
            216 => Win16ShellRegistryRequest::EnumKey {
                key: arg_dword(arguments, 0)?,
                index: arg_dword(arguments, 1)?,
                output: arg_dword(arguments, 2)?,
                capacity: arg_dword(arguments, 3)?,
            },
            217 => Win16ShellRegistryRequest::OpenKey {
                root: arg_dword(arguments, 0)?,
                subkey: self.read_registry_string(arg_dword(arguments, 1)?, memory)?,
                output: arg_dword(arguments, 2)?,
            },
            218 => Win16ShellRegistryRequest::CreateKey {
                root: arg_dword(arguments, 0)?,
                subkey: self.read_registry_string(arg_dword(arguments, 1)?, memory)?,
                output: arg_dword(arguments, 2)?,
            },
            219 => Win16ShellRegistryRequest::DeleteKey {
                root: arg_dword(arguments, 0)?,
                subkey: self.read_registry_string(arg_dword(arguments, 1)?, memory)?,
            },
            220 => Win16ShellRegistryRequest::CloseKey {
                key: arg_dword(arguments, 0)?,
            },
            221 => {
                let length = arg_dword(arguments, 4)?;
                if length > MAX_REGISTRY_BYTES {
                    return Ok(ERROR_INVALID_PARAMETER);
                }
                Win16ShellRegistryRequest::SetValue {
                    key: arg_dword(arguments, 0)?,
                    subkey: self.read_registry_string(arg_dword(arguments, 1)?, memory)?,
                    value_type: arg_dword(arguments, 2)?,
                    value: self.read_registry_bytes(arg_dword(arguments, 3)?, length, memory)?,
                    declared_byte_count: length,
                }
            }
            224 => {
                let byte_count_output = arg_dword(arguments, 3)?;
                let byte_count = self.read_guest_u32(byte_count_output, memory)?;
                Win16ShellRegistryRequest::QueryValue {
                    key: arg_dword(arguments, 0)?,
                    subkey: self.read_registry_string(arg_dword(arguments, 1)?, memory)?,
                    output: arg_dword(arguments, 2)?,
                    byte_count,
                    byte_count_output,
                }
            }
            _ => return Ok(ERROR_CALL_NOT_IMPLEMENTED),
        };
        self.shell_registry_api(request, memory, host)
    }

    fn read_registry_string(&self, far: u32, memory: &Memory) -> Result<Vec<u8>, RuntimeError> {
        if far == 0 {
            return Ok(Vec::new());
        }
        win16_abi::strings::read_ansi_z(&self.selectors, memory, far, MAX_ANSI_BYTES).map_err(
            |error| crate::runtime_error(error).with_context("reading KERNEL registry string"),
        )
    }

    fn read_registry_bytes(
        &self,
        far: u32,
        length: u32,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        let length = usize::try_from(length).map_err(|_| {
            RuntimeError::new(
                Kind::InvalidInput,
                "KERNEL registry value length does not fit the host",
            )
        })?;
        if length == 0 {
            return Ok(Vec::new());
        }
        if far == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "KERNEL registry value pointer is null",
            ));
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Read, length, memory)
            .map_err(crate::runtime_error)?;
        let mut bytes = vec![0_u8; length];
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        Ok(bytes)
    }

    fn read_guest_u32(&self, far: u32, memory: &Memory) -> Result<u32, RuntimeError> {
        if far == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "KERNEL registry size pointer is null",
            ));
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Read, 4, memory)
            .map_err(crate::runtime_error)?;
        let mut bytes = [0_u8; 4];
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

fn arg_word(arguments: &[Win16Argument], index: usize) -> Result<u16, RuntimeError> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "KERNEL remainder word argument is missing",
        )),
    }
}

fn arg_dword(arguments: &[Win16Argument], index: usize) -> Result<u32, RuntimeError> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "KERNEL remainder dword argument is missing",
        )),
    }
}
