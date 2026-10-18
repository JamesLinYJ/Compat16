//! Runtime for KERNEL exports that were declaration-only.
//!
//! Guest selectors and far pointers stay guest values. A call the host cannot
//! perform returns the documented failure value and does not report success.

use guest_core::memory::Memory;
use win16_abi::local_heap::{LocalHeap, LocalHeapError};
use win16_abi::task_database::TASK_DATABASE_ERROR_MODE_OFFSET;
use win16_abi::{
    Access, Win16Argument, Win16KernelRemainderRequest, Win16ReturnKind, Win16ShellRegistryRequest,
};
use x86_cpu::Cpu;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const HFILE_ERROR: u32 = 0xFFFF;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;

pub(super) enum KernelRemainderOutcome {
    Value(u32),
    /// `ExitKernel` ends the guest task. The word is the exit status.
    Terminate(u16),
}

impl Win16State {
    pub(super) fn execute_kernel_remainder(
        &mut self,
        request: Win16KernelRemainderRequest,
        caller_ds: u16,
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
            ordinal, &arguments, caller_ds, memory, host,
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
        caller_ds: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match ordinal {
            14 => self.kernel_local_notify(arg_dword(arguments, 0)?, caller_ds, memory),
            126 => Ok(self.kernel_memory_freed(arg_word(arguments, 0)?)),
            154 => self.kernel_global_notify(arg_dword(arguments, 0)?, memory),
            // Previous-callback or previous-size zero would look like a successful
            // first registration. These calls are not installed.
            38 | 39 | 40 | 106 | 140 | 202 | 341 | 343 | 619 => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 KERNEL registration is not installed",
            )),
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
            // RegisterServiceProcess is BOOL. Zero is the documented failure.
            491 => Ok(0),
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

    /// High word: that module's local-heap size. Low word: `count_free`.
    /// Module 0 is the current instance. Any other word is an `HMODULE`.
    fn kernel_heap_spaces(&self, module: u16, memory: &Memory) -> Result<u32, RuntimeError> {
        let Some(selector) = self.module_local_heap_selector(module) else {
            return Ok(0);
        };
        let Ok((_, mut bytes)) = self.local_segment(selector, false, memory) else {
            return Ok(0);
        };
        let Ok(heap) = LocalHeap::open(&mut bytes) else {
            return Ok(0);
        };
        let free = heap.count_free().map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "read Win16 local heap free space",
                error,
            )
        })?;
        let size = heap.heap_size().map_err(|error| {
            RuntimeError::with_source(Kind::GuestFault, "read Win16 local heap size", error)
        })?;
        Ok((u32::from(size) << 16) | u32::from(free))
    }

    fn module_local_heap_selector(&self, module: u16) -> Option<u16> {
        if module == 0 {
            return Some(self.instance_selector.raw().0);
        }
        let handle = self.modules.by_handle(module)?;
        let record = self.modules.records.get(&handle)?;
        if let Some(definition) = record.definition.as_ref() {
            let number = definition.header.automatic_data_segment;
            if number != 0 {
                if let Some(selector) = record
                    .loaded
                    .as_ref()
                    .and_then(|loaded| loaded.segment_selector(number))
                {
                    return Some(selector.0);
                }
            }
        }
        record
            .builtin_data_selector
            .map(|selector| selector.raw().0)
    }

    /// Stores `procedure` in the caller's local-heap notify slot and returns
    /// the previous guest far procedure. An uninitialized heap is not success.
    fn kernel_local_notify(
        &mut self,
        procedure: u32,
        caller_ds: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let (address, mut bytes) = self.local_segment(caller_ds, true, memory)?;
        let mut heap = match LocalHeap::open(&mut bytes) {
            Ok(heap) => heap,
            Err(LocalHeapError::Uninitialized) => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 LocalNotify has no initialized local heap",
                ));
            }
            Err(error) => {
                return Err(RuntimeError::with_source(
                    Kind::GuestFault,
                    "open Win16 local heap for LocalNotify",
                    error,
                ));
            }
        };
        let previous = heap.replace_notify(procedure).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "store Win16 LocalNotify procedure",
                error,
            )
        })?;
        let spans = heap.take_write_spans();
        drop(heap);
        super::local_heap::commit_local_spans(memory, address, &bytes, &spans)?;
        Ok(previous)
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

    /// `UnicodeToAnsi(source, destination, code_page)`. A null pointer, an
    /// unsupported page, or a destination that cannot hold the ANSI bytes
    /// returns 0 and writes nothing. The word result counts the bytes written,
    /// including the terminating NUL.
    fn kernel_unicode_to_ansi(
        &self,
        arguments: &[Win16Argument],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let source = arg_dword(arguments, 0)?;
        let destination = arg_dword(arguments, 1)?;
        let code_page = arg_word(arguments, 2)?;
        if source == 0 || destination == 0 {
            return Ok(0);
        }
        let page_id = if code_page == 0 {
            u16::try_from(host.win16_ansi_code_page()).unwrap_or(0)
        } else {
            code_page
        };
        let Ok(page) = text_codec::CodePage::try_from(page_id) else {
            return Ok(0);
        };
        let Some(units) = self.read_utf16_z(source, memory) else {
            return Ok(0);
        };
        let Ok(text) = String::from_utf16(&units) else {
            return Ok(0);
        };
        let Ok(encoded) = page.encode(&text) else {
            return Ok(0);
        };
        let width = encoded.len().saturating_add(1);
        let Ok(count) = u16::try_from(width) else {
            return Ok(0);
        };
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
        Ok(u32::from(count))
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
        // The Win32 thunks share checked decoding, not SHELL's NULL data or
        // Win3.1 status conversion. See kernel31/kernel.def and WKTBL2.H.
        let request = Win16ShellRegistryRequest::decode_kernel_export(
            ordinal, arguments, &self.selectors, memory,
        ).map_err(crate::runtime_error)?;
        self.shell_registry_native_status(request, memory, host)
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
