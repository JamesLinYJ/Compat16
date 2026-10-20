//! Guest `AbortProc` for `SetAbortProc` and the print calls that enter it.
//!
//! Windows 3.1 `SetAbortProc` stores an application FAR procedure on a live
//! device context and returns a positive value. `SP_ERROR` (-1) is the
//! failure value. The procedure is `BOOL CALLBACK AbortProc(HDC, int)`: the
//! `int` is zero when spooling is proceeding and `SP_OUTOFDISK` when the
//! caller reports that the spooler is out of disk. Nonzero continues the job.
//! Zero cancels it.
//!
//! `QueryAbort` enters that procedure with the caller's code word and returns
//! the procedure's BOOL. It does not cancel an open spool job. A live DC with
//! no procedure still continues, and an unknown HDC still returns FALSE.
//!
//! `Escape` `STARTDOC`, `NEWFRAME`, and `ENDDOC`, plus `StartDoc`, `StartPage`,
//! `EndPage`, and `EndDoc`, enter the procedure once with code 0 before the
//! host print call. A zero return is `SP_APPABORT` (-2) and that host call is
//! skipped. The Windows 3.1 SDK says GDI terminates a canceled print operation
//! before returning the error, so the application must not send `ENDDOC` or
//! `ABORTDOC` for it. `StartPage`, `EndPage`, `EndDoc`, and the `NEWFRAME` and
//! `ENDDOC` escapes therefore abort the host document when one is already
//! open. `StartDoc` and `STARTDOC` have not opened a host document, so a zero
//! return does not call `AbortDoc`. `AbortDoc` and `Escape` `ABORTDOC` do not
//! ask the procedure, because the application has already canceled the job.
//! Drawing calls such as `TextOut` and `BitBlt` do not enter it. A spooler
//! disk-full condition is not synthesized; the application passes
//! `SP_OUTOFDISK` through `QueryAbort`.

use dos_kernel::DosKernel;
use guest_core::{Registers, Selector, memory::Memory};
use win16_abi::{Access, GdiDeviceRequest, PrintOperation, Win16ReturnKind};
use x86_cpu::Cpu;

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::{CallbackKind, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const SP_ERROR16: u32 = 0xffff;
/// Windows 3.1 `SP_APPABORT`. The abort procedure returned FALSE.
const SP_APPABORT16: u32 = 0xfffe;
/// FAR return, HDC word, and the abort code word.
const CALLBACK_STACK_BYTES: u16 = 8;
/// `SETABORTPROC` escape. The input dword is the procedure address.
pub(super) const SET_ABORT_PROC_ESCAPE: i16 = 9;

pub(super) struct PrintAbortFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    callback: u32,
    after: Option<AbortContinuation>,
    active_call: Option<Win16FarCallbackFrame>,
}

enum AbortContinuation {
    /// Return the procedure BOOL. Do not run a print operation.
    Query,
    /// Run the print operation only when the procedure returns nonzero.
    Device(GdiDeviceRequest),
}

impl Win16State {
    pub(super) fn set_abort_proc(
        &mut self,
        memory: &Memory,
        dc: u16,
        procedure: u32,
    ) -> Result<u32, RuntimeError> {
        if self.guest_gdi.dc(dc).is_none() {
            return Ok(SP_ERROR16);
        }
        if procedure != 0 && !self.abort_procedure_executable(procedure, memory) {
            return Ok(SP_ERROR16);
        }
        self.guest_gdi.set_abort_proc(dc, procedure);
        Ok(1)
    }

    pub(super) fn begin_query_abort(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        dc: u16,
        code: i16,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(procedure) = self.installed_abort_proc(dc) else {
            let continue_job = u32::from(self.guest_gdi.dc(dc).is_some());
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                continue_job,
                return_kind,
            );
        };
        self.enter_abort_proc(
            cpu,
            dos,
            memory,
            procedure,
            dc,
            code,
            return_to,
            return_kind,
            AbortContinuation::Query,
        )?;
        Ok(None)
    }

    /// `dc` is the device context the pending print operation names.
    pub(super) fn device_requests_abort(request: &GdiDeviceRequest) -> Option<u16> {
        match request {
            GdiDeviceRequest::Escape { dc, escape, .. } if escape_calls_abort(*escape) => Some(*dc),
            GdiDeviceRequest::StartDoc { dc, .. } => Some(*dc),
            GdiDeviceRequest::Print { dc, operation } if print_calls_abort(*operation) => Some(*dc),
            _ => None,
        }
    }

    pub(super) fn begin_print_abort(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        request: GdiDeviceRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(dc) = Self::device_requests_abort(&request) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort was started for a call that does not enter AbortProc",
            ));
        };
        let Some(procedure) = self.installed_abort_proc(dc) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort was started without an installed AbortProc",
            ));
        };
        self.enter_abort_proc(
            cpu,
            dos,
            memory,
            procedure,
            dc,
            0,
            return_to,
            return_kind,
            AbortContinuation::Device(request),
        )?;
        Ok(None)
    }

    pub(crate) fn finish_print_abort_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::PrintAbort)?;
        if self
            .print_abort_callbacks
            .last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort callback identity changed before guest return",
            ));
        }
        let mut active_call = self
            .print_abort_callbacks
            .last_mut()
            .and_then(|frame| frame.active_call.take())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 callback gate has no active print abort call",
                )
            })?;
        let callback_result =
            match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active_call) {
                Ok(value) => value,
                Err(error) => {
                    self.print_abort_callbacks
                        .last_mut()
                        .expect("frame checked")
                        .active_call = Some(active_call);
                    return Err(error);
                }
            };
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.print_abort_callbacks
                .last_mut()
                .expect("frame checked")
                .active_call = Some(active_call);
            return Err(error);
        }
        let frame = self.print_abort_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort callback frame disappeared",
            )
        })?;
        let continuation = frame.after.take().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort callback lost its continuation",
            )
        })?;
        let return_to = frame.return_to;
        let return_kind = frame.return_kind;
        let saved = frame.saved.clone();
        let frame = self.print_abort_callbacks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort callback frame disappeared",
            )
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::PrintAbort, callback_id) {
            self.print_abort_callbacks.push(PrintAbortFrame {
                after: Some(continuation),
                ..frame
            });
            return Err(error);
        }
        cpu.regs = saved;
        let value = match continuation {
            AbortContinuation::Query => u32::from(callback_result as u16),
            AbortContinuation::Device(request) => {
                if callback_result as u16 == 0 {
                    self.cancel_aborted_print_document(&request, host)?;
                    SP_APPABORT16
                } else {
                    self.execute_gdi_device(request, memory, host)?
                }
            }
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            value,
            return_kind,
        )?;
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_print_abort_callback_for_teardown(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::PrintAbort)?;
        let frame = self.print_abort_callbacks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "top print abort callback has no family frame",
            )
        })?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top print abort callback identity differs from its family frame",
            ));
        }
        if let Some(mut active_call) = self
            .print_abort_callbacks
            .last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::PrintAbort,
                callback_id,
                cpu,
                dos,
                memory,
                &mut active_call,
            ) {
                self.print_abort_callbacks
                    .last_mut()
                    .expect("frame checked")
                    .active_call = Some(active_call);
                return Err(error);
            }
            self.print_abort_callbacks
                .last_mut()
                .expect("frame checked")
                .active_call = Some(active_call);
        }
        let frame = self.print_abort_callbacks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "print abort callback frame disappeared during teardown",
            )
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::PrintAbort, callback_id) {
            self.print_abort_callbacks.push(frame);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn print_abort_code_references(&self) -> Vec<u32> {
        let mut references = Vec::new();
        references.extend(self.guest_gdi.abort_procedure_references());
        for frame in &self.print_abort_callbacks {
            references.push(frame.callback);
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }

    fn installed_abort_proc(&self, dc: u16) -> Option<u32> {
        self.guest_gdi
            .abort_proc(dc)
            .filter(|procedure| *procedure != 0)
    }

    fn abort_procedure_executable(&self, procedure: u32, memory: &Memory) -> bool {
        let Ok(pointer) = self.selectors.pointer_from_far(procedure) else {
            return false;
        };
        self.selectors
            .translate(pointer, Access::Execute, 1, memory)
            .is_ok()
    }

    fn enter_abort_proc(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        procedure: u32,
        dc: u16,
        code: i16,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        after: AbortContinuation,
    ) -> Result<(), RuntimeError> {
        if !self.abort_procedure_executable(procedure, memory) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 AbortProc is not an executable guest procedure",
            ));
        }
        self.preflight_abort_stack(&cpu.regs, memory)?;
        let callback_id = self.reserve_callback_frame_id()?;
        self.print_abort_callbacks.push(PrintAbortFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to,
            return_kind,
            callback: procedure,
            after: Some(after),
            active_call: None,
        });
        if let Err(error) = self.push_callback_kind(CallbackKind::PrintAbort, callback_id) {
            self.print_abort_callbacks.pop();
            return Err(error);
        }
        if let Err(error) = self.schedule_abort_proc(cpu, dos, memory, dc, code) {
            let frame = self.print_abort_callbacks.pop();
            if let Err(retire) = self.retire_callback_binding(CallbackKind::PrintAbort, callback_id)
            {
                if let Some(frame) = frame {
                    self.print_abort_callbacks.push(frame);
                }
                return Err(error.with_cleanup(
                    "retire a print abort frame that failed before guest entry",
                    retire,
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    fn preflight_abort_stack(
        &self,
        registers: &Registers,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        let stack_pointer = registers
            .sp()
            .checked_sub(CALLBACK_STACK_BYTES)
            .ok_or_else(|| {
                RuntimeError::new(Kind::GuestFault, "Win16 AbortProc stack underflow")
            })?;
        let pointer = self
            .selectors
            .pointer_from_raw(Selector(registers.ss), stack_pointer)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(
                pointer,
                Access::Write,
                usize::from(CALLBACK_STACK_BYTES),
                memory,
            )
            .map_err(crate::runtime_error)?;
        Ok(())
    }

    fn schedule_abort_proc(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        dc: u16,
        code: i16,
    ) -> Result<(), RuntimeError> {
        let frame = self.print_abort_callbacks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort frame is missing",
            )
        })?;
        let callback = frame.callback;
        let saved = frame.saved.clone();
        cpu.regs = saved;
        let active_call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            callback,
            &[
                Win16FarCallbackArgument::Word(dc),
                Win16FarCallbackArgument::Word(code as u16),
            ],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )?;
        let frame = self.print_abort_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort frame disappeared",
            )
        })?;
        frame.active_call = Some(active_call);
        Ok(())
    }
}

fn escape_calls_abort(escape: i16) -> bool {
    // STARTDOC (10), NEWFRAME (1), ENDDOC (11). ABORTDOC (2) is an explicit cancel.
    matches!(escape, 1 | 10 | 11)
}

/// `StartPage`, `EndPage`, `EndDoc`, `NEWFRAME`, and `ENDDOC` continue a
/// document that `StartDoc` already opened. A false abort procedure cancels
/// that document. `STARTDOC` and `StartDoc` run before the host document exists.
fn false_abort_cancels_open_document(request: &GdiDeviceRequest) -> bool {
    match request {
        GdiDeviceRequest::Print { operation, .. } => matches!(
            operation,
            PrintOperation::StartPage | PrintOperation::EndPage | PrintOperation::EndDocument
        ),
        GdiDeviceRequest::Escape { escape, .. } => matches!(*escape, 1 | 11),
        _ => false,
    }
}

impl Win16State {
    fn cancel_aborted_print_document(
        &mut self,
        request: &GdiDeviceRequest,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if !false_abort_cancels_open_document(request) {
            return Ok(());
        }
        let Some(dc) = Self::device_requests_abort(request) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 print abort lost the device context of an open document",
            ));
        };
        self.abort_print_document_if_open(dc, host)
    }
}

fn print_calls_abort(operation: PrintOperation) -> bool {
    matches!(
        operation,
        PrintOperation::StartPage | PrintOperation::EndPage | PrintOperation::EndDocument
    )
}

#[cfg(test)]
#[path = "win16_print_abort_tests.rs"]
mod tests;
