//! GDI spool retirement retains its exact identity until native completion.
use super::{
    ResultValue, RuntimeError, Win16HostSpoolJob, Win16SpoolJobs, last_error,
    remove_network_job_index, status_error, status_success,
};
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;
use windows_sys::Win32::Graphics::Printing::{
    AbortPrinter, ClosePrinter, EndDocPrinter, JOB_CONTROL_DELETE, PRINTER_HANDLE, SetJobW,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Finish {
    EndDocument,
    AbortOpenDocument,
    CancelQueuedJob,
}

impl Win16SpoolJobs {
    pub(super) fn close_job(
        &mut self,
        job: Win16HostSpoolJob,
        cancel: bool,
    ) -> Result<ResultValue, RuntimeError> {
        self.close_job_with(
            job,
            cancel,
            |action, printer, id| {
                // SAFETY: the registry retains this printer and its exact job ID
                // until both the terminal action and ClosePrinter acknowledge it.
                let result = unsafe {
                    match action {
                        Finish::EndDocument => EndDocPrinter(printer),
                        Finish::AbortOpenDocument => AbortPrinter(printer),
                        Finish::CancelQueuedJob => {
                            SetJobW(printer, id, 0, ptr::null(), JOB_CONTROL_DELETE)
                        }
                    }
                };
                if result != 0 {
                    Ok(())
                } else {
                    Err(last_error())
                }
            },
            |printer| {
                // SAFETY: this call borrows the still-owned printer handle.
                if unsafe { ClosePrinter(printer) } != 0 {
                    Ok(())
                } else {
                    Err(last_error())
                }
            },
        )
    }

    fn close_job_with(
        &mut self,
        job: Win16HostSpoolJob,
        cancel: bool,
        mut finish: impl FnMut(Finish, PRINTER_HANDLE, u32) -> Result<(), u32>,
        close: impl FnOnce(PRINTER_HANDLE) -> Result<(), u32>,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get_mut(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        let action = if cancel && !native.terminal_action {
            Some(if native.document_open {
                Finish::AbortOpenDocument
            } else {
                Finish::CancelQueuedJob
            })
        } else if !cancel && native.document_open {
            Some(Finish::EndDocument)
        } else {
            None
        };
        if let Some(action) = action {
            if let Err(error) = finish(action, native.printer, native.job_id) {
                return Ok(status_error(error));
            }
            native.document_open = false;
            native.terminal_action = action != Finish::EndDocument;
        }
        // A retry must not replay EndDocPrinter/AbortPrinter after that phase
        // succeeded. Keeping the entry also lets task cleanup retry this close.
        if let Err(error) = close(native.printer) {
            return Ok(status_error(error));
        }
        let native = self
            .jobs
            .remove(&job)
            .expect("exclusive spool registry retains its closing job");
        remove_network_job_index(&mut self.network_job_index, job, &native);
        Ok(status_success())
    }
}

#[cfg(test)]
#[path = "win16_spool_close_tests.rs"]
mod spool_close_tests;
