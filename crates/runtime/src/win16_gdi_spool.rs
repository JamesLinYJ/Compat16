//! Win16 GDI PRINT.H operations backed by the owned Windows spooler adapter.

use guest_core::{OwnerId, memory::Memory};
use win16_abi::Win16GdiSpoolRequest as Request;

use super::Win16State;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostSpoolOperation,
    Win16HostSpoolResult,
};

const GDI_ERROR: u32 = 0x0000_FFFF;
const SP_OUTOFDISK: u32 = (-4_i16) as u16 as u32;
const SP_OUTOFMEMORY: u32 = (-5_i16) as u16 as u32;

impl Win16State {
    pub(super) fn execute_gdi_spool(
        &mut self,
        request: Request,
        _memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Request::OpenJob {
                output_target,
                document_name,
                legacy_argument,
            } => self.open_gdi_spool_job(output_target, document_name, legacy_argument, host),
            Request::WriteSpool {
                job,
                byte_count,
                bytes,
            } => {
                if byte_count < 0 || usize::try_from(byte_count).ok() != Some(bytes.len()) {
                    return Ok(GDI_ERROR);
                }
                let Some(owner) = self.current_gdi_spool_owner()? else {
                    return Ok(GDI_ERROR);
                };
                let Some(host_job) = self
                    .network_print_jobs
                    .get(&owner)
                    .and_then(|jobs| jobs.host_gdi_job_for_id(job))
                else {
                    return Ok(GDI_ERROR);
                };
                match host.win16_spool(Win16HostSpoolOperation::Write {
                    job: host_job,
                    bytes,
                })? {
                    Win16HostSpoolResult::Write {
                        bytes_written,
                        native_error: None,
                    } if bytes_written <= byte_count as u32 => Ok(bytes_written),
                    Win16HostSpoolResult::Write {
                        native_error: Some(code),
                        ..
                    } => {
                        report_native_error(host, "WriteSpool", code);
                        Ok(spool_error(code))
                    }
                    Win16HostSpoolResult::Write {
                        bytes_written,
                        native_error: None,
                    } => Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        format!(
                            "GDI WriteSpool returned {bytes_written} bytes for a {byte_count}-byte request",
                        ),
                    )),
                    _ => Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "GDI WriteSpool received a different spool result",
                    )),
                }
            }
            Request::CloseJob { job } => self.finish_gdi_spool_job(job, false, 0, host),
            Request::DeleteJob {
                job,
                legacy_argument,
            } => self.finish_gdi_spool_job(job, true, legacy_argument, host),
            Request::StartSpoolPage { job } => self.gdi_spool_page(job, true, host),
            Request::EndSpoolPage { job } => self.gdi_spool_page(job, false, host),
        }
    }

    fn open_gdi_spool_job(
        &mut self,
        output_target: Vec<u8>,
        document_name: Vec<u8>,
        legacy_argument: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // The DDK identifies this WORD as the application's abort DC, despite
        // PRINT.H spelling its type HPJOB. It is never a native HDC. No abort
        // procedure can currently be installed (SetAbortProc reports a gap),
        // but an invalid non-null guest DC must not create a native document.
        if legacy_argument != 0 && self.guest_gdi.dc(legacy_argument).is_none() {
            return Ok(GDI_ERROR);
        }
        let owner = self.current_gdi_spool_owner()?.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "GDI OpenJob has no current Win16 task owner",
            )
        })?;
        self.network_print_jobs.entry(owner).or_default();
        let result = host.win16_spool(Win16HostSpoolOperation::OpenJob {
            owner,
            output_target,
            document_name,
            legacy_argument,
        })?;
        let Win16HostSpoolResult::OpenJob { job, native_error } = result else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "GDI OpenJob received a different spool result",
            ));
        };
        if let Some(code) = native_error {
            report_native_error(host, "OpenJob", code);
            if let Some(job) = job {
                self.release_unexposed_gdi_spool_job(job, host);
            }
            return Ok(spool_error(code));
        }
        let Some(host_job) = job else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "successful GDI OpenJob omitted its host job identity",
            ));
        };
        let mapped = self
            .network_print_jobs
            .get_mut(&owner)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "GDI OpenJob lost its reserved task job table",
                )
            })?
            .gdi_guest_job_id_for(host_job);
        match mapped {
            Ok(job) => Ok(u32::from(job)),
            Err(error) => {
                self.release_unexposed_gdi_spool_job(host_job, host);
                if error.kind() == Kind::ResourceExhausted {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::ResourceExhausted,
                        format!("allocate GDI HPJOB: {error}"),
                    ));
                    Ok(SP_OUTOFMEMORY)
                } else {
                    Err(error)
                }
            }
        }
    }

    fn gdi_spool_page(
        &mut self,
        job: u16,
        start: bool,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(owner) = self.current_gdi_spool_owner()? else {
            return Ok(GDI_ERROR);
        };
        let Some(host_job) = self
            .network_print_jobs
            .get(&owner)
            .and_then(|jobs| jobs.host_gdi_job_for_id(job))
        else {
            return Ok(GDI_ERROR);
        };
        let operation = if start {
            Win16HostSpoolOperation::StartPage { job: host_job }
        } else {
            Win16HostSpoolOperation::EndPage { job: host_job }
        };
        let label = if start {
            "StartSpoolPage"
        } else {
            "EndSpoolPage"
        };
        status_as_gdi_int(host.win16_spool(operation)?, label, host)
    }

    fn finish_gdi_spool_job(
        &mut self,
        guest_job: u16,
        cancel: bool,
        legacy_argument: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(owner) = self.current_gdi_spool_owner()? else {
            return Ok(GDI_ERROR);
        };
        let Some(host_job) = self
            .network_print_jobs
            .get(&owner)
            .and_then(|jobs| jobs.host_gdi_job_for_id(guest_job))
        else {
            return Ok(GDI_ERROR);
        };
        let operation = if cancel {
            Win16HostSpoolOperation::DeleteJob {
                job: host_job,
                legacy_argument,
            }
        } else {
            Win16HostSpoolOperation::CloseJob { job: host_job }
        };
        let label = if cancel { "DeleteJob" } else { "CloseJob" };
        let status = host.win16_spool(operation)?;
        let result = status_as_gdi_int(status, label, host)?;
        if result != 1 {
            // Native failures retain their exact token and phase for retry.
            // Retire the guest alias only after the host acknowledges closure.
            return Ok(result);
        }
        let jobs = self.network_print_jobs.get_mut(&owner).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "GDI spool owner disappeared before job retirement",
            )
        })?;
        if jobs.retire_gdi_guest_job(guest_job) != Some(host_job) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "GDI spool job identity changed during close",
            ));
        }
        self.drop_empty_network_print_owner(owner);
        Ok(result)
    }

    fn current_gdi_spool_owner(&self) -> Result<Option<OwnerId>, RuntimeError> {
        Ok(self.tasks.current())
    }

    fn release_unexposed_gdi_spool_job(
        &mut self,
        job: crate::Win16HostSpoolJob,
        host: &mut impl RuntimeHost,
    ) {
        match host.win16_spool(Win16HostSpoolOperation::ReleaseNetworkJob { job }) {
            Ok(Win16HostSpoolResult::Status {
                succeeded: true, ..
            }) => {}
            Ok(Win16HostSpoolResult::Status {
                succeeded: false,
                native_error,
            }) => {
                if let Some(code) = native_error {
                    report_native_error(host, "release unexposed GDI spool job", code);
                }
            }
            Ok(_) => host.report_diagnostic(&Diagnostic::warning(
                Kind::InternalInvariant,
                "GDI spool cleanup received a different spool result",
            )),
            Err(error) => host.report_diagnostic(&Diagnostic::warning(
                error.kind(),
                format!("GDI spool cleanup could not release its host job: {error}"),
            )),
        }
    }
}

fn status_as_gdi_int(
    result: Win16HostSpoolResult,
    label: &str,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    match result {
        Win16HostSpoolResult::Status {
            succeeded,
            native_error,
        } => {
            if succeeded && native_error.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("GDI {label} reported success with a native failure"),
                ));
            }
            if let Some(code) = native_error {
                report_native_error(host, label, code);
            }
            // DDK Print Manager status is positive on success, negative on
            // failure. A native BOOL failure must never become guest zero.
            Ok(if succeeded {
                1
            } else {
                native_error.map_or(GDI_ERROR, spool_error)
            })
        }
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("GDI {label} received a different spool result"),
        )),
    }
}

fn spool_error(native_error: u32) -> u32 {
    // Windows SDK error numbers: ERROR_HANDLE_DISK_FULL / ERROR_DISK_FULL,
    // ERROR_NOT_ENOUGH_MEMORY / ERROR_OUTOFMEMORY. Other failures have no
    // verified Win16-specific cause. In particular, native cancellation does
    // not establish that a guest abort procedure returned FALSE (SP_APPABORT).
    match native_error {
        39 | 112 => SP_OUTOFDISK,
        8 | 14 => SP_OUTOFMEMORY,
        _ => GDI_ERROR,
    }
}

fn report_native_error(host: &mut impl RuntimeHost, operation: &str, code: u32) {
    host.report_diagnostic(&Diagnostic::warning(
        Kind::HostFailure,
        format!("Win16 GDI {operation} failed with Windows error {code}"),
    ));
}

#[cfg(test)]
#[path = "win16_gdi_spool_tests.rs"]
mod tests;
