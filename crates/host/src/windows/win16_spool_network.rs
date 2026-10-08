//! Windows network print-job ownership and copy-count negotiation.

use std::mem::{align_of, size_of};
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostSpoolDiagnostic, Win16HostSpoolJob,
    Win16HostSpoolResult as ResultValue, Win16HostTaskOwner,
    Win16NetworkPrintJobControl,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_INVALID_PRINTER_NAME,
    ERROR_NOT_SUPPORTED,
};
use windows_sys::Win32::Graphics::Gdi::{DEVMODEW, DM_COPIES};
use windows_sys::Win32::Graphics::Printing::{
    AbortPrinter, ClosePrinter, EndDocPrinter, GetJobW, JOB_CONTROL_DELETE,
    JOB_CONTROL_PAUSE, JOB_CONTROL_RESUME, JOB_INFO_2W, JOB_POSITION_UNSPECIFIED, SetJobW,
};
use windows_sys::Win32::Storage::Xps::DeviceCapabilitiesW;

use super::{
    copy_bytes, copy_wide_units, last_error, ordinal_equal_ignore_case, remove_network_job_index,
    resolve_printer_name, status_error, status_success, NativeJob, Win16SpoolJobs,
};
use super::super::guest_text::GuestTextCodec;

impl Win16SpoolJobs {
    pub(super) fn open_network_job(
        &mut self,
        codec: GuestTextCodec,
        owner: Win16HostTaskOwner,
        queue: &[u8],
        document_name: Option<&[u8]>,
        copies: u16,
    ) -> Result<ResultValue, RuntimeError> {
        if copies == 0 {
            return Ok(ResultValue::NetworkOpenJob {
                job: None,
                queue_name: None,
                copies_applied: false,
                native_error: Some(ERROR_INVALID_PARAMETER),
                copies_error: None,
                copies_diagnostic: None,
            });
        }
        let started = match self.start_job(
            codec,
            queue,
            document_name,
            Some(owner),
            super::StartDocPrinterDataType::Raw,
        )? {
            Ok(started) => started,
            Err(error) => return Ok(ResultValue::NetworkOpenJob {
                job: None,
                queue_name: None,
                copies_applied: false,
                native_error: Some(error),
                copies_error: None,
                copies_diagnostic: None,
            }),
        };
        let job = started.token;
        let queue_name = started.queue_name;

        if copies == 1 {
            // No GetJob/SetJob operation is needed for a normal one-stream
            // submission. This says nothing about copies encoded in PDL.
            return Ok(ResultValue::NetworkOpenJob {
                job: Some(job),
                queue_name: Some(queue_name),
                copies_applied: true,
                native_error: None,
                copies_error: None,
                copies_diagnostic: None,
            });
        }

        // WINNET.H gives the WNet writer a byte stream and no DEVMODE. Its RAW
        // stream is passed through once, unchanged; we do not duplicate or
        // rewrite PDL, whose own commands may determine physical output copies.
        // WFW's OpenJob warning is used because the requested host-controlled
        // copy count cannot be applied to this byte-stream job.
        Ok(ResultValue::NetworkOpenJob {
            job: Some(job),
            queue_name: Some(queue_name),
            copies_applied: false,
            native_error: None,
            copies_error: Some(ERROR_NOT_SUPPORTED),
            copies_diagnostic: Some(Win16HostSpoolDiagnostic {
                kind: Kind::CompatibilityGap,
                message: format!(
                    "WNetOpenJob requested {copies} copies, but this RAW bridge submits the original byte stream once without rewriting it; PDL may specify its own physical output behavior"
                ),
            }),
        })
    }

    pub(super) fn close_network_job(&mut self, job: Win16HostSpoolJob) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get_mut(&job) else {
            return Ok(ResultValue::NetworkCloseJob {
                succeeded: false,
                queue_name: None,
                native_error: Some(ERROR_INVALID_HANDLE),
            });
        };
        if !native.document_open {
            return Ok(ResultValue::NetworkCloseJob {
                succeeded: false,
                queue_name: None,
                native_error: Some(ERROR_INVALID_PARAMETER),
            });
        }
        // Prepare the guest return value before EndDocPrinter. If allocation
        // fails, the live native document and its guest token remain intact.
        let queue_name = copy_bytes(&native.queue_name, "copy WNetCloseJob queue name")?;
        // SAFETY: the registry owns the live printer handle; EndDocPrinter
        // synchronously finishes only this job's current document.
        if unsafe { EndDocPrinter(native.printer) } == 0 {
            return Ok(ResultValue::NetworkCloseJob {
                succeeded: false,
                queue_name: None,
                native_error: Some(last_error()),
            });
        }
        native.document_open = false;
        Ok(ResultValue::NetworkCloseJob {
            succeeded: true,
            queue_name: Some(queue_name),
            native_error: None,
        })
    }

    pub(super) fn abort_network_job(
        &mut self,
        job: Win16HostSpoolJob,
        codec: GuestTextCodec,
        queue: &[u8],
    ) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        match self.queue_matches_job(codec, queue, native)? {
            Ok(true) => {}
            Ok(false) => return Ok(status_error(ERROR_INVALID_PRINTER_NAME)),
            Err(error) => return Ok(status_error(error)),
        }
        if self
            .jobs
            .get(&job)
            .is_some_and(|native| native.terminal_action)
        {
            return self.retire_native_job(job);
        }
        let Some(native) = self.jobs.get(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        // AbortPrinter is the printer API operation for an open document.
        // For a job already closed by WNetCloseJob, SetJob cancels just its
        // native job ID; neither path can remove the host printer queue.
        let result = if native.document_open {
            unsafe { AbortPrinter(native.printer) }
        } else {
            unsafe {
                SetJobW(
                    native.printer,
                    native.job_id,
                    0,
                    ptr::null(),
                    JOB_CONTROL_DELETE,
                )
            }
        };
        if result == 0 {
            return Ok(status_error(last_error()));
        }
        if let Some(native) = self.jobs.get_mut(&job) {
            native.document_open = false;
            native.terminal_action = true;
        }
        self.retire_native_job(job)
    }

    pub(super) fn control_network_job(
        &mut self,
        job: Win16HostSpoolJob,
        codec: GuestTextCodec,
        queue: &[u8],
        control: Win16NetworkPrintJobControl,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        match self.queue_matches_job(codec, queue, native)? {
            Ok(true) => {}
            Ok(false) => return Ok(status_error(ERROR_INVALID_PRINTER_NAME)),
            Err(error) => return Ok(status_error(error)),
        }
        if self
            .jobs
            .get(&job)
            .is_some_and(|native| native.terminal_action)
        {
            return if control == Win16NetworkPrintJobControl::Cancel {
                self.retire_native_job(job)
            } else {
                Ok(status_error(ERROR_INVALID_HANDLE))
            };
        }
        let Some(native) = self.jobs.get(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        if native.document_open && control != Win16NetworkPrintJobControl::Cancel {
            return Ok(status_error(ERROR_INVALID_PARAMETER));
        }
        if native.document_open {
            // WNetAbortJob is the open-handle path; CancelJob is specified
            // for jobs returned by WNetCloseJob.
            return Ok(status_error(ERROR_INVALID_PARAMETER));
        }
        let command = match control {
            Win16NetworkPrintJobControl::Hold => JOB_CONTROL_PAUSE,
            Win16NetworkPrintJobControl::Release => JOB_CONTROL_RESUME,
            Win16NetworkPrintJobControl::Cancel => JOB_CONTROL_DELETE,
        };
        // SAFETY: the exact native job ID and owning printer handle come from
        // this registry entry; the operation never addresses a printer queue.
        if unsafe { SetJobW(native.printer, native.job_id, 0, ptr::null(), command) } == 0 {
            return Ok(status_error(last_error()));
        }
        if control == Win16NetworkPrintJobControl::Cancel {
            if let Some(native) = self.jobs.get_mut(&job) {
                native.terminal_action = true;
            }
            self.retire_native_job(job)
        } else {
            Ok(status_success())
        }
    }

    pub(super) fn set_network_job_copies(
        &mut self,
        job: Win16HostSpoolJob,
        codec: GuestTextCodec,
        queue: &[u8],
        copies: u16,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        match self.queue_matches_job(codec, queue, native)? {
            Ok(true) => {}
            Ok(false) => return Ok(status_error(ERROR_INVALID_PRINTER_NAME)),
            Err(error) => return Ok(status_error(error)),
        }
        let result = self.apply_job_copies(job, copies)?;
        match result {
            CopyApplyOutcome::Applied(_) => Ok(status_success()),
            failure => Ok(status_error(failure.native_error().unwrap_or(ERROR_NOT_SUPPORTED))),
        }
    }

    fn apply_job_copies(
        &self,
        job: Win16HostSpoolJob,
        copies: u16,
    ) -> Result<CopyApplyOutcome, RuntimeError> {
        if copies == 0 {
            return Ok(CopyApplyOutcome::FailedBeforeMutation {
                native_error: ERROR_INVALID_PARAMETER,
            });
        }
        let Some(native) = self.jobs.get(&job) else {
            return Ok(CopyApplyOutcome::FailedBeforeMutation {
                native_error: ERROR_INVALID_HANDLE,
            });
        };
        let (mut storage, capacity_bytes) = match query_job_info_buffer(native)? {
            Ok(buffer) => buffer,
            Err(ERROR_NOT_SUPPORTED) => {
                return Ok(CopyApplyOutcome::UnsupportedBeforeMutation {
                    native_error: ERROR_NOT_SUPPORTED,
                });
            }
            Err(native_error) => {
                return Ok(CopyApplyOutcome::FailedBeforeMutation { native_error });
            }
        };
        let data_type = job_data_type(&storage, capacity_bytes)?;
        if data_type != NetworkJobDataType::Emf {
            return Ok(CopyApplyOutcome::UnsupportedBeforeMutation {
                native_error: ERROR_NOT_SUPPORTED,
            });
        }
        let Some(devmode_pointer) = job_devmode_pointer(&mut storage, capacity_bytes)? else {
            return Ok(CopyApplyOutcome::UnsupportedBeforeMutation {
                native_error: ERROR_NOT_SUPPORTED,
            });
        };
        // SAFETY: job_devmode_pointer validates DEVMODEW and its driver-extra
        // range inside this live GetJobW allocation.
        let devmode = unsafe { &mut *devmode_pointer };
        const DC_COPIES: u16 = 18;
        // SAFETY: the printer and DEVMODE allocations remain owned for this call.
        let mut device_name = copy_wide_units(
            &native.printer_name,
            "terminate network print DEVMODE device name",
        )?;
        device_name.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "terminate network print DEVMODE device name", error,
        ))?;
        device_name.push(0);
        // SAFETY: DeviceCapabilitiesW requires a NUL-terminated device name;
        // this temporary UTF-16 string remains live for the call.
        let max_copies = unsafe { DeviceCapabilitiesW(
            device_name.as_ptr(), ptr::null(), DC_COPIES, ptr::null_mut(), devmode,
        ) };
        if max_copies <= 0 {
            return Ok(CopyApplyOutcome::UnsupportedBeforeMutation {
                native_error: ERROR_NOT_SUPPORTED,
            });
        }
        // WINNET.H's copy-count contract uses the largest supported count
        // when the requested count exceeds the printer's DC_COPIES value.
        let effective_copies = i32::from(copies).min(max_copies);
        let requested = match i16::try_from(effective_copies) {
            Ok(value) => value,
            Err(_) => return Ok(CopyApplyOutcome::FailedBeforeMutation {
                native_error: ERROR_INVALID_PARAMETER,
            }),
        };
        // SAFETY: the validated DEVMODEW is in the owned GetJobW buffer;
        // write only its printer-copy member before publishing DM_COPIES.
        unsafe {
            ptr::addr_of_mut!(devmode.Anonymous1.Anonymous1.dmCopies).write(requested);
        }
        devmode.dmFields |= DM_COPIES;
        let job_info = storage.as_mut_ptr().cast::<JOB_INFO_2W>();
        // Preserve the queue position while explicitly asking SetJobW not to
        // reposition this job; the SDK requires JOB_POSITION_UNSPECIFIED.
        unsafe { (*job_info).Position = JOB_POSITION_UNSPECIFIED };
        // SAFETY: JOB_INFO_2W and DEVMODEW remain inside the writable
        // GetJobW allocation until SetJobW returns.
        if unsafe { SetJobW(native.printer, native.job_id, 2, job_info.cast(), 0) } == 0 {
            return Ok(CopyApplyOutcome::MutationAttempted {
                native_error: super::last_error(),
            });
        }
        let (mut verified, verified_capacity) = match query_job_info_buffer(native)? {
            Ok(buffer) => buffer,
            Err(native_error) => {
                return Ok(CopyApplyOutcome::MutationAttempted { native_error });
            }
        };
        if job_data_type(&verified, verified_capacity)? != NetworkJobDataType::Emf {
            return Ok(CopyApplyOutcome::MutationAttempted {
                native_error: ERROR_NOT_SUPPORTED,
            });
        }
        let Some(verified_pointer) = job_devmode_pointer(&mut verified, verified_capacity)? else {
            return Ok(CopyApplyOutcome::MutationAttempted {
                native_error: ERROR_NOT_SUPPORTED,
            });
        };
        // SAFETY: the helper validates this pointer against the fresh GetJobW output.
        let verified = unsafe { &*verified_pointer };
        let verified_copies = if verified.dmFields & DM_COPIES != 0 {
            // SAFETY: the flag declares this printer-copy member valid; the
            // fresh GetJobW allocation was range- and alignment-checked.
            Some(unsafe { verified.Anonymous1.Anonymous1.dmCopies })
        } else {
            None
        };
        if verified_copies == Some(requested) {
            Ok(CopyApplyOutcome::Applied(u16::try_from(effective_copies).map_err(
                |error| RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "validated printer copy count exceeds WORD",
                    error,
                ),
            )?))
        } else {
            Ok(CopyApplyOutcome::MutationAttempted {
                native_error: ERROR_NOT_SUPPORTED,
            })
        }
    }

    fn queue_matches_job(
        &self,
        codec: GuestTextCodec,
        queue: &[u8],
        native: &NativeJob,
    ) -> Result<Result<bool, u32>, RuntimeError> {
        let target = codec.to_wide_z(queue)?;
        let resolved = match resolve_printer_name(&target)? {
            Ok(name) => name,
            Err(error) => return Ok(Err(error)),
        };
        let resolved = resolved.strip_suffix(&[0]).unwrap_or(&resolved);
        Ok(Ok(ordinal_equal_ignore_case(
            resolved,
            &native.printer_name,
        )))
    }

    fn retire_native_job(&mut self, job: Win16HostSpoolJob) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        // Keep the same opaque token indexed until ClosePrinter succeeds so
        // task cleanup can retry an exact, partially completed release.
        if unsafe { ClosePrinter(native.printer) } == 0 {
            return Ok(status_error(last_error()));
        }
        let Some(native) = self.jobs.remove(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        remove_network_job_index(&mut self.network_job_index, job, &native);
        Ok(status_success())
    }

    pub(super) fn release_network_job(&mut self, job: Win16HostSpoolJob) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.jobs.get_mut(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        if native.network_index_kind == super::NetworkJobIndexKind::SnapshotLease
            && native.document_open
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "borrowed WNet queue snapshot token cannot own an open document",
            ));
        }
        if native.document_open {
            // An unfinished WNet document is aborted before releasing its
            // printer. Borrowed snapshot leases are explicitly never aborted.
            if unsafe { AbortPrinter(native.printer) } == 0 {
                return Ok(status_error(last_error()));
            }
            native.document_open = false;
        }
        if unsafe { ClosePrinter(native.printer) } == 0 {
            return Ok(status_error(last_error()));
        }
        let Some(native) = self.jobs.remove(&job) else {
            return Ok(status_error(ERROR_INVALID_HANDLE));
        };
        remove_network_job_index(&mut self.network_job_index, job, &native);
        Ok(status_success())
    }


}

fn query_job_info_buffer(
    native: &NativeJob,
) -> Result<Result<(Vec<usize>, u32), u32>, RuntimeError> {
    let mut needed = 0u32;
    // SAFETY: this sizing call passes no output buffer and supplies writable
    // storage for the Windows byte count.
    unsafe {
        GetJobW(
            native.printer,
            native.job_id,
            2,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        let error = last_error();
        return Ok(Err(if error == 0 {
            ERROR_NOT_SUPPORTED
        } else {
            error
        }));
    }
    let words = usize::try_from(needed)
        .ok()
        .and_then(|bytes| bytes.checked_add(size_of::<usize>() - 1))
        .map(|bytes| bytes / size_of::<usize>())
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "GetJobW buffer size overflow")
        })?;
    let mut storage = Vec::<usize>::new();
    storage.try_reserve_exact(words).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate GetJobW output buffer",
            error,
        )
    })?;
    storage.resize(words, 0);
    let capacity_bytes = words
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "GetJobW buffer exceeds the Windows DWORD size",
            )
        })?;
    let mut actual_bytes = 0u32;
    // SAFETY: storage is aligned for JOB_INFO_2W and large enough for the
    // supplied byte count. Windows writes one job record and its owned
    // strings/DEVMODE into this temporary allocation.
    if unsafe {
        GetJobW(
            native.printer,
            native.job_id,
            2,
            storage.as_mut_ptr().cast(),
            capacity_bytes,
            &mut actual_bytes,
        )
    } == 0
    {
        return Ok(Err(last_error()));
    }
    let available = actual_bytes.min(capacity_bytes);
    if usize::try_from(available).unwrap_or(0) < size_of::<JOB_INFO_2W>() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "GetJobW returned a truncated JOB_INFO_2W record",
        ));
    }
    Ok(Ok((storage, available)))
}


fn job_devmode_pointer(
    storage: &mut [usize], used_bytes: u32,
) -> Result<Option<*mut DEVMODEW>, RuntimeError> {
    if usize::try_from(used_bytes).unwrap_or(0) < size_of::<JOB_INFO_2W>() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetJobW returned a truncated JOB_INFO_2W record"));
    }
    let info = storage.as_mut_ptr().cast::<JOB_INFO_2W>();
    // SAFETY: the output allocation is aligned and contains a complete record.
    let pointer = unsafe { (*info).pDevMode };
    if pointer.is_null() { return Ok(None); }
    let base = storage.as_ptr() as usize;
    let used = usize::try_from(used_bytes).map_err(|error| RuntimeError::with_source(
        Kind::InternalInvariant, "GetJobW byte count exceeds address space", error))?;
    let end = base.checked_add(used).ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "GetJobW output range overflow"))?;
    let address = pointer as usize;
    if address < base || address.checked_add(size_of::<DEVMODEW>())
        .is_none_or(|last| last > end) || address % align_of::<DEVMODEW>() != 0
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetJobW returned a DEVMODEW outside its output buffer"));
    }
    // SAFETY: range and alignment are checked against the owned buffer.
    let devmode = unsafe { &mut *pointer };
    let declared = usize::from(devmode.dmSize)
        .checked_add(usize::from(devmode.dmDriverExtra))
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "GetJobW DEVMODEW size overflow"))?;
    if usize::from(devmode.dmSize) < size_of::<DEVMODEW>()
        || address.checked_add(declared).is_none_or(|last| last > end)
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetJobW returned an incomplete DEVMODEW"));
    }
    Ok(Some(pointer))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkJobDataType {
    Raw,
    Emf,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyApplyOutcome {
    Applied(u16),
    UnsupportedBeforeMutation {
        native_error: u32,
    },
    FailedBeforeMutation {
        native_error: u32,
    },
    MutationAttempted {
        native_error: u32,
    },
}

impl CopyApplyOutcome {
    fn native_error(self) -> Option<u32> {
        match self {
            Self::Applied(_) => None,
            Self::UnsupportedBeforeMutation { native_error }
            | Self::FailedBeforeMutation { native_error }
            | Self::MutationAttempted { native_error } => Some(native_error),
        }
    }
}

fn job_data_type(
    storage: &[usize],
    used_bytes: u32,
) -> Result<NetworkJobDataType, RuntimeError> {
    if usize::try_from(used_bytes).unwrap_or(0) < size_of::<JOB_INFO_2W>() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetJobW returned a truncated JOB_INFO_2W record"));
    }
    // SAFETY: the aligned storage contains the complete JOB_INFO_2W header.
    let pointer = unsafe { (*storage.as_ptr().cast::<JOB_INFO_2W>()).pDatatype };
    if pointer.is_null() {
        return Ok(NetworkJobDataType::Unknown);
    }
    let base = storage.as_ptr() as usize;
    let used = usize::try_from(used_bytes).map_err(|error| RuntimeError::with_source(
        Kind::InternalInvariant, "GetJobW byte count exceeds address space", error))?;
    let end = base.checked_add(used).ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "GetJobW output range overflow"))?;
    let address = pointer as usize;
    if address < base || address.checked_add(size_of::<u16>()).is_none_or(|last| last > end)
        || address % align_of::<u16>() != 0
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetJobW returned a data-type pointer outside its output buffer"));
    }
    let maximum_units = (end - address) / size_of::<u16>();
    // SAFETY: the pointer and complete containing-buffer range are checked;
    // the scan is capped to the bytes GetJobW actually returned.
    let units = unsafe { std::slice::from_raw_parts(pointer, maximum_units) };
    let Some(length) = units.iter().position(|unit| *unit == 0) else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetJobW returned an unterminated data-type string"));
    };
    let data_type = &units[..length];
    const WINDOWS_EMF_1_008: [u16; 12] = [
        b'N' as u16, b'T' as u16, b' ' as u16, b'E' as u16, b'M' as u16,
        b'F' as u16, b' ' as u16, b'1' as u16, b'.' as u16, b'0' as u16,
        b'0' as u16, b'8' as u16,
    ];
    const RAW: [u16; 3] = [b'R' as u16, b'A' as u16, b'W' as u16];
    const RAW_FF_AUTO: [u16; 13] = [
        b'R' as u16, b'A' as u16, b'W' as u16, b' ' as u16, b'[' as u16,
        b'F' as u16, b'F' as u16, b' ' as u16, b'A' as u16, b'u' as u16,
        b't' as u16, b'o' as u16, b']' as u16,
    ];
    const RAW_FF_APPENDED: [u16; 17] = [
        b'R' as u16, b'A' as u16, b'W' as u16, b' ' as u16, b'[' as u16,
        b'F' as u16, b'F' as u16, b' ' as u16, b'A' as u16, b'p' as u16,
        b'p' as u16, b'e' as u16, b'n' as u16, b'd' as u16, b'e' as u16,
        b'd' as u16, b']' as u16,
    ];
    if ordinal_equal_ignore_case(data_type, &WINDOWS_EMF_1_008) {
        Ok(NetworkJobDataType::Emf)
    } else if ordinal_equal_ignore_case(data_type, &RAW)
        || ordinal_equal_ignore_case(data_type, &RAW_FF_AUTO)
        || ordinal_equal_ignore_case(data_type, &RAW_FF_APPENDED)
    {
        Ok(NetworkJobDataType::Raw)
    } else {
        Ok(NetworkJobDataType::Unknown)
    }
}
