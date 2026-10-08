//! Owned conversion of native Windows printer/job snapshots to WNet DTOs.

use std::mem::{align_of, size_of};
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostNetworkPrintJobSnapshot,
    Win16HostNetworkPrintQueueSnapshot, Win16HostSpoolJob, Win16HostTaskOwner,
};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE,
    ERROR_NOT_SUPPORTED, FILETIME, GetLastError,
};
use windows_sys::Win32::Graphics::Gdi::{DEVMODEW, DM_COPIES};
use windows_sys::Win32::Graphics::Printing::{
    EnumJobsW, GetPrinterW, JOB_INFO_2W, JOB_STATUS_COMPLETE, JOB_STATUS_ERROR,
    JOB_STATUS_OFFLINE, JOB_STATUS_PAPEROUT, JOB_STATUS_PAUSED, JOB_STATUS_PRINTED,
    JOB_STATUS_PRINTING, JOB_STATUS_SPOOLING, JOB_STATUS_USER_INTERVENTION, OpenPrinterW,
    PRINTER_HANDLE, PRINTER_INFO_2W,
    PRINTER_STATUS_ERROR, PRINTER_STATUS_NOT_AVAILABLE, PRINTER_STATUS_OFFLINE,
    PRINTER_STATUS_PAPER_JAM, PRINTER_STATUS_PAPER_OUT, PRINTER_STATUS_PAPER_PROBLEM,
    PRINTER_STATUS_PAUSED, PRINTER_STATUS_SERVER_OFFLINE, PRINTER_STATUS_SERVER_UNKNOWN,
    PRINTER_STATUS_USER_INTERVENTION,
};
use windows_sys::Win32::System::Time::SystemTimeToFileTime;

use runtime::network_print_abi::{
    WNPRJ_DS_COMPLETE, WNPRJ_DS_DESTNOPAPER, WNPRJ_DS_DESTOFFLINE,
    WNPRJ_DS_DESTPAUSED, WNPRJ_DS_ERROR, WNPRJ_DS_INTERV, WNPRJ_QS_PAUSED,
    WNPRJ_QS_PRINTING, WNPRJ_QS_QUEUED, WNPRJ_QS_SPOOLING, WNPRQ_ACTIVE,
    WNPRQ_ERROR, WNPRQ_PAUSE, WNPRQ_PROBLEM,
};
use super::{
    GuestTextCodec, JOB_INFO_LEVEL, MAX_BUFFER_ATTEMPTS, PRINTER_INFO_LEVEL,
    PrinterHandleGuard, Win16SpoolJobs,
};
use super::super::win16_spool_jobs::resolve_printer_name;

struct PrinterInfo {
    name: Vec<u16>,
    comment: Option<Vec<u16>>,
    status: u32,
}

struct JobInfo {
    id: u32,
    username: Option<Vec<u16>>,
    parameters: Option<Vec<u16>>,
    /// WFW's JOBSTRUCT comment is not represented by JOB_INFO_2W.
    comment: Option<Vec<u16>>,
    position: u16,
    status: u32,
    submitted: u32,
    size: u32,
    copies: u16,
}

pub(super) fn open_printer(
    codec: GuestTextCodec,
    queue: &[u8],
) -> Result<Result<(PrinterHandleGuard, Vec<u16>), u32>, RuntimeError> {
    let queue_name = codec.to_wide_z(queue)?;
    let printer_name = match resolve_printer_name(&queue_name)? {
        Ok(name) => name,
        Err(error) => return Ok(Err(error)),
    };
    let stable_name = copy_wide_units(
        printer_name.strip_suffix(&[0]).unwrap_or(&printer_name),
        "copy resolved printer name",
    )?;
    let mut printer = PRINTER_HANDLE::default();
    // SAFETY: the name is NUL-terminated, the output record is writable, and
    // a null defaults pointer requests the queue's configured access policy.
    if unsafe { OpenPrinterW(printer_name.as_ptr().cast_mut(), &mut printer, ptr::null()) } == 0 {
        return Ok(Err(last_error_or_not_supported()));
    }
    if printer.Value.is_null() {
        return Ok(Err(ERROR_INVALID_HANDLE));
    }
    Ok(Ok((PrinterHandleGuard::new(printer), stable_name)))
}

struct GuestJobSnapshotFields {
    id: u32,
    username: Option<Vec<u8>>,
    parameters: Option<Vec<u8>>,
    position: u16,
    status: u16,
    submitted: u32,
    size: u32,
    copies: u16,
    comment: Option<Vec<u8>>,
}

pub(super) struct SnapshotBuildFailure {
    pub(super) error: RuntimeError,
    pub(super) cleanup_jobs: Vec<Win16HostSpoolJob>,
}

impl From<RuntimeError> for SnapshotBuildFailure {
    fn from(error: RuntimeError) -> Self {
        Self { error, cleanup_jobs: Vec::new() }
    }
}

pub(super) fn build_snapshot(
    owner: Win16HostTaskOwner,
    codec: GuestTextCodec,
    printer: PRINTER_HANDLE,
    requested_name: &[u16],
    spool_jobs: &mut Win16SpoolJobs,
) -> Result<Result<Win16HostNetworkPrintQueueSnapshot, u32>, SnapshotBuildFailure> {
    let printer_info = match query_printer_info(printer)? {
        Ok(info) => info,
        Err(error) => return Ok(Err(error)),
    };
    let jobs = match query_jobs(printer)? {
        Ok(jobs) => jobs,
        Err(error) => return Ok(Err(error)),
    };

    let printer_name = if printer_info.name.is_empty() {
        copy_wide_units(requested_name, "copy resolved printer name")?
    } else {
        printer_info.name
    };
    let guest_name = codec.from_wide(&printer_name)?.bytes;
    let guest_comment = printer_info
        .comment
        .as_deref()
        .map(|text| codec.from_wide(text).map(|encoding| encoding.bytes))
        .transpose()?;

    // Finish every fallible text conversion before opening per-job printer
    // handles. A conversion failure therefore cannot orphan partial snapshot
    // leases in the host spool registry.
    let mut fields = Vec::new();
    fields.try_reserve_exact(jobs.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "allocate converted Win16 network print job records",
        error,
    ))?;
    for job in jobs {
        fields.push(GuestJobSnapshotFields {
            id: job.id,
            username: job.username.as_deref()
                .map(|text| codec.from_wide(text).map(|encoding| encoding.bytes))
                .transpose()?,
            parameters: job.parameters.as_deref()
                .map(|text| codec.from_wide(text).map(|encoding| encoding.bytes))
                .transpose()?,
            position: job.position,
            status: map_job_status(job.status, printer_info.status),
            submitted: job.submitted,
            size: job.size,
            copies: job.copies,
            // JOB_INFO_2W exposes no verified field for WINNET.H's job
            // comment; keep it unknown rather than substituting another field.
            comment: job.comment.as_deref()
                .map(|text| codec.from_wide(text).map(|encoding| encoding.bytes))
                .transpose()?,
        });
    }

    let mut guest_jobs = Vec::new();
    guest_jobs.try_reserve_exact(fields.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "allocate Win16 network print job snapshot",
        error,
    ))?;
    let mut registered_new_leases = Vec::new();
    registered_new_leases.try_reserve_exact(fields.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "reserve partial queue snapshot rollback list",
        error,
    ))?;
    for fields in fields {
        let (host_job, created) = match spool_jobs.register_existing_job(owner, &printer_name, fields.id) {
            Ok(value) => value,
            Err(error) => return Err(SnapshotBuildFailure { error, cleanup_jobs: registered_new_leases }),
        };
        if created { registered_new_leases.push(host_job); }
        guest_jobs.push(Win16HostNetworkPrintJobSnapshot {
            job: host_job,
            username: fields.username,
            parameters: fields.parameters,
            position: fields.position,
            status: fields.status,
            submitted: fields.submitted,
            size: fields.size,
            copies: fields.copies,
            comment: fields.comment,
        });
    }

    Ok(Ok(Win16HostNetworkPrintQueueSnapshot {
        name: guest_name,
        comment: guest_comment,
        status: map_queue_status(printer_info.status),
        // WFW defines zero as "not available". Windows does not expose a
        // physical-printer count for every queue provider.
        printer_count: 0,
        jobs: guest_jobs,
    }))
}

fn query_printer_info(printer: PRINTER_HANDLE) -> Result<Result<PrinterInfo, u32>, RuntimeError> {
    let mut needed = 0u32;
    // SAFETY: the null buffer is the documented sizing query; `needed` is a
    // writable byte-count output.
    unsafe { GetPrinterW(printer, PRINTER_INFO_LEVEL, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Ok(Err(last_error_or_not_supported()));
    }

    let mut required = needed;
    let mut last_native_error = ERROR_INSUFFICIENT_BUFFER;
    for _ in 0..MAX_BUFFER_ATTEMPTS {
        let mut storage = aligned_buffer(required, "allocate GetPrinterW buffer")?;
        let capacity = byte_capacity(&storage)?;
        let mut actual = 0u32;
        // SAFETY: storage is word-aligned and writable for the supplied
        // capacity; Windows owns only records and pointers within this buffer.
        if unsafe {
            GetPrinterW(
                printer,
                PRINTER_INFO_LEVEL,
                storage.as_mut_ptr().cast(),
                capacity,
                &mut actual,
            )
        } != 0
        {
            let used = checked_used_bytes(actual, capacity, size_of::<PRINTER_INFO_2W>())?;
            // SAFETY: `used` includes one complete level-2 record and storage
            // is aligned for the native SDK layout.
            let record = unsafe { *storage.as_ptr().cast::<PRINTER_INFO_2W>() };
            let name = copy_wide_string(record.pPrinterName, &storage, used)?.ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "GetPrinterW omitted the printer name",
                )
            })?;
            let comment = copy_wide_string(record.pComment, &storage, used)?;
            return Ok(Ok(PrinterInfo {
                name,
                comment,
                status: record.Status,
            }));
        }

        last_native_error = last_error_or_not_supported();
        if last_native_error != ERROR_INSUFFICIENT_BUFFER {
            return Ok(Err(last_native_error));
        }
        required = grow_required(required, actual)?;
    }
    Ok(Err(last_native_error))
}

fn query_jobs(printer: PRINTER_HANDLE) -> Result<Result<Vec<JobInfo>, u32>, RuntimeError> {
    let mut needed = 0u32;
    let mut returned = 0u32;
    // SAFETY: this null-buffer call requests only the byte count and returned
    // record count; both outputs are writable.
    let sized = unsafe {
        EnumJobsW(
            printer,
            0,
            u32::MAX,
            JOB_INFO_LEVEL,
            ptr::null_mut(),
            0,
            &mut needed,
            &mut returned,
        )
    };
    if needed == 0 {
        if sized != 0 && returned == 0 {
            return Ok(Ok(Vec::new()));
        }
        return Ok(Err(last_error_or_not_supported()));
    }

    let mut required = needed;
    let mut last_native_error = ERROR_INSUFFICIENT_BUFFER;
    for _ in 0..MAX_BUFFER_ATTEMPTS {
        let mut storage = aligned_buffer(required, "allocate EnumJobsW buffer")?;
        let capacity = byte_capacity(&storage)?;
        let mut actual = 0u32;
        let mut returned = 0u32;
        // SAFETY: storage is aligned and writable for the capacity; the
        // printer handle and output counters are owned by this call.
        if unsafe {
            EnumJobsW(
                printer,
                0,
                u32::MAX,
                JOB_INFO_LEVEL,
                storage.as_mut_ptr().cast(),
                capacity,
                &mut actual,
                &mut returned,
            )
        } != 0
        {
            let used = checked_used_bytes(actual, capacity, 0)?;
            let count = usize::try_from(returned).map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "invalid EnumJobsW record count",
                    error,
                )
            })?;
            let records_bytes = count.checked_mul(size_of::<JOB_INFO_2W>()).ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "EnumJobsW record range overflow")
            })?;
            if records_bytes > used {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "EnumJobsW returned records outside its output buffer",
                ));
            }
            // SAFETY: the complete record span was checked against `used` and
            // the `Vec<usize>` allocation provides native structure alignment.
            let records = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<JOB_INFO_2W>(), count)
            };
            let mut jobs = Vec::new();
            jobs.try_reserve_exact(count).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate native printer job records",
                    error,
                )
            })?;
            for record in records {
                let position = u16::try_from(record.Position).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "Win16 network print queue position exceeds WORD",
                        error,
                    )
                })?;
                jobs.push(JobInfo {
                    id: record.JobId,
                    username: copy_wide_string(record.pUserName, &storage, used)?,
                    parameters: copy_wide_string(record.pParameters, &storage, used)?,
                    // JOB_INFO_2W exposes no job comment. Do not substitute
                    // its document title or printer-wide comment for this field.
                    comment: None,
                    position,
                    status: record.Status,
                    submitted: submitted_epoch_seconds(record.Submitted),
                    size: record.Size,
                    copies: copy_count(record.pDevMode, &storage, used)?,
                });
            }
            return Ok(Ok(jobs));
        }

        last_native_error = last_error_or_not_supported();
        if last_native_error != ERROR_INSUFFICIENT_BUFFER {
            return Ok(Err(last_native_error));
        }
        required = grow_required(required, actual)?;
    }
    Ok(Err(last_native_error))
}

fn copy_count(
    pointer: *mut DEVMODEW,
    storage: &[usize],
    used_bytes: usize,
) -> Result<u16, RuntimeError> {
    if pointer.is_null() {
        return Ok(0);
    }
    let address = pointer as usize;
    let (base, end) = checked_buffer_range(storage, used_bytes)?;
    if address < base
        || address % align_of::<DEVMODEW>() != 0
        || address
            .checked_add(size_of::<DEVMODEW>())
            .is_none_or(|after| after > end)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "EnumJobsW returned a DEVMODEW outside its output buffer",
        ));
    }
    // SAFETY: the full aligned DEVMODEW prefix is within the initialized
    // EnumJobsW allocation; the copied record is no longer retained.
    let mode = unsafe { &*pointer };
    let declared_size = usize::from(mode.dmSize)
        .checked_add(usize::from(mode.dmDriverExtra))
        .ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "EnumJobsW DEVMODEW size overflow")
        })?;
    if usize::from(mode.dmSize) < size_of::<DEVMODEW>()
        || address
            .checked_add(declared_size)
            .is_none_or(|after| after > end)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "EnumJobsW returned an incomplete DEVMODEW",
        ));
    }
    if mode.dmFields & DM_COPIES == 0 {
        return Ok(0);
    }
    // SAFETY: DEVMODEW's anonymous union shares the documented printer-mode
    // fields; DM_COPIES selects the dmCopies member for this record.
    let copies = unsafe { mode.Anonymous1.Anonymous1.dmCopies };
    Ok(u16::try_from(copies).unwrap_or(0))
}

fn submitted_epoch_seconds(submitted: windows_sys::Win32::Foundation::SYSTEMTIME) -> u32 {
    const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
    const UNIX_EPOCH_FILETIME_TICKS: u64 = 116_444_736_000_000_000;

    let mut file_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // JOB_INFO_2W documents Submitted as UTC. SystemTimeToFileTime validates
    // the UTC fields and produces 100-nanosecond ticks since 1601-01-01.
    // SAFETY: both structures use the exact Windows ABI layout and do not
    // overlap; `submitted` is copied from the bounded EnumJobsW buffer.
    if unsafe { SystemTimeToFileTime(&submitted, &mut file_time) } == 0 {
        return 0;
    }
    let ticks = (u64::from(file_time.dwHighDateTime) << 32) | u64::from(file_time.dwLowDateTime);
    let Some(unix_ticks) = ticks.checked_sub(UNIX_EPOCH_FILETIME_TICKS) else {
        return 0;
    };
    u32::try_from(unix_ticks / FILETIME_TICKS_PER_SECOND).unwrap_or(0)
}

fn copy_wide_units(source: &[u16], operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

fn copy_wide_string(
    pointer: *const u16,
    storage: &[usize],
    used_bytes: usize,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(text) = wide_string_in_buffer(pointer, storage, used_bytes)? else {
        return Ok(None);
    };
    let mut copy = Vec::new();
    copy.try_reserve_exact(text.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy Windows printer text", error)
    })?;
    copy.extend_from_slice(text);
    Ok(Some(copy))
}

fn wide_string_in_buffer<'a>(
    pointer: *const u16,
    storage: &'a [usize],
    used_bytes: usize,
) -> Result<Option<&'a [u16]>, RuntimeError> {
    if pointer.is_null() {
        return Ok(None);
    }
    let (base, end) = checked_buffer_range(storage, used_bytes)?;
    let address = pointer as usize;
    if address < base || address >= end || address % align_of::<u16>() != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows printer API returned a string outside its output buffer",
        ));
    }
    let capacity = (end - address) / size_of::<u16>();
    // SAFETY: the complete candidate range is bounded by the initialized
    // printer output allocation; the NUL search below stops within it.
    let units = unsafe { std::slice::from_raw_parts(pointer, capacity) };
    let Some(length) = units.iter().position(|unit| *unit == 0) else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows printer API returned an unterminated string",
        ));
    };
    Ok(Some(&units[..length]))
}

fn checked_buffer_range(
    storage: &[usize],
    used_bytes: usize,
) -> Result<(usize, usize), RuntimeError> {
    let base = storage.as_ptr() as usize;
    let capacity = storage
        .len()
        .checked_mul(size_of::<usize>())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Windows printer output buffer size overflow",
            )
        })?;
    if used_bytes > capacity {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows printer byte count exceeds its output allocation",
        ));
    }
    let end = base.checked_add(used_bytes).ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "Windows printer output buffer range overflow",
        )
    })?;
    Ok((base, end))
}

fn aligned_buffer(bytes: u32, operation: &'static str) -> Result<Vec<usize>, RuntimeError> {
    let bytes = usize::try_from(bytes)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    let words = bytes
        .checked_add(size_of::<usize>() - 1)
        .map(|rounded| rounded / size_of::<usize>())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Windows printer buffer size overflow",
            )
        })?;
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(words)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    storage.resize(words, 0);
    Ok(storage)
}

fn byte_capacity(storage: &[usize]) -> Result<u32, RuntimeError> {
    storage
        .len()
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Windows printer buffer exceeds the DWORD ABI",
            )
        })
}

fn checked_used_bytes(actual: u32, capacity: u32, minimum: usize) -> Result<usize, RuntimeError> {
    if actual > capacity {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows printer API byte count exceeds its output allocation",
        ));
    }
    let used = usize::try_from(actual).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "invalid Windows printer byte count",
            error,
        )
    })?;
    if used < minimum {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows printer API returned a truncated record",
        ));
    }
    Ok(used)
}

fn grow_required(current: u32, reported: u32) -> Result<u32, RuntimeError> {
    let next = if reported > current {
        reported
    } else {
        current.checked_mul(2).unwrap_or(u32::MAX)
    };
    if next <= current {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Windows printer output exceeded the DWORD buffer range",
        ));
    }
    Ok(next)
}

fn map_queue_status(status: u32) -> u16 {
    if status & PRINTER_STATUS_PAUSED != 0 {
        WNPRQ_PAUSE
    } else if status
        & (PRINTER_STATUS_ERROR | PRINTER_STATUS_SERVER_UNKNOWN | PRINTER_STATUS_NOT_AVAILABLE)
        != 0
    {
        WNPRQ_ERROR
    } else if status
        & (PRINTER_STATUS_OFFLINE
            | PRINTER_STATUS_SERVER_OFFLINE
            | PRINTER_STATUS_PAPER_JAM
            | PRINTER_STATUS_PAPER_OUT
            | PRINTER_STATUS_PAPER_PROBLEM
            | PRINTER_STATUS_USER_INTERVENTION)
        != 0
    {
        WNPRQ_PROBLEM
    } else {
        WNPRQ_ACTIVE
    }
}

fn map_job_status(job_status: u32, printer_status: u32) -> u16 {
    let queue_status = if job_status & JOB_STATUS_PRINTING != 0 {
        WNPRJ_QS_PRINTING
    } else if job_status & JOB_STATUS_SPOOLING != 0 {
        WNPRJ_QS_SPOOLING
    } else if job_status & JOB_STATUS_PAUSED != 0 {
        WNPRJ_QS_PAUSED
    } else {
        WNPRJ_QS_QUEUED
    };

    let mut status = queue_status;
    if job_status & (JOB_STATUS_COMPLETE | JOB_STATUS_PRINTED) != 0 {
        status |= WNPRJ_DS_COMPLETE;
    }
    if job_status & JOB_STATUS_USER_INTERVENTION != 0
        || printer_status & PRINTER_STATUS_USER_INTERVENTION != 0
    {
        status |= WNPRJ_DS_INTERV;
    }
    if job_status & JOB_STATUS_ERROR != 0
        || printer_status
            & (PRINTER_STATUS_ERROR | PRINTER_STATUS_PAPER_JAM | PRINTER_STATUS_PAPER_PROBLEM)
            != 0
    {
        status |= WNPRJ_DS_ERROR;
    }
    if job_status & JOB_STATUS_OFFLINE != 0
        || printer_status
            & (PRINTER_STATUS_OFFLINE
                | PRINTER_STATUS_SERVER_OFFLINE
                | PRINTER_STATUS_SERVER_UNKNOWN)
            != 0
    {
        status |= WNPRJ_DS_DESTOFFLINE;
    }
    if printer_status & PRINTER_STATUS_PAUSED != 0 {
        status |= WNPRJ_DS_DESTPAUSED;
    }
    if job_status & JOB_STATUS_PAPEROUT != 0 || printer_status & PRINTER_STATUS_PAPER_OUT != 0 {
        status |= WNPRJ_DS_DESTNOPAPER;
    }
    status
}

pub(super) fn last_error_or_not_supported() -> u32 {
    // SAFETY: GetLastError reads the calling thread's Windows status value.
    let error = unsafe { GetLastError() };
    if error == 0 {
        ERROR_NOT_SUPPORTED
    } else {
        error
    }
}
