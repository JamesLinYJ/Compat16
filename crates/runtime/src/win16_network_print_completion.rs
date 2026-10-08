//! WFW return-code projection for native spooler outcomes.

use crate::win16_host_spool::{
    Win16HostNetworkQueueResult, Win16HostSpoolDiagnostic, Win16HostSpoolJob, Win16HostSpoolResult,
};
use crate::{DiagnosticKind as Kind, RuntimeError};
use win16_abi::network_print_abi::{
    WN_ACCESS_DENIED, WN_ALREADY_CONNECTED, WN_BAD_LOCALNAME, WN_BAD_NETNAME,
    WN_BAD_PASSWORD, WN_BAD_VALUE, WN_CANCEL, WN_CANT_SET_COPIES, WN_DEVICE_ERROR,
    WN_FUNCTION_BUSY, WN_MORE_DATA, WN_NET_ERROR, WN_NOT_CONNECTED, WN_NOT_SUPPORTED,
    WN_OUT_OF_MEMORY, WN_SUCCESS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16NetworkPrintOpenCompletion {
    pub(crate) status: u16,
    /// A DDK copy warning can retain a live job and HFILE while the WNet RAW
    /// byte stream is passed through once unchanged. Its PDL may specify its
    /// own physical output behavior; this is not a physical-copy guarantee.
    pub(crate) job: Option<Win16HostSpoolJob>,
    pub(crate) queue_name: Option<Vec<u8>>,
    pub(crate) copies_diagnostic: Option<Win16HostSpoolDiagnostic>,
}

pub(crate) fn open_job(
    result: Win16HostSpoolResult,
) -> Result<Win16NetworkPrintOpenCompletion, RuntimeError> {
    let Win16HostSpoolResult::NetworkOpenJob {
        job,
        queue_name,
        copies_applied,
        native_error,
        copies_error: _,
        copies_diagnostic,
    } = result
    else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "WNetOpenJob received a different host spool result",
        ));
    };
    if let Some(error) = native_error {
        return Ok(Win16NetworkPrintOpenCompletion {
            status: map_native_error(error),
            job,
            queue_name,
            copies_diagnostic,
        });
    }
    let Some(job) = job else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "successful native WNetOpenJob omitted its host job token",
        ));
    };
    if !copies_applied {
        // The host retains a live job for the WNet copy warning path; the
        // original byte stream remains writable and is not rewritten.
        return Ok(Win16NetworkPrintOpenCompletion {
            status: WN_CANT_SET_COPIES,
            job: Some(job),
            queue_name,
            copies_diagnostic,
        });
    }
    Ok(Win16NetworkPrintOpenCompletion {
        status: WN_SUCCESS,
        job: Some(job),
        queue_name,
        copies_diagnostic,
    })
}

/// WFW reports native unsupported SetJobCopies control as WN_NOT_SUPPORTED.
/// WN_CANT_SET_COPIES is used by WNetOpenJob when the requested count cannot
/// be enforced on its RAW byte stream, which is passed through unchanged once.
pub(crate) fn set_job_copies_status(result: Win16HostSpoolResult) -> Result<u16, RuntimeError> {
    match result {
        Win16HostSpoolResult::Status { succeeded: true, .. } => Ok(WN_SUCCESS),
        Win16HostSpoolResult::Status { succeeded: false, native_error: Some(50) } => {
            Ok(WN_NOT_SUPPORTED)
        }
        Win16HostSpoolResult::Status { succeeded: false, native_error } => {
            Ok(native_error.map_or(WN_NET_ERROR, map_native_error))
        }
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "WNetSetJobCopies received a different host spool result")),
    }
}

pub(crate) fn spool_status(result: Win16HostSpoolResult) -> Result<u16, RuntimeError> {
    match result {
        Win16HostSpoolResult::NetworkCloseJob {
            succeeded,
            native_error,
            ..
        }
        | Win16HostSpoolResult::Status {
            succeeded,
            native_error,
        } => Ok(if succeeded {
            WN_SUCCESS
        } else {
            native_error.map_or(WN_NET_ERROR, map_native_error)
        }),
        Win16HostSpoolResult::Write {
            bytes_written: _,
            native_error: _,
        } => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "WNetWriteJob completion has no verified LPINT contract",
        )),
        Win16HostSpoolResult::OpenJob { native_error, job } => Ok(if job.is_some() {
            WN_SUCCESS
        } else {
            native_error.map_or(WN_NET_ERROR, map_native_error)
        }),
        Win16HostSpoolResult::NetworkOpenJob { .. } => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "generic spool completion received a WNetOpenJob result",
        )),
    }
}

pub(crate) fn queue_status(result: Win16HostNetworkQueueResult) -> Result<u16, RuntimeError> {
    match result {
        Win16HostNetworkQueueResult::Watch {
            watch,
            notification_source_id: _,
            native_error,
        } => Ok(if watch.is_some() {
            WN_SUCCESS
        } else {
            native_error.map_or(WN_NET_ERROR, map_native_error)
        }),
        Win16HostNetworkQueueResult::Status {
            succeeded,
            native_error,
        } => Ok(if succeeded {
            WN_SUCCESS
        } else {
            native_error.map_or(WN_NET_ERROR, map_native_error)
        }),
        Win16HostNetworkQueueResult::Snapshot {
            snapshot,
            native_error,
            ..
        } => Ok(if snapshot.is_some() {
            WN_SUCCESS
        } else {
            native_error.map_or(WN_NET_ERROR, map_native_error)
        }),
        Win16HostNetworkQueueResult::Changes { .. } => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "queue-change poll result cannot complete a WNet guest call",
        )),
    }
}

/// Matches the already-used XP NTVDM MapWin32ErrorToWN16 mapping. API-specific
/// failures such as invalid guest HFILEs are projected before this function.
pub(crate) fn map_native_error(error: u32) -> u16 {
    match error {
        0 => WN_SUCCESS,
        50 => WN_NOT_SUPPORTED,
        1223 => WN_CANCEL,
        59 | 1208 => WN_NET_ERROR,
        234 => WN_MORE_DATA,
        87 => WN_BAD_VALUE,
        86 => WN_BAD_PASSWORD,
        5 => WN_ACCESS_DENIED,
        54 => WN_FUNCTION_BUSY,
        8 => WN_OUT_OF_MEMORY,
        67 | 53 => WN_BAD_NETNAME,
        15 => WN_BAD_LOCALNAME,
        85 => WN_ALREADY_CONNECTED,
        31 => WN_DEVICE_ERROR,
        2250 => WN_NOT_CONNECTED,
        other => other as u16,
    }
}
