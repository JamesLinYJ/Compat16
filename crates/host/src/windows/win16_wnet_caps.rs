//! Legacy network capability queries through the installed Windows provider.

use super::WindowsHost;
use runtime::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::WNet::{
    NETINFOSTRUCT, WNetGetNetworkInformationW, WNetGetProviderNameW,
};

// Microsoft WINNET.H's Win16 capability indices and version, not Win32's
// provider flags. Win16's network type is in bits 8..15; modern MPR uses
// bits 16..31. The legacy default provider maps to Windows' SMB provider.
const WNNC_SPEC_VERSION: u16 = 1;
const WNNC_NET_TYPE: u16 = 2;
const WNNC_DRIVER_VERSION: u16 = 3;
const WNNC_USER: u16 = 4;
const WNNC_CONNECTION: u16 = 6;
const WNNC_PRINTING: u16 = 7;
const WNNC_ERROR: u16 = 10;
// Win16 WINNET.H capability masks describe implemented guest entry points.
const WNNC_USR_GET_USER: u16 = 0x0001;
const WNNC_CON_ADD_CONNECTION: u16 = 0x0001;
const WNNC_CON_CANCEL_CONNECTION: u16 = 0x0002;
const WNNC_CON_GET_CONNECTIONS: u16 = 0x0004;
const WNNC_ERR_GET_ERROR: u16 = 0x0001;
const WNNC_ERR_GET_ERROR_TEXT: u16 = 0x0002;
// Local WINNET.H defines ChangeMsg independently from WriteJob: WNetWatchQueue
// posts it through the runtime's asynchronous USER notification path. Keep
// WriteJob (0x8000) absent until its LPINT contract is verified.
const WNNC_PRT_OPEN_JOB: u16 = 0x0002;
const WNNC_PRT_CLOSE_JOB: u16 = 0x0004;
const WNNC_PRT_HOLD_JOB: u16 = 0x0010;
const WNNC_PRT_RELEASE_JOB: u16 = 0x0020;
const WNNC_PRT_CANCEL_JOB: u16 = 0x0040;
const WNNC_PRT_SET_JOB_COPIES: u16 = 0x0080;
const WNNC_PRT_WATCH_QUEUE: u16 = 0x0100;
const WNNC_PRT_UNWATCH_QUEUE: u16 = 0x0200;
const WNNC_PRT_LOCK_QUEUE_DATA: u16 = 0x0400;
const WNNC_PRT_UNLOCK_QUEUE_DATA: u16 = 0x0800;
const WNNC_PRT_CHANGE_MSG: u16 = 0x1000;
const WNNC_PRT_ABORT_JOB: u16 = 0x2000;
const WNNC_IMPLEMENTED_PRINTING: u16 = WNNC_PRT_OPEN_JOB
    | WNNC_PRT_CLOSE_JOB
    | WNNC_PRT_HOLD_JOB
    | WNNC_PRT_RELEASE_JOB
    | WNNC_PRT_CANCEL_JOB
    | WNNC_PRT_SET_JOB_COPIES
    | WNNC_PRT_WATCH_QUEUE
    | WNNC_PRT_UNWATCH_QUEUE
    | WNNC_PRT_LOCK_QUEUE_DATA
    | WNNC_PRT_UNLOCK_QUEUE_DATA
    | WNNC_PRT_CHANGE_MSG
    | WNNC_PRT_ABORT_JOB;
// Windows 3.1 DDK WNetGetCaps specifies 3.10 as 0x030A. This describes
// the guest facade's contract, not a truncated modern provider version.
const WIN16_NETWORK_SPEC_VERSION: u16 = 0x030a;
const WNNC_NET_LANMAN32: u32 = 0x0002_0000;
const NETWORK_DRIVER_INSTANCE: u16 = 0xffff;

pub(super) fn get_caps(host: &mut WindowsHost, index: u16) -> Result<u16, RuntimeError> {
    match index {
        WNNC_SPEC_VERSION => Ok(if provider_type(host)? == 0 {
            0
        } else {
            WIN16_NETWORK_SPEC_VERSION
        }),
        WNNC_NET_TYPE => provider_type(host),
        WNNC_USER | WNNC_CONNECTION | WNNC_ERROR => {
            if provider_type(host)? == 0 {
                return Ok(0);
            }
            Ok(match index {
                WNNC_USER => WNNC_USR_GET_USER,
                WNNC_CONNECTION => {
                    WNNC_CON_ADD_CONNECTION | WNNC_CON_CANCEL_CONNECTION | WNNC_CON_GET_CONNECTIONS
                }
                WNNC_ERROR => WNNC_ERR_GET_ERROR | WNNC_ERR_GET_ERROR_TEXT,
                _ => unreachable!(),
            })
        }
        // Native provider versions are opaque DWORDs; truncating one would
        // invent a Win16 driver version. There is also no guest driver module
        // corresponding to MPR's native handle. These queries report absence.
        WNNC_DRIVER_VERSION | NETWORK_DRIVER_INSTANCE => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "legacy network driver version or module identity is unavailable",
            ));
            Ok(0)
        }
        // Printing flags above reflect only guest calls actually routed by
        // this runtime. Other native provider support cannot claim dialogs
        // or operations whose Win16 bridges are still absent.
        WNNC_PRINTING => {
            if provider_type(host)? == 0 {
                return Ok(0);
            }
            Ok(WNNC_IMPLEMENTED_PRINTING)
        }
        8 | 9 => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "legacy network operation capabilities are not yet bridged",
            ));
            Ok(0)
        }
        _ => Ok(0),
    }
}

fn provider_type(host: &mut WindowsHost) -> Result<u16, RuntimeError> {
    let mut name = vec![0u16; 256];
    loop {
        let mut length = u32::try_from(name.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "network provider name exceeds Windows buffer width",
                error,
            )
        })?;
        // The writable UTF-16 array is owned and length matches its capacity.
        // SAFETY: `WNetGetProviderNameW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let status =
            unsafe { WNetGetProviderNameW(WNNC_NET_LANMAN32, name.as_mut_ptr(), &mut length) };
        if status == ERROR_MORE_DATA && usize::try_from(length).is_ok_and(|n| n > name.len()) {
            let required = usize::try_from(length).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "network provider name extent",
                    error,
                )
            })?;
            name.try_reserve_exact(required - name.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "allocate network provider name",
                        error,
                    )
                })?;
            name.resize(required, 0);
            continue;
        }
        if status != NO_ERROR {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::HostFailure,
                format!(
                    "Windows network provider query returned {status}; no legacy provider reported"
                ),
            ));
            return Ok(0);
        }
        if name.first() == Some(&0) || !name.contains(&0) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Windows returned an empty or unterminated network provider name",
            ));
        }
        break;
    }
    let mut info = NETINFOSTRUCT::default();
    info.cbStructure = core::mem::size_of::<NETINFOSTRUCT>() as u32;
    // The input is terminated and owned. The native struct is aligned, sized
    // with the official binding, and never exposes dwHandle to the guest.
    // SAFETY: `WNetGetNetworkInformationW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let status = unsafe { WNetGetNetworkInformationW(name.as_ptr(), &mut info) };
    if status != NO_ERROR {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::HostFailure,
            format!("Windows network information returned {status}; no legacy provider reported"),
        ));
        return Ok(0);
    }
    let Ok(kind) = u8::try_from(info.wNetType) else {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            "Windows network provider type has no Win16 representation",
        ));
        return Ok(0);
    };
    Ok(u16::from(kind) << 8)
}
