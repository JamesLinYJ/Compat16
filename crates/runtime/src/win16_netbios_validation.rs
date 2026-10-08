//! Result-shape validation for owned Win16 NetBIOS requests.

use zerocopy::FromBytes;

use super::netbios_wire::{
    AdapterStatus16Wire, FindNameHeader16Wire, Ncb16Wire, SessionStatusHeader16Wire,
    FINDNAMEBUF16_BYTES, FINDNAMEHDR16_BYTES, NAMEBUF16_BYTES,
    NCBLISTEN, NCBASTAT, NCBENUM, NCBFINDNAME, NCBSSTAT, NCBSEND, NCBDGSEND,
    NCBDGSENDBC, NCBSENDNA, NCBRECV, NCBRECVANY, NCBDGRECV, NCBDGRECVBC, NCBACTION,
    SESSBUF16_BYTES, SESSBUFHDR16_BYTES, NRC_PENDING,
};
use crate::{DiagnosticKind as Kind, RuntimeError};

const NRC_GOODRET: u8 = 0;
const NRC_INCOMP: u8 = 0x06;
const NRC_BUFLEN: u8 = 0x01;
const NRC_INVDDID: u8 = 0x3b;

/// Microsoft documents NRC_INVDDID as a function-only result that is not
/// returned in the NCB; the WFW 3.1 NCB header defines its value as 0x3b.
/// Keep that result distinct from the NCB completion bytes and retain them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NetbiosResultClass {
    NcbCompletion,
    Pending,
    FunctionOnly(u8),
}

#[derive(Clone, Copy)]
pub(super) struct NetbiosCallValidation {
    pub(super) command: u8,
    pub(super) length: u16,
    buffer_capacity: Option<u16>,
    payload: NetbiosPayloadShape,
}

#[derive(Clone, Copy)]
enum NetbiosPayloadShape {
    None,
    Bytes {
        access: crate::Win16HostNetbiosBufferAccess,
    },
    AdapterStatus {
        capacity: u16,
    },
    SessionStatus {
        capacity: u16,
    },
    FindName {
        capacity: u16,
    },
    LanaEnum {
        capacity: u16,
    },
}

impl NetbiosCallValidation {
    pub(super) fn from_call(call: &crate::Win16HostNetbiosCall, buffer_capacity: Option<u16>) -> Self {
        let payload = match &call.payload {
            crate::Win16HostNetbiosPayload::None => NetbiosPayloadShape::None,
            crate::Win16HostNetbiosPayload::Bytes { access, .. } => {
                NetbiosPayloadShape::Bytes { access: *access }
            }
            crate::Win16HostNetbiosPayload::AdapterStatus { capacity } => {
                NetbiosPayloadShape::AdapterStatus {
                    capacity: *capacity,
                }
            }
            crate::Win16HostNetbiosPayload::SessionStatus { capacity } => {
                NetbiosPayloadShape::SessionStatus {
                    capacity: *capacity,
                }
            }
            crate::Win16HostNetbiosPayload::FindName { capacity } => {
                NetbiosPayloadShape::FindName {
                    capacity: *capacity,
                }
            }
            crate::Win16HostNetbiosPayload::LanaEnum { capacity } => {
                NetbiosPayloadShape::LanaEnum {
                    capacity: *capacity,
                }
            }
        };
        Self {
            command: call.command,
            length: call.length,
            buffer_capacity,
            payload,
        }
    }

    pub(super) fn from_ncb(ncb: &Ncb16Wire) -> Self {
        Self {
            command: ncb.command_code(),
            length: ncb.length.get(),
            buffer_capacity: None,
            payload: NetbiosPayloadShape::None,
        }
    }
}

pub(super) fn validate_result(
    call: &NetbiosCallValidation,
    result: &crate::Win16HostNetbiosResult,
) -> Result<(), RuntimeError> {
    match classify_result(result)? {
        NetbiosResultClass::FunctionOnly(status) => {
            if status != NRC_INVDDID {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "unsupported function-only NetBIOS status classification",
                ));
            }
            return Ok(());
        }
        NetbiosResultClass::Pending => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "pending NetBIOS source was validated as a terminal completion",
            ));
        }
        NetbiosResultClass::NcbCompletion => {}
    }
    if let Some(capacity) = call.buffer_capacity {
        if result.length > capacity
            && !(call.command == NCBFINDNAME && result.function_return == NRC_BUFLEN)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "NetBIOS host returned an NCB length larger than the guest capacity",
            ));
        }
    }
    let data_completed = result.function_return == result.retcode
        && matches!(result.retcode, NRC_GOODRET | NRC_INCOMP);
    let successful = result.function_return == NRC_GOODRET && result.retcode == NRC_GOODRET;
    let call_name_expected = match call.command {
        NCBLISTEN => successful,
        NCBDGRECV | NCBDGRECVBC => data_completed,
        _ => false,
    };
    if result.call_name.is_some() != call_name_expected {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NetBIOS host returned NCB_CALLNAME inconsistent with the completed command",
        ));
    }
    match (&call.payload, &result.payload) {
        (NetbiosPayloadShape::Bytes { access }, crate::Win16HostNetbiosOutput::Bytes { bytes })
            if data_completed && !matches!(access, crate::Win16HostNetbiosBufferAccess::Read) =>
        {
            if bytes.len() != usize::from(result.length) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "NetBIOS output byte count does not match the returned NCB length",
                ));
            }
            Ok(())
        }
        (NetbiosPayloadShape::Bytes { access }, crate::Win16HostNetbiosOutput::None)
            if !data_completed || matches!(access, crate::Win16HostNetbiosBufferAccess::Read) =>
        {
            Ok(())
        }
        (
            NetbiosPayloadShape::AdapterStatus { capacity },
            crate::Win16HostNetbiosOutput::AdapterStatus { bytes },
        ) if successful => {
            validate_adapter_status(bytes, *capacity)?;
            Ok(())
        }
        (
            NetbiosPayloadShape::SessionStatus { capacity },
            crate::Win16HostNetbiosOutput::SessionStatus { bytes },
        ) if successful => {
            validate_session_status(bytes, *capacity, result.length)?;
            Ok(())
        }
        (
            NetbiosPayloadShape::SessionStatus { capacity },
            crate::Win16HostNetbiosOutput::SessionStatus { bytes },
        ) if result.retcode == NRC_INCOMP => {
            validate_partial_session_status(bytes, *capacity, result.length)?;
            Ok(())
        }
        (NetbiosPayloadShape::FindName { capacity }, crate::Win16HostNetbiosOutput::FindName { bytes })
            if successful =>
        {
            validate_find_name(bytes, *capacity)?;
            Ok(())
        }
        (NetbiosPayloadShape::FindName { .. }, crate::Win16HostNetbiosOutput::None)
            if !successful => Ok(()),
        (NetbiosPayloadShape::LanaEnum { capacity }, crate::Win16HostNetbiosOutput::LanaEnum { bytes })
            if successful =>
        {
            validate_lana_enum(bytes, *capacity)?;
            Ok(())
        }
        (NetbiosPayloadShape::LanaEnum { .. }, crate::Win16HostNetbiosOutput::None)
            if !successful => Ok(()),
        (
            NetbiosPayloadShape::AdapterStatus { .. } | NetbiosPayloadShape::SessionStatus { .. },
            crate::Win16HostNetbiosOutput::None,
        ) if !successful => {
            if let NetbiosPayloadShape::SessionStatus { capacity } = call.payload {
                if call.command == NCBSSTAT && result.retcode == NRC_INCOMP && capacity >= 4 {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "NCBSSTAT incomplete completion omitted its available status header",
                    ));
                }
            }
            Ok(())
        }
        (NetbiosPayloadShape::None, crate::Win16HostNetbiosOutput::None) => {
            if is_status_command(call.command) && successful {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "NetBIOS host succeeded without the required status output",
                ));
            }
            if is_data_command(call.command) && call.length != 0 && data_completed {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "NetBIOS host succeeded without the required guest data buffer",
                ));
            }
            if call.command == NCBFINDNAME && successful {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "NCBFINDNAME succeeded without its required output record",
                ));
            }
            if call.command == NCBENUM && successful {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "NCBENUM succeeded without its required LANA_ENUM output",
                ));
            }
            Ok(())
        }
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NetBIOS host returned a payload shape inconsistent with the decoded NCB",
        )),
    }
}

/// Classify terminal, pending, and function-only status shapes shared by the
/// synchronous, asynchronous, and NCBCANCEL projections. Function-only values
/// leave guest NCB bytes intact; pending is accepted only by the submission
/// path and cannot be mistaken for a terminal completion.
pub(super) fn classify_result(
    result: &crate::Win16HostNetbiosResult,
) -> Result<NetbiosResultClass, RuntimeError> {
    if result.function_return == NRC_INVDDID {
        if result.call_name.is_some()
            || !matches!(&result.payload, crate::Win16HostNetbiosOutput::None)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "function-only NRC_INVDDID unexpectedly contains NCB output",
            ));
        }
        return Ok(NetbiosResultClass::FunctionOnly(NRC_INVDDID));
    }
    if result.function_return == NRC_GOODRET
        && result.retcode == NRC_PENDING
        && result.cmd_cplt == NRC_PENDING
    {
        if result.call_name.is_some()
            || !matches!(&result.payload, crate::Win16HostNetbiosOutput::None)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "pending NetBIOS result unexpectedly contains terminal NCB output",
            ));
        }
        return Ok(NetbiosResultClass::Pending);
    }
    if result.retcode != result.cmd_cplt || result.function_return != result.retcode {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native NetBIOS result disagrees across its function and NCB completion fields",
        ));
    }
    Ok(NetbiosResultClass::NcbCompletion)
}

fn validate_lana_enum(bytes: &[u8], capacity: u16) -> Result<(), RuntimeError> {
    const LANA_ENUM_BYTES: usize = 256;
    if bytes.len() != LANA_ENUM_BYTES || bytes.len() > usize::from(capacity) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBENUM projection does not match the fixed LANA_ENUM layout",
        ));
    }
    if usize::from(bytes[0]) > bytes.len() - 1 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBENUM adapter count exceeds the LANA_ENUM array",
        ));
    }
    Ok(())
}

fn validate_find_name(bytes: &[u8], capacity: u16) -> Result<(), RuntimeError> {
    if bytes.len() < FINDNAMEHDR16_BYTES || bytes.len() > usize::from(capacity) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBFINDNAME output does not fit the guest buffer",
        ));
    }
    let header = FindNameHeader16Wire::read_from_bytes(&bytes[..FINDNAMEHDR16_BYTES])
        .map_err(|_| RuntimeError::new(
            Kind::InternalInvariant,
            "NCBFINDNAME output has a malformed fixed header",
        ))?;
    let expected = usize::from(header.node_count.get())
        .checked_mul(FINDNAMEBUF16_BYTES)
        .and_then(|length| length.checked_add(FINDNAMEHDR16_BYTES))
        .ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "NCBFINDNAME node count overflows its output length",
        ))?;
    if bytes.len() != expected {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBFINDNAME node count does not match its returned records",
        ));
    }
    Ok(())
}

fn is_status_command(command: u8) -> bool {
    matches!(command, NCBASTAT | NCBSSTAT | NCBENUM)
}

fn is_data_command(command: u8) -> bool {
    matches!(
        command,
        NCBSEND
            | NCBDGSEND
            | NCBDGSENDBC
            | NCBSENDNA
            | NCBRECV
            | NCBRECVANY
            | NCBDGRECV
            | NCBDGRECVBC
            | NCBACTION
    )
}

fn validate_adapter_status(bytes: &[u8], capacity: u16) -> Result<(), RuntimeError> {
    if bytes.len() < super::netbios_wire::ASTATBUF16_BYTES || bytes.len() > usize::from(capacity) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBASTAT host projection has an invalid guest length",
        ));
    }
    let header =
        AdapterStatus16Wire::read_from_bytes(&bytes[..super::netbios_wire::ASTATBUF16_BYTES])
            .map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "NCBASTAT host projection has a malformed guest header",
                )
            })?;
    let names = usize::from(header.name_count.get())
        .checked_mul(NAMEBUF16_BYTES)
        .and_then(|length| length.checked_add(super::netbios_wire::ASTATBUF16_BYTES))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "NCBASTAT projected name count overflows its output length",
            )
        })?;
    if bytes.len() != names {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBASTAT projected bytes do not match name_count",
        ));
    }
    Ok(())
}

fn validate_session_status(
    bytes: &[u8],
    capacity: u16,
    returned_extent: u16,
) -> Result<(), RuntimeError> {
    if bytes.len() < SESSBUFHDR16_BYTES
        || bytes.len() > usize::from(capacity)
        || bytes.len() > usize::from(returned_extent)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT host projection has an invalid guest length",
        ));
    }
    let header =
        SessionStatusHeader16Wire::read_from_bytes(&bytes[..SESSBUFHDR16_BYTES]).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "NCBSSTAT host projection has a malformed guest header",
            )
        })?;
    let sessions = usize::from(header.num_sess)
        .checked_mul(SESSBUF16_BYTES)
        .and_then(|length| length.checked_add(SESSBUFHDR16_BYTES))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "NCBSSTAT projected session count overflows its output length",
            )
        })?;
    if bytes.len() != sessions {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT projected bytes do not match num_sess",
        ));
    }
    Ok(())
}

fn validate_partial_session_status(
    bytes: &[u8],
    capacity: u16,
    returned_extent: u16,
) -> Result<(), RuntimeError> {
    let extent = usize::from(returned_extent);
    if extent < SESSBUFHDR16_BYTES
        || bytes.len() < SESSBUFHDR16_BYTES
        || bytes.len() > usize::from(capacity)
        || bytes.len() > extent
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT partial output exceeds its returned guest extent",
        ));
    }
    let records_bytes = bytes.len() - SESSBUFHDR16_BYTES;
    if records_bytes % SESSBUF16_BYTES != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT partial output ends inside a session record",
        ));
    }
    let header =
        SessionStatusHeader16Wire::read_from_bytes(&bytes[..SESSBUFHDR16_BYTES]).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "NCBSSTAT partial projection has a malformed guest header",
            )
        })?;
    let available_records = (extent - SESSBUFHDR16_BYTES) / SESSBUF16_BYTES;
    let expected_records = usize::from(header.num_sess).min(available_records);
    let expected_bytes = expected_records
        .checked_mul(SESSBUF16_BYTES)
        .and_then(|length| length.checked_add(SESSBUFHDR16_BYTES))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "NCBSSTAT expected output length overflowed",
            )
        })?;
    if bytes.len() != expected_bytes {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "NCBSSTAT partial projection omitted a complete record in its returned extent",
        ));
    }
    Ok(())
}
