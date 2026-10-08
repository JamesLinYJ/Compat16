//! Command-level NCB buffer directions at the Windows boundary.

pub(super) fn has_flat_payload_contract(command: u8) -> bool {
    matches!(
        command,
        0x10 // NCBCALL
            | 0x11 // NCBLISTEN
            | 0x12 // NCBHANGUP
            | 0x14 // NCBSEND
            | 0x15 // NCBRECV
            | 0x16 // NCBRECVANY
            | 0x20 // NCBDGSEND
            | 0x21 // NCBDGRECV
            | 0x22 // NCBDGSENDBC
            | 0x23 // NCBDGRECVBC
            | 0x30 // NCBADDNAME
            | 0x31 // NCBDELNAME
            | 0x32 // NCBRESET
            | 0x36 // NCBADDGRNAME
            | 0x70 // NCBUNLINK
            | 0x71 // NCBSENDNA
            | 0x73 // NCBLANSTALERT
            | 0x77 // NCBACTION (Windows extension; opaque flat ACTION_HEADER data)
            | 0x79 // NCBTRACE
    )
}

pub(super) fn payload_access_matches_command(
    command: u8,
    access: runtime::Win16HostNetbiosBufferAccess,
) -> bool {
    match command {
        0x14 | 0x20 | 0x22 | 0x71 => {
            matches!(access, runtime::Win16HostNetbiosBufferAccess::Read)
        }
        0x15 | 0x16 | 0x21 | 0x23 => {
            matches!(access, runtime::Win16HostNetbiosBufferAccess::Write)
        }
        0x77 => matches!(access, runtime::Win16HostNetbiosBufferAccess::ReadWrite),
        _ => false,
    }
}
