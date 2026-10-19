//! AH=29h's owned 8.3 result and caller-address boundary.
//! DOS option bits, wildcard fill and the returned byte position do not map
//! to a host path parser. This adapter only builds the unopened FCB prefix;
//! it does not open a file or translate guest coordinates to host pointers.
use crate::caller_address_space::{DosCallAddressSpace, DosPointerAccess, DosSpanPolicy};
use crate::{DosAction, DosError, DosHost};
use guest_core::Registers;

use super::DosKernel;
mod scan;

const PARSED_FCB_BYTES: usize = 16;

impl DosKernel {
    pub(super) fn parse_fcb_name(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &impl DosHost,
    ) -> Result<DosAction, DosError> {
        let input = memory.resolve_caller_pointer(regs.ds, regs.si())?;
        let output = memory.resolve_caller_pointer(regs.es, regs.di())?;
        memory.validate_caller_range(
            output,
            0,
            PARSED_FCB_BYTES,
            DosPointerAccess::Write,
            DosSpanPolicy::OffsetWrap,
        )?;
        let flags = regs.al();
        let parsed = scan::parse(
            memory,
            input,
            flags,
            host.guest_code_page(),
            host.logical_drive_count(),
        )?;
        let mut bytes = [0; PARSED_FCB_BYTES];
        bytes[1..12].fill(b' ');
        // Read only fields actually retained by the flags. Build the entire
        // owned result before writing, including the two zero status words.
        match parsed.drive {
            Some(drive) => bytes[0] = drive,
            None if flags & 2 != 0 => {
                memory.read_caller_range(output, 0, &mut bytes[..1], DosSpanPolicy::OffsetWrap)?
            }
            None => {}
        }
        match parsed.name {
            Some(name) => bytes[1..9].copy_from_slice(&name),
            None if flags & 4 != 0 => {
                memory.read_caller_range(output, 1, &mut bytes[1..9], DosSpanPolicy::OffsetWrap)?
            }
            None => {}
        }
        match parsed.extension {
            Some(extension) => bytes[9..12].copy_from_slice(&extension),
            None if flags & 8 != 0 => {
                memory.read_caller_range(output, 9, &mut bytes[9..12], DosSpanPolicy::OffsetWrap)?
            }
            None => {}
        }
        memory.write_caller_range(output, 0, &bytes, DosSpanPolicy::OffsetWrap)?;
        regs.set_al(parsed.status);
        regs.set_si(regs.si().wrapping_add(parsed.consumed));
        Ok(DosAction::Continue)
    }
}
