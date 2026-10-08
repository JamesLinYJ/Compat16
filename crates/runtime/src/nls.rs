//! Install DOS data in the machine's checked, process-owned guest ROM.

use crate::{DiagnosticKind as Kind, RuntimeError, runtime_error};
use dos_kernel::{DosKernel, collating_table, upper_case_table};
use guest_core::{memory::Memory, real_address};
use text_codec::CodePage;

// F000:0100 is XMS; F000:1000..13FF holds interrupt firmware entries.
// Reserve F000:2000..2FFF for immutable DOS NLS data.
const NLS_SEGMENT: u16 = 0xf000;
const COLLATING_OFFSET: u16 = 0x2000;
const UPPERCASE_OFFSET: u16 = 0x2200;
const CASE_MAP_OFFSET: u16 = 0x0300;

// DOS country-information callbacks receive AL and return AL by FAR return.
// Values below 80h remain unchanged. These are ordinary guest instructions,
// executed through the CPU and checked bus; there is no host pointer/trap.
const fn case_map_code() -> [u8; 14] {
    // XLAT adds the incoming AL, so shift its base past the length word and
    // back by 80h to index the 128-entry DOS uppercase table.
    let base = (UPPERCASE_OFFSET + 2 - 0x80).to_le_bytes();
    [
        0x9c,                   // PUSHF
        0x3c, 0x80,             // CMP AL,80h
        0x72, 0x07,             // JB restore_flags
        0x53,                   // PUSH BX
        0xbb, base[0], base[1],  // MOV BX,uppercase_base
        0x2e, 0xd7,             // CS:XLAT
        0x5b,                   // POP BX
        0x9d,                   // restore_flags: POPF
        0xcb,                   // RETF
    ]
}

pub(crate) fn install(memory: &mut Memory, dos: &mut DosKernel) -> Result<(), RuntimeError> {
    let table = collating_table(CodePage::Cp437)
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "required US CP437 collation table is missing"))?;
    memory.initialize_rom(real_address(NLS_SEGMENT, COLLATING_OFFSET), table)
        .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install DOS NLS ROM", error))?;
    dos.set_collating_table_address(CodePage::Cp437, NLS_SEGMENT, COLLATING_OFFSET)
        .map_err(runtime_error)?;
    let uppercase = upper_case_table(CodePage::Cp437)
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "required US CP437 uppercase table is missing"))?;
    memory.initialize_rom(real_address(NLS_SEGMENT, UPPERCASE_OFFSET), uppercase)
        .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install DOS uppercase ROM", error))?;
    memory.initialize_rom(real_address(NLS_SEGMENT, CASE_MAP_OFFSET), &case_map_code())
        .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install DOS case-map callback", error))?;
    dos.set_uppercase_table_address(CodePage::Cp437, NLS_SEGMENT, UPPERCASE_OFFSET)
        .map_err(runtime_error)?;
    dos.set_case_map_address(CodePage::Cp437, NLS_SEGMENT, CASE_MAP_OFFSET)
        .map_err(runtime_error)
}

#[cfg(test)]
#[path = "nls_tests.rs"]
mod tests;
