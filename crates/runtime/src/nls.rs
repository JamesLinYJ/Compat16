//! Install DOS data in the machine's checked, process-owned guest ROM.

use crate::{DiagnosticKind as Kind, RuntimeError, runtime_error};
use dos_kernel::{DosKernel, collating_table, upper_case_table, dbcs_lead_byte_table};
use guest_core::{memory::Memory, real_address};
use text_codec::CodePage;

// F000:0100 is XMS; F000:1000..13FF holds interrupt firmware entries.
// Reserve F000:2000..2FFF for immutable DOS NLS data.
const NLS_SEGMENT: u16 = 0xf000;
const COLLATING_OFFSET: u16 = 0x2000;
const UPPERCASE_OFFSET: u16 = 0x2200;
const DBCS_OFFSETS: [(CodePage, u16); 2] = [
    (CodePage::Cp437, 0x2300),
    (CodePage::Cp936, 0x2310),
];
const CASE_MAP_OFFSET: u16 = 0x0300;
const PRC_COLLATING_OFFSET: u16 = 0x2400;
const PRC_UPPERCASE_OFFSET: u16 = 0x2600;
const PRC_CASE_MAP_OFFSET: u16 = 0x0320;

// DOS country-information callbacks receive AL and return AL by FAR return.
// Values below 80h remain unchanged. These are ordinary guest instructions,
// executed through the CPU and checked bus; there is no host pointer/trap.
const fn case_map_code(uppercase_offset: u16) -> [u8; 14] {
    // XLAT adds the incoming AL, so shift its base past the length word and
    // back by 80h to index the 128-entry DOS uppercase table.
    let base = (uppercase_offset + 2 - 0x80).to_le_bytes();
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
    for (code_page, offset) in DBCS_OFFSETS {
        memory.initialize_rom(real_address(NLS_SEGMENT, offset), &dbcs_lead_byte_table(code_page))
            .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant,
                "install DOS DBCS ROM", error))?;
        dos.set_dbcs_table_address(code_page, NLS_SEGMENT, offset).map_err(runtime_error)?;
    }
    install_profile(memory, dos, CodePage::Cp437, COLLATING_OFFSET, UPPERCASE_OFFSET, CASE_MAP_OFFSET)?;
    install_profile(memory, dos, CodePage::Cp936, PRC_COLLATING_OFFSET, PRC_UPPERCASE_OFFSET, PRC_CASE_MAP_OFFSET)
}

fn install_profile(
    memory: &mut Memory, dos: &mut DosKernel, page: CodePage,
    collating_offset: u16, uppercase_offset: u16, case_map_offset: u16,
) -> Result<(), RuntimeError> {
    let table = collating_table(page)
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "required DOS profile collation table is missing"))?;
    memory.initialize_rom(real_address(NLS_SEGMENT, collating_offset), table)
        .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install DOS NLS ROM", error))?;
    dos.set_collating_table_address(page, NLS_SEGMENT, collating_offset)
        .map_err(runtime_error)?;
    let uppercase = upper_case_table(page)
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "required DOS profile uppercase table is missing"))?;
    memory.initialize_rom(real_address(NLS_SEGMENT, uppercase_offset), uppercase)
        .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install DOS uppercase ROM", error))?;
    memory.initialize_rom(real_address(NLS_SEGMENT, case_map_offset), &case_map_code(uppercase_offset))
        .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install DOS case-map callback", error))?;
    dos.set_uppercase_table_address(page, NLS_SEGMENT, uppercase_offset)
        .map_err(runtime_error)?;
    dos.set_case_map_address(page, NLS_SEGMENT, case_map_offset)
        .map_err(runtime_error)
}

#[cfg(test)]
#[path = "nls_tests.rs"]
mod tests;
