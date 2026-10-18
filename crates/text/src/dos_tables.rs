//! Shared DOS code-page data used by NLS queries and DOS filenames.

use crate::CodePage;
mod cp437;
mod cp936;

/// Immutable records for the built-in DOS profiles. Their length words are
/// part of the DOS representation; consumers use accessors instead of keeping
/// separate character mappings in each subsystem.
pub struct DosCodePageTables {
    collation: &'static [u8; 258],
    uppercase: &'static [u8; 130],
}

impl DosCodePageTables {
    pub const fn collation_record(&self) -> &'static [u8; 258] { self.collation }
    pub const fn uppercase_record(&self) -> &'static [u8; 130] { self.uppercase }

    /// Case conversion for filenames. The legacy country callback applies
    /// this extended-byte table only to 80h..FFh and leaves ASCII unchanged.
    pub fn uppercase_byte(&self, byte: u8) -> u8 {
        if byte < 0x80 { byte.to_ascii_uppercase() }
        else { self.uppercase[usize::from(byte - 0x80) + 2] }
    }
}

static CP437: DosCodePageTables = DosCodePageTables {
    collation: &cp437::COLLATION,
    uppercase: &cp437::UPPERCASE,
};

static CP936: DosCodePageTables = DosCodePageTables {
    collation: &cp936::COLLATION,
    uppercase: &cp936::UPPERCASE,
};

/// Only profiles backed by verified DOS data are returned here. Encoding
/// support by itself does not imply that a matching DOS NLS profile exists.
pub const fn dos_code_page_tables(code_page: CodePage) -> Option<&'static DosCodePageTables> {
    match code_page {
        CodePage::Cp437 => Some(&CP437),
        CodePage::Cp936 => Some(&CP936),
    }
}
