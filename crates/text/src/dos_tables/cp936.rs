//! Microsoft MS-DOS 4 PRC/936 collation and uppercase records (MIT).
//! Source revision 2d04cacc5322951f187bb17e017c12920ac8ebe2:
//! v4.0/src/DEV/COUNTRY/MKCNTRY.ASM, pr936_collate and pr936_ucase.
//! Copyright (c) Microsoft Corporation. See LICENSES/Microsoft-MS-DOS-MIT.txt.
//!
//! These historical byte weights preserve every high byte. DBCS character
//! boundaries still come from the configured GBK codec; its lead range extends
//! through FEh rather than the older source's FCh.

pub(super) const COLLATION: [u8; 258] = collation();
pub(super) const UPPERCASE: [u8; 130] = uppercase();

const fn collation() -> [u8; 258] {
    let mut record = [0; 258];
    record[1] = 1;
    let mut index = 0;
    while index < 256 {
        record[index + 2] = (index as u8).to_ascii_uppercase();
        index += 1;
    }
    record
}

const fn uppercase() -> [u8; 130] {
    let mut record = [0; 130];
    record[0] = 128;
    let mut index = 0;
    while index < 128 {
        record[index + 2] = (index + 128) as u8;
        index += 1;
    }
    record
}
