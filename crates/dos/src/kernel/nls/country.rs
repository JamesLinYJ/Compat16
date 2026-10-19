//! Verified built-in country/code-page pairs, independent of the host locale.
use super::COUNTRY_CINFO_LEN;
use text_codec::CodePage;

#[derive(Clone, Copy)]
pub(super) struct CountryProfile {
    pub(super) country: u16,
    pub(super) page: CodePage,
}

impl CountryProfile {
    pub(super) const fn current(page: CodePage) -> Self {
        Self {
            country: match page {
                CodePage::Cp437 => 1,
                CodePage::Cp936 => 86,
            },
            page,
        }
    }

    pub(super) fn requested(country: u16, page: CodePage) -> Option<Self> {
        let profile = Self::current(page);
        (country == profile.country).then_some(profile)
    }

    pub(super) fn cinfo(self, case_segment: u16, case_offset: u16) -> [u8; COUNTRY_CINFO_LEN] {
        // Microsoft MKCNTRY.ASM us437_info and pr936_info. The PRC row uses
        // the historical backslash currency byte; no host locale is inferred.
        let mut info = [0; COUNTRY_CINFO_LEN];
        info[0..2].copy_from_slice(&self.country.to_le_bytes());
        info[2..4].copy_from_slice(&self.page.number().to_le_bytes());
        let prc = self.country == 86;
        info[4..6].copy_from_slice(&(if prc { 2_u16 } else { 0 }).to_le_bytes());
        info[6] = if prc { b'\\' } else { b'$' };
        info[11] = b',';
        info[13] = b'.';
        info[15] = b'-';
        info[17] = b':';
        info[20] = 2;
        info[21] = u8::from(prc);
        info[22..24].copy_from_slice(&case_offset.to_le_bytes());
        info[24..26].copy_from_slice(&case_segment.to_le_bytes());
        info[26] = b',';
        info
    }
}
