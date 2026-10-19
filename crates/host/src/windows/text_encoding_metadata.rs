//! Locale and font metadata for selecting a legacy guest ANSI code page.

use windows_sys::Win32::{
    Globalization::{
        CHARSETINFO, GetLocaleInfoW, GetSystemDefaultLCID, IsValidCodePage,
        LOCALE_IDEFAULTANSICODEPAGE, LOCALE_RETURN_NUMBER, TCI_SRCCHARSET, TranslateCharsetInfo,
    },
    Graphics::Gdi::{DEFAULT_CHARSET, SYMBOL_CHARSET},
};

pub fn ansi_code_page_for_language(language: u16) -> Option<u32> {
    if language == 0 {
        return None;
    }
    locale_code_page(u32::from(language))
}

pub fn is_supported_ansi_code_page(page: u32) -> bool {
    // SAFETY: IsValidCodePage takes a code-page integer and no pointers.
    page != 0 && !matches!(page, 1200 | 1201) && unsafe { IsValidCodePage(page) } != 0
}

pub fn legacy_locale_ansi_code_page() -> Option<u32> {
    // The locale's legacy ANSI page remains meaningful when the modern
    // process ACP is UTF-8. Query that metadata rather than inheriting CP_ACP.
    // SAFETY: `GetSystemDefaultLCID` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    locale_code_page(unsafe { GetSystemDefaultLCID() })
}

fn locale_code_page(locale: u32) -> Option<u32> {
    let mut page = 0_u32;
    // LOCALE_RETURN_NUMBER writes a DWORD; cchData is still counted in WCHARs.
    // SAFETY: GetLocaleInfoW writes into a caller-owned buffer of the capacity passed with it.
    let ok = unsafe {
        GetLocaleInfoW(
            locale,
            LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
            (&mut page as *mut u32).cast(),
            2,
        )
    };
    // SAFETY: IsValidCodePage takes a code-page integer and no pointers.
    (ok != 0 && page != 0 && unsafe { IsValidCodePage(page) } != 0).then_some(page)
}

pub fn ansi_code_page_for_charset(charset: u8) -> Option<u32> {
    if charset == DEFAULT_CHARSET || charset == SYMBOL_CHARSET {
        return None;
    }
    let mut info = CHARSETINFO::default();
    // TCI_SRCCHARSET encodes a scalar in lpSrc itself, as specified by Win32;
    // this is not a pointer into guest or host memory and is not dereferenced.
    // SAFETY: `TranslateCharsetInfo` receives a host pointer formed in this function. The pointer is non-null when dereferenced, stays live for this synchronous call, and is not a guest address.
    let ok = unsafe {
        TranslateCharsetInfo(usize::from(charset) as *mut u32, &mut info, TCI_SRCCHARSET)
    };
    // SAFETY: IsValidCodePage takes a code-page integer and no pointers.
    (ok != 0 && info.ciACP != 0 && unsafe { IsValidCodePage(info.ciACP) } != 0)
        .then_some(info.ciACP)
}
