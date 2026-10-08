// OLE2NLS ordinals 1–8 have explicit Win16 ABI declarations. Ordinal 9's
// callback lifetime remains unresolved and therefore has no request binding.
macro_rules! export_catalog_with_ole2nls {
    ($($existing:tt)*) => {
        export_catalog_with_kernel_file_system! {
            $($existing)*
            Ole2NlsGetUserDefaultLcid => OLE2NLS_GET_USER_DEFAULT_LCID:
                ("OLE2NLS", 1u16, Stack, ole2nls::GET_USER_DEFAULT_LCID_PARAMETERS, Dword);
            Ole2NlsGetSystemDefaultLcid => OLE2NLS_GET_SYSTEM_DEFAULT_LCID:
                ("OLE2NLS", 2u16, Stack, ole2nls::GET_SYSTEM_DEFAULT_LCID_PARAMETERS, Dword);
            Ole2NlsGetUserDefaultLangId => OLE2NLS_GET_USER_DEFAULT_LANG_ID:
                ("OLE2NLS", 3u16, Stack, ole2nls::GET_USER_DEFAULT_LANG_ID_PARAMETERS, Word);
            Ole2NlsGetSystemDefaultLangId => OLE2NLS_GET_SYSTEM_DEFAULT_LANG_ID:
                ("OLE2NLS", 4u16, Stack, ole2nls::GET_SYSTEM_DEFAULT_LANG_ID_PARAMETERS, Word);
            // The project spec omits `-ret16`; the catalog keeps its default
            // Dword shape, but the local SDK manuals do not independently verify this width.
            Ole2NlsGetLocaleInfoA => OLE2NLS_GET_LOCALE_INFO_A:
                ("OLE2NLS", 5u16, Stack, ole2nls::GET_LOCALE_INFO_A_PARAMETERS, Dword);
            Ole2NlsLcMapStringA => OLE2NLS_LC_MAP_STRING_A:
                ("OLE2NLS", 6u16, Stack, ole2nls::LC_MAP_STRING_A_PARAMETERS, Word);
            Ole2NlsGetStringTypeA => OLE2NLS_GET_STRING_TYPE_A:
                ("OLE2NLS", 7u16, Stack, ole2nls::GET_STRING_TYPE_A_PARAMETERS, Word);
            Ole2NlsCompareStringA => OLE2NLS_COMPARE_STRING_A:
                ("OLE2NLS", 8u16, Stack, ole2nls::COMPARE_STRING_A_PARAMETERS, Word);
        }
    };
}
