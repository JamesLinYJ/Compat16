// Windows SDK 3.1 WINDOWS.H lines 3918-3923 declare `int` scroll values,
// void range/visibility setters, and a BOOL EnableScrollBar result. This
// semantic catalog keeps those SDK contracts distinct from spec `-ret16`.
macro_rules! export_catalog_with_scroll_bars {
    ($($existing:tt)*) => {
        export_catalog_with_profile_sections! {
            $($existing)*
            UserSetScrollPos => USER_SET_SCROLL_POS:
                ("USER", 62u16, Stack, user_scroll_bar::SET_POSITION_PARAMETERS, Word);
            UserGetScrollPos => USER_GET_SCROLL_POS:
                ("USER", 63u16, Stack, user_scroll_bar::GET_POSITION_PARAMETERS, Word);
            #[doc = "Windows SDK 3.1 WINDOWS.H declares SetScrollRange as void; the spec -ret16 modifier is metadata only."]
            UserSetScrollRange => USER_SET_SCROLL_RANGE:
                ("USER", 64u16, Stack, user_scroll_bar::SET_RANGE_PARAMETERS, Void);
            #[doc = "Windows SDK 3.1 WINDOWS.H declares GetScrollRange as void; the spec -ret16 modifier is metadata only."]
            UserGetScrollRange => USER_GET_SCROLL_RANGE:
                ("USER", 65u16, Stack, user_scroll_bar::GET_RANGE_PARAMETERS, Void);
            #[doc = "Windows SDK 3.1 WINDOWS.H declares ShowScrollBar as void; the spec -ret16 modifier is metadata only."]
            UserShowScrollBar => USER_SHOW_SCROLL_BAR:
                ("USER", 267u16, Stack, user_scroll_bar::SHOW_PARAMETERS, Void);
            UserEnableScrollBar => USER_ENABLE_SCROLL_BAR:
                ("USER", 482u16, Stack, user_scroll_bar::ENABLE_PARAMETERS, Word);
        }
    };
}
