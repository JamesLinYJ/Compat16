// Windows SDK 3.1 USER declarations for cursor, accelerator, and WinHelp APIs.
macro_rules! export_catalog_with_user_cursor_accelerators {
    ($($existing:tt)*) => {
        export_catalog_with_ole2disp_convert! {
            $($existing)*
            UserSetCursor => USER_SET_CURSOR:
                ("USER", 69u16, Stack, user_cursor_accelerator::SET_CURSOR_PARAMETERS, Word);
            UserShowCursor => USER_SHOW_CURSOR:
                ("USER", 71u16, Stack, user_cursor_accelerator::SHOW_CURSOR_PARAMETERS, Word);
            UserWinHelp => USER_WIN_HELP:
                ("USER", 171u16, Stack, user_cursor_accelerator::WIN_HELP_PARAMETERS, Word);
            UserLoadAccelerators => USER_LOAD_ACCELERATORS:
                ("USER", 177u16, Stack, user_cursor_accelerator::LOAD_ACCELERATORS_PARAMETERS, Word);
            UserTranslateAccelerator => USER_TRANSLATE_ACCELERATOR:
                ("USER", 178u16, Stack, user_cursor_accelerator::TRANSLATE_ACCELERATOR_PARAMETERS, Word);
        }
    };
}
