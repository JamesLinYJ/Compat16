// Extend the single descriptor catalog with the known COMMCTRL family.
// The spec's `-ret16` modifier remains export metadata; it does not itself
// define the API result. The three documented void calls have no AX result.
// Other known entries return Win16 WORD-sized handles or BOOL values.
macro_rules! export_catalog_with_common_controls {
    ($($existing:tt)*) => {
        export_catalog! {
            $($existing)*
            #[doc = "The documented Win16 function has no semantic return value. The spec's -ret16 flag remains separate export metadata."]
            CommctrlMenuHelp => COMMCTRL_MENU_HELP: ("COMMCTRL", 2u16, Stack, common_controls_parameters::MENU_HELP_PARAMETERS, Void);
            #[doc = "The documented Win16 function has no semantic return value. The spec's -ret16 flag remains separate export metadata."]
            CommctrlGetEffectiveClientRect => COMMCTRL_GET_EFFECTIVE_CLIENT_RECT: ("COMMCTRL", 4u16, Stack, common_controls_parameters::EFFECTIVE_CLIENT_RECT_PARAMETERS, Void);
            CommctrlCreateStatusWindow => COMMCTRL_CREATE_STATUS_WINDOW: ("COMMCTRL", 6u16, Stack, common_controls_parameters::CREATE_STATUS_WINDOW_PARAMETERS, Word);
            CommctrlCreateToolbar => COMMCTRL_CREATE_TOOLBAR: ("COMMCTRL", 7u16, Stack, common_controls_parameters::CREATE_TOOLBAR_PARAMETERS, Word);
            CommctrlCreateMappedBitmap => COMMCTRL_CREATE_MAPPED_BITMAP: ("COMMCTRL", 8u16, Stack, common_controls_parameters::CREATE_MAPPED_BITMAP_PARAMETERS, Word);
            CommctrlCreateHeaderWindow => COMMCTRL_CREATE_HEADER_WINDOW: ("COMMCTRL", 9u16, Stack, common_controls_parameters::CREATE_HEADER_WINDOW_PARAMETERS, Word);
            CommctrlWritePrivateProfileStruct => COMMCTRL_WRITE_PRIVATE_PROFILE_STRUCT: ("COMMCTRL", 10u16, Stack, common_controls_parameters::PROFILE_STRUCT_PARAMETERS, Word);
            CommctrlGetPrivateProfileStruct => COMMCTRL_GET_PRIVATE_PROFILE_STRUCT: ("COMMCTRL", 11u16, Stack, common_controls_parameters::PROFILE_STRUCT_PARAMETERS, Word);
            CommctrlMakeDragList => COMMCTRL_MAKE_DRAG_LIST: ("COMMCTRL", 13u16, Stack, common_controls_parameters::MAKE_DRAG_LIST_PARAMETERS, Word);
            #[doc = "The documented Win16 initializer has no semantic return value. The spec's -ret16 flag remains separate export metadata."]
            CommctrlInitCommonControls => COMMCTRL_INIT_COMMON_CONTROLS: ("COMMCTRL", 17u16, Stack, &[], Void);
            CommctrlCreateToolbarEx => COMMCTRL_CREATE_TOOLBAR_EX: ("COMMCTRL", 20u16, Stack, common_controls_parameters::CREATE_TOOLBAR_EX_PARAMETERS, Word);
        }
    };
}
