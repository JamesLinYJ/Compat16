// Add CTL3D-family records to the same shared export catalog. The WfW 3.1
// Microsoft sample header confirms the older declared result types; for later
// exports absent there, an external Win16 implementation is comparison evidence
// only. No return behavior is inferred from a -ret16 flag by itself.
macro_rules! export_catalog_with_ctl3d {
    ($($existing:tt)*) => {
        export_catalog_with_common_dialogs! {
            $($existing)*
            Ctl3dGetVersion => CTL3D_GET_VERSION: ("CTL3D", 1u16, Stack, &[], Word);
            Ctl3dSubclassDialog => CTL3D_SUBCLASS_DIALOG:
                ("CTL3D", 2u16, Stack, ctl3d_parameters::TWO_WORDS, Word);
            Ctl3dSubclassControl => CTL3D_SUBCLASS_CONTROL:
                ("CTL3D", 3u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dControlColor => CTL3D_CONTROL_COLOR:
                ("CTL3D", 4u16, Stack, ctl3d_parameters::CTL3D_COLOR, Word);
            Ctl3dIsEnabled => CTL3D_IS_ENABLED: ("CTL3D", 5u16, Stack, &[], Word);
            Ctl3dColorChange => CTL3D_COLOR_CHANGE: ("CTL3D", 6u16, Stack, &[], Word);
            Ctl3dRegister => CTL3D_REGISTER:
                ("CTL3D", 12u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dUnregister => CTL3D_UNREGISTER:
                ("CTL3D", 13u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dAutoSubclass => CTL3D_AUTO_SUBCLASS:
                ("CTL3D", 16u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dControlColorEx => CTL3D_CONTROL_COLOR_EX:
                ("CTL3D", 18u16, Stack, ctl3d_parameters::CTL3D_COLOR_EX, Word);
            // Ordinal 19 has a known stack frame, but no Microsoft prototype
            // or return semantics in the available target SDK; keep only the
            // generated spec metadata until that contract is verified.
            #[doc = "Microsoft's WfW 3.1 CTL3D.H declares this API as returning LONG, a 32-bit Win16 result."]
            Ctl3dDlgFramePaint => CTL3D_DLG_FRAME_PAINT:
                ("CTL3D", 20u16, Stack, ctl3d_parameters::DLG_FRAME_PAINT, Dword);
            Ctl3dSubclassDialogEx => CTL3D_SUBCLASS_DIALOG_EX:
                ("CTL3D", 21u16, Stack, ctl3d_parameters::CTL3D_SUBCLASS_DLG_EX, Word);
            #[doc = "The external Win16 comparison implementation declares this no-result API as void; the available Microsoft target SDK does not declare this later export. The -ret16 spec flag is retained only as export metadata."]
            Ctl3dWinIniChange => CTL3D_WIN_INI_CHANGE: ("CTL3D", 22u16, Stack, &[], Void);
            Ctl3dIsAutoSubclass => CTL3D_IS_AUTO_SUBCLASS: ("CTL3D", 23u16, Stack, &[], Word);
            Ctl3dUnAutoSubclass => CTL3D_UN_AUTO_SUBCLASS: ("CTL3D", 24u16, Stack, &[], Word);
            Ctl3dSubclassControlEx => CTL3D_SUBCLASS_CONTROL_EX:
                ("CTL3D", 25u16, Stack, ctl3d_parameters::CTL3D_SUBCLASS_CONTROL_EX, Word);
            Ctl3dUnsubclassControl => CTL3D_UNSUBCLASS_CONTROL:
                ("CTL3D", 26u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dAutoSubclassEx => CTL3D_AUTO_SUBCLASS_EX:
                ("CTL3D", 27u16, Stack, ctl3d_parameters::CTL3D_AUTO_SUBCLASS_EX, Word);

            Ctl3dV2GetVersion => CTL3DV2_GET_VERSION: ("CTL3DV2", 1u16, Stack, &[], Word);
            Ctl3dV2SubclassDialog => CTL3DV2_SUBCLASS_DIALOG:
                ("CTL3DV2", 2u16, Stack, ctl3d_parameters::TWO_WORDS, Word);
            Ctl3dV2SubclassControl => CTL3DV2_SUBCLASS_CONTROL:
                ("CTL3DV2", 3u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dV2ControlColor => CTL3DV2_CONTROL_COLOR:
                ("CTL3DV2", 4u16, Stack, ctl3d_parameters::CTL3D_COLOR, Word);
            Ctl3dV2IsEnabled => CTL3DV2_IS_ENABLED: ("CTL3DV2", 5u16, Stack, &[], Word);
            Ctl3dV2ColorChange => CTL3DV2_COLOR_CHANGE: ("CTL3DV2", 6u16, Stack, &[], Word);
            Ctl3dV2Register => CTL3DV2_REGISTER:
                ("CTL3DV2", 12u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dV2Unregister => CTL3DV2_UNREGISTER:
                ("CTL3DV2", 13u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dV2AutoSubclass => CTL3DV2_AUTO_SUBCLASS:
                ("CTL3DV2", 16u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dV2ControlColorEx => CTL3DV2_CONTROL_COLOR_EX:
                ("CTL3DV2", 18u16, Stack, ctl3d_parameters::CTL3D_COLOR_EX, Word);
            // Ordinal 19 remains present in generated spec metadata, but is
            // unresolved as an API because its result contract is unknown.
            #[doc = "Microsoft's WfW 3.1 CTL3D.H declares this API as returning LONG, a 32-bit Win16 result."]
            Ctl3dV2DlgFramePaint => CTL3DV2_DLG_FRAME_PAINT:
                ("CTL3DV2", 20u16, Stack, ctl3d_parameters::DLG_FRAME_PAINT, Dword);
            Ctl3dV2SubclassDialogEx => CTL3DV2_SUBCLASS_DIALOG_EX:
                ("CTL3DV2", 21u16, Stack, ctl3d_parameters::CTL3D_SUBCLASS_DLG_EX, Word);
            #[doc = "The external Win16 comparison implementation declares this no-result API as void; the available Microsoft target SDK does not declare this later export. The -ret16 spec flag is retained only as export metadata."]
            Ctl3dV2WinIniChange => CTL3DV2_WIN_INI_CHANGE: ("CTL3DV2", 22u16, Stack, &[], Void);
            Ctl3dV2IsAutoSubclass => CTL3DV2_IS_AUTO_SUBCLASS: ("CTL3DV2", 23u16, Stack, &[], Word);
            Ctl3dV2UnAutoSubclass => CTL3DV2_UN_AUTO_SUBCLASS: ("CTL3DV2", 24u16, Stack, &[], Word);
            Ctl3dV2SubclassControlEx => CTL3DV2_SUBCLASS_CONTROL_EX:
                ("CTL3DV2", 25u16, Stack, ctl3d_parameters::CTL3D_SUBCLASS_CONTROL_EX, Word);
            Ctl3dV2UnsubclassControl => CTL3DV2_UNSUBCLASS_CONTROL:
                ("CTL3DV2", 26u16, Stack, ctl3d_parameters::ONE_WINDOW, Word);
            Ctl3dV2AutoSubclassEx => CTL3DV2_AUTO_SUBCLASS_EX:
                ("CTL3DV2", 27u16, Stack, ctl3d_parameters::CTL3D_AUTO_SUBCLASS_EX, Word);
        }
    };
}
