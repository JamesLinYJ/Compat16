// Add COMMDLG records after common-control descriptors in the shared catalog.
macro_rules! export_catalog_with_common_dialogs {
    ($($existing:tt)*) => {
        export_catalog_with_common_controls! {
            $($existing)*
            CommdlgGetOpenFileName => COMMDLG_GET_OPEN_FILE_NAME:
                ("COMMDLG", 1u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgGetSaveFileName => COMMDLG_GET_SAVE_FILE_NAME:
                ("COMMDLG", 2u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgChooseColor => COMMDLG_CHOOSE_COLOR:
                ("COMMDLG", 5u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgFindText => COMMDLG_FIND_TEXT:
                ("COMMDLG", 11u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgReplaceText => COMMDLG_REPLACE_TEXT:
                ("COMMDLG", 12u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgChooseFont => COMMDLG_CHOOSE_FONT:
                ("COMMDLG", 15u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgPrintDlg => COMMDLG_PRINT_DLG:
                ("COMMDLG", 20u16, Stack, common_dialog_parameters::COMMON_DIALOG_STRUCTURE, Word);
            CommdlgGetFileTitle => COMMDLG_GET_FILE_TITLE:
                ("COMMDLG", 27u16, Stack, common_dialog_parameters::GET_FILE_TITLE_PARAMETERS, Word);
            #[doc = "The Win16 SDK declares this function as returning a DWORD error code."]
            CommdlgExtendedError => COMMDLG_EXTENDED_ERROR:
                ("COMMDLG", 26u16, Stack, &[], Dword);
        }
    };
}
