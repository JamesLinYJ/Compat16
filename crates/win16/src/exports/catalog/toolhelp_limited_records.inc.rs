// Chain the documented task-control exports after the other ToolHelp records.
macro_rules! export_catalog_with_toolhelp_limited {
    ($($existing:tt)*) => {
        export_catalog_with_toolhelp_memory! {
            $($existing)*
            ToolhelpTaskSetCsip => TOOLHELP_TASK_SET_CSIP:
                ("TOOLHELP", 81u16, Stack, toolhelp_limited::TASK_SET_CSIP, Dword);
            ToolhelpTaskSwitch => TOOLHELP_TASK_SWITCH:
                ("TOOLHELP", 83u16, Stack, toolhelp_limited::TASK_SWITCH, Word);
        }
    };
}
