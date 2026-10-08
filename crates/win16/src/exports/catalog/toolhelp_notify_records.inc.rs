// Keep ToolHelp notification exports in the chained catalogue macro so they
// participate in the same generated export slice as the existing families.
macro_rules! export_catalog_with_toolhelp_notify {
    ($($existing:tt)*) => {
        export_catalog_with_ole1! {
            $($existing)*
            ToolhelpNotifyRegister => TOOLHELP_NOTIFY_REGISTER:
                ("TOOLHELP", 73u16, Stack, toolhelp_notify::NOTIFY_REGISTER, Word);
            ToolhelpNotifyUnregister => TOOLHELP_NOTIFY_UNREGISTER:
                ("TOOLHELP", 74u16, Stack, toolhelp_notify::NOTIFY_UNREGISTER, Word);
        }
    };
}
