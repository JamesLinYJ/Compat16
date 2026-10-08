// Chain the memory-information exports into the active catalogue expansion.
macro_rules! export_catalog_with_toolhelp_memory {
    ($($existing:tt)*) => {
        export_catalog_with_toolhelp_notify! {
            $($existing)*
            ToolhelpSystemHeapInfo => TOOLHELP_SYSTEM_HEAP_INFO:
                ("TOOLHELP", 71u16, Stack, toolhelp_memory::SYSTEM_HEAP_INFO, Word);
            ToolhelpMemManInfo => TOOLHELP_MEMMAN_INFO:
                ("TOOLHELP", 72u16, Stack, toolhelp_memory::MEMMAN_INFO, Word);
        }
    };
}
