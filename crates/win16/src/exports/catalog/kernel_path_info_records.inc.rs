// Add KERNEL path exports after the common USER drawing catalog. The Windows
// 3.1 Programmer's Reference, Volume 2, documents directory-query length
// returns and the 144-byte GetTempFileName output minimum.
macro_rules! export_catalog_with_kernel_paths {
    ($($existing:tt)*) => {
        export_catalog_with_user_drawing_objects! {
            $($existing)*
            KernelGetTempFileName => KERNEL_GET_TEMP_FILE_NAME:
                ("KERNEL", 97u16, Stack, kernel_path_info::GET_TEMP_FILE_NAME_PARAMETERS, Word);
            KernelGetWindowsDirectory => KERNEL_GET_WINDOWS_DIRECTORY:
                ("KERNEL", 134u16, Stack, kernel_path_info::GET_WINDOWS_DIRECTORY_PARAMETERS, Word);
            KernelGetSystemDirectory => KERNEL_GET_SYSTEM_DIRECTORY:
                ("KERNEL", 135u16, Stack, kernel_path_info::GET_SYSTEM_DIRECTORY_PARAMETERS, Word);
        }
    };
}
