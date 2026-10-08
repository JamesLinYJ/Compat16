// Windows 3.1 KERNEL FileCDR and filesystem APIs (SDK 3.1 kernel.spec ordinals).
macro_rules! export_catalog_with_kernel_file_system {
    ($($existing:tt)*) => {
        export_catalog_with_kernel_paths! {
            $($existing)*
            KernelFileCdr => KERNEL_FILE_CDR:
                ("KERNEL", 130u16, Stack, kernel_file_system::FILE_CDR, Dword);
            KernelCreateDirectory => KERNEL_CREATE_DIRECTORY:
                ("KERNEL", 144u16, Stack, kernel_file_system::CREATE_DIRECTORY, Word);
            KernelRemoveDirectory => KERNEL_REMOVE_DIRECTORY:
                ("KERNEL", 145u16, Stack, kernel_file_system::REMOVE_DIRECTORY, Word);
            KernelDeleteFile => KERNEL_DELETE_FILE:
                ("KERNEL", 146u16, Stack, kernel_file_system::DELETE_FILE, Word);
            KernelGetCurrentDirectory => KERNEL_GET_CURRENT_DIRECTORY:
                ("KERNEL", 411u16, Stack, kernel_file_system::GET_CURRENT_DIRECTORY, Dword);
            KernelSetCurrentDirectory => KERNEL_SET_CURRENT_DIRECTORY:
                ("KERNEL", 412u16, Stack, kernel_file_system::SET_CURRENT_DIRECTORY, Word);
            KernelFindFirstFile => KERNEL_FIND_FIRST_FILE:
                ("KERNEL", 413u16, Stack, kernel_file_system::FIND_FIRST_FILE, Word);
            KernelFindNextFile => KERNEL_FIND_NEXT_FILE:
                ("KERNEL", 414u16, Stack, kernel_file_system::FIND_NEXT_FILE, Word);
            KernelFindClose => KERNEL_FIND_CLOSE:
                ("KERNEL", 415u16, Stack, kernel_file_system::FIND_CLOSE, Word);
            KernelGetFileAttributes => KERNEL_GET_FILE_ATTRIBUTES:
                ("KERNEL", 420u16, Stack, kernel_file_system::GET_FILE_ATTRIBUTES, Dword);
            KernelSetFileAttributes => KERNEL_SET_FILE_ATTRIBUTES:
                ("KERNEL", 421u16, Stack, kernel_file_system::SET_FILE_ATTRIBUTES, Word);
            KernelGetDiskFreeSpace => KERNEL_GET_DISK_FREE_SPACE:
                ("KERNEL", 422u16, Stack, kernel_file_system::GET_DISK_FREE_SPACE, Word);
        }
    };
}
