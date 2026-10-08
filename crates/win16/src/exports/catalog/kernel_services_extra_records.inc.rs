// Additional KERNEL descriptors backed by existing guest heap operations.

KernelGlobalFreeAll => KERNEL_GLOBAL_FREE_ALL: ("KERNEL", 26u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
KernelGlobalHandleNoRip => KERNEL_GLOBAL_HANDLE_NO_RIP: ("KERNEL", 159u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Dword);
KernelWriteProfileString => KERNEL_WRITE_PROFILE_STRING: ("KERNEL", 59u16, Stack, kernel_services_extra::KERNEL_PROFILE_WRITE, Word);
KernelGetProfileSectionNames => KERNEL_GET_PROFILE_SECTION_NAMES: ("KERNEL", 142u16, Stack, kernel_services_extra::KERNEL_PROFILE_SECTION_NAMES, Word);
KernelGetPrivateProfileSectionNames => KERNEL_GET_PRIVATE_PROFILE_SECTION_NAMES: ("KERNEL", 143u16, Stack, kernel_services_extra::KERNEL_PRIVATE_PROFILE_SECTION_NAMES, Word);
