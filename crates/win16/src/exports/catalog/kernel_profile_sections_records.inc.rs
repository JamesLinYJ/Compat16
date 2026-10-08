// Add the four KERNEL section-profile exports after the existing catalog.
macro_rules! export_catalog_with_profile_sections {
    ($($existing:tt)*) => {
        export_catalog_with_ctl3d! {
            $($existing)*
            KernelWritePrivateProfileSection => KERNEL_WRITE_PRIVATE_PROFILE_SECTION:
                ("KERNEL", 416u16, Stack, kernel_profile_sections::WRITE_PRIVATE_PROFILE_SECTION, Word);
            KernelWriteProfileSection => KERNEL_WRITE_PROFILE_SECTION:
                ("KERNEL", 417u16, Stack, kernel_profile_sections::WRITE_PROFILE_SECTION, Word);
            KernelGetPrivateProfileSection => KERNEL_GET_PRIVATE_PROFILE_SECTION:
                ("KERNEL", 418u16, Stack, kernel_profile_sections::GET_PRIVATE_PROFILE_SECTION, Word);
            KernelGetProfileSection => KERNEL_GET_PROFILE_SECTION:
                ("KERNEL", 419u16, Stack, kernel_profile_sections::GET_PROFILE_SECTION, Word);
        }
    };
}
