// Public Win16 arena exports stay inside the catalog's typed macro input;
// item-scope include! cannot expand the raw record tokens into export_catalog!.
macro_rules! export_catalog_with_global_arena {
    ($($existing:tt)*) => {
        export_catalog_with_kernel_selectors! {
            $($existing)*
            KernelGlobalMasterHandle => KERNEL_GLOBAL_MASTER_HANDLE:
                ("KERNEL", 28u16, Stack, &[], Dword);
            KernelGlobalLruOldest => KERNEL_GLOBAL_LRU_OLDEST:
                ("KERNEL", 163u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
            KernelGlobalLruNewest => KERNEL_GLOBAL_LRU_NEWEST:
                ("KERNEL", 164u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
            KernelGlobalPageLock => KERNEL_GLOBAL_PAGE_LOCK:
                ("KERNEL", 191u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
            KernelGlobalPageUnlock => KERNEL_GLOBAL_PAGE_UNLOCK:
                ("KERNEL", 192u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
            KernelGlobalSmartPageLock => KERNEL_GLOBAL_SMART_PAGE_LOCK:
                ("KERNEL", 230u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
            KernelGlobalSmartPageUnlock => KERNEL_GLOBAL_SMART_PAGE_UNLOCK:
                ("KERNEL", 231u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
            KernelGlobalDosAlloc => KERNEL_GLOBAL_DOS_ALLOC:
                ("KERNEL", 184u16, Stack, kernel::GLOBAL_DOS_ALLOC_PARAMETERS, Dword);
            KernelGlobalDosFree => KERNEL_GLOBAL_DOS_FREE:
                ("KERNEL", 185u16, Stack, kernel::GLOBAL_SELECTOR_PARAMETERS, Word);
            KernelGlobalChangeLockCount => KERNEL_GLOBAL_CHANGE_LOCK_COUNT:
                ("KERNEL", 365u16, Stack, kernel::GLOBAL_CHANGE_LOCK_COUNT_PARAMETERS, Void);
            KernelFarSetOwner => KERNEL_FAR_SET_OWNER:
                ("KERNEL", 403u16, Stack, kernel::GLOBAL_OWNER_PARAMETERS, Word);
            KernelFarGetOwner => KERNEL_FAR_GET_OWNER:
                ("KERNEL", 404u16, Stack, kernel::GLOBAL_HANDLE_PARAMETERS, Word);
        }
    };
}
