// SDK 3.1 WINDOWS.H defines the public selector argument and result widths.
// Additional compatibility exports retain their repository-owned KERNEL
// specification contracts. Values describe guest selectors/addresses only.
macro_rules! export_catalog_with_kernel_selectors {
    ($($existing:tt)*) => {
        export_catalog_with_mci! {
            $($existing)*
            KernelAllocCStoDSAlias => KERNEL_ALLOC_CS_TO_DS_ALIAS:
                ("KERNEL", 170u16, Stack, kernel::ALLOC_CS_TO_DS_ALIAS_PARAMETERS, Word);
            KernelAllocDStoCSAlias => KERNEL_ALLOC_DS_TO_CS_ALIAS:
                ("KERNEL", 171u16, Stack, kernel::GLOBAL_SELECTOR_PARAMETERS, Word);
            KernelAllocAlias => KERNEL_ALLOC_ALIAS:
                ("KERNEL", 172u16, Stack, kernel::GLOBAL_SELECTOR_PARAMETERS, Word);
            KernelAllocSelector => KERNEL_ALLOC_SELECTOR:
                ("KERNEL", 175u16, Stack, kernel::ALLOC_SELECTOR_PARAMETERS, Word);
            KernelFreeSelector => KERNEL_FREE_SELECTOR:
                ("KERNEL", 176u16, Stack, kernel::FREE_SELECTOR_PARAMETERS, Word);
            KernelPrestoChangoSelector => KERNEL_PRESTO_CHANGO_SELECTOR:
                ("KERNEL", 177u16, Stack, kernel::PRESTO_CHANGO_SELECTOR_PARAMETERS, Word);
            KernelLongPtrAdd => KERNEL_LONG_PTR_ADD:
                ("KERNEL", 180u16, Stack, kernel::LONG_PTR_ADD_PARAMETERS, Dword);
            KernelGetSelectorBase => KERNEL_GET_SELECTOR_BASE:
                ("KERNEL", 186u16, Stack, kernel::GLOBAL_SELECTOR_PARAMETERS, Dword);
            KernelSetSelectorBase => KERNEL_SET_SELECTOR_BASE:
                ("KERNEL", 187u16, Stack, kernel::SELECTOR_BASE_PARAMETERS, Word);
            KernelGetSelectorLimit => KERNEL_GET_SELECTOR_LIMIT:
                ("KERNEL", 188u16, Stack, kernel::GLOBAL_SELECTOR_PARAMETERS, Dword);
            KernelSetSelectorLimit => KERNEL_SET_SELECTOR_LIMIT:
                ("KERNEL", 189u16, Stack, kernel::SELECTOR_LIMIT_PARAMETERS, Word);
            KernelSelectorAccessRights => KERNEL_SELECTOR_ACCESS_RIGHTS:
                ("KERNEL", 196u16, Stack, kernel::SELECTOR_ACCESS_RIGHTS_PARAMETERS, Word);
            KernelAllocSelectorArray => KERNEL_ALLOC_SELECTOR_ARRAY:
                ("KERNEL", 206u16, Stack, kernel::SELECTOR_ARRAY_PARAMETERS, Word);
            KernelIsSharedSelector => KERNEL_IS_SHARED_SELECTOR:
                ("KERNEL", 345u16, Stack, kernel::GLOBAL_SELECTOR_PARAMETERS, Word);
            KernelMapSL => KERNEL_MAP_SL:
                ("KERNEL", 357u16, Stack, kernel::FAR_SELECTOR_PARAMETERS, Dword);
            KernelMapLS => KERNEL_MAP_LS:
                ("KERNEL", 358u16, Stack, kernel::LONG_SELECTOR_PARAMETERS, FarPointer);
            KernelUnMapLS => KERNEL_UNMAP_LS:
                ("KERNEL", 359u16, Stack, kernel::FAR_SELECTOR_PARAMETERS, Void);
        }
    };
}
