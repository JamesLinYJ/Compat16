// SDK 3.1 public prototypes use Pascal stack arguments. The declaration
// context flag does not change that guest ABI; KERNEL.15 GlobalAlloc follows
// the same distinction.
macro_rules! export_catalog_with_kernel_diagnostics {
    ($($existing:tt)*) => {
        export_catalog_with_dde! {
            $($existing)*
            KernelOutputDebugString => KERNEL_OUTPUT_DEBUG_STRING:
                ("KERNEL", 115u16, Stack, kernel_diagnostics::OUTPUT_DEBUG_STRING, Void);
            KernelFatalAppExit => KERNEL_FATAL_APP_EXIT:
                ("KERNEL", 137u16, Stack, kernel_diagnostics::FATAL_APP_EXIT, Void);
            KernelDebugBreak => KERNEL_DEBUG_BREAK:
                ("KERNEL", 203u16, Stack, &[], Void);
            KernelFatalExit => KERNEL_FATAL_EXIT:
                ("KERNEL", 1u16, Stack, kernel_diagnostics::FATAL_EXIT, Void);
        }
    };
}
