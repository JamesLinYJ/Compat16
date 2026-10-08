// Insert these ABI descriptors in the export catalog after loading
// `kernel_locale.rs`; each row is backed by a typed decoder and runtime method.

KernelIsDbcsLeadByte => KERNEL_IS_DBCS_LEAD_BYTE: ("KERNEL", 207u16, Stack, kernel_locale::IS_DBCS_LEAD_BYTE, Word);
