//! Owned requests for KERNEL instance and code-segment queries.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelInstanceRequest {
    /// The buffer is a near offset in the caller's current DS. `byte_count`
    /// retains the ABI word; KERNEL interprets it as a signed Win16 `int`.
    GetInstanceData {
        previous_instance: u16,
        buffer_offset: u16,
        byte_count: u16,
    },

    /// Raw guest FARPROC bits. Runtime resolves owned MakeProcInstance thunks
    /// before looking up the containing loaded NE code segment.
    GetCodeHandle { procedure: u32 },

    /// Raw guest FARPROC or module-handle/segment-number pair, plus the far
    /// guest pointer that receives the fixed SEGINFO16 wire structure.
    GetCodeInfo {
        procedure_or_module_segment: u32,
        output: u32,
    },
}
