//! Remaining KERNEL exports.
//!
//! Stack calls carry the decoded guest scalars. Register-context glue carries
//! only the ordinal; the CPU still holds the entry registers. Neither form
//! stores a host pointer.

use crate::Win16Argument;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelRemainderRequest {
    Stack {
        ordinal: u16,
        arguments: Vec<Win16Argument>,
    },
    /// Register-context KERNEL glue. There is no 32-bit callee.
    Register { ordinal: u16 },
}

/// Register-context KERNEL ordinals whose catalog entry has no stack arguments.
pub fn is_kernel_register_remainder(ordinal: u16) -> bool {
    matches!(ordinal, 327 | 472 | 473 | 604 | 620 | 621 | 630 | 631 | 704)
}
