//! Bounded DOS interrupt services for the guest runtime.
#![forbid(unsafe_code)]

mod caller_address_space;
mod diagnostics;
mod kernel;
mod real_mode_address_space;
mod types;

pub use caller_address_space::{
    DosCallAddressSpace, DosCallerId, DosFarPointer, DosPersistentFarPointer, DosPointerAccess,
    DosSpanPolicy,
};
pub use diagnostics::{DosCallerAddressSpaceFailureKind, DosError, DosErrorCode, DosHostError};
pub use kernel::{DosBlockExtent, DosBlockLease, DosChildProcessFailure, DosKernel};
pub use kernel::{SYSTEM_BYTES, SYSTEM_SEGMENT};
pub use kernel::{collating_table, upper_case_table};
pub use kernel::dbcs_lead_byte_table;
pub use types::{
    DosAction, DosDirectoryEntry, DosDiskSpace, DosExecRequest, DosFileAccess, DosFileSharing,
    DosFileDisposition, DosFileOpenOutcome, DosFileOpenRequest, DosFileOpenResult,
    DosFileStatus, DosHost, DosHostFile, DosHostSearch, DosIoctlObjectInfo, DosIoctlStream,
    DosSeekOrigin, DosLocalDateTime,
};
