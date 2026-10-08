mod block_lease;
mod block_view;
mod caller_address_space;
mod console;
mod time;
mod device;
mod directory;
mod disk;
mod dispatch;
mod exec;
mod files;
mod ioctl;
mod memory;
mod nls;
mod protected_scalar;
mod sft;
mod state;
mod system;
mod vectors;
mod version;

pub use block_lease::DosBlockLease;
pub use block_view::DosBlockExtent;
pub use nls::{collating_table, upper_case_table};
pub use state::{DosChildProcessFailure, DosKernel};
pub use system::{SYSTEM_BYTES, SYSTEM_SEGMENT};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "ioctl_tests.rs"]
mod ioctl_tests;

#[cfg(test)]
#[path = "nls_tests.rs"]
mod nls_tests;

#[cfg(test)]
#[path = "nls_country_tests.rs"]
mod nls_country_tests;

#[cfg(test)]
mod device_tests;
#[cfg(test)]
#[path = "disk_tests.rs"]
mod disk_tests;
#[cfg(test)]
mod system_tests;
