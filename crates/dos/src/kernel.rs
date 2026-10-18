mod block_lease;
mod block_view;
mod caller_address_space;
mod console;
mod time;
mod temporary_file;
mod device;
mod directory;
mod disk;
mod dispatch;
mod exec;
mod extended_open;
mod extended_error;
mod files;
mod file_commit;
mod file_time;
mod ioctl;
mod memory;
mod message_addresses;
mod nls;
mod dbcs;
#[cfg(test)]
mod dbcs_tests;
mod protected_scalar;
mod sft;
mod handle_capacity;
mod state;
mod system;
mod vectors;
mod version;

pub use block_lease::DosBlockLease;
pub use block_view::DosBlockExtent;
pub use nls::{collating_table, upper_case_table};
pub use dbcs::dbcs_lead_byte_table;
pub use state::{DosChildProcessFailure, DosKernel};
pub use system::{SYSTEM_BYTES, SYSTEM_SEGMENT};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ioctl_tests;

#[cfg(test)]
mod nls_tests;

#[cfg(test)]
mod nls_country_tests;
#[cfg(test)]
mod nls_prc_tests;

#[cfg(test)]
mod device_tests;
#[cfg(test)]
mod disk_tests;
#[cfg(test)]
mod system_tests;

#[cfg(test)]
mod handle_capacity_tests;

#[cfg(test)]
mod message_addresses_tests;

#[cfg(test)]
mod extended_error_tests;
