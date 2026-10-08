//! Owned KERNEL profile-section arguments.

use crate::Win16OutputBuffer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelProfileSectionRequest {
    WriteProfileSection {
        section: Option<Vec<u8>>,
        entries: Option<Vec<u8>>,
    },
    WritePrivateProfileSection {
        section: Option<Vec<u8>>,
        entries: Option<Vec<u8>>,
        filename: Option<Vec<u8>>,
    },
    GetProfileSection {
        section: Option<Vec<u8>>,
        /// No guest buffer is needed for a zero-capacity query.
        output_buffer: Option<Win16OutputBuffer>,
    },
    GetPrivateProfileSection {
        section: Option<Vec<u8>>,
        output_buffer: Option<Win16OutputBuffer>,
        filename: Option<Vec<u8>>,
    },
}
