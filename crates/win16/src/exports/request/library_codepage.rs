//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16LibraryCodePageRequest {
    IsDbcsLeadByte { value: u8 },
}
