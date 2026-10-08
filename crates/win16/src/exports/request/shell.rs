//! Typed legacy SHELL environment API arguments.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ShellRequest {
    DoEnvironmentSubst { buffer: u32, capacity: u16 },
    FindEnvironmentString { query: Vec<u8> },
}
