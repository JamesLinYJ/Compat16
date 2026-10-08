//! Pointer-free payloads for synchronous Win16 KERNEL path services.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostPathInfoOperation {
    WindowsDirectory,
    SystemDirectory,
    TempFileName { drive: u8, prefix: Option<Vec<u8>>, unique: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostTempFileName {
    /// Full path encoded with the configured guest OEM code page.
    pub path: Vec<u8>,
    pub unique: u16,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostPathInfoResult {
    /// `None` is an ordinary failure from the corresponding Windows API.
    Directory(Option<Vec<u8>>),
    /// A successful nonzero unique value does not create a file; unique zero
    /// creates and closes one according to GetTempFileName semantics.
    TempFileName(Option<Win16HostTempFileName>),
}
