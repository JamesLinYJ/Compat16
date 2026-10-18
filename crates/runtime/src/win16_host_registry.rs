//! Pointer-free SHELL registry requests passed to the native host.
//!
//! Guest HKEY values are runtime aliases. Only opened native keys cross this
//! boundary as opaque identities; predefined roots use documented constants.

/// Opaque native registry-key identity owned by the Windows host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostRegistryKey(pub u64);

/// Predefined Win16 registry roots accepted by the runtime translator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16RegistryRoot {
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
    PerformanceData,
    CurrentConfig,
    DynamicData,
}

impl Win16RegistryRoot {
    /// Map documented native predefined roots. SHELL's legacy 0/1 encodings
    /// are interpreted by its API translator, not by Win32 KERNEL thunks.
    pub const fn from_guest_handle(handle: u32) -> Option<Self> {
        match handle {
            0x8000_0000 => Some(Self::ClassesRoot),
            0x8000_0001 => Some(Self::CurrentUser),
            0x8000_0002 => Some(Self::LocalMachine),
            0x8000_0003 => Some(Self::Users),
            0x8000_0004 => Some(Self::PerformanceData),
            0x8000_0005 => Some(Self::CurrentConfig),
            0x8000_0006 => Some(Self::DynamicData),
            _ => None,
        }
    }
}

/// A key operand translated by the runtime without exposing a native HKEY.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16RegistryKeyRef {
    Predefined(Win16RegistryRoot),
    Opened(Win16HostRegistryKey),
}

/// Owned-data policy for a native registry read; no guest pointers cross here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16RegistryQueryOutput {
    SizeOnly,
    Bounded(u32),
    /// Return the complete converted value for runtime-side Win3.1 truncation.
    Complete,
    /// Preserve the native API's optional-length validation and key lookup.
    WithoutLength {
        data_present: bool,
    },
}

/// Value semantics are independent of buffer and truncation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16RegistryQueryView {
    /// Preserve RegQueryValue's native supported types and error results.
    Native,
    /// Present REG_EXPAND_SZ as its original text to Win3.1 string-only APIs.
    /// Environment references and the stored native value remain unchanged.
    Win31Strings,
}

/// One operation on the process registry namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostRegistryOperation {
    OpenKey {
        root: Win16RegistryKeyRef,
        subkey: Vec<u8>,
    },
    CreateKey {
        root: Win16RegistryKeyRef,
        subkey: Vec<u8>,
    },
    CloseKey {
        key: Win16RegistryKeyRef,
    },
    DeleteKey {
        root: Win16RegistryKeyRef,
        subkey: Vec<u8>,
    },
    SetValue {
        key: Win16RegistryKeyRef,
        subkey: Vec<u8>,
        value_type: u32,
        /// Checked ANSI string bytes, excluding the terminator. The Win16
        /// API's cbData parameter is ignored before this host boundary.
        value: Vec<u8>,
    },
    QueryValue {
        key: Win16RegistryKeyRef,
        subkey: Vec<u8>,
        output: Win16RegistryQueryOutput,
        view: Win16RegistryQueryView,
    },
    EnumKey {
        key: Win16RegistryKeyRef,
        index: u32,
        capacity: u32,
    },
}

/// The result variant identifies the operation that produced it. Registry
/// status values are native Win32 error codes and remain ordinary guest return
/// values; lengths and copied strings use the guest code page after conversion
/// from the Unicode native registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostRegistryResult {
    OpenKey {
        status: u32,
        key: Option<Win16HostRegistryKey>,
    },
    CreateKey {
        status: u32,
        key: Option<Win16HostRegistryKey>,
    },
    CloseKey {
        status: u32,
    },
    DeleteKey {
        status: u32,
    },
    SetValue {
        status: u32,
    },
    QueryValue {
        status: u32,
        value_type: u32,
        /// Required guest-encoded size in bytes, with any REG_SZ NUL included.
        required_bytes: u32,
        /// Guest-encoded value bytes copied; preserves the native terminator.
        bytes: Vec<u8>,
    },
    EnumKey {
        status: u32,
        /// Required capacity including the output NUL.
        required_bytes: u32,
        /// Subkey name bytes without a trailing NUL.
        name: Vec<u8>,
    },
}
