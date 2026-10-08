//! Host-side shell icon extraction requests and opaque icon-token results.

use crate::Win16HostIcon;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostShellIconCall {
    ExtractIcon { path: Vec<u8>, index: i16 },
    ExtractAssociatedIcon { path: Vec<u8>, index: u16 },
    ExtractIconEx {
        path: Vec<u8>,
        index: i16,
        count: u16,
        large: bool,
        small: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostShellIconResult {
    /// A missing/invalid icon is represented by `None`, as the guest API does.
    Icon { icon: Option<Win16HostIcon> },
    /// SHELL.34's Win16 contract returns the numeric sentinel `1` when the
    /// input is not an executable, DLL, or icon file. This is not an HICON and
    /// must never enter the opaque host-icon ownership table. Provenance:
    /// ECMA-234:1995, §5, entry 403.3 (Windows 3.1 APIW); Microsoft Windows
    /// 3.1 Programmer's Reference, Volume 1, §7.4 describes ExtractIcon's
    /// Win16 API surface. The Microsoft Learn ExtractIconW page documents the
    /// corresponding modern Windows host behavior, not the guest contract.
    NonIconFile,
    /// ExtractIcon's index -1 form returns a count instead of an HICON.
    IconCount { count: u32 },
    /// ExtractAssociatedIcon output. When `icon` is present, `path` contains
    /// the returned ANSI path without its terminating NUL and `index` is the
    /// returned resource index. The runtime appends the guest terminator.
    AssociatedIcon {
        icon: Option<Win16HostIcon>,
        path: Vec<u8>,
        index: u16,
    },
    /// `failed` represents the native UINT_MAX failure result. The runtime
    /// leaves guest output arrays unchanged and returns the guest failure code.
    Extracted {
        failed: bool,
        count: u16,
        large: Vec<Option<Win16HostIcon>>,
        small: Vec<Option<Win16HostIcon>>,
    },
}
