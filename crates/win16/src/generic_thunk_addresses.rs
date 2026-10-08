//! Guest-address resolution for `GetVDMPointer32W`.
//!
//! This layer translates a Win16 16:16 value into an offset in guest memory.
//! It never creates or returns a host pointer, and it does not decide whether
//! the resulting range intersects ROM, VGA, or another memory mapping. The
//! runtime validates the actual requested range against `Memory` separately.
//!
//! Microsoft Learn documents `fMode` 0 as real mode and 1 as protected mode,
//! and documents a NULL return on failure. It does not define other mode
//! values or a special input rule for real-mode `0000:0000`; those values are
//! not given invented semantics here. The local Windows 3.1 `WINDOWS.H` reference has
//! no declaration for this later generic-thunk API. For the real-mode layout,
//! the local Windows 3.0 SDK *Guide to Programming*, “Using Huge Memory Blocks
//! in the Standard-Mode Memory Configuration,” describes paragraph-aligned
//! 16-byte segment addresses and offsets within a 64 KiB segment.
//!
//! References:
//! - Microsoft Learn, `GetVDMPointer32W`:
//!   <https://learn.microsoft.com/en-us/previous-versions/aa383698(v=vs.85)>
//! - Local snapshot:
//!   `../../work/reference/windows-sdk/3.0/manuals/Windows_3.0_SDK_Guide_to_Programming_PCjs.html`

use guest_core::{real_address, PhysAddr, Selector};

use crate::{SelectorTable, Win16Error};

const REAL_MODE_SEGMENT_BYTES: u32 = 0x1_0000;

/// Resolved guest offset and the part of its segment still available from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ResolvedGuestAddress {
    /// Checked offset in the runtime's guest address space.
    pub address: PhysAddr,
    /// Bytes from `address` through the end of this real-mode segment or
    /// protected-mode selector limit. Runtime callers must still validate the
    /// actual operation length against `Memory`.
    pub available_length: u32,
}

/// A typed failure while translating a `GetVDMPointer32W` guest address.
///
/// The export's documented failure result is NULL; an outer dispatch layer
/// can map these errors to that guest result while retaining a useful cause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GetVDMPointer32WAddressError {
    /// `fMode` is outside the two values documented by Microsoft.
    UnsupportedMode { mode: u16 },
    /// The protected-mode selector cannot be resolved in this runtime's table.
    Selector {
        selector: u16,
        error: Win16Error,
    },
    /// The protected-mode offset lies beyond the selector's available bytes.
    OffsetOutOfRange {
        selector: u16,
        offset: u16,
        limit: u32,
    },
    /// Adding a protected-mode offset to the guest descriptor base overflowed.
    AddressOverflow { base: PhysAddr, offset: u16 },
}

impl std::fmt::Display for GetVDMPointer32WAddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedMode { mode } => {
                write!(f, "GetVDMPointer32W mode {mode} is unsupported")
            }
            Self::Selector { selector, error } => write!(
                f,
                "GetVDMPointer32W selector 0x{selector:04X} is invalid: {error}"
            ),
            Self::OffsetOutOfRange {
                selector,
                offset,
                limit,
            } => write!(
                f,
                "GetVDMPointer32W offset 0x{offset:04X} exceeds selector 0x{selector:04X} limit 0x{limit:08X}"
            ),
            Self::AddressOverflow { base, offset } => write!(
                f,
                "GetVDMPointer32W guest address 0x{:08X} + 0x{offset:04X} overflows",
                base.0
            ),
        }
    }
}

impl std::error::Error for GetVDMPointer32WAddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Selector { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Resolve one 16:16 guest address according to the documented `fMode`.
///
/// Mode 0 uses the real-mode `segment * 16 + offset` formula, including
/// `0000:0000` as guest offset zero. Mode 1 resolves the selector's current
/// descriptor and checks the offset against its limit. No memory-access
/// rights are imposed here because the API translates an address without an
/// access direction or length; callers validate the later operation with
/// `Memory::validate_ram_range`.
pub fn resolve_get_vdm_pointer32w(
    address_far: u32,
    mode: u16,
    selectors: &SelectorTable,
) -> Result<ResolvedGuestAddress, GetVDMPointer32WAddressError> {
    let offset = address_far as u16;
    let selector_or_segment = (address_far >> 16) as u16;

    match mode {
        0 => {
            // `real_address` is bounded by 16-bit inputs: its largest result
            // is 0x10FFEF, within the guest PhysAddr width.
            Ok(ResolvedGuestAddress {
                address: real_address(selector_or_segment, offset),
                available_length: REAL_MODE_SEGMENT_BYTES - u32::from(offset),
            })
        }
        1 => resolve_protected(selector_or_segment, offset, selectors),
        mode => Err(GetVDMPointer32WAddressError::UnsupportedMode { mode }),
    }
}

fn resolve_protected(
    raw_selector: u16,
    offset: u16,
    selectors: &SelectorTable,
) -> Result<ResolvedGuestAddress, GetVDMPointer32WAddressError> {
    let selector = Selector(raw_selector);
    let reference = selectors.reference(selector).map_err(|error| {
        GetVDMPointer32WAddressError::Selector {
            selector: raw_selector,
            error,
        }
    })?;
    let descriptor = selectors.describe(reference).map_err(|error| {
        GetVDMPointer32WAddressError::Selector {
            selector: raw_selector,
            error,
        }
    })?;

    let offset32 = u32::from(offset);
    if offset32 > descriptor.limit {
        return Err(GetVDMPointer32WAddressError::OffsetOutOfRange {
            selector: raw_selector,
            offset,
            limit: descriptor.limit,
        });
    }

    // GetVDMPointer32W only translates a pointer; it carries no read/write
    // direction, so this uses descriptor identity and limit checks without
    // guessing an access right.
    let address = descriptor
        .base
        .0
        .checked_add(offset32)
        .map(PhysAddr)
        .ok_or(GetVDMPointer32WAddressError::AddressOverflow {
            base: descriptor.base,
            offset,
        })?;
    let available_length = descriptor
        .limit
        .checked_sub(offset32)
        .and_then(|remaining| remaining.checked_add(1))
        .ok_or(GetVDMPointer32WAddressError::OffsetOutOfRange {
            selector: raw_selector,
            offset,
            limit: descriptor.limit,
        })?;

    Ok(ResolvedGuestAddress {
        address,
        available_length,
    })
}
