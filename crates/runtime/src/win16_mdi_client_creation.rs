//! Checked Win16 CLIENTCREATESTRUCT input for the predefined MDI client class.
//!
//! This is a child module of `win16_runtime`. It converts the guest's fixed
//! Win16 wire layout into opaque runtime/host values; guest FAR pointers and
//! HMENU words never cross the host boundary.

use guest_core::memory::Memory;
use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::Win16State;
use crate::{RuntimeError, Win16HostMenu, Win16HostSystemClass};

/// Windows 3.1 SDK `WINDOWS.H` declares `CLIENTCREATESTRUCT` as an `HMENU`
/// followed by a `UINT`. In the 16-bit ABI both fields are WORDs, so the
/// structure is four bytes with fields at offsets zero and two.
const CLIENTCREATESTRUCT16_SIZE: usize = 4;

#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ClientCreateStruct16Wire {
    window_menu: U16,
    first_child_id: U16,
}

const _: () = {
    assert!(core::mem::size_of::<ClientCreateStruct16Wire>() == CLIENTCREATESTRUCT16_SIZE);
    assert!(core::mem::align_of::<ClientCreateStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(ClientCreateStruct16Wire, window_menu) == 0);
    assert!(core::mem::offset_of!(ClientCreateStruct16Wire, first_child_id) == 2);
};

/// Owned `CLIENTCREATESTRUCT` data after guest HMENU validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMdiClientCreate {
    /// Opaque menu identity, or `None` when the guest supplied HMENU zero.
    pub window_menu: Option<Win16HostMenu>,
    pub first_child_id: u16,
}

/// Separates an unrelated CreateWindow call from a valid MDI client request
/// and a request rejected by its guest pointer/menu contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MdiClientCreatePreparation {
    NotMdiClient,
    Prepared(Win16HostMdiClientCreate),
    Rejected,
}

impl Win16State {
    /// Copy and validate the Win16 `CLIENTCREATESTRUCT` only for the exact
    /// predefined MDI client class identity, never by comparing class names.
    pub(super) fn prepare_mdi_client_creation(
        &self,
        class: &super::classes::ResolvedWindowClass,
        parameter: u32,
        memory: &Memory,
    ) -> Result<MdiClientCreatePreparation, RuntimeError> {
        if class.system_kind != Some(Win16HostSystemClass::MdiClient) {
            return Ok(MdiClientCreatePreparation::NotMdiClient);
        }

        // The Windows 3.1 SDK MDI client contract requires lpParam to point
        // to CLIENTCREATESTRUCT. A null FAR cannot be decoded as an all-zero
        // substitute structure.
        if parameter == 0 {
            return Ok(MdiClientCreatePreparation::Rejected);
        }

        let pointer = self
            .selectors
            .pointer_from_far(parameter)
            .map_err(crate::runtime_error)?;
        let mut bytes = [0_u8; CLIENTCREATESTRUCT16_SIZE];
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        let wire = ClientCreateStruct16Wire::read_from_bytes(&bytes).map_err(|_| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "checked CLIENTCREATESTRUCT16 bytes failed their fixed wire decoder",
            )
        })?;

        let guest_menu = wire.window_menu.get();
        let window_menu = if guest_menu == 0 {
            None
        } else {
            let Some(menu) = self.guest_menus.resolve(guest_menu) else {
                // An unknown guest HMENU makes CreateWindow fail normally;
                // it is never reinterpreted as a native handle.
                return Ok(MdiClientCreatePreparation::Rejected);
            };
            Some(menu)
        };

        Ok(MdiClientCreatePreparation::Prepared(
            Win16HostMdiClientCreate {
                window_menu,
                first_child_id: wire.first_child_id.get(),
            },
        ))
    }
}
