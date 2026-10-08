//! Checked conversion of the packed Win16 toolbar request into owned host data.

use guest_core::{memory::Memory, GuestMemory};
use win16_abi::Access;
use zerocopy::byteorder::little_endian::I16;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostCommonControlsOperation as Operation, Win16HostToolbarBitmap,
    Win16HostToolbarButton};

const BUTTON16_SIZE: usize = 8;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
struct ToolbarButton16Wire {
    image_index: I16,
    command_id: I16,
    state: u8,
    style: u8,
    help_data: I16,
}

const _: () = assert!(core::mem::size_of::<ToolbarButton16Wire>() == BUTTON16_SIZE);

impl Win16State {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_toolbar(
        &self,
        memory: &Memory,
        parent: u16,
        style: u32,
        id: u16,
        bitmap_count_word: u16,
        bitmap_instance: u16,
        bitmap_resource: u16,
        buttons_far: u32,
        button_count_word: u16,
        dimensions: (i16, i16, i16, i16, u16),
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Operation>, RuntimeError> {
        let bitmap_count = i16::from_le_bytes(bitmap_count_word.to_le_bytes());
        let button_count = i16::from_le_bytes(button_count_word.to_le_bytes());
        if bitmap_count < 0 || button_count < 0 {
            return Ok(None);
        }
        if dimensions.4 != BUTTON16_SIZE as u16 {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "CreateToolbarEx requires the documented packed 8-byte Win16 TBBUTTON size"));
            return Ok(None);
        }
        let Some(parent) = self.window_handles.get(&parent).copied() else {
            return Ok(None);
        };
        let bitmap = if bitmap_instance == u16::MAX {
            // HINST_COMMCTRL is the documented pseudo-instance used for the
            // built-in toolbar image resources; it is not a guest module.
            Win16HostToolbarBitmap::CommonControlResource(bitmap_resource)
        } else if bitmap_count == 0 {
            Win16HostToolbarBitmap::None
        } else if bitmap_instance == 0 {
            let Some(object) = self.guest_gdi.object(bitmap_resource) else {
                return Ok(None);
            };
            Win16HostToolbarBitmap::GuestObject(object)
        } else {
            let Some(dib) = self.read_toolbar_bitmap(bitmap_instance, bitmap_resource, host)? else {
                return Ok(None);
            };
            Win16HostToolbarBitmap::OwnedDib(dib)
        };
        let buttons = self.read_buttons(memory, buttons_far, button_count as usize)?;
        let (button_width, button_height, bitmap_width, bitmap_height, guest_button_size) = dimensions;
        Ok(Some(Operation::CreateToolbar {
            style, parent, id, bitmap_count, bitmap, buttons,
            button_width, button_height, bitmap_width, bitmap_height,
            guest_button_size,
        }))
    }

    fn read_buttons(
        &self,
        memory: &Memory,
        far: u32,
        count: usize,
    ) -> Result<Vec<Win16HostToolbarButton>, RuntimeError> {
        if count == 0 { return Ok(Vec::new()); }
        if far == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "CreateToolbar has a null button array with a nonzero count"));
        }
        let length = count.checked_mul(BUTTON16_SIZE).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "CreateToolbar button-array extent overflow"))?;
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let end = usize::from(pointer.offset()).checked_add(length).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "CreateToolbar button-array address overflow"))?;
        if end > descriptor.limit as usize + 1 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "CreateToolbar ordinary FAR button array crosses its selector"));
        }
        let address = self.selectors.translate(pointer, Access::Read, length, memory)
            .map_err(crate::runtime_error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "capture CreateToolbar button array", error))?;
        bytes.resize(length, 0);
        memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
        let mut result = Vec::new();
        result.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "convert CreateToolbar button array", error))?;
        for chunk in bytes.chunks_exact(BUTTON16_SIZE) {
            let wire = ToolbarButton16Wire::read_from_bytes(chunk).map_err(|_|
                RuntimeError::new(Kind::InternalInvariant,
                    "captured CreateToolbar button has an invalid fixed wire layout"))?;
            result.push(Win16HostToolbarButton {
                image_index: wire.image_index.get(),
                command_id: wire.command_id.get(),
                state: wire.state,
                style: wire.style,
                help_data: wire.help_data.get(),
            });
        }
        Ok(result)
    }
}
