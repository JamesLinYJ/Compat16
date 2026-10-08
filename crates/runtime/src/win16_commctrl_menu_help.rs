//! Bounded Win16 MenuHelp table capture and guest string-resource translation.

use guest_core::{memory::Memory, GuestMemory};
use win16_abi::Access;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, Win16HostMenu};

const WM_MENUSELECT16: u16 = 0x011f;
const WM_COMMAND16: u16 = 0x0111;
const MF_POPUP16: u16 = 0x0010;

#[derive(Debug)]
pub(super) struct MenuHelpTable {
    pub(super) command_offset: u16,
    pub(super) menu_offset: u16,
    pub(super) popup_ids: Vec<(u16, Win16HostMenu)>,
}

impl Win16State {
    pub(super) fn read_menu_help_offsets(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<(u16, u16), RuntimeError> {
        if far == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "MenuHelp requires a nonnull help-ID table for menu selection"));
        }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let first = read_word(self, memory, pointer, descriptor.limit, 0)?;
        let second = read_word(self, memory, pointer, descriptor.limit, 2)?;
        Ok((first, second))
    }

    pub(super) fn read_menu_help_table(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<MenuHelpTable, RuntimeError> {
        if far == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "MenuHelp popup selection requires a nonnull help-ID table"));
        }
        let (command_offset, menu_offset) = self.read_menu_help_offsets(memory, far)?;
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let mut offset = 4_u32;
        let mut popup_ids = Vec::new();
        loop {
            let popup_id = read_word(self, memory, pointer, descriptor.limit, offset)?;
            let popup_guest = read_word(self, memory, pointer, descriptor.limit,
                offset.checked_add(2).ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                    "MenuHelp table offset overflow"))?)?;
            if popup_id == 0 && popup_guest == 0 { break; }
            if popup_guest != 0 {
                if let Some(menu) = self.guest_menus.resolve(popup_guest) {
                    popup_ids.try_reserve(1).map_err(|error| RuntimeError::with_source(
                        Kind::ResourceExhausted, "capture MenuHelp popup mapping", error))?;
                    popup_ids.push((popup_id, menu));
                }
            }
            offset = offset.checked_add(4).ok_or_else(|| RuntimeError::new(
                Kind::GuestFault, "MenuHelp table offset overflow"))?;
        }
        Ok(MenuHelpTable { command_offset, menu_offset, popup_ids })
    }

    pub(super) fn menu_help_string(
        &self,
        instance: u16,
        string_id: u16,
    ) -> Result<Vec<u8>, RuntimeError> {
        let Some(module) = self.module_handle_for_instance(instance) else {
            return Ok(Vec::new());
        };
        let Some(record) = self.modules.records.get(&module) else { return Ok(Vec::new()); };
        let Some(definition) = record.definition.as_ref() else { return Ok(Vec::new()); };
        let strings = formats::NeStringTable::from_module(&record.image, definition)
            .map_err(crate::runtime_error)?;
        let Some(bytes) = strings.get(string_id).map_err(crate::runtime_error)? else {
            return Ok(Vec::new());
        };
        // The original helper uses LoadString(..., 256), so the ANSI string
        // copied into SB_SETTEXT has at most 255 bytes plus the host NUL.
        let length = bytes.len().min(255);
        let mut copied = Vec::new();
        copied.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "copy MenuHelp string resource", error))?;
        copied.extend_from_slice(&bytes[..length]);
        Ok(copied)
    }
}

pub(super) fn read_word(
    state: &Win16State,
    memory: &Memory,
    base: win16_abi::SegmentedPointer,
    limit: u32,
    offset: u32,
) -> Result<u16, RuntimeError> {
    let first = u32::from(base.offset()).checked_add(offset).ok_or_else(||
        RuntimeError::new(Kind::GuestFault, "MenuHelp table address overflow"))?;
    if first.checked_add(1).is_none_or(|last| last > limit) {
        return Err(RuntimeError::new(Kind::GuestFault,
            "MenuHelp pair-sentinel scan reached the selector boundary"));
    }
    let pointer = state.selectors.add_bytes(base, offset).map_err(crate::runtime_error)?;
    let address = state.selectors.translate(pointer, Access::Read, 2, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = [0_u8; 2];
    memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
    Ok(u16::from_le_bytes(bytes))
}

pub(super) fn selected_help_id(
    message: u16,
    w_param: u16,
    flags: u16,
    command_offset: u16,
) -> Option<u16> {
    match message {
        WM_COMMAND16 => None,
        WM_MENUSELECT16 if flags != u16::MAX => {
            (flags & MF_POPUP16 == 0).then(|| command_offset.wrapping_add(w_param))
        }
        _ => None,
    }
}
