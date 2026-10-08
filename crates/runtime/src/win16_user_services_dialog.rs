//! Win16 dialog-template decoding and guest resource/selector boundaries.

use guest_core::{memory::Memory, Registers};
use win16_abi::{Access, Win16ResourceName, Win16ReturnKind};

use super::{windows::WindowReturn, Win16State};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDialogAtom,
    Win16HostDialogFont, Win16HostDialogItem, Win16HostDialogOperation,
    Win16HostDialogTemplate, Win16HostUserServiceOperation, Win16WindowOperation,
};

// Win16 RT_DIALOG is the predefined numeric resource type ID 5.
const RT_DIALOG: u16 = 5;
const WIN16_DS_SETFONT: u32 = 0x0040;
const MAX_DIALOG_TEMPLATE_BYTES: usize = 1024 * 1024;

struct DialogTemplateReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DialogTemplateReader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(count)?;
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(value)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn word(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn signed_word(&mut self) -> Option<i16> {
        Some(i16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn dword(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string_atom(&mut self) -> Option<Win16HostDialogAtom> {
        let first = self.byte()?;
        if first == 0 {
            return Some(Win16HostDialogAtom::None);
        }
        self.ansi_string_after(first)
    }

    fn resource_atom(&mut self) -> Option<Win16HostDialogAtom> {
        let first = self.byte()?;
        if first == 0 {
            return Some(Win16HostDialogAtom::None);
        }
        if first == 0xff {
            return self.word().map(Win16HostDialogAtom::Ordinal);
        }
        self.ansi_string_after(first)
    }

    fn item_class(&mut self) -> Option<Win16HostDialogAtom> {
        let first = self.byte()?;
        match first {
            0 => Some(Win16HostDialogAtom::None),
            0x80..=0x85 => Some(Win16HostDialogAtom::Ordinal(u16::from(first))),
            0x86..=0xff => None,
            _ => self.ansi_string_after(first),
        }
    }

    fn ansi_string_after(&mut self, first: u8) -> Option<Win16HostDialogAtom> {
        let remaining = self.bytes.get(self.offset..)?;
        let terminator = remaining.iter().position(|byte| *byte == 0)?;
        let end = self.offset.checked_add(terminator)?;
        let string = self.bytes.get(self.offset..end)?;
        self.offset = end.checked_add(1)?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(string.len().checked_add(1)?).ok()?;
        owned.push(first);
        owned.extend_from_slice(string);
        Some(Win16HostDialogAtom::String(owned))
    }
}

/// Decode the documented Win16 `DLGTEMPLATE` representation. This is the
/// Windows 3.x byte format, not the later UTF-16/extended Win32 format.
/// The runtime owns this bounded reader because host USER accepts only a
/// native template after the Win16 byte strings and creation-data counts have
/// been checked and copied; no available codec represents this legacy layout.
/// A malformed or unsupported resource returns `None`, matching the dialog
/// creation APIs' ordinary null-HWND failure result.
pub(crate) fn parse_win16_dialog_template(
    bytes: &[u8],
) -> Option<Win16HostDialogTemplate> {
    if bytes.len() > MAX_DIALOG_TEMPLATE_BYTES { return None; }
    let mut reader = DialogTemplateReader { bytes, offset: 0 };
    let style = reader.dword()?;
    let item_count = usize::from(reader.byte()?);
    let x = reader.signed_word()?;
    let y = reader.signed_word()?;
    let width = reader.signed_word()?;
    let height = reader.signed_word()?;
    let menu = reader.resource_atom()?;
    let class = reader.string_atom()?;
    let title = reader.string_atom()?;
    let font = if style & WIN16_DS_SETFONT != 0 {
        Some(Win16HostDialogFont {
            point_size: reader.signed_word()?,
            face_name: match reader.string_atom()? {
                Win16HostDialogAtom::String(name) => name,
                Win16HostDialogAtom::None
                | Win16HostDialogAtom::Ordinal(_)
                | Win16HostDialogAtom::GuestClass(_) => return None,
            },
        })
    } else {
        None
    };

    let mut items = Vec::new();
    items.try_reserve_exact(item_count).ok()?;
    for _ in 0..item_count {
        let x = reader.signed_word()?;
        let y = reader.signed_word()?;
        let width = reader.signed_word()?;
        let height = reader.signed_word()?;
        let id = reader.word()?;
        let style = reader.dword()?;
        let class = reader.item_class()?;
        let title = reader.resource_atom()?;
        let creation_size = usize::from(reader.byte()?);
        let creation_data = reader.take(creation_size)?;
        let mut owned_creation = Vec::new();
        owned_creation.try_reserve_exact(creation_size).ok()?;
        owned_creation.extend_from_slice(creation_data);
        items.push(Win16HostDialogItem {
            style, x, y, width, height, id, class, guest_class_name: None, title,
            creation_data: owned_creation,
        });
    }

    Some(Win16HostDialogTemplate {
        style, x, y, width, height, menu, menu_template: None, class,
        guest_class_name: None, title, font, items,
    })
}

impl Win16State {
    /// Execute MessageBoxW through the window worker so its modal message
    /// pump can suspend for ordinary guest WndProc continuations. Owner HWND16
    /// values are translated through the shared window table; unknown nonzero
    /// handles receive the API's normal failure value.
    pub(super) fn begin_user_message_box(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        owner: u16,
        text: Option<Vec<u8>>,
        caption: Option<Vec<u8>>,
        style: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let native_owner = if owner == 0 {
            None
        } else if let Some(window) = self.window_handles.get(&owner).copied() {
            Some(window)
        } else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        host.observe_win16_io(&crate::Win16IoEvent::Dialog {
            api: "MessageBox",
            caption: caption.as_deref().unwrap_or_default(),
            text: text.as_deref().unwrap_or_default(),
        });
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::UserService(Win16HostUserServiceOperation::Dialog(
                Win16HostDialogOperation::MessageBox {
                    owner: native_owner,
                    text,
                    caption,
                    style,
                },
            )),
            WindowReturn::UserMessageBox,
            return_to,
        )
    }

    /// Read a memory-template tail only within the selector's declared
    /// allocation, then decode the Win16 byte format.
    pub(super) fn dialog_template_from_far(
        &self,
        memory: &Memory,
        far_pointer: u32,
    ) -> Result<Option<Win16HostDialogTemplate>, RuntimeError> {
        if far_pointer == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far_pointer)
            .map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 dialog template starts beyond its selector limit"))?;
        let length = usize::try_from(available).unwrap_or(usize::MAX)
            .min(MAX_DIALOG_TEMPLATE_BYTES);
        let bytes = self.read_text_bytes(memory, pointer, length)?;
        Ok(parse_win16_dialog_template(&bytes))
    }

    /// Resolve an indirect-dialog HGLOBAL using the guest heap's checked lock
    /// path, copy its bytes, and release the temporary lock before returning.
    pub(super) fn dialog_template_from_global(
        &mut self,
        guest_handle: u16,
        memory: &Memory,
    ) -> Result<Option<Win16HostDialogTemplate>, RuntimeError> {
        if guest_handle == 0 { return Ok(None); }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(None);
        };
        let info = match self.heap.info(identity) {
            Ok(info) if !info.discarded && info.size != 0 => info,
            Ok(_) | Err(win16_abi::Win16Error::InvalidHandle) => return Ok(None),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let length = usize::try_from(info.size).unwrap_or(usize::MAX)
            .min(MAX_DIALOG_TEMPLATE_BYTES);
        let pointer = self.heap.lock(identity, &mut self.selectors, memory)
            .map_err(crate::runtime_error)?;
        let copied = self.read_text_bytes(memory, pointer, length);
        let unlocked = self.heap.unlock(identity, &mut self.selectors);
        let bytes = match (copied, unlocked) {
            (Ok(bytes), Ok(_)) => bytes,
            (Err(error), _) => return Err(error),
            (Ok(_), Err(error)) => return Err(crate::runtime_error(error)),
        };
        Ok(parse_win16_dialog_template(&bytes))
    }

    /// Resolve and decode the predefined `RT_DIALOG` NE type without creating a second
    /// resource registry or changing the existing HGLOBAL ownership rules.
    pub(super) fn dialog_template_from_resource(
        &self,
        module: u16,
        name: &Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16HostDialogTemplate>, RuntimeError> {
        let info = self.find_resource(
            module,
            name,
            &Win16ResourceName::Id(RT_DIALOG),
            host,
        )?;
        if info == 0 { return Ok(None); }
        let Some(metadata) = self.resource_metadata(module, info) else {
            return Ok(None);
        };
        let Some(record) = self.modules.records.get(&metadata.key.module) else {
            return Ok(None);
        };
        let Some(end) = metadata.offset.checked_add(metadata.length) else {
            return Ok(None);
        };
        let Some(bytes) = record.image.get(metadata.offset..end) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 dialog resource metadata exceeds its module image"));
        };
        Ok(parse_win16_dialog_template(bytes))
    }
}

impl Win16State {
    /// Validate a DLGPROC as executable guest code without treating it as a
    /// host callback pointer. The worker later enters it through a dedicated
    /// BOOL16 Pascal callback frame.
    pub(super) fn validate_dialog_procedure(
        &self,
        far_procedure: u32,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        let pointer = self.selectors.pointer_from_far(far_procedure)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Execute, 1, memory)
            .map(|_| ())
            .map_err(crate::runtime_error)
    }
}
