//! Bounded Win16 RT_MENU and LoadMenuIndirect template marshaling.

use formats::{Win16Menu as ParsedMenu, Win16MenuItem as ParsedMenuItem};
use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{Access, SegmentedPointer, Win16ResourceName, MAX_WIN16_STRING_BYTES};
use win16_abi::exports::menu_abi as flags;

use super::super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16MenuTemplate,
    Win16MenuTemplateItem};

const MAX_MENU_TEMPLATE_BYTES: usize = 65_536;
const MAX_MENU_TEMPLATE_ITEMS: usize = 4096;
const MAX_MENU_TEMPLATE_DEPTH: usize = 32;
/// Predefined Win16 resource type from the Windows 3.1 SDK USER/resource ABI.
const RT_MENU_RESOURCE_TYPE: u16 = 4;

impl Win16State {
    pub(in crate::win16_runtime) fn resource_menu_template(
        &self,
        instance: u16,
        name: Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16MenuTemplate>, RuntimeError> {
        let info = self.find_resource(
            instance,
            &name,
            &Win16ResourceName::Id(RT_MENU_RESOURCE_TYPE),
            host,
        )?;
        if info == 0 {
            return Ok(None);
        }
        let Some(metadata) = self.resource_metadata(instance, info) else {
            return Ok(None);
        };
        if self.resource_handlers.contains_key(&(metadata.key.module, metadata.type_index)) {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "LoadMenu cannot invoke the custom KERNEL resource handler for RT_MENU"));
            return Ok(None);
        }
        let Some(record) = self.modules.records.get(&metadata.key.module) else {
            return Ok(None);
        };
        let end = metadata.offset.checked_add(metadata.length).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant, "Win16 RT_MENU file range overflow"))?;
        let Some(bytes) = record.image.get(metadata.offset..end) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 RT_MENU range is outside its owning module image"));
        };
        let parsed = match formats::parse_win16_menu(bytes) {
            Ok(menu) => menu,
            Err(formats::FormatError::AllocationFailed) => {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "cannot allocate parsed Win16 RT_MENU"));
            }
            Err(error) => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("selected RT_MENU resource could not be decoded: {error}")));
                return Ok(None);
            }
        };
        Self::host_menu_template(&parsed, host)
    }

    pub(super) fn host_menu_template(
        menu: &ParsedMenu,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16MenuTemplate>, RuntimeError> {
        let mut items = Vec::new();
        items.try_reserve_exact(menu.items.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve native Win16 menu template", error))?;
        for item in &menu.items {
            let item = match item {
                ParsedMenuItem::Popup { flags, text, menu } => {
                    if flags & (flags::MF_BITMAP | flags::MF_OWNERDRAW) != 0 {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            "RT_MENU popup content is not a text-backed menu item"));
                        return Ok(None);
                    }
                    let Some(submenu) = Self::host_menu_template(menu, host)? else {
                        return Ok(None);
                    };
                    Win16MenuTemplateItem::Popup {
                        flags: *flags, text: clone_menu_bytes(text)?, submenu,
                    }
                }
                ParsedMenuItem::Item { flags, id, text } => {
                    if flags & (flags::MF_BITMAP | flags::MF_OWNERDRAW) != 0 {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            "RT_MENU command content needs bitmap or owner-draw resource conversion"));
                        return Ok(None);
                    }
                    Win16MenuTemplateItem::Command {
                        flags: *flags, id: *id, text: clone_menu_bytes(text)?,
                    }
                }
                ParsedMenuItem::Separator { flags, id } => {
                    Win16MenuTemplateItem::Separator { flags: *flags, id: *id }
                }
            };
            items.push(item);
        }
        Ok(Some(Win16MenuTemplate { items }))
    }

    /// Scan through the outer MF_END while reading only bytes needed to find
    /// the end of this template, then hand the exact prefix to the shared
    /// format parser. Trailing guest data is never copied to the host buffer.
    pub(super) fn read_menu_template(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let descriptor = self.selectors.describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let available = usize::try_from(descriptor.limit)
            .ok().and_then(|limit| limit.checked_add(1))
            .and_then(|end| end.checked_sub(usize::from(pointer.offset())))
            .unwrap_or(0)
            .min(MAX_MENU_TEMPLATE_BYTES);
        let mut reader = MenuTemplateReader {
            selectors: &self.selectors,
            memory,
            base: pointer,
            available,
            offset: 0,
            item_count: 0,
        };
        let Some(version) = reader.read_word()? else { return Ok(None); };
        let Some(extension) = reader.read_word()? else { return Ok(None); };
        if version != 0 { return Ok(None); }
        reader.offset = 4_usize.saturating_add(usize::from(extension));
        if reader.offset > available || !reader.scan_menu(0)? { return Ok(None); }
        self.read_text_bytes(memory, pointer, reader.offset).map(Some)
    }
}

struct MenuTemplateReader<'a> {
    selectors: &'a win16_abi::SelectorTable,
    memory: &'a Memory,
    base: SegmentedPointer,
    available: usize,
    offset: usize,
    item_count: usize,
}

impl MenuTemplateReader<'_> {
    fn read_byte(&mut self) -> Result<Option<u8>, RuntimeError> {
        if self.offset >= self.available { return Ok(None); }
        let offset = u32::try_from(self.offset).map_err(|error| RuntimeError::with_source(
            Kind::GuestFault, "Win16 menu template offset exceeds guest address space", error))?;
        let pointer = self.selectors.add_bytes(self.base, offset)
            .map_err(crate::runtime_error)?;
        let address = self.selectors.translate(pointer, Access::Read, 1, self.memory)
            .map_err(crate::runtime_error)?;
        let mut byte = [0_u8; 1];
        self.memory.read(address, &mut byte).map_err(crate::runtime_error)?;
        self.offset += 1;
        Ok(Some(byte[0]))
    }

    fn read_word(&mut self) -> Result<Option<u16>, RuntimeError> {
        let Some(low) = self.read_byte()? else { return Ok(None); };
        let Some(high) = self.read_byte()? else { return Ok(None); };
        Ok(Some(u16::from_le_bytes([low, high])))
    }

    fn skip_string(&mut self) -> Result<bool, RuntimeError> {
        let mut length = 0_usize;
        loop {
            let Some(byte) = self.read_byte()? else { return Ok(false); };
            if byte == 0 { return Ok(true); }
            length += 1;
            if length > MAX_WIN16_STRING_BYTES { return Ok(false); }
        }
    }

    fn scan_menu(&mut self, depth: usize) -> Result<bool, RuntimeError> {
        if depth > MAX_MENU_TEMPLATE_DEPTH { return Ok(false); }
        loop {
            let Some(serialized_flags) = self.read_word()? else { return Ok(false); };
            self.item_count = self.item_count.saturating_add(1);
            if self.item_count > MAX_MENU_TEMPLATE_ITEMS { return Ok(false); }
            let complete = if serialized_flags & flags::MF_POPUP != 0 {
                self.skip_string()? && self.scan_menu(depth + 1)?
            } else {
                self.read_word()?.is_some() && self.skip_string()?
            };
            if !complete { return Ok(false); }
            if serialized_flags & flags::MF_END != 0 { return Ok(true); }
        }
    }
}

fn clone_menu_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy Win16 menu item text", error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
