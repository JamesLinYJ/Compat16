//! Win16 HICON/HCURSOR handles and NE image resource resolution.

use std::collections::{BTreeMap, BTreeSet};

use formats::{NeCursorResourceTable, NeIconResourceTable, NeResourceId};
use win16_abi::Win16ResourceName;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCursor, Win16HostIcon};

// Win16 ExtractIcon returns 1 for a file which is not an icon container.
// Reserve that status and NULL outside the shared HICON/HCURSOR namespace.
const FIRST_GUEST_IMAGE_HANDLE: u16 = 2;

#[derive(Clone, Copy)]
enum GuestImage {
    Icon(Win16HostIcon),
    Cursor(Win16HostCursor),
}

#[derive(Default)]
pub(super) struct GuestImageHandles {
    images: BTreeMap<u16, GuestImage>,
    system_icons: BTreeMap<u16, u16>,
    system_cursors: BTreeMap<u16, u16>,
    /// USER class-template images remain shared for the class-cache lifetime.
    class_images: BTreeSet<u16>,
    module_icons: Vec<(u16, NeResourceId, u16)>,
    module_cursors: Vec<(u16, NeResourceId, u16)>,
    next_handle: u16,
}

impl GuestImageHandles {
    #[cfg(test)]
    pub(super) fn fill_for_get_cursor_test(&mut self) {
        for handle in FIRST_GUEST_IMAGE_HANDLE..=u16::MAX {
            self.images.insert(handle, GuestImage::Icon(Win16HostIcon(u64::from(handle))));
        }
    }

    pub(super) fn new() -> Self {
        Self { next_handle: FIRST_GUEST_IMAGE_HANDLE, ..Self::default() }
    }

    fn allocate(&mut self, image: GuestImage) -> Option<u16> {
        for _ in FIRST_GUEST_IMAGE_HANDLE..=u16::MAX {
            let handle = self.next_handle.max(FIRST_GUEST_IMAGE_HANDLE);
            self.next_handle = if handle == u16::MAX { FIRST_GUEST_IMAGE_HANDLE }
                else { handle + 1 };
            if let std::collections::btree_map::Entry::Vacant(slot) = self.images.entry(handle) {
                slot.insert(image);
                return Some(handle);
            }
        }
        None
    }

    fn retire_released(&mut self, handle: u16) {
        self.images.remove(&handle);
        self.class_images.remove(&handle);
        self.system_icons.retain(|_, cached| *cached != handle);
        self.system_cursors.retain(|_, cached| *cached != handle);
        self.module_icons.retain(|(_, _, cached)| *cached != handle);
        self.module_cursors.retain(|(_, _, cached)| *cached != handle);
    }

    fn prune_dead_cache_entries(&mut self) {
        let mut live_icons = BTreeSet::new();
        let mut live_cursors = BTreeSet::new();
        for (&handle, image) in &self.images {
            match image {
                GuestImage::Icon(_) => { live_icons.insert(handle); }
                GuestImage::Cursor(_) => { live_cursors.insert(handle); }
            }
        }
        self.system_icons.retain(|_, handle| live_icons.contains(handle));
        self.system_cursors.retain(|_, handle| live_cursors.contains(handle));
        self.module_icons.retain(|(_, _, handle)| live_icons.contains(handle));
        self.module_cursors.retain(|(_, _, handle)| live_cursors.contains(handle));
    }

    pub(super) fn allocate_icon(&mut self, icon: Win16HostIcon) -> Option<(u16, bool)> {
        if let Some(handle) = self.images.iter().find_map(|(&handle, image)| match image {
            GuestImage::Icon(existing) if *existing == icon => Some(handle),
            _ => None,
        }) {
            return Some((handle, false));
        }
        self.allocate(GuestImage::Icon(icon)).map(|handle| (handle, true))
    }

    pub(super) fn take_unpublished_icon(
        &mut self,
        handle: u16,
        expected: Win16HostIcon,
    ) -> bool {
        if !matches!(self.images.get(&handle), Some(GuestImage::Icon(icon)) if *icon == expected) {
            return false;
        }
        self.retire_released(handle);
        true
    }

    pub(super) fn allocate_cursor(&mut self, cursor: Win16HostCursor) -> Option<u16> {
        if let Some(handle) = self.images.iter().find_map(|(&handle, image)| match image {
            GuestImage::Cursor(existing) if *existing == cursor => Some(handle),
            _ => None,
        }) {
            return Some(handle);
        }
        self.allocate(GuestImage::Cursor(cursor))
    }

    pub(super) fn allocate_class_icon(&mut self, icon: Win16HostIcon) -> Option<u16> {
        let (handle, _) = self.allocate_icon(icon)?;
        self.class_images.insert(handle);
        Some(handle)
    }

    pub(super) fn allocate_class_cursor(&mut self, cursor: Win16HostCursor) -> Option<u16> {
        let handle = self.allocate_cursor(cursor)?;
        self.class_images.insert(handle);
        Some(handle)
    }

    pub(super) fn destroy_icon(
        &mut self,
        handle: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.class_images.contains(&handle)
            || self.system_icons.values().any(|cached| *cached == handle) {
            return Ok(false);
        }
        let Some(GuestImage::Icon(icon)) = self.images.get(&handle).copied() else {
            return Ok(false);
        };
        host.win16_release_icon(icon)?;
        self.images.remove(&handle);
        self.module_icons.retain(|(_, _, cached)| *cached != handle);
        Ok(true)
    }

    pub(super) fn destroy_cursor(
        &mut self,
        handle: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.class_images.contains(&handle)
            || self.system_cursors.values().any(|cached| *cached == handle) {
            return Ok(false);
        }
        let Some(GuestImage::Cursor(cursor)) = self.images.get(&handle).copied() else {
            return Ok(false);
        };
        host.win16_release_cursor(cursor)?;
        self.images.remove(&handle);
        self.module_cursors.retain(|(_, _, cached)| *cached != handle);
        Ok(true)
    }

    pub(super) fn icon(&self, handle: u16) -> Option<Win16HostIcon> {
        match self.images.get(&handle)? {
            GuestImage::Icon(icon) => Some(*icon),
            GuestImage::Cursor(_) => None,
        }
    }

    pub(super) fn cursor(&self, handle: u16) -> Option<Win16HostCursor> {
        match self.images.get(&handle)? {
            GuestImage::Cursor(cursor) => Some(*cursor),
            GuestImage::Icon(_) => None,
        }
    }
}

fn resource_id(name: Win16ResourceName) -> NeResourceId {
    match name {
        Win16ResourceName::Id(id) => NeResourceId::Numeric(id),
        Win16ResourceName::Name(bytes) => NeResourceId::Name(bytes),
    }
}

fn same_resource_id(left: &NeResourceId, right: &NeResourceId) -> bool {
    match (left, right) {
        (NeResourceId::Numeric(a), NeResourceId::Numeric(b)) => a == b,
        (NeResourceId::Name(a), NeResourceId::Name(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

fn cached_module_handle(
    cache: &[(u16, NeResourceId, u16)],
    module: u16,
    id: &NeResourceId,
) -> Option<u16> {
    cache.iter().find_map(|(cached_module, cached, handle)| {
        (*cached_module == module && same_resource_id(cached, id)).then_some(*handle)
    })
}

impl Win16State {
    pub(super) fn create_image_masks(&mut self, request: win16_abi::Win16UserResourcesRequest,
        memory: &mut guest_core::memory::Memory, host: &mut impl RuntimeHost)
        -> Result<u16, RuntimeError>
    {
        use win16_abi::Win16UserResourcesRequest as Request;
        let (width, height, planes, bits_per_pixel, and_far, xor_far, hotspot) = match request {
            Request::CreateIcon { width, height, planes, bits_per_pixel, and_mask, xor_mask, .. } =>
                (width, height, planes, bits_per_pixel, and_mask, xor_mask, None),
            Request::CreateCursor { width, height, x_hotspot, y_hotspot, and_mask, xor_mask, .. } =>
                (width, height, 1, 1, and_mask, xor_mask, Some((x_hotspot, y_hotspot))),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "non-image factory request reached mask construction")),
        };
        let Some((and_length, xor_length)) = crate::Win16HostImageMasks::lengths(
            width, height, planes, bits_per_pixel,
        ) else { return Ok(0); };
        if and_far == 0 || xor_far == 0 { return Ok(0); }
        let masks = crate::Win16HostImageMasks {
            width, height, planes, bits_per_pixel,
            and_mask: self.copy_image_mask(memory, and_far, and_length)?,
            xor_mask: self.copy_image_mask(memory, xor_far, xor_length)?,
        };
        // CreateIcon/CreateCursor create independent images, not module
        // resources. Guest HINSTANCE never becomes a native module pointer.
        match hotspot {
            None => {
                let Some(icon) = host.win16_create_icon_masks(&masks)? else { return Ok(0); };
                let Some(handle) = self.guest_images.allocate(GuestImage::Icon(icon)) else {
                    host.win16_release_icon(icon)?;
                    return Ok(0);
                };
                Ok(handle)
            }
            Some((x, y)) => {
                let Some(cursor) = host.win16_create_cursor_masks(&masks, x, y)? else { return Ok(0); };
                let Some(handle) = self.guest_images.allocate(GuestImage::Cursor(cursor)) else {
                    host.win16_release_cursor(cursor)?;
                    return Ok(0);
                };
                Ok(handle)
            }
        }
    }

    fn copy_image_mask(&self, memory: &guest_core::memory::Memory, far: u32, length: usize)
        -> Result<Vec<u8>, RuntimeError>
    {
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, win16_abi::Access::Read, length, memory)
            .map_err(crate::runtime_error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted, "copy guest image mask", error))?;
        bytes.resize(length, 0);
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        Ok(bytes)
    }

    pub(super) fn forget_module_image_cache(&mut self, module_handle: u16) {
        self.guest_images.module_icons
            .retain(|(owner, _, _)| *owner != module_handle);
        self.guest_images.module_cursors
            .retain(|(owner, _, _)| *owner != module_handle);
    }

    pub(super) fn load_icon(
        &mut self, instance: u16, name: Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if instance == 0 {
            let Win16ResourceName::Id(id) = name else { return Ok(0); };
            if let Some(&handle) = self.guest_images.system_icons.get(&id) { return Ok(handle); }
            let Some(icon) = host.win16_load_system_icon(id)? else { return Ok(0); };
            let Some(handle) = self.guest_images.allocate(GuestImage::Icon(icon)) else {
                host.win16_release_icon(icon)?;
                return Ok(0);
            };
            self.guest_images.system_icons.insert(id, handle);
            return Ok(handle);
        }
        let Some(module_handle) = self.module_handle_for_instance(instance) else { return Ok(0); };
        let id = resource_id(name);
        if let Some(handle) = cached_module_handle(
            &self.guest_images.module_icons, module_handle, &id,
        ) {
            return Ok(handle);
        }
        let resources = {
            let Some(record) = self.modules.records.get(&module_handle) else { return Ok(0); };
            let Some(definition) = record.definition.as_ref() else { return Ok(0); };
            NeIconResourceTable::from_module(&record.image, definition)
                .map_err(crate::runtime_error)?
        };
        let Some(group) = resources.group_icon(&id)
            .map_err(crate::runtime_error)? else { return Ok(0); };
        let Some(image_id) = host.win16_select_icon_image(&group)? else { return Ok(0); };
        let Some(bytes) = resources.icon_image(image_id)
            .map_err(crate::runtime_error)? else { return Ok(0); };
        let Some(icon) = host.win16_create_icon(&bytes)? else { return Ok(0); };
        let Some(handle) = self.guest_images.allocate(GuestImage::Icon(icon)) else {
            host.win16_release_icon(icon)?;
            return Ok(0);
        };
        self.guest_images.module_icons.push((module_handle, id, handle));
        Ok(handle)
    }

    pub(super) fn load_cursor(
        &mut self, instance: u16, name: Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if instance == 0 {
            let Win16ResourceName::Id(id) = name else { return Ok(0); };
            if let Some(&handle) = self.guest_images.system_cursors.get(&id) { return Ok(handle); }
            let Some(cursor) = host.win16_load_system_cursor(id)? else { return Ok(0); };
            let Some(handle) = self.guest_images.allocate(GuestImage::Cursor(cursor)) else {
                host.win16_release_cursor(cursor)?;
                return Ok(0);
            };
            self.guest_images.system_cursors.insert(id, handle);
            return Ok(handle);
        }
        let Some(module_handle) = self.module_handle_for_instance(instance) else { return Ok(0); };
        let id = resource_id(name);
        if let Some(handle) = cached_module_handle(
            &self.guest_images.module_cursors, module_handle, &id,
        ) {
            return Ok(handle);
        }
        let resources = {
            let Some(record) = self.modules.records.get(&module_handle) else { return Ok(0); };
            let Some(definition) = record.definition.as_ref() else { return Ok(0); };
            NeCursorResourceTable::from_module(&record.image, definition)
                .map_err(crate::runtime_error)?
        };
        let Some(group) = resources.group_cursor(&id)
            .map_err(crate::runtime_error)? else { return Ok(0); };
        let Some(image_id) = host.win16_select_cursor_image(&group)? else { return Ok(0); };
        let Some(bytes) = resources.cursor_image(image_id)
            .map_err(crate::runtime_error)? else { return Ok(0); };
        let Some(cursor) = host.win16_create_cursor(&bytes)? else { return Ok(0); };
        let Some(handle) = self.guest_images.allocate(GuestImage::Cursor(cursor)) else {
            host.win16_release_cursor(cursor)?;
            return Ok(0);
        };
        self.guest_images.module_cursors.push((module_handle, id, handle));
        Ok(handle)
    }

    pub(super) fn close_images(&mut self, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        // Keep each guest token and its cache entry until the corresponding host
        // release succeeds, so a failed close can be retried without losing ownership.
        let handles: Vec<_> = self.guest_images.images.keys().copied().collect();
        let mut first_error = None;
        for handle in handles {
            let Some(image) = self.guest_images.images.get(&handle).copied() else { continue; };
            match image {
                GuestImage::Icon(icon) => match host.win16_release_icon(icon) {
                    Ok(()) => self.guest_images.retire_released(handle),
                    Err(error) => if first_error.is_none() { first_error = Some(error); },
                },
                GuestImage::Cursor(cursor) => match host.win16_release_cursor(cursor) {
                    Ok(()) => self.guest_images.retire_released(handle),
                    Err(error) => if first_error.is_none() { first_error = Some(error); },
                },
            }
        }
        self.guest_images.prune_dead_cache_entries();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
