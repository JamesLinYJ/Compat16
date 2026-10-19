//! Native USER icon and cursor handles kept apart from guest 16-bit handles.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCursor, Win16HostIcon, Win16HostIconSize,
    Win16HostShellIconCall, Win16HostShellIconResult,
};
use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::UI::Shell::{ExtractAssociatedIconW, ExtractIconExW, ExtractIconW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CopyIcon, CreateIconFromResourceEx, DestroyCursor, DestroyIcon, HICON, LoadCursorW, LoadIconW,
    LookupIconIdFromDirectoryEx, SM_CXCURSOR, SM_CXICON, SM_CXSMICON, SM_CYCURSOR, SM_CYICON,
    SM_CYSMICON,
};

use super::guest_text::GuestTextCodec;

const WINDOWS_3_RESOURCE_VERSION: u32 = 0x0003_0000;

#[path = "win16_image_copy.rs"]
mod copying;
#[path = "win16_image_masks.rs"]
mod masks;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ImageKind {
    Icon,
    Cursor,
}

#[derive(Clone, Copy)]
struct NativeImage {
    // Store the native pointer's bit pattern: raw Windows handles are not
    // Send, while this private table is shared with USER worker threads.
    // Convert back only at the host API boundary; guest handles stay tokens.
    handle: usize,
    kind: ImageKind,
    owned: bool,
}

impl NativeImage {
    fn new(handle: HICON, kind: ImageKind, owned: bool) -> Self {
        Self {
            handle: handle as usize,
            kind,
            owned,
        }
    }

    fn handle(self) -> HICON {
        self.handle as HICON
    }
}

#[path = "win16_image_ownership.rs"]
mod ownership;
pub(super) use ownership::Win16IconLease;
use ownership::{ImageTable, NativeIconGuard};

/// Owns every raw icon slot left by ExtractIconExW until registration consumes it.
struct NativeIconSlots {
    large: Vec<HICON>,
    small: Vec<HICON>,
}

impl NativeIconSlots {
    fn take(&mut self, raw: HICON, large_count: usize, slots: &[(usize, usize)]) {
        // The sorted index makes alias transfer logarithmic plus alias count.
        let start = slots.partition_point(|(handle, _)| *handle < raw as usize);
        for &(handle, index) in &slots[start..] {
            if handle != raw as usize {
                break;
            }
            if index < large_count {
                self.large[index] = std::ptr::null_mut();
            } else {
                self.small[index - large_count] = std::ptr::null_mut();
            }
        }
    }
}

impl Drop for NativeIconSlots {
    fn drop(&mut self) {
        destroy_icon_slots(&mut self.large, &mut self.small);
    }
}

/// Clones refer to one host-private token table. Raw Win32 handles are stored
/// as integer bit patterns so the table is naturally Send + Sync without an
/// unsafe Send implementation for pointer-bearing values.
#[derive(Clone)]
pub(super) struct Win16Images {
    images: Arc<Mutex<ImageTable>>,
    text_codec: GuestTextCodec,
}

impl Win16Images {
    pub(super) fn new(text_codec: GuestTextCodec) -> Self {
        Self {
            images: Arc::new(Mutex::new(ImageTable::new())),
            text_codec,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, ImageTable>, RuntimeError> {
        self.images.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 host image table mutex is poisoned",
            )
        })
    }

    fn insert_owned(&self, mut guard: NativeIconGuard) -> Result<u64, RuntimeError> {
        let mut collision = None;
        let result = {
            let mut table = self.lock()?;
            table.register_owned(&mut guard, &mut collision)
        };
        // Never run native destruction while holding the identity-table mutex.
        drop(guard);
        drop(collision);
        result
    }

    fn adopt_image(&self, handle: HICON, kind: ImageKind) -> Result<u64, RuntimeError> {
        let mut recovered = None;
        let result = {
            let mut table = self.lock()?;
            table.adopt(handle, kind, &mut recovered)
        };
        drop(recovered);
        result
    }

    fn system(&self, id: u16, kind: ImageKind) -> Result<Option<u64>, RuntimeError> {
        // SAFETY: MAKEINTRESOURCEW is a documented low-word resource ID.
        // NULL hInstance selects predefined system icons or cursors.
        let name = usize::from(id) as *const u16;
        let handle = unsafe {
            match kind {
                ImageKind::Icon => LoadIconW(std::ptr::null_mut(), name),
                ImageKind::Cursor => LoadCursorW(std::ptr::null_mut(), name),
            }
        };
        if handle.is_null() {
            return Ok(None);
        }
        self.lock()?.register_borrowed(handle, kind).map(Some)
    }

    pub(super) fn system_icon(&self, id: u16) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.system(id, ImageKind::Icon)
            .map(|token| token.map(Win16HostIcon))
    }

    pub(super) fn system_cursor(&self, id: u16) -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.system(id, ImageKind::Cursor)
            .map(|token| token.map(Win16HostCursor))
    }

    fn select_image(group: &[u8], kind: ImageKind) -> Option<u16> {
        let (width_index, height_index) = match kind {
            ImageKind::Icon => (SM_CXICON, SM_CYICON),
            ImageKind::Cursor => (SM_CXCURSOR, SM_CYCURSOR),
        };
        Self::select_image_with_metrics(group, kind, width_index, height_index)
    }

    fn select_image_with_metrics(
        group: &[u8],
        kind: ImageKind,
        width_index: i32,
        height_index: i32,
    ) -> Option<u16> {
        if group.is_empty() {
            return None;
        }
        // The NE parser has checked the group header, type, count, and full
        // entry extent before this size-less USER32 directory selector reads.
        let width = crate::windows::win32_safe::system_metrics(width_index);
        let height = crate::windows::win32_safe::system_metrics(height_index);
        // SAFETY: `group` is a checked contiguous group directory whose
        // entries remain live throughout this call.
        let id = unsafe {
            LookupIconIdFromDirectoryEx(
                group.as_ptr(),
                i32::from(kind == ImageKind::Icon),
                width,
                height,
                0,
            )
        };
        u16::try_from(id).ok().filter(|id| *id != 0)
    }

    pub(super) fn select_icon_image(group: &[u8]) -> Option<u16> {
        Self::select_image(group, ImageKind::Icon)
    }

    pub(super) fn select_icon_image_sized(group: &[u8], size: Win16HostIconSize) -> Option<u16> {
        let (width_index, height_index) = icon_metrics(size);
        Self::select_image_with_metrics(group, ImageKind::Icon, width_index, height_index)
    }

    pub(super) fn select_cursor_image(group: &[u8]) -> Option<u16> {
        Self::select_image(group, ImageKind::Cursor)
    }

    fn create(&self, image: &[u8], kind: ImageKind) -> Result<Option<u64>, RuntimeError> {
        let (width_index, height_index) = match kind {
            ImageKind::Icon => (SM_CXICON, SM_CYICON),
            ImageKind::Cursor => (SM_CXCURSOR, SM_CYCURSOR),
        };
        self.create_with_metrics(image, kind, width_index, height_index)
    }

    fn create_with_metrics(
        &self,
        image: &[u8],
        kind: ImageKind,
        width_index: i32,
        height_index: i32,
    ) -> Result<Option<u64>, RuntimeError> {
        let size = u32::try_from(image.len()).map_err(|_| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 image exceeds Windows resource size",
            )
        })?;
        if size == 0 {
            return Ok(None);
        }
        let width = crate::windows::win32_safe::system_metrics(width_index);
        let height = crate::windows::win32_safe::system_metrics(height_index);
        // SAFETY: The owned resource image stays live during the call;
        // USER32 validates and copies bitmap data. fIcon selects the format.
        let handle = unsafe {
            CreateIconFromResourceEx(
                image.as_ptr(),
                size,
                i32::from(kind == ImageKind::Icon),
                WINDOWS_3_RESOURCE_VERSION,
                width,
                height,
                0,
            )
        };
        if handle.is_null() {
            return Ok(None);
        }
        self.insert_owned(NativeIconGuard::new_kind(handle, kind))
            .map(Some)
    }

    pub(super) fn create_icon(&self, image: &[u8]) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.create(image, ImageKind::Icon)
            .map(|token| token.map(Win16HostIcon))
    }

    pub(super) fn create_icon_sized(
        &self,
        image: &[u8],
        size: Win16HostIconSize,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        let (width_index, height_index) = icon_metrics(size);
        self.create_with_metrics(image, ImageKind::Icon, width_index, height_index)
            .map(|token| token.map(Win16HostIcon))
    }

    /// Copy an icon returned in native ACM driver details into the host token
    /// table. MSACM owns its HICON; the copy has an independent USER lifetime.
    pub(super) fn retain_acm_icon(
        &self,
        icon: HICON,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        if icon.is_null() {
            return Ok(None);
        }
        // SAFETY: CopyIcon receives an HICON returned by ACM and creates an
        // independently owned icon suitable for the existing image table.
        let copied = unsafe { CopyIcon(icon) };
        if copied.is_null() {
            return Ok(None);
        }
        let token = self.insert_owned(NativeIconGuard::new(copied))?;
        Ok(Some(Win16HostIcon(token)))
    }

    pub(super) fn create_cursor(
        &self,
        image: &[u8],
    ) -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.create(image, ImageKind::Cursor)
            .map(|token| token.map(Win16HostCursor))
    }

    fn release(&self, token: u64, kind: ImageKind) -> Result<(), RuntimeError> {
        let removed = {
            let mut table = self.lock()?;
            if table
                .images
                .get(&token)
                .is_some_and(|image| image.image.kind == kind)
            {
                table.images.remove(&token)
            } else {
                None
            }
        };
        drop(removed);
        self.lock()?.maintain();
        Ok(())
    }

    pub(super) fn release_icon(&self, icon: Win16HostIcon) -> Result<(), RuntimeError> {
        self.release(icon.0, ImageKind::Icon)
    }

    pub(super) fn release_cursor(&self, cursor: Win16HostCursor) -> Result<(), RuntimeError> {
        self.release(cursor.0, ImageKind::Cursor)
    }

    pub(super) fn native_icon(&self, icon: Win16HostIcon) -> Result<Option<HICON>, RuntimeError> {
        Ok(self
            .lock()?
            .images
            .get(&icon.0)
            .filter(|image| image.image.kind == ImageKind::Icon)
            .map(|image| image.image.handle()))
    }

    pub(super) fn lease_icon(
        &self,
        icon: Win16HostIcon,
    ) -> Result<Option<Win16IconLease>, RuntimeError> {
        let retained = self
            .lock()?
            .images
            .get(&icon.0)
            .filter(|image| image.image.kind == ImageKind::Icon)
            .cloned();
        Ok(retained.map(Win16IconLease))
    }

    pub(super) fn native_cursor(
        &self,
        cursor: Win16HostCursor,
    ) -> Result<Option<HICON>, RuntimeError> {
        Ok(self
            .lock()?
            .images
            .get(&cursor.0)
            .filter(|image| image.image.kind == ImageKind::Cursor)
            .map(|image| image.image.handle()))
    }

    /// Preserve any live host owner, including one retained only by a suspended
    /// USER call. Unknown native images retain their external ownership contract.
    pub(super) fn adopt_borrowed_icon(
        &self,
        icon: HICON,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        if icon.is_null() {
            return Ok(None);
        }
        self.adopt_image(icon, ImageKind::Icon)
            .map(Win16HostIcon)
            .map(Some)
    }

    pub(super) fn adopt_borrowed_cursor(
        &self,
        cursor: HICON,
    ) -> Result<Option<Win16HostCursor>, RuntimeError> {
        if cursor.is_null() {
            return Ok(None);
        }
        self.adopt_image(cursor, ImageKind::Cursor)
            .map(Win16HostCursor)
            .map(Some)
    }

    pub(super) fn shell_icon_call(
        &self,
        call: Win16HostShellIconCall,
    ) -> Result<Win16HostShellIconResult, RuntimeError> {
        match call {
            Win16HostShellIconCall::ExtractIcon { path, index } => {
                let path = nul_terminated_path(self.text_codec, &path)?;
                let instance = crate::windows::win32_safe::current_module();
                if instance.is_null() {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "Win16 host process module instance is unavailable",
                    ));
                }
                // SAFETY: `path` is a live NUL-terminated copy for the call;
                // the instance is from this host process, never a guest handle.
                // SHELL.34 uses FFFF as its count query; every other WORD
                // value is a zero-extended icon index. The shared request
                // keeps the original signed stack decode, so restore its raw
                // WORD bits here instead of sign-extending other negatives.
                let native_index = if index == -1 {
                    u32::MAX
                } else {
                    u32::from(index as u16)
                };
                // SAFETY: `ExtractIconW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                let icon = unsafe { ExtractIconW(instance, path.as_ptr(), native_index) };
                if index == -1 {
                    return Ok(Win16HostShellIconResult::IconCount {
                        count: icon as usize as u32,
                    });
                }
                if icon.is_null() {
                    return Ok(Win16HostShellIconResult::Icon { icon: None });
                }
                // Preserve the Win16 SHELL.34 result instead of treating 1 as
                // a native HICON: ECMA-234:1995 §5, entry 403.3 specifies that
                // ExtractIcon returns 1 for a file that is not an executable,
                // DLL, or icon file. The Windows 3.1 Programmer's Reference,
                // Volume 1 §7.4 documents this Win16 entry point; Microsoft
                // Learn's ExtractIconW page is only corroboration for the
                // modern host API mapping.
                if icon as usize == 1 {
                    return Ok(Win16HostShellIconResult::NonIconFile);
                }
                let token = self.insert_owned(NativeIconGuard::new(icon))?;
                Ok(Win16HostShellIconResult::Icon {
                    icon: Some(Win16HostIcon(token)),
                })
            }
            Win16HostShellIconCall::ExtractAssociatedIcon { path, index } => {
                let max_path = MAX_PATH as usize;
                let wide_path = wide_path(self.text_codec, &path)?;
                if wide_path.len() >= max_path {
                    return Ok(Win16HostShellIconResult::AssociatedIcon {
                        icon: None,
                        path: Vec::new(),
                        index,
                    });
                }
                let instance = crate::windows::win32_safe::current_module();
                if instance.is_null() {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "Win16 host process module instance is unavailable",
                    ));
                }
                // Copy decoded guest text into the W API's MAX_PATH buffer;
                // neither a guest pointer nor guest bytes cross this boundary.
                let mut path_buffer = [0u16; MAX_PATH as usize];
                path_buffer[..wide_path.len()].copy_from_slice(&wide_path);
                let mut icon_index = index;
                // SAFETY: Both mutable outputs are this call's owned, bounded
                // buffers; `instance` belongs to the native host process.
                let icon = unsafe {
                    ExtractAssociatedIconW(instance, path_buffer.as_mut_ptr(), &mut icon_index)
                };
                if icon.is_null() {
                    return Ok(Win16HostShellIconResult::AssociatedIcon {
                        icon: None,
                        path: Vec::new(),
                        index,
                    });
                }
                let guard = NativeIconGuard::new(icon);
                let Some(path_length) = path_buffer.iter().position(|unit| *unit == 0) else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "native ExtractAssociatedIcon output is not NUL-terminated",
                    ));
                };
                let returned_path = self
                    .text_codec
                    .from_wide_bounded(&path_buffer[..path_length], max_path - 1)?
                    .bytes;
                let token = self.insert_owned(guard)?;
                Ok(Win16HostShellIconResult::AssociatedIcon {
                    icon: Some(Win16HostIcon(token)),
                    path: returned_path,
                    index: icon_index,
                })
            }
            Win16HostShellIconCall::ExtractIconEx {
                path,
                index,
                count,
                large,
                small,
            } => {
                let path = nul_terminated_path(self.text_codec, &path)?;
                let length = usize::from(count);
                let mut slots = NativeIconSlots {
                    large: icon_slots(length, large)?,
                    small: icon_slots(length, small)?,
                };
                // SAFETY: Each requested output points to `count` initialized
                // HICON slots owned by this call. Null suppresses that output.
                let result = unsafe {
                    ExtractIconExW(
                        path.as_ptr(),
                        i32::from(index),
                        if large && length != 0 {
                            slots.large.as_mut_ptr()
                        } else {
                            std::ptr::null_mut()
                        },
                        if small && length != 0 {
                            slots.small.as_mut_ptr()
                        } else {
                            std::ptr::null_mut()
                        },
                        u32::from(count),
                    )
                };
                if result == u32::MAX {
                    return Ok(Win16HostShellIconResult::Extracted {
                        failed: true,
                        count: 0,
                        large: Vec::new(),
                        small: Vec::new(),
                    });
                }
                let count = u16::try_from(result).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "native ExtractIconEx result exceeds the Win16 scalar width",
                        error,
                    )
                })?;
                if index == -1 && !large && !small {
                    return Ok(Win16HostShellIconResult::Extracted {
                        failed: false,
                        count,
                        large: Vec::new(),
                        small: Vec::new(),
                    });
                }

                // The scalar can report more icons than fit in this call's
                // output slots. Keep it independent from each array's extent.
                // Preserve null holes before the last initialized handle.
                let large_extent = slots
                    .large
                    .iter()
                    .rposition(|slot| !slot.is_null())
                    .map_or(0, |index| index + 1);
                let small_extent = slots
                    .small
                    .iter()
                    .rposition(|slot| !slot.is_null())
                    .map_or(0, |index| index + 1);
                let (large_result, small_result) = self.retain_extracted_slots(
                    &mut slots,
                    large_extent,
                    large,
                    small_extent,
                    small,
                )?;
                Ok(Win16HostShellIconResult::Extracted {
                    failed: false,
                    count,
                    large: large_result,
                    small: small_result,
                })
            }
        }
    }

    fn retain_extracted_slots(
        &self,
        slots: &mut NativeIconSlots,
        large_count: usize,
        large_requested: bool,
        small_count: usize,
        small_requested: bool,
    ) -> Result<(Vec<Option<Win16HostIcon>>, Vec<Option<Win16HostIcon>>), RuntimeError> {
        self.retain_extracted_slots_with(
            slots,
            large_count,
            large_requested,
            small_count,
            small_requested,
            |raw| self.insert_owned(NativeIconGuard::new(raw)),
        )
    }

    fn retain_extracted_slots_with(
        &self,
        slots: &mut NativeIconSlots,
        large_count: usize,
        large_requested: bool,
        small_count: usize,
        small_requested: bool,
        mut register: impl FnMut(HICON) -> Result<u64, RuntimeError>,
    ) -> Result<(Vec<Option<Win16HostIcon>>, Vec<Option<Win16HostIcon>>), RuntimeError> {
        let mut result = (Vec::new(), Vec::new());
        let total = large_count.saturating_add(small_count);
        if result
            .0
            .try_reserve_exact(if large_requested { large_count } else { 0 })
            .and_then(|_| {
                result
                    .1
                    .try_reserve_exact(if small_requested { small_count } else { 0 })
            })
            .is_err()
        {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "could not retain extracted icon results",
            ));
        }
        let mut retained = Vec::new();
        if retained.try_reserve_exact(total).is_err() {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "could not track extracted icon ownership",
            ));
        }

        let mut originals = Vec::new();
        originals.try_reserve_exact(total).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot extracted icon slot identities",
                error,
            )
        })?;
        originals.extend_from_slice(&slots.large[..large_count]);
        originals.extend_from_slice(&slots.small[..small_count]);
        let mut transfer_slots = Vec::new();
        transfer_slots.try_reserve_exact(total).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "index extracted icon ownership transfers",
                error,
            )
        })?;
        transfer_slots.extend(
            originals
                .iter()
                .enumerate()
                .filter_map(|(index, raw)| (!raw.is_null()).then_some((*raw as usize, index))),
        );
        transfer_slots.sort_unstable_by_key(|entry| entry.0);
        let mut published = BTreeMap::new();

        if large_requested {
            for index in 0..large_count {
                let raw = originals[index];
                if raw.is_null() {
                    result.0.push(None);
                    continue;
                }
                let registration = if let Some(&token) = published.get(&(raw as usize)) {
                    Ok(token)
                } else {
                    slots.take(raw, large_count, &transfer_slots);
                    register(raw).map(|token| {
                        published.insert(raw as usize, token);
                        retained.push(Win16HostIcon(token));
                        token
                    })
                };
                match registration {
                    Ok(token) => {
                        let icon = Win16HostIcon(token);
                        result.0.push(Some(icon));
                    }
                    Err(error) => {
                        return Err(self.rollback_retained_icons(retained, error));
                    }
                }
            }
        }
        if small_requested {
            for index in 0..small_count {
                let raw = originals[large_count + index];
                if raw.is_null() {
                    result.1.push(None);
                    continue;
                }
                let registration = if let Some(&token) = published.get(&(raw as usize)) {
                    Ok(token)
                } else {
                    slots.take(raw, large_count, &transfer_slots);
                    register(raw).map(|token| {
                        published.insert(raw as usize, token);
                        retained.push(Win16HostIcon(token));
                        token
                    })
                };
                match registration {
                    Ok(token) => {
                        let icon = Win16HostIcon(token);
                        result.1.push(Some(icon));
                    }
                    Err(error) => {
                        return Err(self.rollback_retained_icons(retained, error));
                    }
                }
            }
        }
        Ok(result)
    }

    fn rollback_retained_icons(
        &self,
        retained: Vec<Win16HostIcon>,
        original_error: RuntimeError,
    ) -> RuntimeError {
        let mut first_release_error = None;
        let mut release_failure_count = 0usize;
        for icon in retained {
            if let Err(error) = self.release_icon(icon) {
                release_failure_count += 1;
                if first_release_error.is_none() {
                    first_release_error = Some(error);
                }
            }
        }
        match first_release_error {
            Some(release_error) => RuntimeError::with_source(
                Kind::InternalInvariant,
                "failed to roll back retained shell icons",
                release_error,
            ).with_context(format!(
                "original registration failure: {original_error}; {release_failure_count} rollback release(s) failed",
            )),
            None => original_error,
        }
    }
}

fn nul_terminated_path(codec: GuestTextCodec, path: &[u8]) -> Result<Vec<u16>, RuntimeError> {
    validate_path(path)?;
    codec.to_wide_z(path)
}

fn wide_path(codec: GuestTextCodec, path: &[u8]) -> Result<Vec<u16>, RuntimeError> {
    validate_path(path)?;
    codec.to_wide(path)
}

fn validate_path(path: &[u8]) -> Result<(), RuntimeError> {
    if path.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 shell icon path contains an embedded NUL",
        ));
    }
    Ok(())
}

fn icon_slots(count: usize, requested: bool) -> Result<Vec<HICON>, RuntimeError> {
    if !requested {
        return Ok(Vec::new());
    }
    let mut slots = Vec::new();
    slots.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "could not allocate native icon output slots",
            error,
        )
    })?;
    slots.resize(count, std::ptr::null_mut());
    Ok(slots)
}

fn destroy_icon_slots(large: &mut [HICON], small: &mut [HICON]) {
    visit_unique_icon_slots(large, small, |icon| {
        destroy(NativeImage::new(icon, ImageKind::Icon, true));
    });
}

fn visit_unique_icon_slots(large: &mut [HICON], small: &mut [HICON], mut visit: impl FnMut(HICON)) {
    // Sorting in place avoids allocation and quadratic alias scans in Drop.
    large.sort_unstable_by_key(|icon| *icon as usize);
    small.sort_unstable_by_key(|icon| *icon as usize);
    let mut large = large.iter().copied().peekable();
    let mut small = small.iter().copied().peekable();
    let mut previous = std::ptr::null_mut();
    while large.peek().is_some() || small.peek().is_some() {
        let from_large = match (large.peek(), small.peek()) {
            (Some(left), Some(right)) => (*left as usize) <= (*right as usize),
            (Some(_), None) => true,
            _ => false,
        };
        let next = if from_large {
            large.next()
        } else {
            small.next()
        };
        if let Some(icon) = next {
            if !icon.is_null() && icon != previous {
                visit(icon);
            }
            previous = icon;
        }
    }
}

fn icon_metrics(size: Win16HostIconSize) -> (i32, i32) {
    match size {
        Win16HostIconSize::Large => (SM_CXICON, SM_CYICON),
        Win16HostIconSize::Small => (SM_CXSMICON, SM_CYSMICON),
    }
}

fn destroy(image: NativeImage) {
    if !image.owned {
        return;
    }
    // SAFETY: The token table marks icons created or extracted by this host as owned.
    unsafe {
        match image.kind {
            ImageKind::Icon => {
                DestroyIcon(image.handle());
            }
            ImageKind::Cursor => {
                DestroyCursor(image.handle());
            }
        }
    }
}
