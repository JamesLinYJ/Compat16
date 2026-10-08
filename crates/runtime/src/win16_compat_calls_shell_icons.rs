//! SHELL icon extraction and shared Win16 icon/cursor lifetime handling.

use guest_core::{memory::Memory, Selector};
use win16_abi::{
    Win16DestroyImageRequest, Win16GuestImageKind, Win16ShellIconRequest,
};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostIcon,
    Win16HostShellIconCall, Win16HostShellIconResult,
};

#[path = "win16_compat_calls_shell_icons_ne.rs"]
mod ne_icons;

const GMEM_FIXED_ZERO_INIT: u16 = 0x0040;
// The native API uses MAX_PATH (260) bytes, as documented by Microsoft in
// Maximum Path Length Limitation. This bounds only the copied host string;
// guest write spans use the returned string length, not a guessed capacity.
// SHELL.36's Win16 stack slots come from specs/shell.spec; the historical
// private ordinal is listed in Schulman, Undocumented Windows (1992), ch. 2.
const SHELL_NATIVE_MAX_PATH: usize = 260;

struct GuestIconAdoption {
    host_icon: Win16HostIcon,
    guest_handle: Option<u16>,
    newly_allocated: bool,
}

impl Win16State {
    pub(super) fn destroy_guest_image(
        &mut self,
        request: Win16DestroyImageRequest,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let destroyed = match request.kind {
            Win16GuestImageKind::Icon => self.guest_images.destroy_icon(request.handle, host)?,
            Win16GuestImageKind::Cursor => self.guest_images.destroy_cursor(request.handle, host)?,
        };
        Ok(u32::from(destroyed))
    }

    pub(super) fn shell_icon_api(
        &mut self,
        request: Win16ShellIconRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ShellIconRequest::ExtractIcon { path, index, .. } => {
                let result = match ne_icons::extract_icon(
                    host, &path, &self.module_path, index,
                )? {
                    Some(result) => result,
                    None => host.win16_shell_icons(Win16HostShellIconCall::ExtractIcon {
                        path, index,
                    })?,
                };
                match (index, result) {
                    (-1, Win16HostShellIconResult::IconCount { count }) => {
                        Ok(u32::from(count as u16))
                    }
                    (-1, Win16HostShellIconResult::Icon { icon: Some(icon) }) => {
                        host.win16_release_icon(icon)?;
                        Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 ExtractIcon count query returned an icon token"))
                    }
                    (index, Win16HostShellIconResult::NonIconFile) if index != -1 => Ok(1),
                    (index, Win16HostShellIconResult::Icon { icon }) if index != -1 => {
                        self.adopt_one_icon(icon, host).map(u32::from)
                    }
                    (_, unexpected) => {
                        self.release_shell_icon_result(unexpected, host)?;
                        Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 ExtractIcon host result does not match its request"))
                    }
                }
            }
            Win16ShellIconRequest::ExtractAssociatedIcon { path, index, .. } => {
                self.extract_associated_icon(path, index, memory, host)
            }
            Win16ShellIconRequest::InternalExtractIcon { path, index, count, .. } => {
                self.internal_extract_icon(path, index, count, memory, host)
            }
            Win16ShellIconRequest::ExtractIconEx {
                path, index, large_output, small_output, count,
            } => self.extract_icon_ex(path, index, large_output, small_output, count, memory, host),
        }
    }

    fn adopt_one_icon(
        &mut self,
        icon: Option<Win16HostIcon>,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(icon) = icon else { return Ok(0); };
        if let Some((handle, _)) = self.guest_images.allocate_icon(icon) {
            return Ok(handle);
        }
        host.win16_release_icon(icon)?;
        Ok(0)
    }

    fn extract_associated_icon(
        &mut self,
        path_far: u32,
        index_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some((path_pointer, path)) = self.read_associated_icon_path(memory, path_far)? else {
            return Ok(0);
        };
        let index_pointer = self.selectors.pointer_from_far(index_far)
            .map_err(crate::runtime_error)?;
        let index_bytes = self.read_text_bytes(memory, index_pointer, 2)?;
        self.preflight_text_write(memory, index_pointer, 2)?;
        let index = u16::from_le_bytes([index_bytes[0], index_bytes[1]]);
        let result = host.win16_shell_icons(Win16HostShellIconCall::ExtractAssociatedIcon {
            path: path.clone(),
            index,
        })?;
        let (icon, returned_path, returned_index) = match result {
            Win16HostShellIconResult::AssociatedIcon { icon, path, index } => {
                (icon, path, index)
            }
            unexpected => {
                self.release_shell_icon_result(unexpected, host)?;
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 ExtractAssociatedIcon host result does not match its request"));
            }
        };
        let Some(icon) = icon else { return Ok(0); };

        if returned_path.len() >= SHELL_NATIVE_MAX_PATH || returned_path.contains(&0) {
            return Err(self.release_icon_after_error(icon, RuntimeError::new(
                Kind::InternalInvariant,
                "native ExtractAssociatedIcon returned an invalid MAX_PATH string",
            ), host));
        }
        let mut output_path = Vec::new();
        if let Err(error) = output_path.try_reserve_exact(returned_path.len() + 1) {
            return Err(self.release_icon_after_error(icon, RuntimeError::with_source(
                Kind::ResourceExhausted,
                "could not encode Win16 ExtractAssociatedIcon path output",
                error,
            ), host));
        }
        output_path.extend_from_slice(&returned_path);
        output_path.push(0);

        // Reserve the guest icon identity before writing either output so a
        // full handle table leaves the caller's in/out values untouched.
        let Some((guest_handle, newly_allocated)) = self.guest_images.allocate_icon(icon) else {
            host.win16_release_icon(icon)?;
            return Ok(0);
        };
        let adoption = GuestIconAdoption {
            host_icon: icon,
            guest_handle: Some(guest_handle),
            newly_allocated,
        };

        let path_write = match self.prepare_text_write(memory, path_pointer, output_path.len()) {
            Ok(write) => write,
            Err(error) => return Err(self.rollback_associated_icon(adoption, error, host)),
        };
        let previous_path = match self.read_text_bytes(memory, path_pointer, output_path.len()) {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.rollback_associated_icon(adoption, error, host)),
        };
        if let Err(error) = path_write.commit(memory, &output_path) {
            return Err(self.rollback_associated_icon(adoption, error, host));
        }
        if let Err(error) = self.write_text_bytes(memory, index_pointer, &returned_index.to_le_bytes()) {
            let error = match self.write_text_bytes(memory, path_pointer, &previous_path) {
                Ok(()) => error,
                Err(rollback_error) => RuntimeError::with_source(
                    Kind::InternalInvariant,
                    format!("Win16 ExtractAssociatedIcon index write failed ({error}) and path rollback failed"),
                    rollback_error,
                ),
            };
            return Err(self.rollback_associated_icon(adoption, error, host));
        }
        Ok(u32::from(guest_handle))
    }

    fn read_associated_icon_path(
        &self,
        memory: &Memory,
        path_far: u32,
    ) -> Result<Option<(win16_abi::SegmentedPointer, Vec<u8>)>, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(path_far)
            .map_err(crate::runtime_error)?;
        let mut path = Vec::new();
        path.try_reserve_exact(SHELL_NATIVE_MAX_PATH - 1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "could not copy Win16 ExtractAssociatedIcon path", error))?;
        for offset in 0..SHELL_NATIVE_MAX_PATH {
            let current = self.selectors.add_bytes(pointer, offset as u32)
                .map_err(crate::runtime_error)?;
            let byte = self.read_text_bytes(memory, current, 1)?[0];
            if byte == 0 { return Ok(Some((pointer, path))); }
            if offset + 1 == SHELL_NATIVE_MAX_PATH { return Ok(None); }
            path.push(byte);
        }
        Ok(None)
    }

    fn rollback_associated_icon(
        &mut self,
        adoption: GuestIconAdoption,
        error: RuntimeError,
        host: &mut impl RuntimeHost,
    ) -> RuntimeError {
        match self.rollback_icon_adoptions(std::slice::from_ref(&adoption), host) {
            Ok(()) => error,
            Err(rollback_error) => RuntimeError::with_source(
                Kind::InternalInvariant,
                format!("{error}; releasing the associated icon after failed guest output also failed"),
                rollback_error,
            ),
        }
    }

    fn release_icon_after_error(
        &mut self,
        icon: Win16HostIcon,
        error: RuntimeError,
        host: &mut impl RuntimeHost,
    ) -> RuntimeError {
        match host.win16_release_icon(icon) {
            Ok(()) => error,
            Err(release_error) => RuntimeError::with_source(
                Kind::InternalInvariant,
                format!("{error}; releasing the associated icon after invalid host output also failed"),
                release_error,
            ),
        }
    }

    fn internal_extract_icon(
        &mut self,
        path: Vec<u8>,
        index: i16,
        requested_count: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if requested_count == 0 { return Ok(0); }
        let count_query = index == -1;
        let result = match ne_icons::extract_icon_ex(
            host,
            &path,
            &self.module_path,
            index,
            if count_query { 0 } else { requested_count },
            !count_query,
            false,
            count_query,
        )? {
            Some(result) => result,
            None => host.win16_shell_icons(Win16HostShellIconCall::ExtractIconEx {
                path,
                index,
                count: if count_query { 0 } else { requested_count },
                large: !count_query,
                small: false,
            })?,
        };
        let (count, icons) = match result {
            Win16HostShellIconResult::Extracted { failed: true, large, small, .. } => {
                self.release_icon_arrays(&large, &small, host)?;
                return Ok(0);
            }
            Win16HostShellIconResult::Extracted { failed: false, count, large, small } => {
                if count_query {
                    if !large.is_empty() || !small.is_empty() {
                        self.release_icon_arrays(&large, &small, host)?;
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 InternalExtractIcon count query returned icon arrays"));
                    }
                    return self.allocate_icon_count_block(requested_count, count, memory, host);
                }
                if !small.is_empty() || large.len() != usize::from(count)
                    || count > requested_count
                {
                    self.release_icon_arrays(&large, &small, host)?;
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 InternalExtractIcon host result exceeds its declared capacity"));
                }
                if count == 0 { return Ok(0); }
                (count, large)
            }
            unexpected => {
                self.release_shell_icon_result(unexpected, host)?;
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 InternalExtractIcon host result does not match its request"));
            }
        };
        self.allocate_extracted_icon_block(requested_count, count, &icons, memory, host)
    }

    fn allocate_icon_count_block(
        &mut self,
        requested_count: u16,
        icon_count: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let size = u32::from(requested_count).checked_mul(2).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 InternalExtractIcon array size overflow",
        ))?;
        let block = self.global_alloc(GMEM_FIXED_ZERO_INIT, size, memory, host)?;
        if block == 0 { return Ok(0); }
        let pointer = match self.selectors.pointer_from_raw(Selector(block), 0) {
            Ok(pointer) => pointer,
            Err(error) => {
                let _ = self.global_free(block)?;
                return Err(crate::runtime_error(error));
            }
        };
        if let Err(error) = self.write_text_bytes(memory, pointer, &icon_count.to_le_bytes()) {
            let _ = self.global_free(block)?;
            return Err(error);
        }
        Ok(u32::from(block))
    }

    fn allocate_extracted_icon_block(
        &mut self,
        requested_count: u16,
        count: u16,
        icons: &[Option<Win16HostIcon>],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let size = u32::from(requested_count).checked_mul(2).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 InternalExtractIcon array size overflow",
        ))?;
        let mut adoptions = Vec::new();
        if let Err(error) = adoptions.try_reserve_exact(icons.len()) {
            self.release_icon_arrays(icons, &[], host)?;
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted, "could not map extracted Win16 icons", error,
            ));
        }
        let guest_icons = match self.map_host_icons(icons, &mut adoptions) {
            Ok(handles) => handles,
            Err(error) => {
                self.release_unmapped_icons(icons, &adoptions, host)?;
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        };
        if adoptions.iter().any(|adoption| adoption.guest_handle.is_none()) {
            self.rollback_icon_adoptions(&adoptions, host)?;
            return Ok(0);
        }
        let mut bytes = Vec::new();
        if let Err(error) = bytes.try_reserve_exact(guest_icons.len().saturating_mul(2)) {
            self.rollback_icon_adoptions(&adoptions, host)?;
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted, "could not encode extracted Win16 icon handles", error,
            ));
        }
        for handle in &guest_icons { bytes.extend_from_slice(&handle.to_le_bytes()); }
        let block = match self.global_alloc(GMEM_FIXED_ZERO_INIT, size, memory, host) {
            Ok(0) => {
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Ok(0);
            }
            Ok(block) => block,
            Err(error) => {
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        };
        let pointer = match self.selectors.pointer_from_raw(Selector(block), 0) {
            Ok(pointer) => pointer,
            Err(error) => {
                let _ = self.global_free(block)?;
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(crate::runtime_error(error));
            }
        };
        if let Err(error) = self.write_text_bytes(memory, pointer, &bytes) {
            let _ = self.global_free(block)?;
            self.rollback_icon_adoptions(&adoptions, host)?;
            return Err(error);
        }
        if guest_icons.len() != usize::from(count) {
            let _ = self.global_free(block)?;
            self.rollback_icon_adoptions(&adoptions, host)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 InternalExtractIcon result length changed while writing"));
        }
        Ok(u32::from(block))
    }

    fn extract_icon_ex(
        &mut self,
        path: Vec<u8>,
        index: i16,
        large_output: u32,
        small_output: u32,
        requested_count: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let count_query = index == -1 && large_output == 0 && small_output == 0;
        if !count_query && requested_count == 0 { return Ok(0); }
        if !count_query && large_output == 0 && small_output == 0 { return Ok(0); }
        let output_bytes = usize::from(requested_count).checked_mul(2).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "Win16 ExtractIconEx output size overflow"))?;
        let large_write = self.prepare_shell_icon_output(memory, large_output, output_bytes)?;
        let small_write = self.prepare_shell_icon_output(memory, small_output, output_bytes)?;
        let previous_large = if large_output != 0 && output_bytes != 0 {
            let pointer = self.selectors.pointer_from_far(large_output)
                .map_err(crate::runtime_error)?;
            Some(self.read_text_bytes(memory, pointer, output_bytes)?)
        } else { None };
        let large_requested = large_output != 0;
        let small_requested = small_output != 0;
        let result = match ne_icons::extract_icon_ex(
            host,
            &path,
            &self.module_path,
            index,
            requested_count,
            large_requested,
            small_requested,
            count_query,
        )? {
            Some(result) => result,
            None => host.win16_shell_icons(Win16HostShellIconCall::ExtractIconEx {
                path,
                index,
                count: requested_count,
                large: large_requested,
                small: small_requested,
            })?,
        };
        let (count, large, small) = match result {
            Win16HostShellIconResult::Extracted { failed: true, large, small, .. } => {
                self.release_icon_arrays(&large, &small, host)?;
                return Ok(0);
            }
            Win16HostShellIconResult::Extracted { failed: false, count, large, small } => {
                if count_query {
                    if !large.is_empty() || !small.is_empty() {
                        self.release_icon_arrays(&large, &small, host)?;
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 ExtractIconEx count query returned icon arrays"));
                    }
                    return Ok(u32::from(count));
                }
                // ExtractIconEx's scalar is independent of each output span:
                // one requested group with both sizes can return two icons.
                if large.len() > usize::from(requested_count)
                    || small.len() > usize::from(requested_count)
                    || usize::from(count) > large.len().saturating_add(small.len())
                    || (large_output == 0 && !large.is_empty())
                    || (small_output == 0 && !small.is_empty())
                {
                    self.release_icon_arrays(&large, &small, host)?;
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 ExtractIconEx host result exceeds its declared output"));
                }
                (count, large, small)
            }
            unexpected => {
                self.release_shell_icon_result(unexpected, host)?;
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 ExtractIconEx host result does not match its request"));
            }
        };
        if count == 0 {
            self.release_icon_arrays(&large, &small, host)?;
            return Ok(0);
        }

        let capacity = large.len().saturating_add(small.len());
        let mut adoptions = Vec::new();
        if let Err(error) = adoptions.try_reserve_exact(capacity) {
            self.release_icon_arrays(&large, &small, host)?;
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted, "could not map extracted Win16 icons", error,
            ));
        }
        let guest_large = match self.map_host_icons(&large, &mut adoptions) {
            Ok(handles) => handles,
            Err(error) => {
                self.release_unmapped_icons(&large, &adoptions, host)?;
                self.release_unmapped_icons(&small, &adoptions, host)?;
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        };
        let guest_small = match self.map_host_icons(&small, &mut adoptions) {
            Ok(handles) => handles,
            Err(error) => {
                self.release_unmapped_icons(&large, &adoptions, host)?;
                self.release_unmapped_icons(&small, &adoptions, host)?;
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        };
        if adoptions.iter().any(|adoption| adoption.guest_handle.is_none()) {
            self.rollback_icon_adoptions(&adoptions, host)?;
            return Ok(0);
        }

        let large_bytes = match icon_words_to_bytes(&guest_large) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        };
        let small_bytes = match icon_words_to_bytes(&guest_small) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        };
        if let Some(write) = large_write {
            if let Err(error) = write.commit(memory, &large_bytes) {
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        }
        if let Some(write) = small_write {
            if let Err(error) = write.commit(memory, &small_bytes) {
                if let Some(previous) = previous_large {
                    let pointer = self.selectors.pointer_from_far(large_output)
                        .map_err(crate::runtime_error)?;
                    if let Err(rollback_error) = self.write_text_bytes(memory, pointer, &previous) {
                        self.rollback_icon_adoptions(&adoptions, host)?;
                        return Err(RuntimeError::with_source(Kind::InternalInvariant,
                            format!("Win16 ExtractIconEx output rollback failed after {error}"),
                            rollback_error));
                    }
                }
                self.rollback_icon_adoptions(&adoptions, host)?;
                return Err(error);
            }
        }
        Ok(u32::from(count))
    }

    fn prepare_shell_icon_output(
        &self,
        memory: &Memory,
        output: u32,
        capacity: usize,
    ) -> Result<Option<super::text_memory::PreparedTextWrite>, RuntimeError> {
        if output == 0 || capacity == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        self.prepare_text_write(memory, pointer, capacity).map(Some)
    }

    fn map_host_icons(
        &mut self,
        icons: &[Option<Win16HostIcon>],
        adoptions: &mut Vec<GuestIconAdoption>,
    ) -> Result<Vec<u16>, RuntimeError> {
        let mut handles = Vec::new();
        handles.try_reserve_exact(icons.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "could not encode extracted Win16 icon handles", error,
        ))?;
        for icon in icons {
            let Some(icon) = *icon else {
                handles.push(0);
                continue;
            };
            if let Some(existing) = adoptions.iter().find(|adoption| adoption.host_icon == icon) {
                handles.push(existing.guest_handle.unwrap_or(0));
                continue;
            }
            match self.guest_images.allocate_icon(icon) {
                Some((handle, newly_allocated)) => {
                    adoptions.push(GuestIconAdoption {
                        host_icon: icon,
                        guest_handle: Some(handle),
                        newly_allocated,
                    });
                    handles.push(handle);
                }
                None => {
                    adoptions.push(GuestIconAdoption {
                        host_icon: icon,
                        guest_handle: None,
                        newly_allocated: false,
                    });
                    handles.push(0);
                }
            }
        }
        Ok(handles)
    }

    fn rollback_icon_adoptions(
        &mut self,
        adoptions: &[GuestIconAdoption],
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        for adoption in adoptions {
            if adoption.newly_allocated {
                if let Some(handle) = adoption.guest_handle {
                    let _ = self.guest_images.destroy_icon(handle, host)?;
                }
            } else if adoption.guest_handle.is_none() {
                host.win16_release_icon(adoption.host_icon)?;
            }
        }
        Ok(())
    }

    fn release_unmapped_icons(
        &mut self,
        icons: &[Option<Win16HostIcon>],
        adoptions: &[GuestIconAdoption],
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        for icon in icons.iter().flatten() {
            if !adoptions.iter().any(|adoption| adoption.host_icon == *icon) {
                host.win16_release_icon(*icon)?;
            }
        }
        Ok(())
    }

    fn release_icon_arrays(
        &mut self,
        large: &[Option<Win16HostIcon>],
        small: &[Option<Win16HostIcon>],
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        for icon in large.iter().chain(small).flatten() {
            host.win16_release_icon(*icon)?;
        }
        Ok(())
    }

    fn release_shell_icon_result(
        &mut self,
        result: Win16HostShellIconResult,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        match result {
            Win16HostShellIconResult::Icon { icon: Some(icon) } => host.win16_release_icon(icon),
            Win16HostShellIconResult::AssociatedIcon { icon: Some(icon), .. } => {
                host.win16_release_icon(icon)
            }
            Win16HostShellIconResult::Icon { icon: None }
            | Win16HostShellIconResult::AssociatedIcon { icon: None, .. }
            | Win16HostShellIconResult::NonIconFile
            | Win16HostShellIconResult::IconCount { .. } => Ok(()),
            Win16HostShellIconResult::Extracted { large, small, .. } => {
                self.release_icon_arrays(&large, &small, host)
            }
        }
    }
}

fn icon_words_to_bytes(handles: &[u16]) -> Result<Vec<u8>, RuntimeError> {
    let length = handles.len().checked_mul(2).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 icon output size overflow",
    ))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "could not encode Win16 icon output handles", error,
    ))?;
    for handle in handles { bytes.extend_from_slice(&handle.to_le_bytes()); }
    Ok(bytes)
}
