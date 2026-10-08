//! VER compatibility calls over checked guest buffers and copied host results.

use guest_core::{GuestMemory, Registers};
use guest_core::memory::Memory;
use win16_abi::{SegmentedPointer, Win16ResourceName, Win16ReturnKind,
    Win16VerRequest};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostResourceName};

impl Win16State {
    pub(super) fn ver_compat_api(
        &mut self,
        request: Win16VerRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let value = match request {
            Win16VerRequest::VerGetFileResourceSize {
                path, resource_type, resource_name, size_output,
            } => {
                let output = if size_output == 0 { None } else {
                    let pointer = self.selectors.pointer_from_far(size_output)
                        .map_err(crate::runtime_error)?;
                    Some((pointer, self.prepare_text_write(memory, pointer, 4)?))
                };
                let resource = host.win16_ver_resource_size(
                    &path,
                    &host_resource_name(resource_type),
                    &host_resource_name(resource_name),
                )?;
                let (size, offset) = resource.unwrap_or((0, 0));
                if let Some((_, prepared)) = output {
                    prepared.commit(memory, &offset.to_le_bytes())?;
                }
                size
            }
            Win16VerRequest::VerGetFileResource {
                path, resource_type, resource_name, offset, count, output,
            } => {
                let capacity = checked_guest_capacity(count as u32, memory)?;
                let destination = if capacity == 0 {
                    None
                } else {
                    let pointer = self.selectors.pointer_from_far(output)
                        .map_err(crate::runtime_error)?;
                    Some((pointer, self.prepare_text_write(memory, pointer, capacity)?))
                };
                let initial = if let Some((pointer, _)) = destination {
                    self.read_text_bytes(memory, pointer, capacity)?
                } else {
                    Vec::new()
                };
                let resource = host.win16_ver_resource(
                    &path,
                    &host_resource_name(resource_type),
                    &host_resource_name(resource_name),
                    offset as u32,
                    count as u32,
                    initial,
                )?;
                match resource {
                    Some(bytes) => {
                        if bytes.len() > capacity {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "host GetFileResource exceeded the guest byte count"));
                        }
                        if let Some((_, prepared)) = destination {
                            prepared.commit(memory, &bytes)?;
                        }
                        bytes.len() as u32
                    }
                    None => 0,
                }
            }
            Win16VerRequest::VerGetFileVersionInfoSize { path, handle_output } => {
                let pointer = self.selectors.pointer_from_far(handle_output)
                    .map_err(crate::runtime_error)?;
                let output = self.prepare_text_write(memory, pointer, 4)?;
                let version = host.win16_ver_file_info_size(&path)?;
                let (size, handle) = version.unwrap_or((0, 0));
                output.commit(memory, &handle.to_le_bytes())?;
                size
            }
            Win16VerRequest::VerGetFileVersionInfo { path, handle, capacity, output } => {
                let capacity = checked_guest_capacity(capacity, memory)?;
                let destination = if capacity == 0 {
                    None
                } else {
                    let pointer = self.selectors.pointer_from_far(output)
                        .map_err(crate::runtime_error)?;
                    Some((pointer, self.prepare_text_write(memory, pointer, capacity)?))
                };
                let initial = if let Some((pointer, _)) = destination {
                    self.read_text_bytes(memory, pointer, capacity)?
                } else {
                    Vec::new()
                };
                match host.win16_ver_file_info(&path, handle, initial)? {
                    Some((bytes, copied)) => {
                        if bytes.len() > capacity || copied as usize != bytes.len() {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "host GetFileVersionInfo returned an invalid copy length"));
                        }
                        if let Some((_, prepared)) = destination {
                            prepared.commit(memory, &bytes)?;
                        }
                        copied
                    }
                    None => 0,
                }
            }
            Win16VerRequest::VerFindFile {
                flags, file, windows_dir, app_dir,
                dir_output, dir_capacity_output,
                file_output, file_capacity_output,
            } => self.ver_find_file(
                flags, &file, &windows_dir, &app_dir,
                dir_output, dir_capacity_output, file_output, file_capacity_output,
                memory, host,
            )?,
            Win16VerRequest::VerInstallFile {
                flags, source, destination, source_dir, destination_dir, current_dir,
                scratch_output, scratch_capacity_output,
            } => self.ver_install_file(
                flags, &source, &destination, &source_dir, &destination_dir, &current_dir,
                scratch_output, scratch_capacity_output,
                memory, host,
            )?,
            Win16VerRequest::VerLanguageName { language, output, capacity } => {
                let capacity = usize::from(capacity);
                let destination = if capacity == 0 {
                    None
                } else {
                    let pointer = self.selectors.pointer_from_far(output)
                        .map_err(crate::runtime_error)?;
                    Some((pointer, self.prepare_text_write(memory, pointer, capacity)?))
                };
                let initial = if let Some((pointer, _)) = destination {
                    self.read_text_bytes(memory, pointer, capacity)?
                } else {
                    Vec::new()
                };
                let (bytes, count) = host.win16_ver_language_name(language, initial)?;
                if bytes.len() != capacity {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "host VerLanguageName changed the guest capacity"));
                }
                if count > capacity as u32 {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "host VerLanguageName exceeded the guest output capacity"));
                }
                if let Some((_, prepared)) = destination {
                    prepared.commit(memory, &bytes)?;
                }
                count
            }
            Win16VerRequest::VerQueryValue {
                block, sub_block, value_output, length_output,
            } => self.ver_query_value(
                block, &sub_block, value_output, length_output,
                memory, host,
            )?,
        };
        self.complete_return(registers, return_to.0, return_to.1,
            return_to.2, value, return_kind)
    }

    fn ver_find_file(
        &mut self,
        flags: u16,
        file: &[u8],
        windows_dir: &[u8],
        app_dir: &[u8],
        dir_output: u32,
        dir_capacity_output: u32,
        file_output: u32,
        file_capacity_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let directory = self.read_optional_word(memory, dir_capacity_output)?;
        let destination = self.read_optional_word(memory, file_capacity_output)?;
        let directory_write = directory.as_ref().map(|(pointer, _)|
            self.prepare_text_write(memory, *pointer, 2)).transpose()?;
        let destination_write = destination.as_ref().map(|(pointer, _)|
            self.prepare_text_write(memory, *pointer, 2)).transpose()?;
        let dir_capacity = directory.as_ref().map_or(0, |(_, value)| *value);
        let file_capacity = destination.as_ref().map_or(0, |(_, value)| *value);
        let dir_buffer = self.prepare_optional_text_buffer(memory, dir_output, dir_capacity)?;
        let file_buffer = self.prepare_optional_text_buffer(memory, file_output, file_capacity)?;
        let dir_buffer_write = dir_buffer.as_ref().map(|(pointer, _)|
            self.prepare_text_write(memory, *pointer, usize::from(dir_capacity))).transpose()?;
        let file_buffer_write = file_buffer.as_ref().map(|(pointer, _)|
            self.prepare_text_write(memory, *pointer, usize::from(file_capacity))).transpose()?;

        let (status, dir_bytes, dir_length, file_bytes, file_length) = host.win16_ver_find_file(
            flags, file, windows_dir, app_dir,
            dir_buffer.as_ref().map_or_else(Vec::new, |(_, bytes)| bytes.clone()),
            dir_capacity,
            file_buffer.as_ref().map_or_else(Vec::new, |(_, bytes)| bytes.clone()),
            file_capacity,
        )?;
        if dir_bytes.len() != usize::from(dir_capacity)
            || file_bytes.len() != usize::from(file_capacity)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host VerFindFile changed an output-buffer capacity"));
        }
        if let Some(prepared) = dir_buffer_write { prepared.commit(memory, &dir_bytes)?; }
        if let Some(prepared) = file_buffer_write { prepared.commit(memory, &file_bytes)?; }
        if let Some(prepared) = directory_write { prepared.commit(memory, &dir_length.to_le_bytes())?; }
        if let Some(prepared) = destination_write { prepared.commit(memory, &file_length.to_le_bytes())?; }

        Ok(status)
    }

    fn ver_install_file(
        &mut self,
        flags: u16,
        source: &[u8],
        destination: &[u8],
        source_dir: &[u8],
        destination_dir: &[u8],
        current_dir: &[u8],
        scratch_output: u32,
        scratch_capacity_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let capacity_pointer = self.selectors.pointer_from_far(scratch_capacity_output)
            .map_err(crate::runtime_error)?;
        let capacity_bytes = self.read_text_bytes(memory, capacity_pointer, 2)?;
        let capacity = u16::from_le_bytes([capacity_bytes[0], capacity_bytes[1]]);
        let capacity_write = self.prepare_text_write(memory, capacity_pointer, 2)?;
        let output = self.prepare_optional_text_buffer(memory, scratch_output, capacity)?;
        let output_write = output.as_ref().map(|(pointer, _)|
            self.prepare_text_write(memory, *pointer, usize::from(capacity))).transpose()?;
        let initial = output.as_ref().map_or_else(Vec::new, |(_, bytes)| bytes.clone());
        let (status, bytes, new_capacity) = host.win16_ver_install_file(
            flags, source, destination, source_dir, destination_dir, current_dir,
            initial, capacity,
        )?;
        if bytes.len() != usize::from(capacity) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host VerInstallFile changed the scratch-buffer capacity"));
        }
        if let Some(prepared) = output_write { prepared.commit(memory, &bytes)?; }
        capacity_write.commit(memory, &new_capacity.to_le_bytes())?;
        Ok(status)
    }

    fn ver_query_value(
        &mut self,
        block_far: u32,
        sub_block: &[u8],
        value_output: u32,
        length_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let block = self.selectors.pointer_from_far(block_far)
            .map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(block.selector())
            .map_err(crate::runtime_error)?;
        let available = descriptor.limit
            .checked_sub(u32::from(block.offset()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "version block begins outside its guest selector"))? as usize;
        let mut root_length = [0; 2];
        self.selectors.read(memory, block, &mut root_length)
            .map_err(crate::runtime_error)?;
        let Ok(block_length) = compat_services::win16_ver::version_info_extent(
            &root_length, available,
        ) else {
            return Ok(0);
        };
        let block_bytes = self.read_text_bytes(memory, block, block_length)?;

        let value_pointer_output = self.selectors.pointer_from_far(value_output)
            .map_err(crate::runtime_error)?;
        let value_output_write = self.prepare_text_write(memory, value_pointer_output, 4)?;
        let length_output_write = if length_output == 0 { None } else {
            let pointer = self.selectors.pointer_from_far(length_output)
                .map_err(crate::runtime_error)?;
            Some((pointer, self.prepare_text_write(memory, pointer, 2)?))
        };

        let Some((offset, length)) = host.win16_ver_query_value(block_bytes, sub_block)? else {
            return Ok(0);
        };
        if offset.checked_add(usize::try_from(length).map_err(|error|
            RuntimeError::with_source(Kind::InternalInvariant,
                "host VerQueryValue length does not fit host memory", error))?)
            .is_none_or(|end| end > block_length)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host VerQueryValue result exceeds the copied version block"));
        }
        let Some(value_offset) = usize::from(block.offset()).checked_add(offset)
            .filter(|offset| *offset <= usize::from(u16::MAX)) else {
            return Ok(0);
        };
        let value_pointer = self.selectors.add_bytes(block, offset as u32)
            .map_err(crate::runtime_error)?;
        let far_value = (u32::from(value_pointer.selector().raw().0) << 16)
            | u32::from(u16::try_from(value_offset).map_err(|error|
                RuntimeError::with_source(Kind::InternalInvariant,
                    "guest version value offset exceeds a selector", error))?);
        value_output_write.commit(memory, &far_value.to_le_bytes())?;
        if let Some((_, prepared)) = length_output_write {
            prepared.commit(memory, &(length as u16).to_le_bytes())?;
        }
        Ok(1)
    }

    fn read_optional_word(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<Option<(SegmentedPointer, u16)>, RuntimeError> {
        let Some(pointer) = self.optional_pointer(far)? else { return Ok(None); };
        let bytes = self.read_text_bytes(memory, pointer, 2)?;
        let value = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok(Some((pointer, value)))
    }

    fn prepare_optional_text_buffer(
        &self,
        memory: &Memory,
        far: u32,
        capacity: u16,
    ) -> Result<Option<(SegmentedPointer, Vec<u8>)>, RuntimeError> {
        if capacity == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        let length = usize::from(capacity);
        let bytes = self.read_text_bytes(memory, pointer, length)?;
        Ok(Some((pointer, bytes)))
    }

    fn optional_pointer(&self, far: u32) -> Result<Option<SegmentedPointer>, RuntimeError> {
        if far == 0 { Ok(None) } else {
            self.selectors.pointer_from_far(far).map(Some).map_err(crate::runtime_error)
        }
    }
}

fn host_resource_name(name: Win16ResourceName) -> Win16HostResourceName {
    match name {
        Win16ResourceName::Id(id) => Win16HostResourceName::Id(id),
        Win16ResourceName::Name(bytes) => Win16HostResourceName::Name(bytes),
    }
}

fn checked_guest_capacity(count: u32, memory: &Memory) -> Result<usize, RuntimeError> {
    let capacity = usize::try_from(count).map_err(|error| RuntimeError::with_source(
        Kind::GuestFault, "Win16 version output length does not fit host memory", error,
    ))?;
    if capacity > memory.len() as usize {
        return Err(RuntimeError::new(Kind::GuestFault,
            "Win16 version output length exceeds all guest memory"));
    }
    Ok(capacity)
}
