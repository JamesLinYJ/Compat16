use crate::caller_address_space::{
    DosCallAddressSpace, DosCallerId, DosPersistentFarPointer, DosPointerAccess, DosSpanPolicy,
};
use crate::{DosAction, DosDirectoryEntry, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::Registers;

use super::DosKernel;
use super::caller_address_space::{
    read_dta_prefix, search_address_key, validate_dta_read, validate_dta_write, write_dta,
};
use super::memory::read_dos_c_string;
use super::state::{DosSearchPattern, SearchKey, SearchState};

impl DosKernel {
    pub(super) fn create_directory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        if !valid_non_search_path(&path, host.guest_code_page()) {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
            return Ok(DosAction::Continue);
        }
        match host.directory_create(&path) {
            Ok(()) => Self::success(regs),
            Err(error) => Self::failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn remove_directory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        if !valid_non_search_path(&path, host.guest_code_page()) {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
            return Ok(DosAction::Continue);
        }
        match host.directory_remove(&path) {
            Ok(()) => Self::success(regs),
            Err(error) => Self::failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn change_directory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::PathNotFound));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        if path.len() > 64 || !valid_non_search_path(&path, host.guest_code_page()) {
            Self::failure(regs, DosHostError::new(DosErrorCode::PathNotFound));
            return Ok(DosAction::Continue);
        }
        match host.directory_set_current(&path) {
            Ok(()) => Self::success(regs),
            Err(error) => Self::failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn get_current_directory(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let drive = match regs.dl() {
            0 => {
                let current = host.current_drive();
                if current > 25 {
                    return Err(DosError::HostContractViolation(
                        "host returned an invalid current drive",
                    ));
                }
                current
            }
            1..=26 => regs.dl() - 1,
            _ => {
                Self::failure(regs, DosHostError::new(DosErrorCode::UnknownUnit));
                return Ok(DosAction::Continue);
            }
        };
        let pointer = memory.resolve_caller_pointer(regs.ds, regs.si())?;
        // DOS specifies a 64-byte ASCIIZ destination. Preflight all 64 bytes
        // before asking the host so a failed guest destination cannot advance
        // any host-side state.
        memory.validate_caller_range(
            pointer,
            0,
            64,
            DosPointerAccess::Write,
            DosSpanPolicy::Linear,
        )?;
        let mut path = [0; 63];
        let count = match host.directory_get_current(drive, &mut path) {
            Ok(count) if count <= path.len() => count,
            Ok(_) => {
                return Err(DosError::HostContractViolation(
                    "current directory exceeded its output buffer",
                ));
            }
            Err(error) => {
                Self::failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };
        let mut result = Vec::with_capacity(count + 1);
        result.extend_from_slice(&path[..count]);
        result.push(0);
        memory.write_caller_range(pointer, 0, &result, DosSpanPolicy::Linear)?;
        Self::success(regs);
        Ok(DosAction::Continue)
    }

    pub(super) fn file_attributes(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let subfunction = regs.al();
        if subfunction > 1 {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        if !valid_non_search_path(&path, host.guest_code_page()) {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
            return Ok(DosAction::Continue);
        }
        match subfunction {
            0 => match host.file_get_attributes(&path) {
                Ok(attributes) if attributes & !0x3f == 0 => {
                    regs.set_cx(u16::from(attributes));
                    Self::success(regs);
                }
                Ok(_) => {
                    return Err(DosError::HostContractViolation(
                        "host returned unknown DOS file attribute bits",
                    ));
                }
                Err(error) => Self::failure(regs, error),
            },
            1 => {
                let raw_attributes = regs.cx();
                if raw_attributes & 0x0018 != 0 {
                    Self::failure(regs, DosHostError::new(DosErrorCode::AccessDenied));
                    return Ok(DosAction::Continue);
                }
                if raw_attributes & !0x0027 != 0 {
                    Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                    return Ok(DosAction::Continue);
                }
                match host.file_set_attributes(&path, raw_attributes as u8) {
                    Ok(()) => Self::success(regs),
                    Err(error) => Self::failure(regs, error),
                }
            }
            _ => unreachable!("validated file attribute subfunction"),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn rename_file(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let old_path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        let new_path = match read_dos_c_string(memory, regs.es, regs.di()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        let code_page = host.guest_code_page();
        let has_wildcards = match (
            path_has_wildcard(&old_path, code_page),
            path_has_wildcard(&new_path, code_page),
        ) {
            (Ok(old), Ok(new)) => old || new,
            _ => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
        };
        if !valid_non_search_path(&old_path, code_page)
            || !valid_non_search_path(&new_path, code_page)
            || has_wildcards
        {
            Self::failure(regs, DosHostError::new(DosErrorCode::FileNotFound));
            return Ok(DosAction::Continue);
        }
        let default_drive = host.current_drive();
        if default_drive > 25 {
            return Err(DosError::HostContractViolation(
                "host returned an invalid current drive",
            ));
        }
        let old_drive = match dos_path_drive(&old_path, code_page) {
            Ok(Some(drive)) => drive,
            Ok(None) => default_drive,
            Err(error) => {
                Self::failure(regs, DosHostError::new(error));
                return Ok(DosAction::Continue);
            }
        };
        let new_drive = match dos_path_drive(&new_path, code_page) {
            Ok(Some(drive)) => drive,
            Ok(None) => default_drive,
            Err(error) => {
                Self::failure(regs, DosHostError::new(error));
                return Ok(DosAction::Continue);
            }
        };
        if old_drive != new_drive {
            Self::failure(regs, DosHostError::new(DosErrorCode::NotSameDevice));
            return Ok(DosAction::Continue);
        }
        match host.file_rename(&old_path, &new_path) {
            Ok(()) => Self::success(regs),
            Err(error) => Self::failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn find_first(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let dta_pointer = self.caller_dta(memory)?;
        validate_dta_write(memory, dta_pointer)?;
        let path = match read_dos_c_string(memory, regs.ds, regs.dx()) {
            Ok(path) => path,
            Err(DosError::MalformedGuestInput(_)) => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        let (directory, pattern) = match parse_search_spec(&path, host) {
            Ok(parsed) => parsed,
            Err(error) => {
                Self::failure(regs, DosHostError::new(error));
                return Ok(DosAction::Continue);
            }
        };
        let key = self.search_key(memory.caller_id(), dta_pointer);
        if let Some(old) = self.searches.get(&key).copied() {
            if let Err(error) = host.directory_search_close(old.host_search) {
                Self::failure(regs, error);
                return Ok(DosAction::Continue);
            }
            self.searches.remove(&key);
        }
        let host_search = match host.directory_search_open(&directory) {
            Ok(search) => search,
            Err(error) => {
                Self::failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };
        let state = SearchState {
            host_search,
            identity: self.allocate_search_identity(),
            pattern,
            attributes: regs.cl() & 0x1f,
        };
        match next_matching_entry(host, state) {
            Ok(Some(entry)) => {
                if let Err(error) = write_search_result(
                    memory,
                    dta_pointer,
                    state.identity,
                    &entry,
                    host.guest_code_page(),
                ) {
                    self.searches.insert(key, state);
                    return Err(error);
                }
                self.searches.insert(key, state);
                Self::success(regs);
            }
            Ok(None) => match host.directory_search_close(host_search) {
                Ok(()) => Self::failure(regs, DosHostError::new(DosErrorCode::NoMoreFiles)),
                Err(error) => {
                    self.searches.insert(key, state);
                    Self::failure(regs, error);
                }
            },
            Err(NextSearchError::Host(error)) => match host.directory_search_close(host_search) {
                Ok(()) => Self::failure(regs, error),
                Err(_) => {
                    self.searches.insert(key, state);
                    Self::failure(regs, error);
                }
            },
            Err(NextSearchError::InvalidEntry) => {
                if host.directory_search_close(host_search).is_err() {
                    self.searches.insert(key, state);
                }
                return Err(DosError::HostContractViolation(
                    "directory search returned an invalid DOS short name or attributes",
                ));
            }
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn find_next(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let dta_pointer = self.caller_dta(memory)?;
        let key = self.search_key(memory.caller_id(), dta_pointer);
        let state = self.searches.get(&key).copied();
        let Some(state) = state else {
            Self::failure(regs, DosHostError::new(DosErrorCode::NoMoreFiles));
            return Ok(DosAction::Continue);
        };

        // The DOS DTA's first 21 bytes are reserved for FindNext state. Our
        // portable core stores an opaque identity there and also binds it to
        // the active PSP and DTA address, so copied or stale DTAs cannot resume
        // a different caller's host enumeration.
        let mut marker = [0; 8];
        validate_dta_read(memory, dta_pointer, marker.len())?;
        read_dta_prefix(memory, dta_pointer, &mut marker)?;
        if marker != search_marker(state.identity) {
            if host.directory_search_close(state.host_search).is_ok() {
                self.searches.remove(&key);
            }
            Self::failure(regs, DosHostError::new(DosErrorCode::NoMoreFiles));
            return Ok(DosAction::Continue);
        }
        validate_dta_write(memory, dta_pointer)?;

        match next_matching_entry(host, state) {
            Ok(Some(entry)) => {
                write_search_result(
                    memory,
                    dta_pointer,
                    state.identity,
                    &entry,
                    host.guest_code_page(),
                )?;
                Self::success(regs);
            }
            Ok(None) => match host.directory_search_close(state.host_search) {
                Ok(()) => {
                    self.searches.remove(&key);
                    Self::failure(regs, DosHostError::new(DosErrorCode::NoMoreFiles));
                }
                Err(error) => Self::failure(regs, error),
            },
            Err(NextSearchError::Host(error)) => Self::failure(regs, error),
            Err(NextSearchError::InvalidEntry) => {
                if host.directory_search_close(state.host_search).is_ok() {
                    self.searches.remove(&key);
                }
                return Err(DosError::HostContractViolation(
                    "directory search returned an invalid DOS short name or attributes",
                ));
            }
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn search_key(
        &self,
        caller: DosCallerId,
        pointer: DosPersistentFarPointer,
    ) -> SearchKey {
        let (_, dta_segment, dta_offset, dta_lease) = search_address_key(caller, pointer);
        SearchKey {
            psp_segment: self.psp_segment,
            caller,
            dta_segment,
            dta_offset,
            dta_lease,
        }
    }

    pub(super) fn allocate_search_identity(&mut self) -> u32 {
        loop {
            self.next_search_identity = self.next_search_identity.wrapping_add(1);
            if self.next_search_identity == 0 {
                continue;
            }
            if !self
                .searches
                .values()
                .any(|state| state.identity == self.next_search_identity)
            {
                return self.next_search_identity;
            }
        }
    }
}

enum NextSearchError {
    Host(DosHostError),
    InvalidEntry,
}

fn next_matching_entry(
    host: &mut impl DosHost,
    state: SearchState,
) -> Result<Option<DosDirectoryEntry>, NextSearchError> {
    loop {
        let Some(entry) = host
            .directory_search_next(state.host_search)
            .map_err(NextSearchError::Host)?
        else {
            return Ok(None);
        };
        let Some((name, extension)) = short_name_fields(&entry.short_name, host.guest_code_page())
        else {
            return Err(NextSearchError::InvalidEntry);
        };
        if entry.attributes & !0x3f != 0 {
            return Err(NextSearchError::InvalidEntry);
        }
        let is_dot_directory =
            entry.short_name.as_slice() == b"." || entry.short_name.as_slice() == b"..";
        if is_dot_directory && entry.attributes & 0x10 == 0 {
            return Err(NextSearchError::InvalidEntry);
        }
        if search_attribute_matches(state.attributes, entry.attributes)
            && dos_field_matches(&state.pattern.name, &name)
            && dos_field_matches(&state.pattern.extension, &extension)
        {
            return Ok(Some(entry));
        }
    }
}

pub(super) fn search_attribute_matches(search: u8, found: u8) -> bool {
    const SEARCHED_ATTRIBUTES: u8 = 0x02 | 0x04 | 0x08 | 0x10;
    const VOLUME_LABEL: u8 = 0x08;
    let requested = search & SEARCHED_ATTRIBUTES;
    let present = found & SEARCHED_ATTRIBUTES;

    // DOS treats this as a volume-label-only search only when no other
    // searched attribute is requested. In every mixed search, each special
    // attribute on a candidate must be present in the request mask.
    if requested == VOLUME_LABEL {
        return present & VOLUME_LABEL != 0;
    }
    present & !requested == 0
}

pub(super) fn dos_field_matches(pattern: &[u8], candidate: &[u8]) -> bool {
    pattern.len() == candidate.len()
        && pattern
            .iter()
            .zip(candidate)
            .all(|(&wanted, &found)| wanted == b'?' || wanted == found)
}

pub(super) fn parse_search_spec(
    path: &[u8],
    host: &impl DosHost,
) -> Result<(Vec<u8>, DosSearchPattern), DosErrorCode> {
    if path.is_empty() {
        return Err(DosErrorCode::InvalidData);
    }
    let page = host.guest_code_page();
    let path_chars = encoded_characters(path, page)?;
    if path_chars
        .iter()
        .any(|character| character.byte_range.len() == 1 && path[character.byte_range.start] < b' ')
    {
        return Err(DosErrorCode::InvalidData);
    }
    let drive = dos_path_drive(path, page)?;
    let split = path_chars
        .iter()
        .filter(|character| {
            character.is_standalone_ascii(b'\\') || character.is_standalone_ascii(b'/')
        })
        .map(|character| character.byte_range.start)
        .last();
    let (directory, filename) = match split {
        Some(index) => (&path[..=index], &path[index + 1..]),
        None if drive.is_some() => (&path[..2], &path[2..]),
        None => (&[][..], path),
    };
    let filename_chars = encoded_characters(filename, page)?;
    if filename.is_empty()
        || filename_chars
            .iter()
            .any(|character| character.is_standalone_ascii(b':'))
        || path_has_wildcard(directory, page)?
    {
        return Err(DosErrorCode::FileNotFound);
    }
    // DOS directory entries `.` and `..` are legal FindFirst targets. They
    // occupy the first bytes of the 8.3 base field, with the remaining bytes
    // (including the extension) blank-padded.
    if filename == b"." || filename == b".." {
        let mut pattern = DosSearchPattern {
            name: [b' '; 8],
            extension: [b' '; 3],
        };
        pattern.name[..filename.len()].copy_from_slice(filename);
        return Ok((directory.to_vec(), pattern));
    }
    let mut dots = filename_chars
        .iter()
        .filter(|character| character.is_standalone_ascii(b'.'))
        .map(|character| character.byte_range.start);
    let dot = dots.next();
    if dots.next().is_some() {
        return Err(DosErrorCode::FileNotFound);
    }
    let (name, extension) = match dot {
        Some(dot) => (&filename[..dot], Some(&filename[dot + 1..])),
        None => (filename, None),
    };
    if name.is_empty() || name.len() > 8 {
        return Err(DosErrorCode::FileNotFound);
    }
    let mut pattern = DosSearchPattern {
        name: [b' '; 8],
        extension: [b' '; 3],
    };
    expand_pattern_field(name, &mut pattern.name, page)?.ok_or(DosErrorCode::FileNotFound)?;
    if let Some(extension) = extension {
        if extension.len() > 3 {
            return Err(DosErrorCode::FileNotFound);
        }
        expand_pattern_field(extension, &mut pattern.extension, page)?
            .ok_or(DosErrorCode::FileNotFound)?;
    }
    Ok((directory.to_vec(), pattern))
}

fn expand_pattern_field(
    input: &[u8],
    output: &mut [u8],
    page: text_codec::CodePage,
) -> Result<Option<()>, DosErrorCode> {
    if input.len() > output.len() {
        return Ok(None);
    }
    let uppercase =
        text_codec::uppercase_oem_name(input, page).map_err(|_| DosErrorCode::InvalidData)?;
    if uppercase.len() != input.len() {
        return Err(DosErrorCode::InvalidData);
    }
    for character in encoded_characters(&uppercase, page)? {
        let start = character.byte_range.start;
        let end = character.byte_range.end;
        if end > output.len() {
            return Ok(None);
        }
        if character.is_standalone_ascii(b'*') {
            output[start..].fill(b'?');
            return Ok(Some(()));
        }
        if character.is_standalone_ascii(b'?') {
            output[start] = b'?';
        } else if [b'/', b'\\', b':', b'.', b'<', b'>', b'"', b'|']
            .iter()
            .any(|&token| character.is_standalone_ascii(token))
        {
            return Ok(None);
        } else {
            output[start..end].copy_from_slice(&uppercase[start..end]);
        }
    }
    Ok(Some(()))
}

pub(super) fn short_name_fields(
    name: &[u8],
    page: text_codec::CodePage,
) -> Option<([u8; 8], [u8; 3])> {
    // `.` and `..` are the two legal special directory entries returned by
    // FindFirst. Keep this exception local to search serialization/matching;
    // ordinary DOS filenames still use the normal 8.3 validation below.
    if name == b"." || name == b".." {
        let mut base = [b' '; 8];
        base[..name.len()].copy_from_slice(name);
        return Some((base, [b' '; 3]));
    }
    if name.is_empty() || name.len() > 12 {
        return None;
    }
    let characters = encoded_characters(name, page).ok()?;
    if characters.iter().any(|character| {
        (character.byte_range.len() == 1 && name[character.byte_range.start] < b' ')
            || [b' ', b'/', b'\\', b':', b'*', b'?', b'<', b'>', b'"', b'|']
                .iter()
                .any(|&token| character.is_standalone_ascii(token))
    }) {
        return None;
    }
    let mut dots = characters
        .iter()
        .filter(|character| character.is_standalone_ascii(b'.'))
        .map(|character| character.byte_range.start);
    let dot = dots.next();
    if dots.next().is_some() {
        return None;
    }
    let (base, extension) = match dot {
        Some(dot) => (&name[..dot], Some(&name[dot + 1..])),
        None => (name, None),
    };
    if base.is_empty() || base.len() > 8 {
        return None;
    }
    if let Some(extension) = extension {
        if extension.is_empty() || extension.len() > 3 {
            return None;
        }
    }
    let uppercase_base = text_codec::uppercase_oem_name(base, page).ok()?;
    let uppercase_extension = match extension {
        Some(extension) => text_codec::uppercase_oem_name(extension, page).ok()?,
        None => Vec::new(),
    };
    let mut base_field = [b' '; 8];
    let mut extension_field = [b' '; 3];
    base_field[..uppercase_base.len()].copy_from_slice(&uppercase_base);
    extension_field[..uppercase_extension.len()].copy_from_slice(&uppercase_extension);
    Some((base_field, extension_field))
}

fn write_search_result(
    memory: &mut impl DosCallAddressSpace,
    dta_pointer: DosPersistentFarPointer,
    identity: u32,
    entry: &DosDirectoryEntry,
    page: text_codec::CodePage,
) -> Result<(), DosError> {
    let Some(_) = short_name_fields(&entry.short_name, page) else {
        return Err(DosError::HostContractViolation(
            "host returned an invalid DOS short name",
        ));
    };
    if entry.attributes & !0x3f != 0 {
        return Err(DosError::HostContractViolation(
            "host returned unknown DOS file attribute bits",
        ));
    }
    let mut dta = [0; 43];
    dta[..8].copy_from_slice(&search_marker(identity));
    dta[0x15] = entry.attributes;
    dta[0x16..0x18].copy_from_slice(&entry.write_time.to_le_bytes());
    dta[0x18..0x1a].copy_from_slice(&entry.write_date.to_le_bytes());
    dta[0x1a..0x1e].copy_from_slice(&entry.size.to_le_bytes());
    let uppercase = text_codec::uppercase_oem_name(&entry.short_name, page)
        .map_err(|_| DosError::HostContractViolation("host returned an invalid OEM short name"))?;
    if uppercase.len() != entry.short_name.len() || uppercase.len() > 12 {
        return Err(DosError::HostContractViolation(
            "host returned an invalid OEM short name length",
        ));
    }
    dta[0x1e..0x1e + uppercase.len()].copy_from_slice(&uppercase);
    write_dta(memory, dta_pointer, &dta)?;
    Ok(())
}

fn search_marker(identity: u32) -> [u8; 8] {
    let mut marker = [0; 8];
    marker[..4].copy_from_slice(b"WDOS");
    marker[4..].copy_from_slice(&identity.to_le_bytes());
    marker
}

fn encoded_characters(
    bytes: &[u8],
    page: text_codec::CodePage,
) -> Result<Vec<text_codec::EncodedCharacter>, DosErrorCode> {
    text_codec::encoded_characters(bytes, page)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DosErrorCode::InvalidData)
}

fn path_has_wildcard(path: &[u8], page: text_codec::CodePage) -> Result<bool, DosErrorCode> {
    let mut has_wildcard = false;
    // Continue decoding after a match so malformed trailing bytes still fail.
    for character in text_codec::encoded_characters(path, page) {
        let character = character.map_err(|_| DosErrorCode::InvalidData)?;
        has_wildcard |=
            character.is_standalone_ascii(b'*') || character.is_standalone_ascii(b'?');
    }
    Ok(has_wildcard)
}

fn valid_non_search_path(path: &[u8], page: text_codec::CodePage) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut valid = true;
    for character in text_codec::encoded_characters(path, page) {
        let Ok(character) = character else {
            return false;
        };
        let invalid = (character.byte_range.len() == 1
            && path[character.byte_range.start] < b' ')
            || character.is_standalone_ascii(b'*')
            || character.is_standalone_ascii(b'?')
            // A drive colon follows exactly one ASCII alphabetic byte.
            || (character.is_standalone_ascii(b':')
                && !(character.byte_range.start == 1 && path[0].is_ascii_alphabetic()));
        // Keep decoding so malformed trailing bytes are still rejected.
        valid &= !invalid;
    }
    valid
}

pub(super) fn dos_path_drive(
    path: &[u8],
    page: text_codec::CodePage,
) -> Result<Option<u8>, DosErrorCode> {
    let mut first_is_drive_letter = false;
    let mut second_is_colon = false;
    let mut has_colon = false;
    let mut has_later_colon = false;
    for (index, character) in text_codec::encoded_characters(path, page).enumerate() {
        let character = character.map_err(|_| DosErrorCode::InvalidData)?;
        let is_colon = character.is_standalone_ascii(b':');
        has_colon |= is_colon;
        match index {
            0 => {
                first_is_drive_letter = character.is_standalone_ascii(path[0])
                    && path[0].is_ascii_alphabetic();
            }
            1 => second_is_colon = is_colon,
            _ => has_later_colon |= is_colon,
        }
    }
    if !has_colon {
        return Ok(None);
    }
    if !first_is_drive_letter || !second_is_colon || has_later_colon {
        return Err(DosErrorCode::InvalidData);
    }
    Ok(Some(dos_upper(path[0]) - b'A'))
}

fn dos_upper(byte: u8) -> u8 {
    byte.to_ascii_uppercase()
}
