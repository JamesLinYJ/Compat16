use crate::{DosAction, DosDirectoryEntry, DosDiskSpace, DosError, DosErrorCode, DosFileAccess, DosFileSharing, DosFileStatus, DosHost, DosHostError, DosHostFile, DosHostSearch, DosIoctlObjectInfo, DosIoctlStream, DosKernel, DosSeekOrigin};
use crate::{DosFileDisposition, DosFileOpenOutcome, DosFileOpenRequest, DosFileOpenResult};
use super::directory::{dos_path_drive, parse_search_spec, search_attribute_matches};
use super::state::Handle;
use super::directory::{dos_field_matches, short_name_fields};
#[path = "fcb_search_tests.rs"]
mod fcb_search_tests;
#[path = "canonical_name_tests.rs"]
mod canonical_name_tests;
use std::collections::{BTreeMap, VecDeque};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

pub(super) struct TestMemory(Vec<u8>);

impl TestMemory {
    pub(super) fn new() -> Self { Self::with_size(0x20_000) }
    pub(super) fn with_size(bytes: usize) -> Self { Self(vec![0; bytes]) }
    pub(super) fn put(&mut self, address: u32, bytes: &[u8]) {
        self.0[address as usize..address as usize + bytes.len()].copy_from_slice(bytes);
    }
}

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 { self.0.len() as u32 }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, bytes.len())?;
        let start = address.0 as usize;
        bytes.copy_from_slice(&self.0[start..start + bytes.len()]);
        Ok(())
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, bytes.len())?;
        let start = address.0 as usize;
        self.0[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Default)]
struct FileState { bytes: Vec<u8>, cursor: u32, written: bool, status: Option<DosFileStatus> }

#[derive(Default)]
struct TestDirectorySearch { entries: Vec<DosDirectoryEntry>, next: usize }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SftQuery {
    StandardInfo(DosIoctlStream),
    FileInfo(DosHostFile),
    FileStatus(DosHostFile),
}

#[derive(Default)]
pub(super) struct TestHost {
    sft_queries: std::cell::RefCell<Vec<SftQuery>>,
    input: VecDeque<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    paths: BTreeMap<Vec<u8>, u64>,
    attributes: BTreeMap<Vec<u8>, u8>,
    directories: BTreeMap<Vec<u8>, ()>,
    current_directories: BTreeMap<u8, Vec<u8>>,
    files: BTreeMap<u64, FileState>,
    handles: BTreeMap<DosHostFile, u64>,
    searches: BTreeMap<DosHostSearch, TestDirectorySearch>,
    search_open_calls: Vec<Vec<u8>>,
    search_next_calls: Vec<DosHostSearch>,
    search_close_calls: Vec<DosHostSearch>,
    search_open_error: Option<DosErrorCode>,
    search_next_error: Option<DosErrorCode>,
    search_close_error: Option<DosErrorCode>,
    search_entries_override: Option<Vec<DosDirectoryEntry>>,
    short_names: BTreeMap<(Vec<u8>, Vec<u8>), Vec<u8>>,
    short_name_queries: Vec<(Vec<u8>, Vec<u8>)>,
    next_id: u64,
    next_search_id: u64,
    drive: u8,
    disk_space: Option<DosDiskSpace>,
    duplicate_calls: usize,
    file_duplicate_attempts: usize,
    file_close_calls: usize,
    fail_duplicate_at: Option<usize>,
    create_new_calls: usize,
    create_new_paths: Vec<Vec<u8>>,
    local_time: Option<crate::DosLocalDateTime>,
    fail_create_new: Option<DosErrorCode>,
    create_new_token_override: Option<DosHostFile>,
    extended_open_calls: Vec<(Vec<u8>, DosFileOpenRequest)>,
    extended_open_error: Option<DosErrorCode>,
    extended_open_result_override: Option<DosFileOpenResult>,
    file_close_error: Option<DosErrorCode>,
    file_commit_calls: Vec<DosHostFile>,
    file_commit_error: Option<DosErrorCode>,
    duplicate_token_override: Option<DosHostFile>,
    max_file_write: Option<usize>,
    file_write_calls: Vec<(DosHostFile, Vec<u8>)>,
    file_seek_calls: Vec<(DosHostFile, i32, DosSeekOrigin)>,
    file_set_len_calls: Vec<(DosHostFile, u32)>,
    pub(super) code_page: Option<text_codec::CodePage>,
    redirected_standard_streams: bool,
    standard_info_override: Option<DosIoctlObjectInfo>,
    input_eof: bool,
    last_open_access: Option<DosFileAccess>,
    file_status_calls: Vec<DosHostFile>,
    file_status_error: Option<DosErrorCode>,
    file_set_write_time_calls: Vec<(DosHostFile, u16, u16)>,
    file_set_write_time_error: Option<DosErrorCode>,
    file_input_status_calls: Vec<DosHostFile>,
    file_input_status_error: Option<DosErrorCode>,
    file_read_calls: Vec<(DosHostFile, usize)>,
    file_read_error: Option<DosErrorCode>,
    file_read_count_override: Option<usize>,
    stdin_poll_calls: usize,
}

impl TestHost {
    // Clear and reserve outside timed batches so trace allocation cannot favor
    // either full-refresh candidate. Each file record emits two queries.
    pub(super) fn prepare_sft_queries(&mut self, records: usize, rounds: usize) {
        let queries = self.sft_queries.get_mut();
        queries.clear();
        queries.reserve(2 * records * rounds);
        self.file_status_calls.clear();
        self.file_status_calls.reserve(records * rounds);
    }

    pub(super) fn sft_queries(&self) -> Vec<SftQuery> {
        self.sft_queries.borrow().clone()
    }

    pub(super) fn set_file_status(&mut self, file: DosHostFile, status: DosFileStatus) {
        self.file_for(file).unwrap().status = Some(status);
    }

    pub(super) fn sft_status_calls(&self) -> &[DosHostFile] {
        &self.file_status_calls
    }

    pub(super) fn file_handle_activity(&self) -> (usize, usize, usize) {
        (self.file_duplicate_attempts, self.file_close_calls, self.handles.len())
    }

    pub(super) fn set_current_drive(&mut self, drive: u8) { self.drive = drive; }

    pub(super) fn set_disk_space(&mut self, space: DosDiskSpace) { self.disk_space = Some(space); }

    pub(super) fn redirect_standard_streams(&mut self) {
        self.redirected_standard_streams = true;
    }

    pub(super) fn set_standard_input_eof(&mut self, input_eof: bool) {
        self.input_eof = input_eof;
    }

    fn open_new(&mut self, path: &[u8], truncate: bool) -> DosHostFile {
        let file_id = if let Some(id) = self.paths.get(path).copied() {
            if truncate { self.files.insert(id, FileState::default()); }
            id
        } else {
            self.next_id += 1;
            let id = self.next_id;
            self.paths.insert(path.to_vec(), id);
            self.files.insert(id, FileState::default());
            id
        };
        self.next_id += 1;
        let token = DosHostFile(self.next_id);
        self.handles.insert(token, file_id);
        token
    }

    fn file_for(&mut self, token: DosHostFile) -> Result<&mut FileState, DosHostError> {
        let id = self.handles.get(&token).copied().ok_or(DosHostError::new(DosErrorCode::InvalidHandle))?;
        self.files.get_mut(&id).ok_or(DosHostError::new(DosErrorCode::InvalidHandle))
    }
}

impl DosHost for TestHost {
    fn local_date_time(&mut self) -> Result<crate::DosLocalDateTime, DosHostError> {
        self.local_time.ok_or_else(|| DosHostError::new(DosErrorCode::InvalidFunction))
    }
    fn read_stdin(&mut self, output: &mut [u8]) -> Result<usize, DosHostError> {
        let mut count = 0;
        while count < output.len() {
            let Some(byte) = self.input.pop_front() else { break; };
            output[count] = byte;
            count += 1;
        }
        Ok(count)
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        self.stdin_poll_calls += 1;
        Ok(self.input.pop_front())
    }
    fn write_stdout(&mut self, input: &[u8]) -> Result<usize, DosHostError> { self.stdout.extend_from_slice(input); Ok(input.len()) }
    fn write_stderr(&mut self, input: &[u8]) -> Result<usize, DosHostError> { self.stderr.extend_from_slice(input); Ok(input.len()) }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { self.input.clear(); Ok(()) }

    fn file_create(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError> {
        self.attributes.insert(path.to_vec(), attributes);
        Ok(self.open_new(path, true))
    }
    fn file_create_new(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError> {
        self.create_new_calls += 1;
        self.create_new_paths.push(path.to_vec());
        if let Some(code) = self.fail_create_new {
            return Err(DosHostError::new(code));
        }
        if let Some(token) = self.create_new_token_override {
            return Ok(token);
        }
        if self.paths.contains_key(path) || self.directories.contains_key(path) {
            return Err(DosHostError::new(DosErrorCode::FileExists));
        }
        self.attributes.insert(path.to_vec(), attributes);
        Ok(self.open_new(path, false))
    }
    fn file_open(&mut self, path: &[u8], access: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        if !self.paths.contains_key(path) { return Err(DosHostError::new(DosErrorCode::FileNotFound)); }
        self.last_open_access = Some(access);
        Ok(self.open_new(path, false))
    }
    fn file_extended_open(&mut self, path: &[u8], request: DosFileOpenRequest) -> Result<DosFileOpenResult, DosHostError> {
        self.extended_open_calls.push((path.to_vec(), request));
        if let Some(code) = self.extended_open_error {
            return Err(DosHostError::new(code));
        }
        if let Some(result) = self.extended_open_result_override {
            return Ok(result);
        }
        let exists = self.paths.contains_key(path);
        if self.directories.contains_key(path) {
            return Err(DosHostError::new(DosErrorCode::AccessDenied));
        }
        let outcome = match (request.disposition, exists) {
            (DosFileDisposition::CreateNew, true) => return Err(DosHostError::new(DosErrorCode::FileExists)),
            (DosFileDisposition::OpenExisting | DosFileDisposition::ReplaceExisting, false) => return Err(DosHostError::new(DosErrorCode::FileNotFound)),
            (DosFileDisposition::ReplaceExisting | DosFileDisposition::ReplaceOrCreate, true) => {
                self.attributes.insert(path.to_vec(), request.attributes);
                DosFileOpenOutcome::Replaced
            }
            (_, true) => DosFileOpenOutcome::Opened,
            (_, false) => {
                if request.access == DosFileAccess::ReadOnly {
                    return Err(DosHostError::new(DosErrorCode::InvalidFunction));
                }
                self.attributes.insert(path.to_vec(), request.attributes);
                DosFileOpenOutcome::Created
            }
        };
        self.last_open_access = Some(request.access);
        Ok(DosFileOpenResult { file: self.open_new(path, outcome == DosFileOpenOutcome::Replaced), outcome })
    }
    fn file_open_with_sharing(&mut self, path: &[u8], access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> {
        self.file_open(path, access)
    }
    fn file_duplicate(&mut self, file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        self.file_duplicate_attempts += 1;
        let id = self.handles.get(&file).copied().ok_or(DosHostError::new(DosErrorCode::InvalidHandle))?;
        self.duplicate_calls += 1;
        if self.fail_duplicate_at == Some(self.duplicate_calls) {
            return Err(DosHostError::new(DosErrorCode::AccessDenied));
        }
        if let Some(copy) = self.duplicate_token_override {
            return Ok(copy);
        }
        self.next_id += 1;
        let copy = DosHostFile(self.next_id);
        self.handles.insert(copy, id);
        Ok(copy)
    }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        self.file_close_calls += 1;
        if let Some(code) = self.file_close_error { return Err(DosHostError::new(code)); }
        self.handles.remove(&file).map(|_| ()).ok_or(DosHostError::new(DosErrorCode::InvalidHandle))
    }
    fn file_commit(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        self.file_commit_calls.push(file);
        self.file_for(file)?;
        match self.file_commit_error {
            Some(code) => Err(DosHostError::new(code)),
            None => Ok(()),
        }
    }
    fn file_read(&mut self, file: DosHostFile, output: &mut [u8]) -> Result<usize, DosHostError> {
        self.file_read_calls.push((file, output.len()));
        if let Some(code) = self.file_read_error { return Err(DosHostError::new(code)); }
        if let Some(count) = self.file_read_count_override { return Ok(count); }
        let state = self.file_for(file)?;
        let start = state.cursor as usize;
        if start >= state.bytes.len() { return Ok(0); }
        let count = output.len().min(state.bytes.len().saturating_sub(start));
        output[..count].copy_from_slice(&state.bytes[start..start + count]);
        state.cursor += count as u32;
        Ok(count)
    }
    fn file_write(&mut self, file: DosHostFile, input: &[u8]) -> Result<usize, DosHostError> {
        self.file_write_calls.push((file, input.to_vec()));
        let input = &input[..self.max_file_write.unwrap_or(input.len()).min(input.len())];
        let state = self.file_for(file)?;
        state.written = true;
        let start = state.cursor as usize;
        let end = start.checked_add(input.len()).ok_or(DosHostError::new(DosErrorCode::DiskFull))?;
        if state.bytes.len() < end { state.bytes.resize(end, 0); }
        state.bytes[start..end].copy_from_slice(input);
        state.cursor = end as u32;
        Ok(input.len())
    }
    fn file_seek(&mut self, file: DosHostFile, offset: i32, origin: DosSeekOrigin) -> Result<u32, DosHostError> {
        self.file_seek_calls.push((file, offset, origin));
        let state = self.file_for(file)?;
        let base = match origin { DosSeekOrigin::Start => 0i64, DosSeekOrigin::Current => i64::from(state.cursor), DosSeekOrigin::End => state.bytes.len() as i64 };
        let displacement = match origin {
            DosSeekOrigin::Start => i64::from(offset as u32),
            DosSeekOrigin::Current | DosSeekOrigin::End => i64::from(offset),
        };
        let position = base + displacement;
        if !(0..=i64::from(u32::MAX)).contains(&position) { return Err(DosHostError::new(DosErrorCode::InvalidData)); }
        state.cursor = position as u32;
        Ok(state.cursor)
    }
    fn file_set_len(&mut self, file: DosHostFile, length: u32) -> Result<(), DosHostError> {
        self.file_set_len_calls.push((file, length));
        let state = self.file_for(file)?;
        state.written = true;
        state.bytes.resize(length as usize, 0);
        Ok(())
    }

    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        self.sft_queries.borrow_mut().push(SftQuery::FileStatus(file));
        self.file_status_calls.push(file);
        if let Some(error) = self.file_status_error {
            return Err(DosHostError::new(error));
        }
        let state = self.file_for(file)?;
        let mut status = state.status.ok_or(DosHostError::new(DosErrorCode::InvalidFunction))?;
        status.size = state.bytes.len() as u32;
        status.position = state.cursor;
        Ok(status)
    }

    fn file_set_write_time(&mut self, file: DosHostFile, time: u16, date: u16) -> Result<(), DosHostError> {
        self.file_set_write_time_calls.push((file, time, date));
        if let Some(code) = self.file_set_write_time_error {
            return Err(DosHostError::new(code));
        }
        let state = self.file_for(file)?;
        let status = state.status.as_mut().ok_or(DosHostError::new(DosErrorCode::InvalidFunction))?;
        status.write_time = time;
        status.write_date = date;
        state.written = true;
        Ok(())
    }

    fn file_input_status(&mut self, file: DosHostFile) -> Result<bool, DosHostError> {
        self.file_input_status_calls.push(file);
        if let Some(code) = self.file_input_status_error {
            return Err(DosHostError::new(code));
        }
        let state = self.file_for(file)?;
        Ok(u64::from(state.cursor) < state.bytes.len() as u64)
    }

    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        self.sft_queries.borrow_mut().push(SftQuery::FileInfo(file));
        let file_id = self.handles.get(&file).copied()
            .ok_or(DosHostError::new(DosErrorCode::InvalidHandle))?;
        let state = self.files.get(&file_id)
            .ok_or(DosHostError::new(DosErrorCode::InvalidHandle))?;
        Ok(DosIoctlObjectInfo::File { drive: 2, written: state.written })
    }

    fn standard_ioctl_info(&self, stream: DosIoctlStream) -> Result<DosIoctlObjectInfo, DosHostError> {
        self.sft_queries.borrow_mut().push(SftQuery::StandardInfo(stream));
        if let Some(info) = self.standard_info_override { return Ok(info); }
        if self.redirected_standard_streams {
            return Err(DosHostError::new(DosErrorCode::InvalidFunction));
        }
        let (standard_input, standard_output) = match stream {
            DosIoctlStream::Input => (true, false),
            DosIoctlStream::Output | DosIoctlStream::Error => (false, true),
        };
        Ok(DosIoctlObjectInfo::CharacterDevice {
            input_eof: self.input_eof,
            raw_mode: true,
            standard_input,
            standard_output,
        })
    }
    fn file_delete(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        let id = self.paths.remove(path).ok_or(DosHostError::new(DosErrorCode::FileNotFound))?;
        self.attributes.remove(path);
        self.files.remove(&id);
        self.handles.retain(|_, file_id| *file_id != id);
        Ok(())
    }

    fn directory_create(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        if path.is_empty() || self.paths.contains_key(path) || self.directories.contains_key(path) {
            return Err(DosHostError::new(DosErrorCode::AccessDenied));
        }
        let parent = test_parent(path);
        if !test_is_root(path) && !parent.is_empty() && !self.directories.contains_key(parent) && !test_is_root(parent) {
            return Err(DosHostError::new(DosErrorCode::PathNotFound));
        }
        self.directories.insert(path.to_vec(), ());
        Ok(())
    }

    fn directory_remove(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        if !self.directories.contains_key(path) { return Err(DosHostError::new(DosErrorCode::PathNotFound)); }
        if self.current_directories.values().any(|current| test_strip_separator(current) == test_strip_separator(path)) {
            return Err(DosHostError::new(DosErrorCode::CannotRemoveCurrentDirectory));
        }
        if self.directories.keys().any(|child| test_strip_separator(test_parent(child)) == test_strip_separator(path))
            || self.paths.keys().any(|child| test_strip_separator(test_parent(child)) == test_strip_separator(path))
        {
            return Err(DosHostError::new(DosErrorCode::AccessDenied));
        }
        self.directories.remove(path);
        Ok(())
    }

    fn directory_set_current(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        if !test_is_root(path) && !self.directories.contains_key(path) {
            return Err(DosHostError::new(DosErrorCode::PathNotFound));
        }
        let drive = dos_path_drive(path, self.guest_code_page()).ok().flatten().unwrap_or(self.drive);
        self.current_directories.insert(drive, path.to_vec());
        Ok(())
    }

    fn directory_get_current(&mut self, drive: u8, output: &mut [u8]) -> Result<usize, DosHostError> {
        if drive > 2 { return Err(DosHostError::new(DosErrorCode::UnknownUnit)); }
        let path = self.current_directories.get(&drive).map(Vec::as_slice).unwrap_or_default();
        let relative = path.iter().position(|byte| *byte == b'\\' || *byte == b'/')
            .map(|index| &path[index + 1..]).unwrap_or(path);
        if relative.len() > output.len() { return Err(DosHostError::new(DosErrorCode::GeneralFailure)); }
        output[..relative.len()].copy_from_slice(relative);
        Ok(relative.len())
    }

    fn file_short_name(&mut self, parent: &[u8], name: &[u8]) -> Result<Option<Vec<u8>>, DosHostError> {
        let key = (parent.to_vec(), name.to_vec());
        self.short_name_queries.push(key.clone());
        Ok(self.short_names.get(&key).cloned())
    }
    fn file_rename(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<(), DosHostError> {
        if self.paths.contains_key(new_path) || self.directories.contains_key(new_path) {
            return Err(DosHostError::new(DosErrorCode::AccessDenied));
        }
        let id = self.paths.remove(old_path).ok_or(DosHostError::new(DosErrorCode::FileNotFound))?;
        self.paths.insert(new_path.to_vec(), id);
        if let Some(attributes) = self.attributes.remove(old_path) {
            self.attributes.insert(new_path.to_vec(), attributes);
        }
        Ok(())
    }

    fn file_get_attributes(&mut self, path: &[u8]) -> Result<u8, DosHostError> {
        if self.directories.contains_key(path) { return Ok(0x10); }
        if !self.paths.contains_key(path) { return Err(DosHostError::new(DosErrorCode::FileNotFound)); }
        Ok(*self.attributes.get(path).unwrap_or(&0))
    }

    fn file_set_attributes(&mut self, path: &[u8], attributes: u8) -> Result<(), DosHostError> {
        if self.directories.contains_key(path) { return Err(DosHostError::new(DosErrorCode::AccessDenied)); }
        if !self.paths.contains_key(path) { return Err(DosHostError::new(DosErrorCode::FileNotFound)); }
        self.attributes.insert(path.to_vec(), attributes);
        Ok(())
    }

    fn directory_search_open(&mut self, directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        self.search_open_calls.push(directory.to_vec());
        if let Some(code) = self.search_open_error { return Err(DosHostError::new(code)); }
        let normalized = test_strip_separator(directory);
        if !normalized.is_empty() && !test_is_root(normalized) && !self.directories.contains_key(normalized) {
            return Err(DosHostError::new(DosErrorCode::PathNotFound));
        }
        let mut entries = Vec::new();
        for path in self.paths.keys().filter(|path| test_strip_separator(test_parent(path)) == normalized) {
            let short_name = test_leaf(path).to_vec();
            let size = self.paths.get(path).and_then(|id| self.files.get(id)).map(|file| file.bytes.len() as u32).unwrap_or(0);
            entries.push(DosDirectoryEntry {
                short_name,
                attributes: *self.attributes.get(path).unwrap_or(&0),
                write_time: 0,
                write_date: 0,
                size,
            });
        }
        for path in self.directories.keys().filter(|path| test_strip_separator(test_parent(path)) == normalized) {
            entries.push(DosDirectoryEntry {
                short_name: test_leaf(path).to_vec(),
                attributes: 0x10,
                write_time: 0,
                write_date: 0,
                size: 0,
            });
        }
        if let Some(override_entries) = &self.search_entries_override { entries = override_entries.clone(); }
        self.next_search_id += 1;
        let token = DosHostSearch(self.next_search_id);
        self.searches.insert(token, TestDirectorySearch { entries, next: 0 });
        Ok(token)
    }

    fn directory_search_next(&mut self, search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        self.search_next_calls.push(search);
        if let Some(code) = self.search_next_error { return Err(DosHostError::new(code)); }
        let state = self.searches.get_mut(&search).ok_or(DosHostError::new(DosErrorCode::InvalidHandle))?;
        let entry = state.entries.get(state.next).cloned();
        if entry.is_some() { state.next += 1; }
        Ok(entry)
    }

    fn directory_search_close(&mut self, search: DosHostSearch) -> Result<(), DosHostError> {
        self.search_close_calls.push(search);
        if let Some(code) = self.search_close_error { return Err(DosHostError::new(code)); }
        self.searches.remove(&search).map(|_| ()).ok_or(DosHostError::new(DosErrorCode::InvalidHandle))
    }

    fn guest_code_page(&self) -> text_codec::CodePage {
        self.code_page.unwrap_or(text_codec::CodePage::Cp437)
    }

    fn current_drive(&self) -> u8 { self.drive }
    fn select_drive(&mut self, drive: u8) -> Result<(), DosHostError> {
        if drive >= 26 { return Err(DosHostError::new(DosErrorCode::UnknownUnit)); }
        self.drive = drive;
        Ok(())
    }
    fn logical_drive_count(&self) -> u8 { 3 }
    fn disk_space(&self, drive: u8) -> Result<DosDiskSpace, DosHostError> {
        if drive != 2 {
            return Err(DosHostError::new(DosErrorCode::UnknownUnit));
        }
        self.disk_space.ok_or_else(|| DosHostError::new(DosErrorCode::UnknownUnit))
    }
}

fn test_parent(path: &[u8]) -> &[u8] {
    path.iter().rposition(|byte| *byte == b'\\' || *byte == b'/')
        .map(|index| &path[..=index]).unwrap_or_default()
}

fn test_leaf(path: &[u8]) -> &[u8] {
    path.iter().rposition(|byte| *byte == b'\\' || *byte == b'/')
        .map(|index| &path[index + 1..]).unwrap_or(path)
}

fn test_is_root(path: &[u8]) -> bool {
    path.len() == 1 && matches!(path[0], b'\\' | b'/')
        || path.len() == 3 && path[0].is_ascii_alphabetic() && path[1] == b':' && matches!(path[2], b'\\' | b'/')
}

fn test_strip_separator(path: &[u8]) -> &[u8] {
    if test_is_root(path) { return path; }
    path.strip_suffix(b"\\").or_else(|| path.strip_suffix(b"/")).unwrap_or(path)
}

fn set_ah(regs: &mut Registers, function: u8) { regs.set_ah(function); }

#[test]
fn console_calls_echo_poll_and_preserve_polled_input() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    host.input.extend([b'Z', b'Q']);
    set_ah(&mut regs, 0x01);
    assert_eq!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap(), DosAction::Continue);
    assert_eq!(regs.al(), b'Z');
    assert_eq!(host.stdout, b"Z");

    set_ah(&mut regs, 0x0b);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.al(), 0xff);
    set_ah(&mut regs, 0x07);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.al(), b'Q');
    assert_eq!(host.stdout, b"Z");
}

#[test]
fn dollar_string_is_bounded_and_keeps_embedded_nul() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"a\0b$");
    let mut regs = Registers::default();
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    set_ah(&mut regs, 0x09);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(host.stdout, b"a\0b");
    assert_eq!(regs.al(), b'$');
}

fn force_stdout(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    regs: &mut Registers,
    source: u16,
) {
    regs.set_bx(source);
    regs.set_cx(1);
    regs.set_ax(0x4600);
    dos.interrupt(0x21, regs, memory, host).unwrap();
    assert!(!regs.carry());
}

fn create_output_file(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    regs: &mut Registers,
) -> u16 {
    memory.put(0x10100, b"OUT.DAT\0");
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    regs.set_cx(0);
    regs.set_ax(0x3c00);
    dos.interrupt(0x21, regs, memory, host).unwrap();
    assert!(!regs.carry());
    regs.ax()
}

#[test]
fn character_output_follows_forced_file_handle_and_restored_stdout() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_bx(1);
    regs.set_ax(0x4500);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let saved_stdout = regs.ax();
    let output = create_output_file(&mut dos, &mut host, &mut memory, &mut regs);
    force_stdout(&mut dos, &mut host, &mut memory, &mut regs, output);
    // The redirected alias remains usable after the original handle closes.
    regs.set_bx(output);
    regs.set_ax(0x3e00);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    host.max_file_write = Some(1); // Exercise the string's partial-write loop.
    for (service, byte) in [(0x02, b'A'), (0x06, b'B')] {
        regs.set_ah(service);
        regs.set_dl(byte);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        assert_eq!(regs.al(), byte);
    }
    memory.put(0x10200, b"C\0D$");
    regs.set_dx(0x0200);
    regs.set_ah(0x09);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.al(), b'$');
    host.input.push_back(b'E');
    regs.set_ah(0x01);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.al(), b'E');
    let file = host.paths[b"OUT.DAT".as_slice()];
    assert_eq!(host.files[&file].bytes, b"ABC\0DE");
    assert_eq!(host.files[&file].cursor, 6);
    assert!(host.stdout.is_empty());
    assert!(host.stderr.is_empty());

    force_stdout(&mut dos, &mut host, &mut memory, &mut regs, saved_stdout);
    regs.set_ah(0x02);
    regs.set_dl(b'Z');
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(host.stdout, b"Z");
    assert_eq!(host.files[&file].bytes, b"ABC\0DE");
}

#[test]
fn character_and_string_output_follow_forced_stderr() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    force_stdout(&mut dos, &mut host, &mut memory, &mut regs, 2);
    regs.set_ah(0x02);
    regs.set_dl(b'X');
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    memory.put(0x10100, b"YZ$");
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    regs.set_ah(0x09);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert_eq!(regs.al(), b'$');
    assert_eq!(host.stderr, b"XYZ");
    assert!(host.stdout.is_empty());
}

#[test]
fn redirected_output_zero_progress_preserves_disk_full_error() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    let output = create_output_file(&mut dos, &mut host, &mut memory, &mut regs);
    force_stdout(&mut dos, &mut host, &mut memory, &mut regs, output);
    host.max_file_write = Some(0);
    memory.put(0x10200, b"text$");
    for service in [0x02, 0x06, 0x09] {
        regs.set_dx(if service == 0x09 { 0x0200 } else { u16::from(b'X') });
        regs.set_ah(service);
        regs.set_carry(false);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(regs.carry());
        assert_eq!(regs.ax(), DosErrorCode::DiskFull as u16);
    }
    let file = host.paths[b"OUT.DAT".as_slice()];
    assert!(host.files[&file].bytes.is_empty());
    assert!(host.stdout.is_empty());
}

#[test]
fn dollar_string_preserves_invalid_closed_stdout_error() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_bx(1);
    regs.set_ax(0x3e00);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    memory.put(0x10100, b"text$");
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    regs.set_ah(0x09);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::InvalidHandle as u16);
    assert!(host.stdout.is_empty());
}

#[test]
fn create_write_seek_read_close_and_delete_use_host_files() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"C:\\TEST.DAT\0");
    memory.put(0x10300, b"abc");
    let mut regs = Registers::default();
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    regs.set_cx(0);
    set_ah(&mut regs, 0x3c);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let handle = regs.ax();
    assert_eq!(handle, 3); // Only stdin/stdout/stderr are initially installed.
    assert!(!regs.carry());

    regs.set_bx(handle);
    regs.set_cx(3);
    regs.set_dx(0x0300);
    set_ah(&mut regs, 0x40);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.ax(), 3);

    regs.set_bx(handle);
    regs.set_ax(0x4200);
    regs.set_cx(0);
    regs.set_dx(0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.dx(), 0);
    assert_eq!(regs.ax(), 0);

    regs.set_bx(handle);
    regs.ds = 0x1000;
    regs.set_dx(0x0400);
    regs.set_cx(3);
    set_ah(&mut regs, 0x3f);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let mut got = [0; 3];
    memory.read(PhysAddr(0x10400), &mut got).unwrap();
    assert_eq!(got, *b"abc");

    regs.set_bx(handle);
    set_ah(&mut regs, 0x3e);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    set_ah(&mut regs, 0x41);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert!(host.paths.is_empty());
}

#[test]
fn invalid_read_buffer_does_not_advance_host_file() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"x.bin\0");
    let file = host.file_create(b"x.bin", 0).unwrap();
    let mut regs = Registers::default();
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    set_ah(&mut regs, 0x3d);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let handle = regs.ax();
    let host_file = host.handles[&file];
    host.files.get_mut(&host_file).unwrap().bytes = b"abc".to_vec();
    regs.set_bx(handle);
    regs.ds = 0xffff;
    regs.set_dx(0xffff);
    regs.set_cx(3);
    set_ah(&mut regs, 0x3f);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::Memory(_))));
    assert_eq!(host.files[&host_file].cursor, 0);
}

#[test]
fn buffered_input_checks_full_guest_output_before_consuming_console_input() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    host.input.extend([b'x', b'\r']);
    let mut memory = TestMemory::new();
    memory.put(0x1_fffe, &[1]);
    let mut regs = Registers::default();
    regs.ds = 0x1fff;
    regs.set_dx(0x000e);
    set_ah(&mut regs, 0x0a);
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::Memory(_))
    ));
    assert_eq!(host.input.len(), 2);
}

#[test]
fn handle_inheritance_rolls_back_partial_host_duplicates() {
    let mut parent = DosKernel::new(0x1000);
    let mut child = DosKernel::new(0x2000);
    let mut host = TestHost::default();
    let file_a = host.file_create(b"a", 0).unwrap();
    let file_b = host.file_create(b"b", 0).unwrap();
    parent.handles.insert(5, Handle::File(file_a));
    parent.handles.insert(6, Handle::File(file_b));
    assert!(parent.file_table.register_open(5, 2).is_some());
    assert!(parent.file_table.register_open(6, 2).is_some());
    let original_host_handles = host.handles.clone();
    let original_child_handles = child.handles.clone();
    host.fail_duplicate_at = Some(2);

    assert!(matches!(
        child.inherit_handles_from(&parent, &mut host),
        Err(DosError::HostOperation(error)) if error.code == DosErrorCode::AccessDenied
    ));
    assert_eq!(host.duplicate_calls, 2);
    assert_eq!(host.handles, original_host_handles);
    assert_eq!(child.handles, original_child_handles);
    assert!(child.orphan_file_handles.is_empty());
}

#[test]
fn psp_dta_drive_exit_and_unsupported_calls_are_explicit() {
    let mut dos = DosKernel::new(0x1234);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.ds = 0x2222;
    regs.set_dx(0x3333);
    set_ah(&mut regs, 0x1a);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    set_ah(&mut regs, 0x2f);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!((regs.es, regs.bx()), (0x2222, 0x3333));
    set_ah(&mut regs, 0x51);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.bx(), 0x1234);

    set_ah(&mut regs, 0x0e);
    regs.set_dl(4);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(host.current_drive(), 4);
    assert_eq!(regs.al(), 3);

    set_ah(&mut regs, 0x61); // AH=60h now has the canonical-name buffer contract.
    assert_eq!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap(), DosAction::Continue);
    assert_eq!(regs.ax(), DosErrorCode::InvalidFunction as u16);
    assert!(regs.carry());

    set_ah(&mut regs, 0x51);
    assert_eq!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap(), DosAction::Continue);
    assert_eq!(regs.bx(), 0x1234);

    assert_eq!(dos.interrupt(0x10, &mut regs, &mut memory, &mut host).unwrap(), DosAction::Unhandled);
    assert_eq!(dos.interrupt(0x20, &mut regs, &mut memory, &mut host).unwrap(), DosAction::Exit(0));
}

#[test]
fn interrupt_vector_services_use_ivt_and_preserve_unmentioned_state() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.eax = 0x1234_00ff;
    regs.ebx = 0x5678_9abc;
    regs.ecx = 0x1357_2468;
    regs.edx = 0x9abc_def0;
    regs.esi = 0x1122_3344;
    regs.edi = 0x5566_7788;
    regs.ebp = 0x99aa_bbcc;
    regs.esp = 0xddee_ff00;
    regs.eip = 0x3141_5926;
    regs.eflags = 0x0000_0ad7;
    regs.cs = 0x1111;
    regs.ds = 0x2222;
    regs.es = 0x3333;
    regs.ss = 0x4444;
    regs.fs = 0x5555;
    regs.gs = 0x6666;

    set_ah(&mut regs, 0x25);
    let before_set = regs.clone();
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(&memory.0[0x3fc..0x400], &[0xf0, 0xde, 0x22, 0x22]);
    assert_eq!(regs, before_set);

    memory.put(0x3fc, &[0x34, 0x12, 0x78, 0x56]);
    set_ah(&mut regs, 0x35);
    let before_get = regs.clone();
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let mut expected = before_get;
    expected.es = 0x5678;
    expected.set_bx(0x1234);
    assert_eq!(regs, expected);
}

#[test]
fn interrupt_vector_services_reject_short_ivt_memory_before_mutation() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory(vec![0xa5; 0x3ff]);
    let mut regs = Registers::default();
    regs.eax = 0x4321_00ff;
    regs.ebx = 0x8765_4321;
    regs.edx = 0x1234_5678;
    regs.eflags = 0x0000_0ad7;
    regs.ds = 0x1111;
    regs.es = 0x2222;

    set_ah(&mut regs, 0x25);
    let before_set = regs.clone();
    let before_memory = memory.0.clone();
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::Memory(_))
    ));
    assert_eq!(regs, before_set);
    assert_eq!(memory.0, before_memory);

    set_ah(&mut regs, 0x35);
    let before_get = regs.clone();
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::Memory(_))
    ));
    assert_eq!(regs, before_get);
}

#[test]
fn directory_attributes_rename_and_current_directory_use_host_operations() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.ds = 0x1000;

    memory.put(0x10100, b"C:\\WORK\0");
    regs.set_dx(0x0100);
    set_ah(&mut regs, 0x39);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert!(host.directories.contains_key(b"C:\\WORK".as_slice()));

    host.drive = 2;
    set_ah(&mut regs, 0x3b);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    regs.set_si(0x0200);
    regs.set_dl(0);
    set_ah(&mut regs, 0x47);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let mut cwd = [0; 5];
    memory.read(PhysAddr(0x10200), &mut cwd).unwrap();
    assert_eq!(&cwd, b"WORK\0");

    let file = host.file_create(b"C:\\WORK\\A.TXT", 0).unwrap();
    host.file_close(file).unwrap();
    memory.put(0x10300, b"C:\\WORK\\A.TXT\0");
    regs.set_dx(0x0300);
    regs.set_cx(0x0027);
    regs.set_al(1);
    set_ah(&mut regs, 0x43);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());

    regs.set_al(0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs.cx(), 0x0027);

    memory.put(0x10400, b"C:\\WORK\\B.TXT\0");
    regs.ds = 0x1000;
    regs.set_dx(0x0300);
    regs.es = 0x1000;
    regs.set_di(0x0400);
    set_ah(&mut regs, 0x56);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert!(!host.paths.contains_key(b"C:\\WORK\\A.TXT".as_slice()));
    assert!(host.paths.contains_key(b"C:\\WORK\\B.TXT".as_slice()));
    assert_eq!(host.file_get_attributes(b"C:\\WORK\\B.TXT").unwrap(), 0x27);

    memory.put(0x10500, b"D:\\WORK\\C.TXT\0");
    regs.set_di(0x0500);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::NotSameDevice as u16);

    host.file_delete(b"C:\\WORK\\B.TXT").unwrap();
    regs.set_dx(0x0100);
    set_ah(&mut regs, 0x3a);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::CannotRemoveCurrentDirectory as u16);

    memory.put(0x10600, b"C:\\\0");
    regs.set_dx(0x0600);
    set_ah(&mut regs, 0x3b);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    regs.set_dx(0x0100);
    set_ah(&mut regs, 0x3a);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert!(!host.directories.contains_key(b"C:\\WORK".as_slice()));
}

#[test]
fn find_first_next_serialize_dta_and_bind_state_to_psp_and_dta() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    host.directory_create(b"C:\\LIST").unwrap();
    add_test_file(&mut host, b"C:\\LIST\\A.TXT", 0, b"one");
    add_test_file(&mut host, b"C:\\LIST\\AB.TXT", 0x02, b"hidden");
    add_test_file(&mut host, b"C:\\LIST\\NOTE.BIN", 0, b"other");
    memory.put(0x10100, b"C:\\LIST\\A*.*\0");

    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    regs.set_cx(0x0002); // include normal and hidden entries
    set_ah(&mut regs, 0x4e);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let mut dta = [0; 43];
    memory.read(PhysAddr(0x10080), &mut dta).unwrap();
    assert_eq!(dta[0x15], 0);
    assert_eq!(u32::from_le_bytes(dta[0x1a..0x1e].try_into().unwrap()), 3);
    assert_eq!(&dta[0x1e..0x24], b"A.TXT\0");

    memory.0.truncate(0x10088); // marker is readable, complete 43-byte DTA is not writable
    set_ah(&mut regs, 0x4f);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::Memory(_))));
    assert_eq!(host.searches.len(), 1);

    memory.0.resize(0x20_000, 0);
    regs.set_bx(0x2000);
    set_ah(&mut regs, 0x50);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    set_ah(&mut regs, 0x4f);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::NoMoreFiles as u16);
    assert_eq!(host.searches.len(), 1);

    regs.set_bx(0x1000);
    set_ah(&mut regs, 0x50);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    set_ah(&mut regs, 0x4f);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    memory.read(PhysAddr(0x10080), &mut dta).unwrap();
    assert_eq!(dta[0x15], 0x02);
    assert_eq!(&dta[0x1e..0x25], b"AB.TXT\0");

    set_ah(&mut regs, 0x4f);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::NoMoreFiles as u16);
    assert!(host.searches.is_empty());
}

#[test]
fn dos_wildcards_expand_to_fixed_83_fields_and_attributes_follow_dos_rules() {
    let host = TestHost::default();
    let (_, foo_star) = parse_search_spec(b"foo*.*", &host).unwrap();
    assert_eq!(&foo_star.name[..3], b"FOO");
    assert!(foo_star.name[3..].iter().all(|byte| *byte == b'?'));
    assert!(foo_star.extension.iter().all(|byte| *byte == b'?'));
    let (_, all) = parse_search_spec(b"*.*", &host).unwrap();
    let (name, extension) = short_name_fields(b"README", text_codec::CodePage::Cp437).unwrap();
    assert!(dos_field_matches(&all.name, &name));
    assert!(dos_field_matches(&all.extension, &extension));
    assert!(search_attribute_matches(0, 0x20)); // read-only/archive don't hide normal files
    assert!(!search_attribute_matches(0, 0x02));
    assert!(search_attribute_matches(0x02, 0x02));
    assert!(search_attribute_matches(0x10, 0x10));
    assert!(!search_attribute_matches(0x08, 0));
    assert!(search_attribute_matches(0x08, 0x08));
}

#[test]
fn cp936_trail_backslash_does_not_split_a_dos_search_path() {
    let host = TestHost { code_page: Some(text_codec::CodePage::Cp936), ..TestHost::default() };
    let path = [b'C', b':', b'\\', 0x81, b'\\', b'.', b'T', b'X', b'T'];
    let (directory, pattern) = parse_search_spec(&path, &host).unwrap();
    assert_eq!(directory, b"C:\\");
    let folded = text_codec::uppercase_oem_name(&[0x81, b'\\'], text_codec::CodePage::Cp936).unwrap();
    assert_eq!(&pattern.name[..2], folded);
    assert_eq!(&pattern.name[2..], b"      ");
    assert_eq!(&pattern.extension, b"TXT");
}

#[test]
fn mcb_resize_allocate_and_free_keep_a_valid_chain() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();

    set_ah(&mut regs, 0x4a);
    regs.es = 0x1000;
    regs.set_bx(0x0800);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());

    set_ah(&mut regs, 0x48);
    regs.set_bx(0x0020);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let allocated_segment = regs.ax();
    assert_eq!(allocated_segment, 0x1801);
    assert!(!regs.carry());

    set_ah(&mut regs, 0x49);
    regs.es = allocated_segment;
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());

    let chain = dos.mcb_chain(&mut memory).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].owner(), 0x1000);
    assert_eq!(chain[1].owner(), 0);
    assert_eq!(chain[1].kind(), b'Z');
}

fn add_test_file(host: &mut TestHost, path: &[u8], attributes: u8, bytes: &[u8]) {
    let token = host.file_create(path, attributes).unwrap();
    host.file_for(token).unwrap().bytes = bytes.to_vec();
    host.file_close(token).unwrap();
}

#[test]
fn duplicate_services_reject_owned_tokens_without_closing_or_replacing_handles() {
    for service in [0x45, 0x46] {
        for reused_token in 0..3 {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let source = host.file_create(b"source", 0).unwrap();
            let target = host.file_create(b"target", 0).unwrap();
            let orphan = host.file_create(b"orphan", 0).unwrap();
            dos.handles.insert(3, Handle::File(source));
            dos.handles.insert(4, Handle::File(target));
            assert!(dos.file_table.register_open(3, 2).is_some());
            assert!(dos.file_table.register_open(4, 2).is_some());
            dos.reserve_file_cleanup_slot().unwrap();
            dos.retain_unclosed_file(orphan).unwrap();
            let original_handles = dos.handles.clone();
            let original_host_handles = host.handles.clone();
            host.duplicate_token_override = Some([source, target, orphan][reused_token]);
            let mut regs = Registers::default();
            regs.set_ah(service);
            regs.set_bx(3);
            regs.set_cx(4);

            assert!(matches!(
                dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
                Err(DosError::HostContractViolation(_))
            ));
            assert_eq!(host.duplicate_calls, 1);
            assert_eq!(dos.handles, original_handles);
            assert_eq!(host.handles, original_host_handles);
            assert!(dos.file_table.can_duplicate_handle(3, 5));
            assert!(dos.file_table.can_duplicate_handle(4, 5));
            assert!(!dos.file_table.can_duplicate_handle(5, 6));
            assert_eq!(dos.orphan_file_handles, vec![orphan]);
        }
    }
}

#[test]
fn handle_inheritance_rejects_other_parent_tokens_without_closing_them() {
    let mut parent = DosKernel::new(0x1000);
    let mut child = DosKernel::new(0x2000);
    let mut host = TestHost::default();
    let source = host.file_create(b"source", 0).unwrap();
    let other = host.file_create(b"other", 0).unwrap();
    parent.handles.insert(3, Handle::File(source));
    parent.handles.insert(4, Handle::File(other));
    assert!(parent.file_table.register_open(3, 2).is_some());
    assert!(parent.file_table.register_open(4, 2).is_some());
    let original_host_handles = host.handles.clone();
    let original_child_handles = child.handles.clone();
    host.duplicate_token_override = Some(other);

    assert!(matches!(
        child.inherit_handles_from(&parent, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    assert_eq!(host.duplicate_calls, 1);
    assert_eq!(host.handles, original_host_handles);
    assert_eq!(child.handles, original_child_handles);
    assert!(child.orphan_file_handles.is_empty());
}

#[test]
fn duplicate_services_keep_shared_cursor_and_independent_close_ownership() {
    for service in [0x45, 0x46] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let source = host.file_create(b"source", 0).unwrap();
        let target = host.file_create(b"target", 0).unwrap();
        host.file_write(source, b"abc").unwrap();
        host.file_seek(source, 0, DosSeekOrigin::Start).unwrap();
        dos.handles.insert(3, Handle::File(source));
        dos.handles.insert(4, Handle::File(target));
        assert!(dos.file_table.register_open(3, 2).is_some());
        assert!(dos.file_table.register_open(4, 2).is_some());
        let mut regs = Registers::default();
        regs.set_ah(service);
        regs.set_bx(3);
        regs.set_cx(4);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        let duplicate = regs.ax();
        assert_eq!(duplicate, if service == 0x45 { 5 } else { 4 });
        let Handle::File(copy) = dos.handles[&duplicate] else {
            panic!("duplicate must be a host file");
        };
        assert_ne!(copy, source);
        assert_eq!(host.handles.contains_key(&target), service == 0x45);
        let mut byte = [0];
        assert_eq!(host.file_read(copy, &mut byte).unwrap(), 1);
        assert_eq!(byte, [b'a']);
        assert_eq!(host.file_seek(source, 0, DosSeekOrigin::Current).unwrap(), 1);

        regs.set_ah(0x3e);
        regs.set_bx(duplicate);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        assert!(!host.handles.contains_key(&copy));
        assert_eq!(host.file_read(source, &mut byte).unwrap(), 1);
        assert_eq!(byte, [b'b']);
    }
}


#[test]
fn character_input_follows_forced_duplicate_without_consuming_console_cache() {
    for service in [0x01, 0x07, 0x08, 0x0a] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let source = host.file_create(b"input", 0).unwrap();
        host.file_write(source, b"\0\r").unwrap();
        host.file_seek(source, 0, DosSeekOrigin::Start).unwrap();
        dos.handles.insert(3, Handle::File(source));
        assert!(dos.file_table.register_open(3, 2).is_some());
        dos.pending_input = Some(b'p');
        host.input.extend([b'q']);
        let mut regs = Registers::default();
        regs.set_ax(0x4600);
        regs.set_bx(3);
        regs.set_cx(0);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());

        regs.set_ah(service);
        regs.ds = 0x1000;
        regs.set_dx(0x0100);
        memory.put(0x10100, &[4, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        if service == 0x0a {
            let mut result = [0; 3];
            memory.read(PhysAddr(0x10101), &mut result).unwrap();
            assert_eq!(result, [1, 0, b'\r']);
            assert_eq!(host.stdout, b"\0\r\n");
        } else {
            assert_eq!(regs.al(), 0); // NUL is data, not EOF.
            assert_eq!(host.stdout.as_slice(), if service == 0x01 { b"\0".as_slice() } else { b"".as_slice() });
        }
        assert_eq!(dos.pending_input, Some(b'p'));
        assert_eq!(host.input.front(), Some(&b'q'));
        assert_eq!(host.file_seek(source, 0, DosSeekOrigin::Current).unwrap(),
            if service == 0x0a { 2 } else { 1 });
    }
}

#[test]
fn character_input_rejects_closed_or_wrong_direction_standard_input() {
    for replacement in [None, Some(super::state::StandardHandle::Output)] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        dos.handles.remove(&0);
        if let Some(kind) = replacement {
            dos.handles.insert(0, Handle::Standard(kind));
        }
        dos.pending_input = Some(b'p');
        let mut regs = Registers::default();
        regs.set_ah(0x08);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(regs.carry());
        assert_eq!(regs.ax(), DosErrorCode::InvalidHandle as u16);
        assert_eq!(dos.pending_input, Some(b'p'));
    }
}

#[test]
fn redirected_character_input_eof_does_not_fabricate_a_byte_or_use_console_input() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let file = host.file_create(b"empty", 0).unwrap();
    dos.handles.insert(0, Handle::File(file));
    dos.pending_input = Some(b'p');
    let mut regs = Registers::default();
    regs.set_ah(0x01);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::GeneralFailure as u16);
    assert!(host.stdout.is_empty());
    assert_eq!(dos.pending_input, Some(b'p'));
}


#[test]
fn real_mode_dta_query_returns_words_without_dereferencing_but_search_validates() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_ah(0x1a);
    regs.ds = 0xffff;
    regs.set_dx(0xffff);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    regs.set_ah(0x2f);
    let mut expected = regs.clone();
    expected.es = 0xffff;
    expected.set_bx(0xffff);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs, expected);

    memory.put(0x10100, b"*.*\0");
    regs.set_ah(0x4e);
    regs.ds = 0x1000;
    regs.set_dx(0x0100);
    regs.set_cx(0);
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::Memory(MemoryError::OutOfBounds { .. }))
    ));
    assert_eq!(host.next_search_id, 0);
    assert!(host.searches.is_empty());
}

#[path = "create_new_tests.rs"]
mod create_new_tests;

#[path = "file_time_tests.rs"]
mod file_time_tests;

#[path = "file_commit_tests.rs"]
mod file_commit_tests;

#[path = "extended_open_tests.rs"]
mod extended_open_tests;

#[path = "temporary_file_tests.rs"]
mod temporary_file_tests;

#[path = "input_polling_tests.rs"]
mod input_polling_tests;

#[path = "handle_capacity_lifecycle_tests.rs"]
mod handle_capacity_lifecycle_tests;

#[path = "search_exhaustion_tests.rs"]
mod search_exhaustion_tests;

#[path = "file_seek_tests.rs"]
mod file_seek_tests;

#[path = "file_read_access_tests.rs"]
mod file_read_access_tests;

#[path = "file_write_access_tests.rs"]
mod file_write_access_tests;

#[path = "current_directory_tests.rs"]
mod current_directory_tests;
