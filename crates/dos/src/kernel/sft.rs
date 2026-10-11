//! Guest-visible DOS 4 system file table and per-process job file table.
//!
//! The SFT entry layout follows Microsoft's DOS 4 `SF.INC`: 59 bytes per
//! entry. Guest PSP handles index the JFT, whose bytes contain SFT indices;
//! `0xff` denotes a closed JFT slot. Host file tokens remain in `DosKernel`.

use std::collections::BTreeMap;
use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;

use crate::{
    DosError, DosErrorCode, DosFileStatus, DosHost, DosIoctlObjectInfo, DosIoctlStream,
};
use guest_core::{GuestMemory, real_address};

use super::state::{DosKernel, Handle, StandardHandle};
use super::system::{CON_HEADER_OFFSET, SFT_OFFSET, SFT_ENTRY_COUNT,
    SFT_ENTRY_BYTES as SFT_ENTRY_LEN, SFT_HEADER_BYTES as SFT_HEADER_LEN};

// Small tables, including three standard handles plus one file, avoid the
// fixed index setup cost measured in full-refresh benchmarks.
const DIRECT_SFT_RECORD_LIMIT: usize = 4;

pub(super) const DEFAULT_JFT_LEN: u16 = 20;
pub(super) const MAX_JFT_LEN: u16 = 0xfffe;
pub(super) const PSP_JFT_COUNT_OFFSET: u16 = 0x32;
pub(super) const PSP_JFT_POINTER_OFFSET: u16 = 0x34;

const SF_REF_COUNT: usize = 0;
const SF_MODE: usize = 2;
const SF_ATTRIBUTES: usize = 4;
const SF_DEVICE_INFO: usize = 5;
const SF_DEVICE_HEADER: usize = 7;
const SF_TIME: usize = 13;
const SF_DATE: usize = 15;
const SF_SIZE: usize = 17;
const SF_POSITION: usize = 21;
const SF_SHORT_NAME: usize = 32;
const SFT_MODE_NO_INHERIT: u16 = 0x0080;

const SFT_DEVICE: u16 = 0x0080;
const SFT_DEVICE_EOF: u16 = 0x0040;
const SFT_DEVICE_RAW: u16 = 0x0020;
const SFT_DEVICE_CON_OUT: u16 = 0x0002;
const SFT_DEVICE_CON_IN: u16 = 0x0001;
const SFT_FILE_CLEAN: u16 = 0x0040;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SftKind {
    File,
    Standard(StandardHandle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SftEntry {
    references: u16,
    mode: u16,
    kind: SftKind,
    attributes: u8,
    device_info: u16,
    device_header: Option<(u16, u16)>,
    status: Option<DosFileStatus>,
}

impl SftEntry {
    fn standard(kind: StandardHandle) -> Self {
        let mode = match kind {
            StandardHandle::Input => 0,
            StandardHandle::Output | StandardHandle::Error => 1,
        };
        Self {
            references: 1,
            mode,
            kind: SftKind::Standard(kind),
            attributes: 0,
            device_info: 0,
            device_header: None,
            status: None,
        }
    }

    fn file(mode: u16) -> Self {
        Self {
            references: 1,
            mode,
            kind: SftKind::File,
            attributes: 0,
            device_info: 0,
            device_header: None,
            status: None,
        }
    }

    fn encode(self) -> [u8; SFT_ENTRY_LEN] {
        let mut bytes = [0; SFT_ENTRY_LEN];
        bytes[SF_REF_COUNT..SF_REF_COUNT + 2].copy_from_slice(&self.references.to_le_bytes());
        bytes[SF_MODE..SF_MODE + 2].copy_from_slice(&self.mode.to_le_bytes());
        bytes[SF_ATTRIBUTES] = self.attributes;
        bytes[SF_DEVICE_INFO..SF_DEVICE_INFO + 2]
            .copy_from_slice(&self.device_info.to_le_bytes());
        if let Some((offset, segment)) = self.device_header {
            bytes[SF_DEVICE_HEADER..SF_DEVICE_HEADER + 2].copy_from_slice(&offset.to_le_bytes());
            bytes[SF_DEVICE_HEADER + 2..SF_DEVICE_HEADER + 4]
                .copy_from_slice(&segment.to_le_bytes());
        }
        if matches!(self.kind, SftKind::Standard(_)) && self.device_header.is_some() {
            bytes[SF_SHORT_NAME..SF_SHORT_NAME + 11].copy_from_slice(b"CON        ");
        }
        if let Some(status) = self.status {
            bytes[SF_TIME..SF_TIME + 2].copy_from_slice(&status.write_time.to_le_bytes());
            bytes[SF_DATE..SF_DATE + 2].copy_from_slice(&status.write_date.to_le_bytes());
            bytes[SF_SIZE..SF_SIZE + 4].copy_from_slice(&status.size.to_le_bytes());
            bytes[SF_POSITION..SF_POSITION + 4].copy_from_slice(&status.position.to_le_bytes());
            bytes[SF_SHORT_NAME..SF_SHORT_NAME + 11].copy_from_slice(&status.short_name);
            bytes[SF_ATTRIBUTES] = status.attributes;
        }
        // Cluster, directory, sharing, and filesystem-specific fields are not
        // supplied by this host-file backend, so they remain zeroed.
        bytes
    }
}

#[derive(Debug)]
struct SftPool {
    entries: [Option<SftEntry>; SFT_ENTRY_COUNT],
}

/// Per-process JFT aliases over shared SFT records. Clones created through
/// `inherit_from` share the SFT pool, while each process keeps its own JFT map.
#[derive(Debug)]
pub(super) struct FileTable {
    handles: BTreeMap<u16, u8>,
    pool: Rc<RefCell<SftPool>>,
}

impl FileTable {
    pub(super) fn new() -> Self {
        let mut entries = std::array::from_fn(|_| None);
        entries[0] = Some(SftEntry::standard(StandardHandle::Input));
        entries[1] = Some(SftEntry::standard(StandardHandle::Output));
        entries[2] = Some(SftEntry::standard(StandardHandle::Error));
        Self {
            handles: BTreeMap::from([(0, 0), (1, 1), (2, 2)]),
            pool: Rc::new(RefCell::new(SftPool { entries })),
        }
    }

    fn pool(&self) -> RefMut<'_, SftPool> {
        self.pool.borrow_mut()
    }

    pub(super) fn has_free_slot(&self) -> bool {
        self.pool().entries.iter().any(Option::is_none)
    }

    pub(super) fn is_handle_inheritable(&self, guest_handle: u16) -> bool {
        let Some(&index) = self.handles.get(&guest_handle) else { return false; };
        self.pool_read().entries[index as usize]
            .is_some_and(|entry| entry.mode & SFT_MODE_NO_INHERIT == 0)
    }

    /// Access mode from the owned SFT, never its guest-writable projection.
    pub(super) fn file_open_mode(&self, guest_handle: u16) -> Option<u16> {
        let &index = self.handles.get(&guest_handle)?;
        self.pool_read().entries[index as usize]
            .filter(|entry| entry.kind == SftKind::File)
            .map(|entry| entry.mode)
    }

    pub(super) fn can_duplicate_handle(&self, source: u16, target: u16) -> bool {
        if target >= MAX_JFT_LEN { return false; }
        let Some(&index) = self.handles.get(&source) else { return false; };
        if self.handles.get(&target) == Some(&index) { return true; }
        self.pool().entries[index as usize].is_some_and(|entry| entry.references < u16::MAX)
    }

    pub(super) fn register_open(&mut self, guest_handle: u16, mode: u16) -> Option<u8> {
        if guest_handle >= MAX_JFT_LEN || self.handles.contains_key(&guest_handle) {
            return None;
        }
        let shared_pool = Rc::clone(&self.pool);
        let mut pool = shared_pool.borrow_mut();
        let (index, slot) = pool.entries.iter_mut().enumerate().find(|(_, slot)| slot.is_none())?;
        *slot = Some(SftEntry::file(mode));
        let index = u8::try_from(index).ok()?;
        drop(pool);
        self.handles.insert(guest_handle, index);
        Some(index)
    }

    /// Alias `target` to the SFT object referenced by `source`, replacing any
    /// previous target entry. This is also the table operation for DOS forcedup.
    pub(super) fn duplicate_handle(&mut self, source: u16, target: u16) -> bool {
        if source == target {
            return self.handles.contains_key(&source);
        }
        if target >= MAX_JFT_LEN {
            return false;
        }
        let Some(source_index) = self.handles.get(&source).copied() else {
            return false;
        };
        if self.handles.get(&target) == Some(&source_index) { return true; }
        let shared_pool = Rc::clone(&self.pool);
        let mut pool = shared_pool.borrow_mut();
        let Some(source_entry) = pool.entries[source_index as usize].as_mut() else {
            return false;
        };
        let Some(new_count) = source_entry.references.checked_add(1) else {
            return false;
        };
        source_entry.references = new_count;

        if let Some(old_index) = self.handles.remove(&target) {
            release_entry(&mut pool, old_index);
        }
        self.handles.insert(target, source_index);
        true
    }

    pub(super) fn remove_handle(&mut self, guest_handle: u16) {
        if let Some(index) = self.handles.remove(&guest_handle) {
            let mut pool = self.pool();
            release_entry(&mut pool, index);
        }
    }

    pub(super) fn clear(&mut self) {
        let indices: Vec<_> = self.handles.values().copied().collect();
        self.handles.clear();
        let mut pool = self.pool();
        for index in indices {
            release_entry(&mut pool, index);
        }
    }

    /// Copy the parent's JFT mappings into this process and share its SFT pool.
    /// Handles opened with DOS's no-inherit flag are omitted. Returns false
    /// without changing this table if an SFT reference would overflow.
    pub(super) fn inherit_from(&mut self, parent: &FileTable) -> bool {
        let parent_pool = Rc::clone(&parent.pool);
        let parent_handles = {
            let pool = parent_pool.borrow();
            let mut inherited = BTreeMap::new();
            for (&handle, &index) in &parent.handles {
                let Some(entry) = pool.entries[index as usize] else { return false; };
                if handle < DEFAULT_JFT_LEN && entry.mode & SFT_MODE_NO_INHERIT == 0 {
                    inherited.insert(handle, index);
                }
            }
            inherited
        };
        let mut occurrences = BTreeMap::<u8, u32>::new();
        for &index in parent_handles.values() {
            *occurrences.entry(index).or_default() += 1;
        }
        {
            let pool = parent_pool.borrow();
            for (&index, &copies) in &occurrences {
                let Some(entry) = pool.entries[index as usize] else { return false; };
                if u32::from(entry.references) + copies > u32::from(u16::MAX) {
                    return false;
                }
            }
        }

        {
            let mut pool = parent_pool.borrow_mut();
            for (index, copies) in &occurrences {
                let entry = pool.entries[*index as usize].as_mut().expect("preflighted SFT slot");
                entry.references += *copies as u16;
            }
        }
        self.clear();
        self.pool = parent_pool;
        self.handles = parent_handles;
        true
    }

    fn pool_read(&self) -> Ref<'_, SftPool> {
        self.pool.borrow()
    }

    fn update_entry(&self, index: u8, entry: SftEntry) -> bool {
        let mut pool = self.pool();
        let Some(slot) = pool.entries[index as usize].as_mut() else { return false; };
        *slot = entry;
        true
    }

    fn entries_snapshot(&self) -> Vec<(u8, SftEntry)> {
        self.pool_read().entries.iter().enumerate().filter_map(|(index, entry)| {
            entry.map(|entry| (index as u8, entry))
        }).collect()
    }

    fn index_for_handle(&self, guest_handle: u16) -> Option<u8> {
        self.handles.get(&guest_handle).copied()
    }

    fn representative(
        &self,
        index: u8,
        handles: impl IntoIterator<Item = (u16, Handle)>,
    ) -> Option<Handle> {
        handles.into_iter().find_map(|(guest, handle)| {
            (self.index_for_handle(guest) == Some(index)).then_some(handle)
        })
    }

    /// Select the lowest DOS handle for each live SFT once per refresh. The
    /// caller supplies handles in ascending guest-handle order. Stop when all
    /// live records have a representative, avoiding a scan of trailing aliases.
    /// Missing mappings remain for refresh's existing checks.
    fn representatives(
        &self,
        records: &[(u8, SftEntry)],
        handles: impl IntoIterator<Item = (u16, Handle)>,
    ) -> [Option<Handle>; SFT_ENTRY_COUNT] {
        let mut representatives = [None; SFT_ENTRY_COUNT];
        let mut needed = [false; SFT_ENTRY_COUNT];
        for &(index, _) in records {
            needed[usize::from(index)] = true;
        }
        let mut remaining = records.len();
        if remaining == 0 { return representatives; }
        for (guest, handle) in handles {
            let Some(index) = self.index_for_handle(guest) else { continue; };
            let Some(required) = needed.get_mut(usize::from(index)) else { continue; };
            if *required {
                representatives[usize::from(index)] = Some(handle);
                *required = false;
                remaining -= 1;
                if remaining == 0 { break; }
            }
        }
        representatives
    }

    pub(super) fn live_handles(&self) -> impl ExactSizeIterator<Item = (u16, u8)> + '_ {
        self.handles.iter().map(|(&handle, &index)| (handle, index))
    }
}

impl Drop for FileTable {
    fn drop(&mut self) { self.clear(); }
}

fn release_entry(pool: &mut SftPool, index: u8) {
    let Some(entry) = pool.entries[index as usize].as_mut() else { return; };
    if entry.references <= 1 {
        pool.entries[index as usize] = None;
    } else {
        entry.references -= 1;
    }
}

impl DosKernel {
    /// Preflight the PSP's current JFT and the guest SFT storage before any DOS
    /// operation can have host-visible side effects.
    pub(super) fn validate_jft(&self, memory: &impl GuestMemory) -> Result<(), DosError> {
        let Some(system) = self.system_tables.as_ref() else { return Ok(()); };
        self.validate_jft_metadata(memory)?;
        let sft_address = real_address(system.segment, SFT_OFFSET);
        memory.validate_write(sft_address, SFT_HEADER_LEN + SFT_ENTRY_COUNT * SFT_ENTRY_LEN)?;
        Ok(())
    }

    pub(super) fn validate_jft_metadata(&self, memory: &impl GuestMemory) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        let header = real_address(self.jft_owner_psp, PSP_JFT_COUNT_OFFSET);
        memory.validate_read(header, 6)?;
        let count = memory.read_u16(header)?;
        if !(DEFAULT_JFT_LEN..=MAX_JFT_LEN).contains(&count) || count != self.jft_capacity {
            return Err(DosError::MalformedGuestInput("PSP JFT size differs from the owned capacity"));
        }
        let pointer = real_address(self.jft_owner_psp, PSP_JFT_POINTER_OFFSET);
        let offset = memory.read_u16(pointer)?;
        let segment = memory.read_u16(real_address(self.jft_owner_psp, PSP_JFT_POINTER_OFFSET + 2))?;
        if u32::from(offset) + u32::from(count) > 0x1_0000 {
            return Err(DosError::MalformedGuestInput("PSP JFT crosses a segment boundary"));
        }
        if let Some(lease) = self.jft_storage.as_ref() {
            if offset != 0 || segment != lease.extent().data_segment()
                || lease.extent().owner_psp_segment() != self.jft_owner_psp
            {
                return Err(DosError::MalformedGuestInput("PSP JFT pointer differs from its owned storage"));
            }
        } else if count != DEFAULT_JFT_LEN {
            return Err(DosError::HostContractViolation("expanded JFT has no owned storage"));
        }
        let address = real_address(segment, offset);
        memory.validate_read(address, usize::from(count))?;
        memory.validate_write(address, usize::from(count))?;
        for (handle, _) in self.file_table.live_handles() {
            if handle >= count {
                return Err(DosError::MalformedGuestInput("open handle is outside the PSP JFT"));
            }
        }
        Ok(())
    }

    /// Refresh guest SFT entries and this PSP's JFT from tracked handles.
    /// Calls without installed system tables preserve the legacy DOS unit-test path.
    pub(super) fn refresh_sft(
        &mut self,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        self.refresh_sft_with(memory, host, |dos, records, host, system_segment| {
            if records.len() <= DIRECT_SFT_RECORD_LIMIT {
                for (index, entry) in records.iter_mut() {
                    let current = dos.file_table.representative(
                        *index, dos.handles.iter().map(|(&guest, &handle)| (guest, handle)),
                    );
                    refresh_entry(entry, current, host, system_segment)?;
                }
            } else {
                let representatives = dos.file_table.representatives(
                    records,
                    dos.handles.iter().map(|(&guest, &handle)| (guest, handle)),
                );
                for (index, entry) in records.iter_mut() {
                    refresh_entry(entry, representatives[usize::from(*index)], host, system_segment)?;
                }
            }
            Ok(())
        })
    }

    // Keep validation, snapshots, pool publication, serialization, and both
    // guest writes shared with the test-only pre-indexing baseline. The closure
    // is statically dispatched and replaces only selection plus host queries.
    fn refresh_sft_with<H: DosHost>(
        &mut self,
        memory: &mut impl GuestMemory,
        host: &mut H,
        refresh_records: impl FnOnce(&Self, &mut [(u8, SftEntry)], &mut H, u16) -> Result<(), DosError>,
    ) -> Result<(), DosError> {
        let Some(system) = self.system_tables.as_ref() else { return Ok(()); };
        self.validate_jft(memory)?;

        let (jft_count, jft_offset, jft_segment) = read_jft_pointer(self.jft_owner_psp, memory)?;
        let sft_address = real_address(system.segment, SFT_OFFSET);
        let sft_len = SFT_HEADER_LEN + SFT_ENTRY_COUNT * SFT_ENTRY_LEN;
        memory.validate_write(sft_address, sft_len)?;

        let mut records = self.file_table.entries_snapshot();
        refresh_records(self, &mut records, host, system.segment)?;

        let mut sft_bytes = vec![0; sft_len];
        sft_bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        sft_bytes[4..6].copy_from_slice(&(SFT_ENTRY_COUNT as u16).to_le_bytes());
        for (index, entry) in records {
            let start = SFT_HEADER_LEN + usize::from(index) * SFT_ENTRY_LEN;
            sft_bytes[start..start + SFT_ENTRY_LEN].copy_from_slice(&entry.encode());
            if !self.file_table.update_entry(index, entry) {
                return Err(DosError::HostContractViolation("SFT slot disappeared during refresh"));
            }
        }
        let mut jft_bytes = vec![0xff; usize::from(jft_count)];
        for (handle, index) in self.file_table.live_handles() {
            let Some(Handle::File(_) | Handle::Standard(_)) = self.handles.get(&handle) else {
                return Err(DosError::HostContractViolation("JFT mapping has no live DOS handle"));
            };
            let Some(slot) = jft_bytes.get_mut(usize::from(handle)) else {
                return Err(DosError::MalformedGuestInput("open handle is outside the PSP JFT"));
            };
            *slot = index;
        }
        for &handle in self.handles.keys() {
            if self.file_table.index_for_handle(handle).is_none() {
                return Err(DosError::HostContractViolation("DOS handle has no SFT mapping"));
            }
        }

        memory.write(sft_address, &sft_bytes)?;
        memory.write(real_address(jft_segment, jft_offset), &jft_bytes)?;
        Ok(())
    }
}

fn read_jft_pointer(
    psp_segment: u16,
    memory: &impl GuestMemory,
) -> Result<(u16, u16, u16), DosError> {
    let count = memory.read_u16(real_address(psp_segment, PSP_JFT_COUNT_OFFSET))?;
    let offset = memory.read_u16(real_address(psp_segment, PSP_JFT_POINTER_OFFSET))?;
    let segment = memory.read_u16(real_address(psp_segment, PSP_JFT_POINTER_OFFSET + 2))?;
    Ok((count, offset, segment))
}

fn refresh_entry(
    entry: &mut SftEntry,
    current: Option<Handle>,
    host: &mut impl DosHost,
    system_segment: u16,
) -> Result<(), DosError> {
    let Some(current) = current else { return Ok(()); };
    match (entry.kind, current) {
        (SftKind::File, Handle::File(file)) => refresh_file_entry(entry, file, host),
        (SftKind::Standard(kind), Handle::Standard(current_kind)) if kind == current_kind => {
            refresh_standard_entry(entry, kind, host, system_segment)
        }
        _ => Err(DosError::HostContractViolation("JFT handle kind disagrees with its SFT entry")),
    }
}

fn refresh_file_entry(
    entry: &mut SftEntry,
    file: crate::DosHostFile,
    host: &mut impl DosHost,
) -> Result<(), DosError> {
    let info = host.file_ioctl_info(file).map_err(DosError::HostOperation)?;
    let DosIoctlObjectInfo::File { drive, written } = info else {
        return Err(DosError::HostContractViolation("DOS file token was reported as a character device"));
    };
    if drive > 25 {
        return Err(DosError::HostContractViolation("host returned a drive outside A: through Z:"));
    }
    let status = host.file_status(file).map_err(DosError::HostOperation)?;
    if status.attributes & !0x3f != 0 {
        return Err(DosError::HostContractViolation("host returned unsupported DOS file attribute bits"));
    }
    entry.attributes = status.attributes;
    entry.device_info = u16::from(drive) | if written { 0 } else { SFT_FILE_CLEAN };
    entry.device_header = None; // No guest DPB is installed for host-backed files.
    entry.status = Some(status);
    Ok(())
}

fn refresh_standard_entry(
    entry: &mut SftEntry,
    kind: StandardHandle,
    host: &impl DosHost,
    system_segment: u16,
) -> Result<(), DosError> {
    let stream = match kind {
        StandardHandle::Input => DosIoctlStream::Input,
        StandardHandle::Output => DosIoctlStream::Output,
        StandardHandle::Error => DosIoctlStream::Error,
    };
    match host.standard_ioctl_info(stream) {
        Ok(DosIoctlObjectInfo::CharacterDevice {
            input_eof,
            raw_mode,
            standard_input,
            standard_output,
        }) => {
            entry.device_info = SFT_DEVICE
                | if input_eof { 0 } else { SFT_DEVICE_EOF }
                | if raw_mode { SFT_DEVICE_RAW } else { 0 }
                | if standard_input { SFT_DEVICE_CON_IN } else { 0 }
                | if standard_output { SFT_DEVICE_CON_OUT } else { 0 };
            entry.device_header = if standard_input || standard_output {
                Some((CON_HEADER_OFFSET, system_segment))
            } else {
                None
            };
            entry.attributes = 0;
            entry.status = None;
        }
        Ok(DosIoctlObjectInfo::File { drive, written }) => {
            if drive > 25 {
                return Err(DosError::HostContractViolation("host returned a drive outside A: through Z:"));
            }
            entry.device_info = u16::from(drive) | if written { 0 } else { SFT_FILE_CLEAN };
            entry.device_header = None;
            entry.attributes = 0;
            entry.status = None;
        }
        Err(error) if matches!(error.code,
            DosErrorCode::InvalidFunction | DosErrorCode::InvalidHandle) => {
            // A GUI process may have no native standard handles. Its tracked
            // DOS standard slots still exist, but their backing object cannot
            // be classified, just like an unknown redirected stream. Refresh
            // metadata without inventing a CON device or aborting an unrelated
            // DOS call. Actual stream I/O and IOCTL retain the host's error.
            entry.device_info = 0;
            entry.device_header = None;
            entry.attributes = 0;
            entry.status = None;
        }
        Err(error) => return Err(DosError::HostOperation(error)),
    }
    Ok(())
}

#[cfg(test)]
#[path = "sft_tests.rs"]
mod tests;
