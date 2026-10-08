//! Owned physical memory for the guest machine, plus an A20-aware bus view.
//!
//! [`Memory`] implements [`crate::GuestMemory`] as raw physical memory. This is
//! intentional: backing stores such as XMS and DPMI need to address their
//! physical bytes without being affected by the CPU's A20 gate. CPU and DOS
//! real-address accesses should use [`Memory::bus`], whose `GuestMemory`
//! implementation decodes A20 on every access.

use std::cell::RefCell;
use std::ops::Range;
use std::rc::Rc;

use crate::{AtomicMemoryRange, MemoryError, PhysAddr};

#[path = "memory_storage.rs"]
mod memory_storage;
use memory_storage::MemoryBacking;
pub use memory_storage::MemoryStorage;
#[path = "memory/memory_atomic.rs"]
mod memory_atomic;
#[path = "memory_device_mapping.rs"]
mod memory_device_mapping;
pub use memory_device_mapping::DeviceMappingHandle;

/// The default physical memory size: 16 MiB above the 1 MiB real-mode space.
pub const DEFAULT_MEMORY_SIZE: u32 = 17 * 1024 * 1024;

/// Start of the protected physical ROM window.
pub const ROM_START: u32 = 0x000f_0000;
/// Exclusive end of the protected physical ROM window.
pub const ROM_END: u32 = 0x0010_0000;

const A20_MASK: u32 = 0x0010_0000;
const A20_BANK_SIZE: u64 = 0x0010_0000;

/// A process-owned device view over a guest-physical memory aperture.
///
/// Offsets passed to the device are relative to the start passed to
/// [`Memory::map_device`]. The validation hooks run for every mapped chunk in
/// a complete access before any device read/write callback runs. Validation
/// hooks must be side-effect free. Implementors must make successful
/// validation a promise that the corresponding callback will not fail for
/// ordinary device-state reasons; writes must validate all rejection
/// conditions up front. The memory owner cannot roll back device state if an
/// implementation returns an unexpected error after successful validation.
///
/// `read` takes `&self` so devices with read side effects can keep their
/// process-owned state behind interior mutability. Reads may update latches
/// only after the owner has preflighted the full physical or A20-bus request.
pub trait MemoryMappedDevice {
    /// Validate a read before any part of the containing access is performed.
    fn validate_read(&self, _offset: u32, _length: u32) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Validate a write before any part of the containing access is performed.
    fn validate_write(&self, _offset: u32, _length: u32) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Read an aperture-relative range into `output`.
    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError>;

    /// Write an aperture-relative range from `input`.
    fn write(&self, offset: u32, input: &[u8]) -> Result<(), MemoryError>;

    /// Atomically read, transform, and write one provider-local range set.
    /// Implementations must serialize this with ordinary device accesses.
    /// The default keeps devices that cannot provide that guarantee from
    /// silently falling back to separate reads and writes.
    fn atomic_update(
        &self,
        _ranges: &[AtomicMemoryRange],
        _value: &mut [u8],
        _update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        Err(MemoryError::AtomicityUnavailable)
    }
}

struct DeviceMapping {
    identity: u64,
    start: u32,
    end: u32,
    device: Rc<dyn MemoryMappedDevice>,
}

#[derive(Clone, Copy)]
struct AccessChunk {
    address: u32,
    length: usize,
    device_index: Option<usize>,
}

/// Retained identity of one memory owner and its address-routing configuration.
/// It retains no storage borrow and grants no access to guest or host bytes.
/// A slice or collection index cannot identify routing across callback frames;
/// reuse the existing owner brand and a nonwrapping epoch for that contract.
#[derive(Clone)]
pub struct MemoryDomainSnapshot {
    owner: Rc<()>,
    size_bytes: u32,
    routing_epoch: u64,
}

impl PartialEq for MemoryDomainSnapshot {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.size_bytes == other.size_bytes
            && self.routing_epoch == other.routing_epoch
    }
}

impl Eq for MemoryDomainSnapshot {}

/// The single owner of the simulated guest's memory bytes.
///
/// Guest bytes live in ordinary process-owned storage: by default a `Vec<u8>`,
/// or an explicitly supplied safe [`MemoryStorage`]. Guest physical addresses
/// are checked offsets into that storage. This does not map host physical RAM,
/// kernel memory, device memory, or hardware ports.
///
/// Ordinary physical writes and mutable mappings cannot modify the ROM
/// window. [`Memory::initialize_rom`] is the explicit loader-only path for
/// filling it. Raw slices returned by `map_physical` borrow this owner and
/// cannot outlive it. Device-mapping handles are opaque unmap identities; they
/// do not borrow this owner and dropping one does not remove its mapping.
pub struct Memory {
    backing: MemoryBacking,
    storage_failure: RefCell<Option<MemoryError>>,
    size_bytes: u32,
    a20_enabled: bool,
    devices: Vec<DeviceMapping>,
    device_mapping_owner: Rc<()>,
    next_device_mapping_identity: Option<u64>,
    routing_epoch: u64,
}

impl Memory {
    /// Allocate the default 17 MiB zero-filled guest memory.
    pub fn new() -> Result<Self, MemoryError> {
        Self::with_size(DEFAULT_MEMORY_SIZE)
    }

    /// Allocate a zero-filled guest-memory buffer of `size` bytes.
    ///
    /// At least 1 MiB is required because the protected ROM window is part of
    /// the physical-memory contract. Allocation failure is returned instead
    /// of panicking.
    pub fn with_size(size: u32) -> Result<Self, MemoryError> {
        if size < ROM_END {
            return Err(MemoryError::InvalidMapping);
        }

        let capacity = usize::try_from(size).map_err(|_| MemoryError::AllocationFailed)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| MemoryError::AllocationFailed)?;
        bytes.resize(capacity, 0);

        Ok(Self {
            backing: MemoryBacking::Owned(bytes),
            storage_failure: RefCell::new(None),
            size_bytes: size,
            a20_enabled: true,
            devices: Vec::new(),
            device_mapping_owner: Rc::new(()),
            next_device_mapping_identity: Some(1),
            routing_epoch: 0,
        })
    }

    /// Use initialized host-owned storage for guest physical memory.
    ///
    /// The storage's size is captured once and must remain fixed for this
    /// `Memory` lifetime. It must already provide readable and writable bytes
    /// throughout its full range. At least the protected ROM window must fit.
    /// External storage never exposes a Rust slice through physical mapping.
    pub fn with_storage(storage: Box<dyn MemoryStorage>) -> Result<Self, MemoryError> {
        let size_bytes = storage.len();
        if size_bytes < ROM_END {
            return Err(MemoryError::InvalidMapping);
        }
        Ok(Self {
            backing: MemoryBacking::external(storage, size_bytes),
            storage_failure: RefCell::new(None),
            size_bytes,
            a20_enabled: true,
            devices: Vec::new(),
            device_mapping_owner: Rc::new(()),
            next_device_mapping_identity: Some(1),
            routing_epoch: 0,
        })
    }

    /// Return the physical memory size in bytes.
    pub fn size_bytes(&self) -> u32 {
        self.size_bytes
    }

    /// Capture the fixed backing owner and current routing configuration.
    /// Ordinary RAM writes do not invalidate this identity.
    pub fn domain_snapshot(&self) -> MemoryDomainSnapshot {
        MemoryDomainSnapshot {
            owner: Rc::clone(&self.device_mapping_owner),
            size_bytes: self.size_bytes,
            routing_epoch: self.routing_epoch,
        }
    }

    /// Check a retained identity without reading storage or mapped devices.
    pub fn domain_matches(&self, snapshot: &MemoryDomainSnapshot) -> bool {
        Rc::ptr_eq(&self.device_mapping_owner, &snapshot.owner)
            && self.size_bytes == snapshot.size_bytes
            && self.routing_epoch == snapshot.routing_epoch
    }

    fn next_routing_epoch(&self) -> Result<u64, MemoryError> {
        self.routing_epoch
            .checked_add(1)
            .ok_or(MemoryError::RoutingEpochExhausted)
    }

    /// Return the first fatal RAM or mapped-device storage failure, if any.
    ///
    /// Once a backing or mapped device reports `StorageAccess`, all later
    /// accesses fail with this same error. The failure remains available even
    /// if an upper layer translated an intermediate guest operation's error.
    pub fn storage_failure(&self) -> Option<MemoryError> {
        self.storage_failure.borrow().clone()
    }

    fn check_storage_failure(&self) -> Result<(), MemoryError> {
        match self.storage_failure() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn record_storage_result<T>(
        &self,
        result: Result<T, MemoryError>,
    ) -> Result<T, MemoryError> {
        match result {
            Err(error) if matches!(&error, MemoryError::StorageAccess { .. }) => {
                let mut failure = self.storage_failure.borrow_mut();
                Err(failure.get_or_insert(error).clone())
            }
            other => other,
        }
    }

    fn read_backing(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        self.check_storage_failure()?;
        let result = self.backing.read(offset, output);
        self.record_storage_result(result)
    }

    fn write_backing(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        self.check_storage_failure()?;
        let result = self.backing.write(offset, input);
        self.record_storage_result(result)
    }

    /// Whether the A20 gate is open for accesses through [`Memory::bus`].
    pub fn a20_enabled(&self) -> bool {
        self.a20_enabled
    }

    /// Set the A20 gate state used by subsequently-created and live bus views.
    pub fn set_a20_enabled(&mut self, enabled: bool) -> Result<(), MemoryError> {
        if self.a20_enabled == enabled {
            return Ok(());
        }
        let epoch = self.next_routing_epoch()?;
        self.a20_enabled = enabled;
        self.routing_epoch = epoch;
        Ok(())
    }

    /// Borrow an A20-aware guest bus for CPU and DOS real-address accesses.
    ///
    /// The view keeps an exclusive borrow of this owner, preventing the A20
    /// setting or physical bytes from changing independently while it is in
    /// use. The view is not a second memory allocation.
    pub fn bus(&mut self) -> BusMemory<'_> {
        BusMemory { memory: self }
    }

    /// Read raw physical bytes, without applying the A20 gate.
    pub fn read_physical(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        self.check_storage_failure()?;
        let touches_device = self.validate_physical_access(address, output.len(), false)?;
        if !touches_device {
            return self.read_backing(address.0, output);
        }
        let chunks = self.physical_chunks(address.0, output.len());
        self.read_chunks(&chunks, output)?;
        Ok(())
    }

    /// Write raw physical bytes, without applying the A20 gate.
    ///
    /// The whole guest range, including ROM protection and device validation,
    /// is checked before backing access. A storage failure is propagated with
    /// its transfer count; external storage may have completed a partial write
    /// and is not rewritten from a snapshot.
    pub fn write_physical(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        self.check_storage_failure()?;
        let touches_device = self.validate_physical_access(address, input.len(), true)?;
        if !touches_device {
            return self.write_backing(address.0, input);
        }
        let chunks = self.physical_chunks(address.0, input.len());
        self.write_chunks(&chunks, input)?;
        Ok(())
    }

    /// Initialize bytes in the protected ROM window.
    ///
    /// This privileged path accepts only a range fully contained in
    /// `0xF0000..0x100000`; it never grants mutable access to the ROM through
    /// an ordinary mapping or [`crate::GuestMemory::write`].
    pub fn initialize_rom(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        self.check_storage_failure()?;
        let range = self.checked_physical_range(address, input.len())?;
        let inside_rom = if input.is_empty() {
            (ROM_START as usize..=ROM_END as usize).contains(&range.start)
        } else {
            range.start >= ROM_START as usize && range.end <= ROM_END as usize
        };
        if !inside_rom {
            return Err(MemoryError::InvalidMapping);
        }
        self.write_backing(address.0, input)
    }

    /// Borrow one checked, contiguous raw physical range for reading.
    ///
    /// The returned slice has the same lifetime as `&self`. This is a raw
    /// physical mapping; it does not apply A20 decoding. External storage does
    /// not expose a slice and returns [`MemoryError::InvalidMapping`].
    pub fn map_physical(&self, address: PhysAddr, length: usize) -> Result<&[u8], MemoryError> {
        self.check_storage_failure()?;
        let range = self.checked_physical_range(address, length)?;
        self.reject_device_overlap(address.0, length)?;
        self.backing.owned_bytes()
            .and_then(|bytes| bytes.get(range))
            .ok_or(MemoryError::InvalidMapping)
    }

    /// Borrow one checked, contiguous raw physical range for writing.
    ///
    /// The borrow prevents other access to this owner for its lifetime. ROM
    /// ranges are rejected before the mutable slice is created. External
    /// storage does not expose a slice and returns [`MemoryError::InvalidMapping`].
    pub fn map_physical_mut(
        &mut self,
        address: PhysAddr,
        length: usize,
    ) -> Result<&mut [u8], MemoryError> {
        self.check_storage_failure()?;
        let range = self.checked_physical_range(address, length)?;
        Self::check_writable_range(address.0, length, &range)?;
        self.reject_device_overlap(address.0, length)?;
        self.backing.owned_bytes_mut()
            .and_then(|bytes| bytes.get_mut(range))
            .ok_or(MemoryError::InvalidMapping)
    }

    /// Validate a contiguous range of ordinary guest RAM without returning a
    /// Rust slice. Device apertures are rejected, and writes also respect ROM.
    pub fn validate_ram_range(
        &self,
        address: PhysAddr,
        length: usize,
        writable: bool,
    ) -> Result<(), MemoryError> {
        self.check_storage_failure()?;
        let range = self.checked_physical_range(address, length)?;
        if writable {
            Self::check_writable_range(address.0, length, &range)?;
        }
        self.reject_device_overlap(address.0, length)
    }

    fn reject_device_overlap(&self, address: u32, length: usize) -> Result<(), MemoryError> {
        if self.device_overlaps(address, length) {
            return Err(MemoryError::InvalidMapping);
        }
        Ok(())
    }

    fn device_overlaps(&self, address: u32, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let Ok(length) = u64::try_from(length) else {
            return true;
        };
        let Some(end) = u64::from(address).checked_add(length) else {
            return true;
        };
        self.devices.iter().any(|mapping| {
            u64::from(address) < u64::from(mapping.end) && u64::from(mapping.start) < end
        })
    }

    fn physical_chunks(&self, address: u32, length: usize) -> Vec<AccessChunk> {
        let mut chunks = Vec::new();
        let end = u64::from(address) + length as u64;
        let mut cursor = u64::from(address);
        while cursor < end {
            let current = cursor as u32;
            let (device_index, chunk_end) = self.chunk_end(current, end);
            let chunk_length = (chunk_end - cursor) as usize;
            chunks.push(AccessChunk {
                address: current,
                length: chunk_length,
                device_index,
            });
            cursor = chunk_end;
        }
        chunks
    }

    fn chunk_end(&self, address: u32, end: u64) -> (Option<usize>, u64) {
        for (index, mapping) in self.devices.iter().enumerate() {
            if address >= mapping.start && address < mapping.end {
                return (Some(index), end.min(u64::from(mapping.end)));
            }
            if address < mapping.start {
                return (None, end.min(u64::from(mapping.start)));
            }
        }
        (None, end)
    }

    fn validate_physical_access(
        &self,
        address: PhysAddr,
        length: usize,
        write: bool,
    ) -> Result<bool, MemoryError> {
        self.check_storage_failure()?;
        let range = self.checked_physical_range(address, length)?;
        if write {
            Self::check_writable_range(address.0, length, &range)?;
        }
        if !self.device_overlaps(address.0, length) {
            return Ok(false);
        }
        let chunks = self.physical_chunks(address.0, length);
        self.validate_device_chunks(&chunks, write)?;
        Ok(true)
    }

    fn validate_device_chunks(
        &self,
        chunks: &[AccessChunk],
        write: bool,
    ) -> Result<(), MemoryError> {
        for chunk in chunks {
            let Some(index) = chunk.device_index else {
                continue;
            };
            let mapping = &self.devices[index];
            let offset = chunk.address - mapping.start;
            let length = u32::try_from(chunk.length).map_err(|_| MemoryError::AddressOverflow)?;
            if write {
                self.record_storage_result(mapping.device.validate_write(offset, length))?;
            } else {
                self.record_storage_result(mapping.device.validate_read(offset, length))?;
            }
        }
        Ok(())
    }

    fn read_chunks(&self, chunks: &[AccessChunk], output: &mut [u8]) -> Result<(), MemoryError> {
        let mut output_offset = 0usize;
        for chunk in chunks {
            let output_end = output_offset + chunk.length;
            let output_part = &mut output[output_offset..output_end];
            if let Some(index) = chunk.device_index {
                let mapping = &self.devices[index];
                self.record_storage_result(mapping.device.read(
                    chunk.address - mapping.start, output_part,
                ))?;
            } else {
                self.read_backing(chunk.address, output_part)?;
            }
            output_offset = output_end;
        }
        Ok(())
    }

    fn write_chunks(&mut self, chunks: &[AccessChunk], input: &[u8]) -> Result<(), MemoryError> {
        // Device callbacks run only after every chunk has been validated. Run
        // them before storage writes. External storage errors are propagated;
        // a backend-reported partial transfer is not snapshot-restored.
        let mut input_offset = 0usize;
        for chunk in chunks {
            let input_end = input_offset + chunk.length;
            if let Some(index) = chunk.device_index {
                let mapping = &self.devices[index];
                self.record_storage_result(mapping.device.write(
                    chunk.address - mapping.start,
                    &input[input_offset..input_end],
                ))?;
            }
            input_offset = input_end;
        }

        input_offset = 0;
        for chunk in chunks {
            let input_end = input_offset + chunk.length;
            if chunk.device_index.is_none() {
                self.write_backing(
                    chunk.address,
                    &input[input_offset..input_end],
                )?;
            }
            input_offset = input_end;
        }
        Ok(())
    }

    fn checked_physical_range(
        &self,
        address: PhysAddr,
        length: usize,
    ) -> Result<Range<usize>, MemoryError> {
        let start = u64::from(address.0);
        let length_u64 = u64::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start
            .checked_add(length_u64)
            .ok_or(MemoryError::AddressOverflow)?;
        if end > (u64::from(u32::MAX) + 1) {
            return Err(MemoryError::AddressOverflow);
        }
        if start > u64::from(self.size_bytes()) || end > u64::from(self.size_bytes()) {
            return Err(MemoryError::OutOfBounds {
                address: address.0,
                length,
            });
        }

        let start = usize::try_from(start).map_err(|_| MemoryError::AddressOverflow)?;
        let end = usize::try_from(end).map_err(|_| MemoryError::AddressOverflow)?;
        Ok(start..end)
    }

    fn check_writable_range(
        address: u32,
        length: usize,
        range: &Range<usize>,
    ) -> Result<(), MemoryError> {
        if !range.is_empty() && range.start < ROM_END as usize && range.end > ROM_START as usize {
            return Err(MemoryError::ReadOnly { address, length });
        }
        Ok(())
    }

    fn decode_a20(&self, address: u32) -> u32 {
        if self.a20_enabled {
            address
        } else {
            address & !A20_MASK
        }
    }

    fn checked_bus_logical_end(address: PhysAddr, length: usize) -> Result<u64, MemoryError> {
        let length = u64::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        let end = u64::from(address.0)
            .checked_add(length)
            .ok_or(MemoryError::AddressOverflow)?;
        if end > (u64::from(u32::MAX) + 1) {
            return Err(MemoryError::AddressOverflow);
        }
        Ok(end)
    }

    fn bus_chunk_length(&self, logical_address: u64, logical_end: u64) -> usize {
        let remaining = logical_end - logical_address;
        if self.a20_enabled {
            remaining as usize
        } else {
            let until_bank_end = A20_BANK_SIZE - (logical_address % A20_BANK_SIZE);
            remaining.min(until_bank_end) as usize
        }
    }

    fn validate_bus_range(
        &self,
        address: PhysAddr,
        length: usize,
        write: bool,
    ) -> Result<bool, MemoryError> {
        self.check_storage_failure()?;
        let logical_end = Self::checked_bus_logical_end(address, length)?;
        if length == 0 {
            let decoded = self.decode_a20(address.0);
            let range = self.checked_physical_range(PhysAddr(decoded), 0)?;
            if write {
                Self::check_writable_range(decoded, 0, &range)?;
            }
            return Ok(false);
        }

        let mut cursor = u64::from(address.0);
        let mut touches_device = false;
        while cursor < logical_end {
            let logical_address = cursor as u32;
            let decoded = self.decode_a20(logical_address);
            let chunk_length = self.bus_chunk_length(cursor, logical_end);
            let range = self.checked_physical_range(PhysAddr(decoded), chunk_length)?;
            if write {
                Self::check_writable_range(decoded, chunk_length, &range)?;
            }
            if self.device_overlaps(decoded, chunk_length) {
                touches_device = true;
                let chunks = self.physical_chunks(decoded, chunk_length);
                self.validate_device_chunks(&chunks, write)?;
            }
            cursor += chunk_length as u64;
        }
        Ok(touches_device)
    }

    fn bus_chunks(&self, address: PhysAddr, length: usize) -> Vec<AccessChunk> {
        let logical_end = u64::from(address.0) + length as u64;
        let mut cursor = u64::from(address.0);
        let mut chunks = Vec::new();
        while cursor < logical_end {
            let decoded = self.decode_a20(cursor as u32);
            let bus_length = self.bus_chunk_length(cursor, logical_end);
            chunks.extend(self.physical_chunks(decoded, bus_length));
            cursor += bus_length as u64;
        }
        chunks
    }

    fn read_bus(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        let touches_device = self.validate_bus_range(address, output.len(), false)?;
        if !touches_device {
            let logical_end = Self::checked_bus_logical_end(address, output.len())?;
            let mut cursor = u64::from(address.0);
            let mut output_offset = 0usize;
            while cursor < logical_end {
                let decoded = self.decode_a20(cursor as u32);
                let chunk_length = self.bus_chunk_length(cursor, logical_end);
                let output_end = output_offset + chunk_length;
                self.read_backing(decoded, &mut output[output_offset..output_end])?;
                output_offset = output_end;
                cursor += chunk_length as u64;
            }
            return Ok(());
        }
        let chunks = self.bus_chunks(address, output.len());
        self.read_chunks(&chunks, output)
    }

    fn write_bus(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        // Validate every decoded physical chunk, including ROM protection,
        // and every mapped device before attempting any write. A backing
        // transfer failure may still leave the reported partial transfer.
        let touches_device = self.validate_bus_range(address, input.len(), true)?;
        if !touches_device {
            let logical_end = Self::checked_bus_logical_end(address, input.len())?;
            let mut cursor = u64::from(address.0);
            let mut input_offset = 0usize;
            while cursor < logical_end {
                let decoded = self.decode_a20(cursor as u32);
                let chunk_length = self.bus_chunk_length(cursor, logical_end);
                let input_end = input_offset + chunk_length;
                self.write_backing(decoded, &input[input_offset..input_end])?;
                input_offset = input_end;
                cursor += chunk_length as u64;
            }
            return Ok(());
        }
        let chunks = self.bus_chunks(address, input.len());
        self.write_chunks(&chunks, input)
    }
}

/// A borrowed guest bus that applies the owner's A20 setting.
///
/// When A20 is disabled, bit 20 is cleared independently for each real-mode
/// address. Cross-bank operations may therefore access two non-contiguous
    /// physical regions; [`crate::GuestMemory::read`] handles those safely and writes
    /// validate every decoded region before attempting the write. A backing
    /// transfer failure is propagated with its transferred-byte count and is
    /// not rolled back from a snapshot.
pub struct BusMemory<'a> {
    memory: &'a mut Memory,
}

impl BusMemory<'_> {
    /// Return the current A20 gate state.
    pub fn a20_enabled(&self) -> bool {
        self.memory.a20_enabled()
    }

    /// Borrow the checked, process-owned guest storage without A20 decoding.
    /// Protected ABI selectors resolve against this backing; real-mode DOS
    /// addresses continue through this bus view's [`crate::GuestMemory`] methods.
    pub fn backing(&self) -> &Memory {
        self.memory
    }

    /// Mutably borrow the same checked guest backing without A20 decoding.
    pub fn backing_mut(&mut self) -> &mut Memory {
        self.memory
    }
}
