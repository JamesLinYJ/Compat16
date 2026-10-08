use std::rc::Rc;

use crate::{MemoryError, PhysAddr};

use super::{DeviceMapping, Memory, MemoryMappedDevice, ROM_END, ROM_START};

/// Opaque identity for removing one device mapping from its owning [`Memory`].
///
/// Cloning the handle creates another reference to the same identity. Dropping
/// a handle does not unmap the device; callers explicitly remove it with
/// [`Memory::unmap_device`].
/// Standard collection indices do not identify an allocation's owner or
/// survive removal and address reuse. The owner brand and monotonic identity
/// preserve those two guest aperture constraints without exposing addresses.
#[derive(Clone)]
pub struct DeviceMappingHandle {
    owner: Rc<()>,
    identity: u64,
}

impl Memory {
    /// Verify that a retained handle still names the exact process-owned
    /// device aperture expected by an owner before retiring its selector.
    /// This read-only check does not borrow or expose the device storage.
    pub fn device_mapping_matches(
        &self,
        handle: &DeviceMappingHandle,
        start: PhysAddr,
        length: u32,
        device: &Rc<dyn MemoryMappedDevice>,
    ) -> bool {
        if !Rc::ptr_eq(&self.device_mapping_owner, &handle.owner) || length == 0 {
            return false;
        }
        let Some(end) = start.0.checked_add(length) else { return false; };
        self.devices.iter().any(|mapping| {
            mapping.identity == handle.identity
                && mapping.start == start.0
                && mapping.end == end
                && Rc::ptr_eq(&mapping.device, device)
        })
    }

    /// Map a process-owned device over a guest-physical address range.
    ///
    /// The range must be non-empty, in bounds, disjoint from the protected ROM
    /// window, and disjoint from existing devices. Mapped-device bytes remain
    /// backed by the configured process-owned storage, but all supported
    /// physical and bus accesses are routed to the device instead. Borrowed raw
    /// slices that overlap the aperture are rejected so there is no second
    /// visible copy of device state.
    ///
    /// The mapping remains installed when this method discards its temporary
    /// handle.
    pub fn map_device(
        &mut self,
        start: PhysAddr,
        length: u32,
        device: Rc<dyn MemoryMappedDevice>,
    ) -> Result<(), MemoryError> {
        let _handle = self.map_device_scoped(start, length, device)?;
        Ok(())
    }

    /// Map a process-owned device and return a handle that can explicitly
    /// remove this exact mapping later.
    ///
    /// Invalid ranges, ROM overlap, and overlap with another device are
    /// rejected. Failed validation or allocation leaves the mapping list and
    /// next identity unchanged.
    pub fn map_device_scoped(
        &mut self,
        start: PhysAddr,
        length: u32,
        device: Rc<dyn MemoryMappedDevice>,
    ) -> Result<DeviceMappingHandle, MemoryError> {
        if length == 0 {
            return Err(MemoryError::InvalidMapping);
        }
        let end = start
            .0
            .checked_add(length)
            .ok_or(MemoryError::AddressOverflow)?;
        let range = self.checked_physical_range(start, length as usize)?;
        if range.start < ROM_END as usize && range.end > ROM_START as usize {
            return Err(MemoryError::InvalidMapping);
        }
        if self.devices.iter().any(|mapping| {
            u64::from(start.0) < u64::from(mapping.end)
                && u64::from(mapping.start) < u64::from(end)
        }) {
            return Err(MemoryError::InvalidMapping);
        }

        let identity = self
            .next_device_mapping_identity
            .ok_or(MemoryError::MappingIdentityExhausted)?;
        let routing_epoch = self.next_routing_epoch()?;
        let insertion = self
            .devices
            .binary_search_by_key(&start.0, |mapping| mapping.start)
            .unwrap_or_else(|index| index);
        self.devices
            .try_reserve(1)
            .map_err(|_| MemoryError::AllocationFailed)?;

        self.devices.insert(
            insertion,
            DeviceMapping {
                identity,
                start: start.0,
                end,
                device,
            },
        );
        self.next_device_mapping_identity = identity.checked_add(1);
        self.routing_epoch = routing_epoch;

        Ok(DeviceMappingHandle {
            owner: Rc::clone(&self.device_mapping_owner),
            identity,
        })
    }

    /// Remove the mapping named by `handle` and return its retained device.
    ///
    /// Handles from another `Memory`, already removed handles, and handles for
    /// mappings no longer present are rejected without changing memory bytes
    /// or the mapping list. Removing an overlay never copies its bytes into
    /// ordinary RAM; the returned `Rc` lets the caller manage the device's
    /// lifetime explicitly.
    pub fn unmap_device(
        &mut self,
        handle: &DeviceMappingHandle,
    ) -> Result<Rc<dyn MemoryMappedDevice>, MemoryError> {
        if !Rc::ptr_eq(&self.device_mapping_owner, &handle.owner) {
            return Err(MemoryError::InvalidMapping);
        }
        let Some(index) = self
            .devices
            .iter()
            .position(|mapping| mapping.identity == handle.identity)
        else {
            return Err(MemoryError::InvalidMapping);
        };

        let routing_epoch = self.next_routing_epoch()?;
        let device = self.devices.remove(index).device;
        self.routing_epoch = routing_epoch;
        Ok(device)
    }
}
