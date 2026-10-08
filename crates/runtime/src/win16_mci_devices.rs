use super::*;

impl Win16State {
    pub(super) fn resolve_mci_device(&self, guest: u16) -> Option<Win16MciDeviceEntry> {
        self.mci
            .devices
            .get(&guest)
            .copied()
            .filter(|entry| !entry.closed)
    }

    pub(super) fn resolve_mci_window(&self, guest: u16) -> Option<crate::Win16HostWindow> {
        self.window_handles.get(&guest).copied()
    }

    pub(super) fn retain_mci_device(
        &mut self,
        device: Win16HostMciDevice,
        device_type: Option<u32>,
        creator_task: u16,
    ) -> Result<u16, RuntimeError> {
        if let Some((guest, entry)) = self
            .mci
            .devices
            .iter_mut()
            .find(|(_, entry)| entry.host == device)
        {
            if entry.closed {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "host reused a retired Win16 MCI device identity",
                ));
            }
            if entry.device_type.is_none() {
                entry.device_type = device_type;
            }
            return Ok(*guest);
        }
        if self
            .mci
            .devices
            .values()
            .any(|entry| entry.host == device && entry.closed)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host reused a retired Win16 MCI device identity",
            ));
        }
        for _ in 0..u16::MAX {
            let guest = self.mci.next_guest_id.wrapping_add(1);
            self.mci.next_guest_id = guest;
            if guest == 0
                || guest == MCI_ALL_DEVICE_ID
                || self.mci.devices.contains_key(&guest)
                || self.mci.reserved_guest_ids.contains(&guest)
            {
                continue;
            }
            self.mci.devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI device alias",
                    error,
                )
            })?;
            self.mci.devices.insert(
                guest,
                Win16MciDeviceEntry {
                    host: device,
                    device_type,
                    creator_task,
                    closed: false,
                },
            );
            return Ok(guest);
        }
        Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 MCI guest device aliases exhausted",
        ))
    }

    pub(super) fn retain_mci_yield_source(&mut self, host: Win16HostMciDevice) {
        if let Some(procedure) = self.mci.yield_procedures.get(&host) {
            let owner = crate::Win16HostMciYieldRegistration {
                device: host,
                registration: procedure.registration,
            };
            if !self.mci.retired_yield_sources.contains(&owner) {
                self.mci.retired_yield_sources.push(owner);
            }
        }
    }

    pub(super) fn retain_all_mci_yield_sources(&mut self) {
        let retired = &mut self.mci.retired_yield_sources;
        for (device, procedure) in &self.mci.yield_procedures {
            let owner = crate::Win16HostMciYieldRegistration {
                device: *device,
                registration: procedure.registration,
            };
            if !retired.contains(&owner) {
                retired.push(owner);
            }
        }
    }

    pub(super) fn retire_mci_device(&mut self, guest: u16) {
        if let Some(host) = self.mci.devices.get(&guest).map(|entry| entry.host) {
            self.retain_mci_yield_source(host);
            self.retain_retired_mci_device(host);
            self.retire_mci_host_device(host);
        }
    }

    pub(super) fn retire_all_mci_devices(&mut self) {
        self.retain_all_mci_yield_sources();
        let orphan_devices = &mut self.mci.orphan_devices;
        for entry in self.mci.devices.values().filter(|entry| !entry.closed) {
            if !orphan_devices.contains(&entry.host) {
                orphan_devices.push(entry.host);
            }
        }
        for entry in self.mci.devices.values_mut() {
            entry.closed = true;
        }
        self.mci.yield_procedures.clear();
        self.mci.driver_data.clear();
    }

    pub(super) fn retain_retired_mci_device(&mut self, host: Win16HostMciDevice) {
        if !self.mci.orphan_devices.contains(&host) {
            self.mci.orphan_devices.push(host);
        }
    }

    pub(super) fn retire_mci_host_device(&mut self, host: Win16HostMciDevice) {
        for entry in self
            .mci
            .devices
            .values_mut()
            .filter(|entry| entry.host == host)
        {
            entry.closed = true;
        }
        self.mci.yield_procedures.remove(&host);
        self.mci.driver_data.remove(&host);
    }

    pub(super) fn retire_mci_host_device_with_sources(&mut self, host: Win16HostMciDevice) {
        self.retain_mci_yield_source(host);
        self.retain_retired_mci_device(host);
        self.retire_mci_host_device(host);
    }

    pub(super) fn reserve_mci_guest_id(&mut self) -> Result<u16, RuntimeError> {
        self.mci.devices.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 MCI device alias",
                error,
            )
        })?;
        self.mci
            .reserved_guest_ids
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI alias token",
                    error,
                )
            })?;
        // The Win16 MCI API stores a 32-bit guest driver-data value. Keep it
        // separate from the pointer-sized native driver-private slot.
        self.mci.driver_data.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 MCI guest driver-data slot",
                error,
            )
        })?;
        for _ in 0..u16::MAX {
            let guest = self.mci.next_guest_id.wrapping_add(1);
            self.mci.next_guest_id = guest;
            if guest != 0
                && guest != MCI_ALL_DEVICE_ID
                && !self.mci.devices.contains_key(&guest)
                && self.mci.reserved_guest_ids.insert(guest)
            {
                return Ok(guest);
            }
        }
        Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 MCI guest device aliases exhausted",
        ))
    }

    pub(super) fn release_reserved_from_request(&mut self, request: &Win16MciRequest) {
        let id = match request {
            Win16MciRequest::SendCommand {
                reserved_device_id, ..
            }
            | Win16MciRequest::SendString {
                reserved_device_id, ..
            }
            | Win16MciRequest::Execute {
                reserved_device_id, ..
            } => *reserved_device_id,
            _ => None,
        };
        if let Some(id) = id {
            self.mci.reserved_guest_ids.remove(&id);
        }
    }

    pub(super) fn commit_reserved_mci_device(
        &mut self,
        guest: u16,
        device: Win16HostMciDevice,
        device_type: Option<u32>,
        creator_task: u16,
    ) -> Result<u16, RuntimeError> {
        if !self.mci.reserved_guest_ids.remove(&guest) || self.mci.devices.contains_key(&guest) {
            self.retain_orphan_mci_device(device);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI open lost its pre-reserved guest device alias",
            ));
        }
        let existing = self
            .mci
            .devices
            .iter_mut()
            .find(|(_, entry)| entry.host == device)
            .map(|(existing_guest, entry)| {
                if !entry.closed && entry.device_type.is_none() {
                    entry.device_type = device_type;
                }
                (*existing_guest, entry.closed)
            });
        if let Some((existing_guest, closed)) = existing {
            if closed {
                self.retain_orphan_mci_device(device);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "host reused a retired Win16 MCI device identity",
                ));
            }
            self.mci.orphan_devices.retain(|orphan| *orphan != device);
            return Ok(existing_guest);
        }
        if self.mci.devices.values().any(|entry| entry.host == device && entry.closed) {
            self.retain_orphan_mci_device(device);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host reused a retired Win16 MCI device identity",
            ));
        }
        self.mci.devices.insert(
            guest,
            Win16MciDeviceEntry {
                host: device,
                device_type,
                creator_task,
                closed: false,
            },
        );
        self.mci.orphan_devices.retain(|orphan| *orphan != device);
        Ok(guest)
    }

    pub(super) fn retain_orphan_mci_device(&mut self, device: Win16HostMciDevice) {
        if !self.mci.orphan_devices.contains(&device) {
            self.mci.orphan_devices.push(device);
        }
    }
}
