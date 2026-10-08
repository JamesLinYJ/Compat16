use super::*;
use std::collections::HashSet;

pub(super) struct NativeDevice {
    pub(super) identity: Win16HostMciDevice,
    pub(super) device_type: Option<u32>,
    pub(super) notification_source_id: u64,
}

#[derive(Default)]
pub(super) struct NativeDeviceRegistry {
    pub(super) by_native: HashMap<u32, NativeDevice>,
    pub(super) by_identity: HashMap<Win16HostMciDevice, u32>,
    pub(super) retired_identities: HashSet<Win16HostMciDevice>,
    pub(super) generations: HashMap<u32, u64>,
    next_yield_registration: u64,
    pub(super) yield_registrations: HashMap<Win16HostMciDevice, Win16HostMciYieldRegistrationId>,
    pub(super) retired_yield_registrations: HashSet<Win16HostMciYieldRegistration>,
    pub(super) orphan_aliases: Vec<Vec<u8>>,
    pub(super) orphan_native_ids: Vec<u32>,
}

impl NativeDeviceRegistry {
    pub(super) fn retired_snapshot(
        &self,
        output: &mut Vec<Win16HostMciDevice>,
    ) -> Result<(), RuntimeError> {
        output.try_reserve_exact(self.retired_identities.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact retired MCI device identities for shutdown receipt",
                error,
            )
        })?;
        output.extend(self.retired_identities.iter().copied());
        output.sort_unstable();
        Ok(())
    }

    pub(super) fn reserve_yield_registration(
        &mut self,
        device: Win16HostMciDevice,
    ) -> Result<Win16HostMciYieldRegistrationId, RuntimeError> {
        self.yield_registrations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI yield registration owner before installation",
                error,
            )
        })?;
        self.retired_yield_registrations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI yield registration tombstone before installation",
                error,
            )
        })?;
        if !self.by_identity.contains_key(&device) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI yield registration references an unowned device generation",
            ));
        }
        let next = self.next_yield_registration.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native MCI yield registration identity space is exhausted",
            )
        })?;
        self.next_yield_registration = next;
        Ok(Win16HostMciYieldRegistrationId(next))
    }

    pub(super) fn publish_yield_registration(
        &mut self,
        device: Win16HostMciDevice,
        registration: Win16HostMciYieldRegistrationId,
    ) {
        self.yield_registrations.insert(device, registration);
    }

    pub(super) fn current_yield_registration(
        &self,
        device: Win16HostMciDevice,
    ) -> Option<Win16HostMciYieldRegistrationId> {
        self.yield_registrations.get(&device).copied()
    }

    pub(super) fn yield_registration_snapshot(
        &self,
    ) -> Result<Vec<Win16HostMciYieldRegistration>, RuntimeError> {
        let mut registrations = Vec::new();
        registrations
            .try_reserve_exact(self.yield_registrations.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI yield-source owner snapshot",
                    error,
                )
            })?;
        registrations.extend(self.yield_registrations.iter().map(|(device, registration)| {
            Win16HostMciYieldRegistration {
                device: *device,
                registration: *registration,
            }
        }));
        registrations.sort_unstable();
        Ok(registrations)
    }

    pub(super) fn retire_yield_registration(
        &mut self,
        device: Win16HostMciDevice,
        registration: Win16HostMciYieldRegistrationId,
    ) -> Result<(), RuntimeError> {
        if self.yield_registrations.get(&device) != Some(&registration) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI yield registration generation changed before retirement",
            ));
        }
        self.yield_registrations.remove(&device);
        self.retired_yield_registrations.insert(Win16HostMciYieldRegistration {
            device,
            registration,
        });
        Ok(())
    }

    pub(super) fn identity(
        &mut self,
        native_id: u32,
        device_type: Option<u32>,
        notification_source_id: u64,
    ) -> Result<Win16HostMciDevice, RuntimeError> {
        if notification_source_id == 0 || notification_source_id == u64::MAX {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI device has a zero or reserved guest notification source ID",
            ));
        }
        if native_id == 0 || native_id == u32::MAX {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "MCI returned a reserved native device identifier",
            ));
        }
        if let Some(entry) = self.by_native.get_mut(&native_id) {
            if entry.notification_source_id != notification_source_id {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI device source ID changed within one device generation",
                ));
            }
            if entry.device_type.is_none() {
                entry.device_type = device_type;
            }
            return Ok(entry.identity);
        }
        self.by_native.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI device identity",
                error,
            )
        })?;
        self.by_identity.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI reverse identity",
                error,
            )
        })?;
        self.generations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI generation",
                error,
            )
        })?;
        self.retired_identities
            .try_reserve(self.by_identity.len().saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact retired-token tombstone before native MCI open",
                    error,
                )
            })?;
        let generation = self
            .generations
            .get(&native_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "native MCI device generation is exhausted",
                )
            })?;
        let token = NEXT_HOST_TOKEN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value: u64| {
                value.checked_add(1)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "host MCI device token space is exhausted",
                )
            })?;
        let identity = Win16HostMciDevice { token, generation };
        self.generations.insert(native_id, generation);
        self.by_native.insert(
            native_id,
            NativeDevice {
                identity,
                device_type,
                notification_source_id,
            },
        );
        self.by_identity.insert(identity, native_id);
        Ok(identity)
    }

    pub(super) fn resolve(&self, identity: Win16HostMciDevice) -> Option<(u32, Option<u32>)> {
        let native_id = *self.by_identity.get(&identity)?;
        let native = self.by_native.get(&native_id)?;
        (native.identity == identity).then_some((native_id, native.device_type))
    }

    pub(super) fn existing_identity(&self, native_id: u32) -> Option<Win16HostMciDevice> {
        self.by_native.get(&native_id).map(|entry| entry.identity)
    }

    pub(super) fn notification_source_id(
        &self,
        identity: Win16HostMciDevice,
    ) -> Option<u64> {
        let native_id = *self.by_identity.get(&identity)?;
        let entry = self.by_native.get(&native_id)?;
        (entry.identity == identity).then_some(entry.notification_source_id)
    }

    pub(super) fn is_retired(&self, identity: Win16HostMciDevice) -> bool {
        self.retired_identities.contains(&identity)
    }

    pub(super) fn retain_orphan_alias(&mut self, alias: Vec<u8>) {
        self.orphan_aliases.push(alias);
    }

    pub(super) fn retain_orphan_native_id(&mut self, native_id: u32) {
        self.orphan_native_ids.push(native_id);
    }

    pub(super) fn orphan_native_snapshot(&self) -> Result<Vec<u32>, RuntimeError> {
        let mut native_ids = Vec::new();
        native_ids
            .try_reserve_exact(self.orphan_native_ids.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MCI orphan native-ID snapshot",
                    error,
                )
            })?;
        native_ids.extend_from_slice(&self.orphan_native_ids);
        Ok(native_ids)
    }

    pub(super) fn retire_orphan_native_id(&mut self, native_id: u32) {
        if let Some(index) = self
            .orphan_native_ids
            .iter()
            .position(|retained| *retained == native_id)
        {
            self.orphan_native_ids.remove(index);
        }
    }

    pub(super) fn orphan_alias_snapshot(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let mut aliases = Vec::new();
        aliases
            .try_reserve_exact(self.orphan_aliases.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MCI orphan alias snapshot",
                    error,
                )
            })?;
        for alias in &self.orphan_aliases {
            let mut copy = Vec::new();
            copy.try_reserve_exact(alias.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy MCI orphan alias for close retry",
                    error,
                )
            })?;
            copy.extend_from_slice(alias);
            aliases.push(copy);
        }
        Ok(aliases)
    }

    pub(super) fn retire_orphan_alias(&mut self, alias: &[u8]) {
        if let Some(index) = self.orphan_aliases.iter().position(|entry| entry == alias) {
            self.orphan_aliases.remove(index);
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
            && self.by_native.is_empty()
            && self.yield_registrations.is_empty()
            && self.orphan_aliases.is_empty()
            && self.orphan_native_ids.is_empty()
    }

    pub(super) fn forget(&mut self, identity: Win16HostMciDevice) {
        if let Some(native_id) = self.by_identity.remove(&identity) {
            self.by_native.remove(&native_id);
            self.retired_identities.insert(identity);
        }
    }

    pub(super) fn retire_every_live_identity(&mut self) {
        for identity in self.by_identity.keys().copied() {
            self.retired_identities.insert(identity);
        }
        self.by_identity.clear();
        self.by_native.clear();
    }

    pub(super) fn snapshot(&self) -> Result<Vec<(Win16HostMciDevice, u32)>, RuntimeError> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.by_identity.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native MCI identity snapshot",
                    error,
                )
            })?;
        entries.extend(
            self.by_identity
                .iter()
                .map(|(identity, native)| (*identity, *native)),
        );
        Ok(entries)
    }
}
