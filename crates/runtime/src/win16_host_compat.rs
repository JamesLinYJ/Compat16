//! Shared guest-side state for native Win16 compatibility-library services.
//!
//! The environment selector is a checked alias of the complete DOS-owned
//! allocation. SHELL services rescan its live double-NUL list and return real
//! guest FAR addresses without returning host pointers or reading beyond the
//! selector's current legal span.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use win16_abi::{SegmentedPointer, SelectorRef, SelectorTable};

use crate::{DiagnosticKind as Kind, RuntimeError};
use crate::win16_environment::Win16Environment;

/// Resource selector passed between the runtime and its native VER adapter.
/// String names own copied guest bytes; numeric identifiers are values, never
/// pointer-shaped integers crossing the host boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostResourceName {
    Id(u16),
    Name(Vec<u8>),
}

#[derive(Debug)]
pub(crate) struct Win16CompatState {
    environment: Win16Environment,
    registry_keys: BTreeMap<u32, crate::Win16HostRegistryKey>,
    next_registry_handle: u32,
}

const FIRST_GUEST_REGISTRY_HANDLE: u32 = 0x0001_0000;
const ERROR_INVALID_HANDLE: u32 = 6;

impl Win16CompatState {
    pub(crate) fn load(
        selectors: &mut SelectorTable,
        environment: dos_kernel::DosBlockExtent,
        initial_logical_bytes: usize,
        memory: &mut Memory,
    ) -> Result<Self, RuntimeError> {
        let environment = Win16Environment::load(
            selectors, environment, initial_logical_bytes, memory,
        )?;
        Ok(Self {
            environment,
            registry_keys: BTreeMap::new(),
            next_registry_handle: FIRST_GUEST_REGISTRY_HANDLE,
        })
    }

    /// Selector alias for the complete DOS-owned environment allocation.
    /// The runtime writes this raw word into its protected PDB at creation.
    pub(crate) fn environment_selector(&self) -> SelectorRef {
        self.environment.selector()
    }

    /// Bind the protected PDB identity used to resolve its live environment
    /// selector field. The saved SelectorRef prevents generation reuse.
    pub(crate) fn bind_pdb(&mut self, pdb: SelectorRef) {
        self.environment.bind_pdb(pdb);
    }

    /// Resolve the current PDB environment selector to a checked guest FAR.
    pub(crate) fn environment_pointer(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<SegmentedPointer, RuntimeError> {
        self.environment.pointer(selectors, memory)
    }

    /// Translate a predefined root constant or a runtime-issued guest HKEY.
    /// Invalid guest handles stay normal Win16 registry error results.
    pub(crate) fn registry_key(
        &self,
        guest_handle: u32,
    ) -> Result<crate::Win16RegistryKeyRef, u32> {
        if let Some(root) = crate::Win16RegistryRoot::from_guest_handle(guest_handle) {
            return Ok(crate::Win16RegistryKeyRef::Predefined(root));
        }
        self.registry_keys.get(&guest_handle).copied()
            .map(crate::Win16RegistryKeyRef::Opened)
            .ok_or(ERROR_INVALID_HANDLE)
    }

    /// Assign a nonzero opaque guest HKEY after a successful native open.
    pub(crate) fn add_registry_key(
        &mut self,
        key: crate::Win16HostRegistryKey,
    ) -> Result<u32, RuntimeError> {
        let mut candidate = self.next_registry_handle.max(FIRST_GUEST_REGISTRY_HANDLE);
        loop {
            if !self.registry_keys.contains_key(&candidate)
                && crate::Win16RegistryRoot::from_guest_handle(candidate).is_none()
            {
                self.registry_keys.insert(candidate, key);
                self.next_registry_handle = candidate.checked_add(1).unwrap_or(candidate);
                return Ok(candidate);
            }
            candidate = candidate.checked_add(1).ok_or_else(||
                RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 registry guest-handle range is exhausted"))?;
        }
    }

    /// Retire one opened-key alias after the host confirms RegCloseKey.
    pub(crate) fn remove_registry_key(&mut self, guest_handle: u32) {
        self.registry_keys.remove(&guest_handle);
    }

    /// Transfer all remaining native key identities to task cleanup.
    pub(crate) fn take_registry_keys(
        &mut self,
    ) -> impl Iterator<Item = crate::Win16HostRegistryKey> {
        std::mem::take(&mut self.registry_keys).into_values()
    }

    /// Find an environment entry in the guest DOS block and return its guest
    /// FAR address. No host environment lookup or host pointer is involved.
    pub(crate) fn find_environment_string(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        query: &[u8],
    ) -> Result<u32, RuntimeError> {
        self.environment.find_environment_string(selectors, memory, query)
    }

    /// Return one checked owned snapshot for `DoEnvironmentSubst`.
    pub(crate) fn environment_list_bytes(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.environment.list_bytes(selectors, memory)
    }
}
