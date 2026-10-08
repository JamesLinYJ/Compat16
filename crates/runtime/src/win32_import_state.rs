//! Task-owned identities for Windows modules, guest handles and service gates.
//!
//! No entry stores a native pointer. Monotonic identities and tombstoned gate
//! slots prevent a stale DWORD from acquiring a later owner's meaning.

use std::sync::atomic::{AtomicU64, Ordering};

#[path = "win32_import_state/search_handles.rs"]
pub(crate) mod search_handles;
use search_handles::SearchHandleRecord;

use crate::{DiagnosticKind as Kind, RuntimeError, pe32::Pe32ModuleIdentity};

use super::{
    win32_import_catalog::Win32ImportService,
    win32_import_host::{Win32HostHandle, Win32HostModule, Win32HostModuleOwner,
        Win32HostResolvedExport, Win32ImportString},
};

const FIRST_GUEST_HANDLE: u32 = 0xd000_0001;
const GUEST_HANDLE_LIMIT: u32 = 0xe000_0000;
const FIRST_MODULE_HANDLE: u32 = 0xa000_0001;
const MODULE_HANDLE_LIMIT: u32 = 0xb000_0000;
const GATE_STRIDE: u32 = 16;
static NEXT_PE32_TASK_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Win32SystemModuleIdentity { id: u64, generation: u64 }

impl Win32SystemModuleIdentity {
    pub(crate) const fn id(self) -> u64 { self.id }
    pub(crate) const fn generation(self) -> u64 { self.generation }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win32ServiceGate {
    pub(crate) address: u32,
    pub(crate) provider: Win32SystemModuleIdentity,
    pub(crate) service: Win32ImportService,
    pub(crate) export: Win32HostResolvedExport,
}

#[derive(Debug)]
pub(crate) struct Win32GateReservation {
    slot: usize,
    serial: u64,
    provider: Win32SystemModuleIdentity,
    service: Win32ImportService,
    export: Win32HostResolvedExport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateState { Vacant, Reserved, Published, Retired, Poisoned }

#[derive(Clone, Copy, Debug)]
struct GateSlot {
    state: GateState,
    serial: u64,
    provider: Option<Win32SystemModuleIdentity>,
    service: Option<Win32ImportService>,
    export: Option<Win32HostResolvedExport>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderState { Live, Releasing }

#[derive(Debug)]
struct ProviderRecord {
    identity: Win32SystemModuleIdentity,
    host_owner: Win32HostModuleOwner,
    guest_handle: u32,
    host: Win32HostModule,
    requested_basename: Win32ImportString,
    path: Vec<u16>,
    guest_references: u32,
    borrowed_lookup_lease: bool,
    dependencies: Vec<Pe32ModuleIdentity>,
    invocation_pins: u32,
    state: ProviderState,
}

#[derive(Clone, Copy, Debug)]
struct GuestHandleRecord {
    value: u32,
    reservation: u64,
    native: Option<Win32HostHandle>,
    closing: bool,
}

#[derive(Debug)]
pub(crate) struct Win32GuestHandleReservation { value: u32, serial: u64 }

#[derive(Debug)]
pub(crate) struct Win32SystemModuleReservation {
    identity: Win32SystemModuleIdentity,
    host_owner: Win32HostModuleOwner,
    guest_handle: u32,
    requested_basename: Win32ImportString,
}

/// Keeps one exact provider generation alive while a catalogued native export
/// is executing. This is independent of guest-visible LoadLibrary references.
#[derive(Debug)]
pub(crate) struct Win32ProviderInvocationPin {
    identity: Win32SystemModuleIdentity,
}

impl Win32ProviderInvocationPin {
    pub(crate) const fn provider(&self) -> Win32SystemModuleIdentity { self.identity }
}

impl Win32SystemModuleReservation {
    pub(crate) fn copy_requested_basename(&self) -> Result<Win32ImportString, RuntimeError> {
        copy_import_string(&self.requested_basename)
    }
}

impl Win32GateReservation {
    pub(crate) fn address(&self, state: &Win32ImportState) -> Result<u32, RuntimeError> {
        let slot = state.gates.get(self.slot)
            .ok_or_else(|| invariant("PE32 gate reservation slot is outside its page"))?;
        if slot.state != GateState::Reserved || slot.serial != self.serial
            || slot.provider != Some(self.provider) || slot.service != Some(self.service)
            || slot.export != Some(self.export)
        { return Err(invariant("PE32 service-gate reservation is stale")); }
        state.slot_address(self.slot)
    }
}

/// Per-PE32-task native resource identity. The owner is the task dispatcher,
/// not an individual DLL: Windows handles normally outlive the module that
/// created them unless the DLL itself closes them.
pub(crate) struct Win32ImportState {
    task_id: u64,
    providers: Vec<ProviderRecord>,
    gates: Vec<GateSlot>,
    guest_handles: Vec<GuestHandleRecord>,
    search_handles: Vec<SearchHandleRecord>,
    gate_base: u32,
    gate_bytes: u32,
    next_provider_id: Option<u64>,
    next_generation: Option<u64>,
    next_gate_serial: Option<u64>,
    next_handle_serial: Option<u64>,
    next_guest_handle: Option<u32>,
    next_search_serial: Option<u64>,
    next_guest_search_handle: Option<u32>,
    next_module_handle: Option<u32>,
    last_error: u32,
}

impl Win32ImportState {
    /// Reserve service gates from the already-owned PE32 support lease. Slot 0
    /// is the independent return gate; service gates occupy unique 16-byte
    /// cells and are never reused within the task.
    pub(crate) fn new(
        gate_base: u32, gate_bytes: u32, stack_start: u32, stack_end: u32,
    ) -> Result<Self, RuntimeError> {
        if gate_bytes < GATE_STRIDE * 2 || gate_base % GATE_STRIDE != 0 {
            return Err(invariant("invalid PE32 host-service gate reservation"));
        }
        if stack_start >= stack_end || stack_end != gate_base {
            return Err(invariant("invalid PE32 host-service stack bounds"));
        }
        let count = usize::try_from(gate_bytes / GATE_STRIDE - 1)
            .map_err(|_| exhausted("PE32 host-service gate slots"))?;
        let task_id = NEXT_PE32_TASK_ID.try_update(Ordering::Relaxed, Ordering::Relaxed,
            |next| next.checked_add(1)).map_err(|_| exhausted("PE32 task identities"))?;
        let mut gates = Vec::new();
        gates.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve PE32 host-service gate slots", error)
        })?;
        gates.resize(count, GateSlot {
            state: GateState::Vacant, serial: 0, provider: None, service: None, export: None,
        });
        Ok(Self {
            task_id, providers: Vec::new(), gates, guest_handles: Vec::new(),
            search_handles: Vec::new(), gate_base,
            gate_bytes, next_provider_id: Some(1), next_generation: Some(1),
            next_gate_serial: Some(1), next_handle_serial: Some(1),
            next_guest_handle: Some(FIRST_GUEST_HANDLE),
            next_search_serial: Some(1),
            next_guest_search_handle: Some(search_handles::FIRST_GUEST_SEARCH_HANDLE),
            next_module_handle: Some(FIRST_MODULE_HANDLE), last_error: 0,
        })
    }

    pub(crate) const fn last_error(&self) -> u32 { self.last_error }
    pub(crate) fn set_last_error(&mut self, value: u32) { self.last_error = value; }

    pub(crate) fn service_gate_guard_addresses(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.gates.len()).filter_map(|index| {
            let slot = u32::try_from(index).ok()?.checked_add(1)?;
            self.gate_base.checked_add(slot.checked_mul(GATE_STRIDE)?)
        })
    }

    pub(crate) fn reserve_system_module(
        &mut self, requested_basename: &Win32ImportString,
    ) -> Result<Win32SystemModuleReservation, RuntimeError> {
        if !valid_basename(requested_basename) {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "system-provider reservation requires a DLL basename"));
        }
        let id = self.next_provider_id.ok_or_else(|| exhausted("PE32 system-module IDs"))?;
        let generation = self.next_generation.ok_or_else(|| exhausted("PE32 module generations"))?;
        let guest_handle = self.next_module_handle
            .ok_or_else(|| exhausted("PE32 system-module guest handles"))?;
        if guest_handle >= MODULE_HANDLE_LIMIT {
            return Err(exhausted("PE32 system-module guest handles"));
        }
        let basename = copy_import_string(requested_basename)?;
        self.providers.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve PE32 system-module owner", error)
        })?;
        self.next_provider_id = id.checked_add(1);
        self.next_generation = generation.checked_add(1);
        self.next_module_handle = guest_handle.checked_add(1);
        Ok(Win32SystemModuleReservation {
            identity: Win32SystemModuleIdentity { id, generation },
            host_owner: Win32HostModuleOwner::from_parts(self.task_id, id, generation), guest_handle,
            requested_basename: basename,
        })
    }

    pub(crate) fn register_system_module(
        &mut self, reservation: Win32SystemModuleReservation,
        host: Win32HostModule, path: Vec<u16>, guest_references: u32,
        borrowed_lookup_lease: bool,
    ) -> Result<Win32SystemModuleIdentity, RuntimeError> {
        let identity = reservation.identity;
        if reservation.host_owner.task() != self.task_id
            || reservation.host_owner.provider() != identity.id()
            || reservation.host_owner.generation() != identity.generation()
        {
            return Err(invariant("native provider owner differs from its reserved generation"));
        }
        if self.providers.iter().any(|record| record.host == host) {
            return Err(invariant("task registered duplicate native provider ownership"));
        }
        self.providers.push(ProviderRecord {
            identity, host_owner: reservation.host_owner, guest_handle: reservation.guest_handle, host,
            requested_basename: reservation.requested_basename, path, guest_references,
            borrowed_lookup_lease,
            dependencies: Vec::new(), invocation_pins: 0, state: ProviderState::Live,
        });
        Ok(identity)
    }

    pub(crate) fn module(&self, identity: Win32SystemModuleIdentity)
        -> Result<(Win32HostModule, &[u16]), RuntimeError> {
        let record = self.provider(identity)?;
        Ok((record.host, &record.path))
    }

    pub(crate) fn host_owner(&self, identity: Win32SystemModuleIdentity)
        -> Result<Win32HostModuleOwner, RuntimeError> {
        Ok(self.provider(identity)?.host_owner)
    }

    pub(crate) fn reservation_owner(
        &self, reservation: &Win32SystemModuleReservation,
    ) -> Win32HostModuleOwner { reservation.host_owner }

    pub(crate) fn find_module(&self, basename: &[u8]) -> Option<Win32SystemModuleIdentity> {
        self.providers.iter().find(|record| record.state == ProviderState::Live
            && import_name_matches(&record.requested_basename, basename))
            .map(|record| record.identity)
    }

    pub(crate) fn find_module_by_wide(&self, basename: &[u16]) -> Option<Win32SystemModuleIdentity> {
        self.providers.iter().find(|record| record.state == ProviderState::Live
            && import_name_matches_wide(&record.requested_basename, basename))
            .map(|record| record.identity)
    }

    /// Resolves a host loader token back to the single runtime generation that
    /// owns it. This is used only after Windows has confirmed a loaded module
    /// by HMODULE identity; basename equality is not sufficient for paths.
    pub(crate) fn find_module_by_host(
        &self, host: Win32HostModule,
    ) -> Result<Option<Win32SystemModuleIdentity>, RuntimeError> {
        let mut found = None;
        for record in &self.providers {
            if record.host != host { continue; }
            if record.state != ProviderState::Live {
                return Err(invariant("native module token is already retiring"));
            }
            if found.replace(record.identity).is_some() {
                return Err(invariant("one native module token has multiple PE32 provider owners"));
            }
        }
        Ok(found)
    }

    pub(crate) fn guest_module_handle(
        &self, identity: Win32SystemModuleIdentity,
    ) -> Result<u32, RuntimeError> { Ok(self.provider(identity)?.guest_handle) }

    pub(crate) fn guest_reference_count(
        &self, identity: Win32SystemModuleIdentity,
    ) -> Result<u32, RuntimeError> { Ok(self.provider(identity)?.guest_references) }

    pub(crate) fn system_module_for_handle(
        &self, handle: u32,
    ) -> Option<Win32SystemModuleIdentity> {
        self.providers.iter().find(|record| record.guest_handle == handle
            && record.state == ProviderState::Live).map(|record| record.identity)
    }

    pub(crate) fn retain_module(&mut self, identity: Win32SystemModuleIdentity)
        -> Result<(), RuntimeError> {
        let record = self.provider_mut(identity)?;
        if record.state != ProviderState::Live {
            return Err(invariant("retained a PE32 system module during release"));
        }
        record.guest_references = record.guest_references.checked_add(1)
            .ok_or_else(|| exhausted("PE32 system-module reference count"))?;
        Ok(())
    }

    /// Keeps a borrowed GetModuleHandle identity live until task teardown.
    /// This lease is independent of guest LoadLibrary references and calls.
    pub(crate) fn retain_lookup_lease(
        &mut self, identity: Win32SystemModuleIdentity,
    ) -> Result<(), RuntimeError> {
        let record = self.provider_mut(identity)?;
        if record.state != ProviderState::Live {
            return Err(invariant("borrowed lookup pinned a PE32 provider during release"));
        }
        record.borrowed_lookup_lease = true;
        Ok(())
    }

    /// Protects a native provider during one checked typed call without
    /// changing what guest FreeLibrary observes in its reference count.
    pub(crate) fn pin_invocation(
        &mut self, identity: Win32SystemModuleIdentity,
    ) -> Result<Win32ProviderInvocationPin, RuntimeError> {
        let record = self.provider_mut(identity)?;
        if record.state != ProviderState::Live {
            return Err(invariant("pinned a PE32 provider during release"));
        }
        record.invocation_pins = record.invocation_pins.checked_add(1)
            .ok_or_else(|| exhausted("PE32 system-provider invocation pins"))?;
        Ok(Win32ProviderInvocationPin { identity })
    }

    /// Consumes one exact-generation invocation lease. The opaque native
    /// module token is returned only when every guest, image, and call owner
    /// has retired; the caller then completes FreeLibrary or restores Live.
    pub(crate) fn release_invocation_pin(
        &mut self, pin: Win32ProviderInvocationPin,
    ) -> Result<Option<Win32HostModule>, RuntimeError> {
        let index = self.providers.iter().position(|record| record.identity == pin.identity)
            .ok_or_else(|| invariant("PE32 provider invocation pin names a stale generation"))?;
        let record = &mut self.providers[index];
        if record.state != ProviderState::Live {
            return Err(invariant("PE32 provider invocation pin overlaps native release"));
        }
        record.invocation_pins = record.invocation_pins.checked_sub(1)
            .ok_or_else(|| invariant("PE32 provider invocation pin was already released"))?;
        if record.invocation_pins == 0 && record.guest_references == 0
            && !record.borrowed_lookup_lease
            && record.dependencies.is_empty()
        {
            record.state = ProviderState::Releasing;
            Ok(Some(record.host))
        } else {
            Ok(None)
        }
    }

    /// Returns the host token only after guest references, image dependencies,
    /// and active native-call pins permit retirement. A failed FreeLibrary
    /// leaves the record live for retry.
    pub(crate) fn begin_release_module(
        &mut self, identity: Win32SystemModuleIdentity,
    ) -> Result<Option<Win32HostModule>, RuntimeError> {
        let record = self.provider_mut(identity)?;
        if record.state != ProviderState::Live || record.guest_references == 0 {
            return Err(invariant("PE32 system-module reference is not live"));
        }
        if record.guest_references > 1 || record.borrowed_lookup_lease
            || !record.dependencies.is_empty()
            || record.invocation_pins != 0
        {
            record.guest_references -= 1;
            return Ok(None);
        }
        record.state = ProviderState::Releasing;
        Ok(Some(record.host))
    }

    pub(crate) fn live_system_modules(&self) -> impl Iterator<Item = Win32SystemModuleIdentity> + '_ {
        self.providers.iter().filter(|record| record.state == ProviderState::Live)
            .map(|record| record.identity)
    }

    pub(crate) fn begin_shutdown_release_module(
        &mut self, identity: Win32SystemModuleIdentity,
    ) -> Result<Option<Win32HostModule>, RuntimeError> {
        let record = self.provider_mut(identity)?;
        if record.state != ProviderState::Live {
            return Err(invariant("PE32 system-module shutdown release is already active"));
        }
        record.guest_references = 0;
        record.borrowed_lookup_lease = false;
        if !record.dependencies.is_empty() || record.invocation_pins != 0 {
            return Ok(None);
        }
        record.state = ProviderState::Releasing;
        Ok(Some(record.host))
    }

        pub(crate) fn finish_release_module(
        &mut self, identity: Win32SystemModuleIdentity, released: bool,
    ) -> Result<(), RuntimeError> {
        let index = self.provider_index(identity)?;
        if self.providers[index].state != ProviderState::Releasing {
            return Err(invariant("system-module release completion has no matching request"));
        }
        if !released {
            self.providers[index].state = ProviderState::Live;
            return Ok(());
        }
        self.providers.swap_remove(index);
        for slot in &mut self.gates {
            if slot.provider == Some(identity) && slot.state == GateState::Published {
                slot.state = GateState::Retired;
            }
        }
        Ok(())
    }

        pub(crate) fn pin_dependencies(
        &mut self, providers: &[Win32SystemModuleIdentity], owner: Pe32ModuleIdentity,
    ) -> Result<(), RuntimeError> {
        for (index, identity) in providers.iter().copied().enumerate() {
            if providers[..index].contains(&identity) { continue; }
            let record = self.provider_mut(identity)?;
            if record.state != ProviderState::Live {
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "PE32 import provider is already retiring"));
            }
            if !record.dependencies.contains(&owner) {
                record.dependencies.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "reserve PE32 import-provider dependency", error)
                })?;
            }
        }
        for (index, identity) in providers.iter().copied().enumerate() {
            if providers[..index].contains(&identity) { continue; }
            let record = self.provider_mut(identity)?;
            if !record.dependencies.contains(&owner) { record.dependencies.push(owner); }
        }
        Ok(())
    }

    pub(crate) fn unpin_dependency(
        &mut self, identity: Win32SystemModuleIdentity, owner: Pe32ModuleIdentity,
    ) -> Result<Option<Win32HostModule>, RuntimeError> {
        let record = self.provider_mut(identity)?;
        let index = record.dependencies.iter().position(|value| *value == owner)
            .ok_or_else(|| invariant("PE32 import-provider dependency is absent"))?;
        if record.state != ProviderState::Live {
            return Err(invariant("PE32 dependency release overlaps another provider release"));
        }
        if record.dependencies.len() == 1 && record.guest_references == 0
            && !record.borrowed_lookup_lease
            && record.invocation_pins == 0
        {
            // Keep the final dependency attached while FreeLibrary is in flight.
            // A failed native release restores Live and lets the image owner retry.
            record.state = ProviderState::Releasing;
            Ok(Some(record.host))
        } else {
            record.dependencies.swap_remove(index);
            Ok(None)
        }
    }

    pub(crate) fn reserve_service_gate(
        &mut self, provider: Win32SystemModuleIdentity, service: Win32ImportService,
        export: Win32HostResolvedExport,
    ) -> Result<Result<Win32ServiceGate, Win32GateReservation>, RuntimeError> {
        self.provider(provider)?;
        if let Some(index) = self.gates.iter().position(|slot| slot.state == GateState::Published
                && slot.provider == Some(provider) && slot.service == Some(service)) {
            let slot = self.gates[index];
            return Ok(Ok(Win32ServiceGate {
                address: self.slot_address(index)?, provider, service,
                export: slot.export.ok_or_else(|| invariant("published gate has no export binding"))?,
            }));
        }
        let Some(index) = self.gates.iter().position(|slot| slot.state == GateState::Vacant) else {
                return Err(exhausted("PE32 host-service gate page"));
            };
        let serial = self.next_gate_serial.ok_or_else(|| exhausted("PE32 gate generations"))?;
        self.slot_address(index)?;
        let slot = &mut self.gates[index];
        slot.state = GateState::Reserved;
        slot.serial = serial;
        slot.provider = Some(provider);
        slot.service = Some(service);
        slot.export = Some(export);
        self.next_gate_serial = serial.checked_add(1);
        Ok(Err(Win32GateReservation { slot: index, serial, provider, service, export }))
    }

    pub(crate) fn publish_service_gate(
        &mut self, reservation: Win32GateReservation,
    ) -> Result<Win32ServiceGate, RuntimeError> {
        let address = self.slot_address(reservation.slot)?;
        if self.provider(reservation.provider)?.state != ProviderState::Live {
            let slot = self.gates.get_mut(reservation.slot)
                .ok_or_else(|| invariant("PE32 gate reservation slot is outside its page"))?;
            slot.state = GateState::Poisoned;
            return Err(invariant("PE32 gate provider retired before publication"));
        }
        let slot = self.gates.get_mut(reservation.slot)
            .ok_or_else(|| invariant("PE32 gate reservation slot is outside its page"))?;
        if slot.state != GateState::Reserved || slot.serial != reservation.serial
            || slot.provider != Some(reservation.provider) || slot.service != Some(reservation.service)
            || slot.export != Some(reservation.export)
        { return Err(invariant("PE32 host-service gate reservation is stale")); }
        slot.state = GateState::Published;
        Ok(Win32ServiceGate {
            address,
            provider: reservation.provider,
            service: reservation.service,
            export: slot.export.ok_or_else(|| invariant("published gate has no export binding"))?,
        })
    }

    /// A gate write failure permanently poisons that slot. The caller must not
    /// publish its address or recycle it for another service.
    pub(crate) fn poison_service_gate(
        &mut self, reservation: Win32GateReservation,
    ) -> Result<(), RuntimeError> {
        let slot = self.gates.get_mut(reservation.slot)
            .ok_or_else(|| invariant("PE32 poisoned gate slot is outside its page"))?;
        if slot.state != GateState::Reserved || slot.serial != reservation.serial
            || slot.export != Some(reservation.export) {
            return Err(invariant("PE32 gate poison does not match its reservation"));
        }
        slot.state = GateState::Poisoned;
        Ok(())
    }

    pub(crate) fn cancel_gate_reservation(
        &mut self, reservation: Win32GateReservation,
    ) -> Result<(), RuntimeError> {
        let slot = self.gates.get_mut(reservation.slot)
            .ok_or_else(|| invariant("PE32 cancelled gate slot is outside its page"))?;
        if slot.state != GateState::Reserved || slot.serial != reservation.serial
            || slot.provider != Some(reservation.provider) || slot.service != Some(reservation.service)
            || slot.export != Some(reservation.export)
        { return Err(invariant("PE32 gate cancellation does not match its reservation")); }
        *slot = GateSlot { state: GateState::Vacant, serial: 0, provider: None, service: None,
            export: None };
        Ok(())
    }

    pub(crate) fn service_gate(&self, address: u32) -> Option<Win32ServiceGate> {
        let delta = address.checked_sub(self.gate_base)?;
        if delta % GATE_STRIDE != 0 || delta == 0 || delta >= self.gate_bytes { return None; }
        let index = usize::try_from(delta / GATE_STRIDE - 1).ok()?;
        let slot = self.gates.get(index)?;
        if slot.state != GateState::Published { return None; }
        let provider = slot.provider?;
        if self.provider(provider).ok()?.state != ProviderState::Live { return None; }
        Some(Win32ServiceGate { address, provider, service: slot.service?, export: slot.export? })
    }

    pub(crate) fn reserve_guest_handle(
        &mut self,
    ) -> Result<Win32GuestHandleReservation, RuntimeError> {
        let value = self.next_guest_handle.ok_or_else(|| exhausted("PE32 guest handles"))?;
        if value >= GUEST_HANDLE_LIMIT { return Err(exhausted("PE32 guest handles")); }
        let serial = self.next_handle_serial.ok_or_else(|| exhausted("PE32 handle generations"))?;
        self.guest_handles.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve PE32 guest handle", error)
        })?;
        self.next_guest_handle = value.checked_add(1);
        self.next_handle_serial = serial.checked_add(1);
        self.guest_handles.push(GuestHandleRecord {
            value, reservation: serial, native: None, closing: false,
        });
        Ok(Win32GuestHandleReservation { value, serial })
    }

    pub(crate) fn publish_guest_handle(
        &mut self, reservation: Win32GuestHandleReservation, native: Win32HostHandle,
    ) -> Result<u32, RuntimeError> {
        let record = self.guest_handles.iter_mut().find(|record|
            record.value == reservation.value && record.reservation == reservation.serial)
            .ok_or_else(|| invariant("PE32 guest handle reservation is stale"))?;
        if record.native.is_some() || record.closing {
            return Err(invariant("PE32 guest handle reservation was already completed"));
        }
        record.native = Some(native);
        Ok(record.value)
    }

    pub(crate) fn cancel_guest_handle(
        &mut self, reservation: Win32GuestHandleReservation,
    ) -> Result<(), RuntimeError> {
        let index = self.guest_handles.iter().position(|record|
            record.value == reservation.value && record.reservation == reservation.serial)
            .ok_or_else(|| invariant("PE32 guest handle reservation is stale"))?;
        if self.guest_handles[index].native.is_some() {
            return Err(invariant("cancelled PE32 guest handle owns a native resource"));
        }
        self.guest_handles.swap_remove(index);
        Ok(())
    }

    pub(crate) fn native_handle(&self, value: u32) -> Option<Win32HostHandle> {
        self.guest_handles.iter().find(|record| record.value == value && !record.closing)
            .and_then(|record| record.native)
    }

    pub(crate) fn live_guest_handles(&self) -> impl Iterator<Item = (u32, Win32HostHandle)> + '_ {
        self.guest_handles.iter().filter_map(|record| record.native
            .filter(|_| !record.closing).map(|native| (record.value, native)))
    }

    pub(crate) fn begin_close_handle(&mut self, value: u32)
        -> Result<Win32HostHandle, RuntimeError> {
        let record = self.guest_handles.iter_mut().find(|record| record.value == value)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "invalid PE32 guest HANDLE"))?;
        let native = record.native.ok_or_else(|| invariant("PE32 HANDLE is not published"))?;
        if record.closing { return Err(invariant("PE32 HANDLE close is already active")); }
        record.closing = true;
        Ok(native)
    }

    pub(crate) fn finish_close_handle(&mut self, value: u32, closed: bool)
        -> Result<(), RuntimeError> {
        let index = self.guest_handles.iter().position(|record| record.value == value)
            .ok_or_else(|| invariant("PE32 HANDLE disappeared during close"))?;
        if !self.guest_handles[index].closing {
            return Err(invariant("PE32 HANDLE close completion has no matching request"));
        }
        if closed { self.guest_handles.swap_remove(index); }
        else { self.guest_handles[index].closing = false; }
        Ok(())
    }

    fn provider(&self, identity: Win32SystemModuleIdentity)
        -> Result<&ProviderRecord, RuntimeError> {
        self.providers.iter().find(|record| record.identity == identity)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "stale PE32 system-module generation"))
    }

    fn provider_mut(&mut self, identity: Win32SystemModuleIdentity)
        -> Result<&mut ProviderRecord, RuntimeError> {
        self.providers.iter_mut().find(|record| record.identity == identity)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "stale PE32 system-module generation"))
    }

    fn provider_index(&self, identity: Win32SystemModuleIdentity)
        -> Result<usize, RuntimeError> {
        self.providers.iter().position(|record| record.identity == identity)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "stale PE32 system-module generation"))
    }

    fn slot_address(&self, index: usize) -> Result<u32, RuntimeError> {
        let offset = u32::try_from(index + 1).ok().and_then(|slot| slot.checked_mul(GATE_STRIDE))
            .ok_or_else(|| invariant("PE32 service-gate slot overflowed"))?;
        let address = self.gate_base.checked_add(offset)
            .ok_or_else(|| invariant("PE32 service-gate address overflowed"))?;
        if offset.checked_add(GATE_STRIDE).is_none_or(|end| end > self.gate_bytes) {
            return Err(invariant("PE32 service gate exceeds reserved support page"));
        }
        Ok(address)
    }

}

fn wide_ascii_case_eq(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| {
        ascii_lower(*left) == ascii_lower(*right)
    })
}

fn valid_basename(name: &Win32ImportString) -> bool {
    match name {
        Win32ImportString::Ansi(value) => !value.is_empty() && !value.contains(&0)
            && !value.iter().any(|unit| matches!(*unit, b'/' | b'\\' | b':')),
        Win32ImportString::Wide(value) => !value.is_empty() && !value.contains(&0)
            && !value.iter().any(|unit| matches!(*unit, 0x2f | 0x5c | 0x3a)),
    }
}

fn copy_import_string(value: &Win32ImportString) -> Result<Win32ImportString, RuntimeError> {
    fn copy<T: Copy>(source: &[T]) -> Result<Vec<T>, RuntimeError> {
        let mut result = Vec::new();
        result.try_reserve_exact(source.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve PE32 system-module basename", error))?;
        result.extend_from_slice(source);
        Ok(result)
    }
    Ok(match value {
        Win32ImportString::Ansi(value) => Win32ImportString::Ansi(copy(value)?),
        Win32ImportString::Wide(value) => Win32ImportString::Wide(copy(value)?),
    })
}

fn import_name_matches(stored: &Win32ImportString, name: &[u8]) -> bool {
    match stored {
        Win32ImportString::Ansi(value) => value.len() == name.len()
            && value.iter().zip(name).all(|(left, right)| left.eq_ignore_ascii_case(right)),
        Win32ImportString::Wide(value) => value.len() == name.len()
            && value.iter().zip(name).all(|(left, right)| {
                *left <= 0x7f && (*left as u8).eq_ignore_ascii_case(right)
            }),
    }
}

fn import_name_matches_wide(stored: &Win32ImportString, name: &[u16]) -> bool {
    // Cross-encoding matches are limited to ASCII because the ANSI code page is
    // not retained here; non-ASCII names match only in their original encoding.
    match stored {
        Win32ImportString::Ansi(value) => value.len() == name.len()
            && value.iter().zip(name).all(|(left, right)| {
                *right <= 0x7f && left.eq_ignore_ascii_case(&(*right as u8))
            }),
        Win32ImportString::Wide(value) => wide_ascii_case_eq(value, name),
    }
}

fn ascii_lower(value: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&value) { value + 0x20 } else { value }
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
