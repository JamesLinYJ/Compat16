//! Protected Win16 implementation of the DOS caller-address boundary.
//!
//! DOS-owned metadata is accessed through the A20-aware machine bus. Caller
//! operands keep their protected selector:offset coordinates and are resolved
//! through the Win16 selector table against raw guest memory, without A20
//! decoding; neither domain is converted into the other's address form.

#[path = "win16_dos_address_space/checked.rs"]
mod checked;
#[path = "win16_dos_address_space/lifecycle.rs"]
mod lifecycle;
#[cfg(test)]
#[path = "win16_dos_exec_fcb_tests.rs"]
mod exec_fcb_tests;
use checked::{address_failure, alias_layout, memory_failure, selector_access, selector_failure};

use dos_kernel::{
    DosCallAddressSpace, DosCallerAddressSpaceFailureKind as FailureKind, DosCallerId, DosError,
    DosFarPointer, DosHost, DosKernel, DosPersistentFarPointer, DosPointerAccess, DosSpanPolicy,
};
use guest_core::memory::{BusMemory, Memory};
use guest_core::{GuestMemory, MemoryError, OwnerId, PhysAddr, Selector};
use win16_abi::{SegmentedPointer, SelectorRef, SelectorTable};

use crate::{RuntimeError, runtime_error};

use super::Win16State;

const SELECTOR_BYTES: usize = 0x1_0000;

/// Per-Win16-state caller identities, retained pointers and DOS-backed aliases.
/// The process-wide caller IDs and local lease counter are never reused.
#[derive(Debug)]
pub(super) struct Win16DosCallerAddresses {
    callers: Vec<CallerIdentity>,
    next_lease: u64,
    leases: Vec<RetainedPointer>,
    aliases: Vec<DosAlias>,
}

impl Default for Win16DosCallerAddresses {
    fn default() -> Self {
        Self {
            callers: Vec::new(),
            next_lease: 1,
            leases: Vec::new(),
            aliases: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CallerIdentity {
    owner: OwnerId,
    caller: DosCallerId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DosCallerDomain {
    ProtectedWin16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseKey {
    caller: DosCallerId,
    domain: DosCallerDomain,
    selector: SelectorRef,
    offset: u16,
}

#[derive(Clone, Copy, Debug)]
struct RetainedPointer {
    key: LeaseKey,
    pointer: DosFarPointer,
    token: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DosAlias {
    caller: DosCallerId,
    source_segment: u16,
    source_offset: u16,
    requested_length: usize,
    access: DosPointerAccess,
    selector: SelectorRef,
}

/// One synchronous DOS call's protected caller view and canonical DOS bus.
pub(super) struct Win16DosAddressSpace<'a> {
    selectors: &'a mut SelectorTable,
    addresses: &'a mut Win16DosCallerAddresses,
    memory: BusMemory<'a>,
    caller: DosCallerId,
}

impl Win16State {
    /// Construct the caller view for a particular Win16 task. Each owner gets
    /// a process-wide nonzero DOS identity, distinct even across Win16State
    /// instances; zero remains reserved for real mode.
    pub(super) fn dos_call_address_space<'a>(
        &'a mut self,
        memory: &'a mut Memory,
        owner: OwnerId,
    ) -> Result<Win16DosAddressSpace<'a>, DosError> {
        let caller = self.dos_caller_addresses.caller_id(owner)?;
        Ok(Win16DosAddressSpace {
            selectors: &mut self.selectors,
            addresses: &mut self.dos_caller_addresses,
            memory: memory.bus(),
            caller,
        })
    }

    /// Retire one caller only after DOS has closed its searches and released
    /// retained DTA tokens. Call before that task's selector generations are
    /// freed. A DOS child process exit is not a Win16 task teardown.
    pub(super) fn release_dos_caller_address_space(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl DosHost,
        owner: OwnerId,
    ) -> Result<(), RuntimeError> {
        let Some(caller) = self
            .dos_caller_addresses
            .existing_caller_id(owner)
            .map_err(runtime_error)?
        else {
            return Ok(());
        };
        {
            let mut address_space = Win16DosAddressSpace {
                selectors: &mut self.selectors,
                addresses: &mut self.dos_caller_addresses,
                memory: memory.bus(),
                caller,
            };
            dos.release_caller_address_space(&mut address_space, host)
                .map_err(runtime_error)?;
        }

        // DOS state no longer publishes a retained pointer for this owner.
        // Free only the aliases created by this adapter; guest selectors and
        // DOS-owned physical bytes remain owned by their original allocators.
        self.dos_caller_addresses
            .release_aliases(caller, &mut self.selectors)
            .map_err(runtime_error)?;
        // Keep DOS range pins until every selector backed by them is gone.
        // If selector retirement fails, this call is skipped and the pins stay
        // in the shared DOS lease registry for a later teardown retry.
        dos.release_caller_dta_backing_leases(memory, caller)
            .map_err(runtime_error)?;
        self.dos_caller_addresses
            .retire_caller(owner, caller)
            .map_err(runtime_error)
    }
}

impl Win16DosCallerAddresses {
    fn retain(
        &mut self,
        caller: DosCallerId,
        pointer: DosFarPointer,
        selector: SelectorRef,
    ) -> Result<DosPersistentFarPointer, DosError> {
        let key = LeaseKey {
            caller,
            domain: DosCallerDomain::ProtectedWin16,
            selector,
            offset: pointer.words().1,
        };
        if let Some(existing) = self.leases.iter().find(|entry| entry.key == key) {
            return Ok(DosPersistentFarPointer::new(pointer, existing.token));
        }
        if self.next_lease == 0 {
            return Err(address_failure(
                FailureKind::ResourceExhausted,
                "retain protected DOS pointer",
                "protected DOS pointer lease identity space is exhausted",
            ));
        }
        self.leases.try_reserve(1).map_err(|error| {
            DosError::caller_address_space(
                FailureKind::ResourceExhausted,
                "retain protected DOS pointer",
                error,
            )
        })?;
        let token = self.next_lease;
        self.next_lease = token.checked_add(1).unwrap_or(0);
        self.leases.push(RetainedPointer {
            key,
            pointer,
            token,
        });
        Ok(DosPersistentFarPointer::new(pointer, token))
    }

    fn retained(
        &self,
        caller: DosCallerId,
        pointer: DosPersistentFarPointer,
        operation: &'static str,
    ) -> Result<RetainedPointer, DosError> {
        if pointer.pointer().caller() != caller || pointer.lease() == 0 {
            return Err(address_failure(
                FailureKind::InvalidPointer,
                operation,
                "persistent pointer belongs to another caller or has no protected lease",
            ));
        }
        let record = self
            .leases
            .iter()
            .find(|entry| entry.token == pointer.lease())
            .copied()
            .ok_or_else(|| {
                address_failure(
                    FailureKind::InvalidPointer,
                    operation,
                    "persistent pointer lease is unknown or already released",
                )
            })?;
        if record.key.caller != caller
            || record.key.domain != DosCallerDomain::ProtectedWin16
            || record.pointer != pointer.pointer()
        {
            return Err(address_failure(
                FailureKind::InvalidPointer,
                operation,
                "persistent pointer token does not match its owner and far address",
            ));
        }
        Ok(record)
    }

    fn release_lease(
        &mut self,
        caller: DosCallerId,
        pointer: DosPersistentFarPointer,
    ) -> Result<(), DosError> {
        let record = self.retained(caller, pointer, "release protected DOS pointer")?;
        let index = self
            .leases
            .iter()
            .position(|entry| entry.token == record.token)
            .ok_or_else(|| {
                address_failure(
                    FailureKind::InternalInvariant,
                    "release protected DOS pointer",
                    "validated protected DOS lease disappeared",
                )
            })?;
        self.leases.remove(index);
        Ok(())
    }

    fn find_alias(
        &self,
        caller: DosCallerId,
        segment: u16,
        offset: u16,
        length: usize,
        access: DosPointerAccess,
    ) -> Option<DosAlias> {
        let (key_offset, key_length) = if access == DosPointerAccess::Execute {
            (0, SELECTOR_BYTES)
        } else {
            (offset, length)
        };
        self.aliases
            .iter()
            .find(|alias| {
                alias.caller == caller
                    && alias.source_segment == segment
                    && alias.source_offset == key_offset
                    && alias.requested_length == key_length
                    && alias.access == access
            })
            .copied()
    }

    fn release_aliases(
        &mut self,
        caller: DosCallerId,
        selectors: &mut SelectorTable,
    ) -> Result<(), DosError> {
        while let Some(index) = self.aliases.iter().position(|alias| alias.caller == caller) {
            let alias = self.aliases[index];
            selectors.free_block(alias.selector).map_err(|error| {
                DosError::caller_address_space(
                    FailureKind::InternalInvariant,
                    "release protected DOS alias selector",
                    error,
                )
            })?;
            self.aliases.remove(index);
        }
        Ok(())
    }
}

impl Win16DosAddressSpace<'_> {
    fn ensure_pointer(
        &self,
        pointer: DosFarPointer,
        operation: &'static str,
    ) -> Result<(u16, u16), DosError> {
        match pointer {
            DosFarPointer::Protected {
                caller,
                selector,
                offset,
            } if caller == self.caller => Ok((selector, offset)),
            _ => Err(address_failure(
                FailureKind::InvalidPointer,
                operation,
                "caller pointer is not a protected selector:offset owned by this task",
            )),
        }
    }

    fn current_selector(&self, raw: u16, operation: &'static str) -> Result<SelectorRef, DosError> {
        self.selectors
            .reference(Selector(raw))
            .map_err(|error| selector_failure(operation, error))
    }

    fn translated_range(
        &mut self,
        raw_selector: u16,
        offset: u16,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
        operation: &'static str,
    ) -> Result<(SelectorRef, PhysAddr), DosError> {
        let start = u32::from(offset)
            .checked_add(u32::try_from(byte_offset).map_err(|error| {
                DosError::caller_address_space(FailureKind::InvalidPointer, operation, error)
            })?)
            .ok_or_else(|| {
                address_failure(
                    FailureKind::InvalidPointer,
                    operation,
                    "protected caller offset arithmetic overflowed",
                )
            })?;
        let length32 = u32::try_from(length).map_err(|error| {
            DosError::caller_address_space(FailureKind::InvalidPointer, operation, error)
        })?;
        let end = start.checked_add(length32).ok_or_else(|| {
            address_failure(
                FailureKind::InvalidPointer,
                operation,
                "protected caller range arithmetic overflowed",
            )
        })?;
        if start > u32::from(u16::MAX) || end > u32::from(u16::MAX) + 1 {
            return Err(address_failure(
                FailureKind::InvalidPointer,
                operation,
                "protected DOS caller span crosses its selector offset boundary",
            ));
        }
        let selector = self.current_selector(raw_selector, operation)?;
        let pointer = SegmentedPointer::new(selector, start as u16);
        let access = selector_access(access);
        // A protected selector base is already a guest linear address. A20
        // folding belongs to real-mode DOS addresses and must not remap it.
        let address = self
            .selectors
            .translate(pointer, access, length, self.memory.backing())
            .map_err(|error| selector_failure(operation, error))?;
        Ok((selector, address))
    }

    fn validate_retained_generation(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
        operation: &'static str,
    ) -> Result<(RetainedPointer, PhysAddr), DosError> {
        let retained = self.addresses.retained(self.caller, pointer, operation)?;
        let (raw, offset) = self.ensure_pointer(retained.pointer, operation)?;
        let (current, address) =
            self.translated_range(raw, offset, byte_offset, length, access, operation)?;
        if current != retained.key.selector {
            return Err(address_failure(
                FailureKind::InvalidPointer,
                operation,
                "protected selector was retired or rebound after DOS retained this pointer",
            ));
        }
        Ok((retained, address))
    }

    fn read_at(
        &mut self,
        raw: u16,
        offset: u16,
        byte_offset: usize,
        output: &mut [u8],
        operation: &'static str,
    ) -> Result<(), DosError> {
        let (_, address) = self.translated_range(
            raw,
            offset,
            byte_offset,
            output.len(),
            DosPointerAccess::Read,
            operation,
        )?;
        self.memory
            .backing()
            .read(address, output)
            .map_err(|error| memory_failure(operation, error))
    }

    fn write_at(
        &mut self,
        raw: u16,
        offset: u16,
        byte_offset: usize,
        input: &[u8],
        operation: &'static str,
    ) -> Result<(), DosError> {
        let (_, address) = self.translated_range(
            raw,
            offset,
            byte_offset,
            input.len(),
            DosPointerAccess::Write,
            operation,
        )?;
        self.memory
            .backing_mut()
            .write(address, input)
            .map_err(|error| memory_failure(operation, error))
    }

    fn expose_alias(
        &mut self,
        segment: u16,
        offset: u16,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<DosFarPointer, DosError> {
        if length == 0 || length > SELECTOR_BYTES {
            return Err(address_failure(
                FailureKind::InvalidPointer,
                "expose DOS-owned memory to protected caller",
                "DOS alias must describe a nonempty span no larger than one selector",
            ));
        }
        let (base, allocation_length, key_offset, key_length, rights) =
            alias_layout(segment, offset, length, access)?;
        if let Some(alias) = self
            .addresses
            .find_alias(self.caller, segment, offset, length, access)
        {
            let descriptor = self
                .selectors
                .describe(alias.selector)
                .map_err(|error| selector_failure("validate DOS alias", error))?;
            let expected_limit = u32::try_from(allocation_length - 1).map_err(|error| {
                DosError::caller_address_space(
                    FailureKind::InternalInvariant,
                    "validate DOS alias layout",
                    error,
                )
            })?;
            if !descriptor.present
                || descriptor.selector != alias.selector.raw()
                || descriptor.base != base
                || descriptor.limit != expected_limit
                || descriptor.rights != rights
                || descriptor.segment_index != 0
                || descriptor.segment_count != 1
            {
                return Err(address_failure(
                    FailureKind::InvalidPointer,
                    "validate cached DOS alias",
                    "cached DOS alias selector no longer maps its original span and access rights",
                ));
            }
            return Ok(DosFarPointer::protected(
                self.caller,
                alias.selector.raw().0,
                if access == DosPointerAccess::Execute {
                    offset
                } else {
                    0
                },
            ));
        }

        self.addresses.aliases.try_reserve(1).map_err(|error| {
            DosError::caller_address_space(
                FailureKind::ResourceExhausted,
                "allocate DOS alias record",
                error,
            )
        })?;
        let selector = self
            .selectors
            .alloc_block(base, allocation_length, rights, self.memory.backing())
            .map_err(|error| selector_failure("allocate DOS caller alias", error))?;
        self.addresses.aliases.push(DosAlias {
            caller: self.caller,
            source_segment: segment,
            source_offset: key_offset,
            requested_length: key_length,
            access,
            selector,
        });
        Ok(DosFarPointer::protected(
            self.caller,
            selector.raw().0,
            if access == DosPointerAccess::Execute {
                offset
            } else {
                0
            },
        ))
    }
}

impl GuestMemory for Win16DosAddressSpace<'_> {
    fn len(&self) -> u32 {
        self.memory.len()
    }

    fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory.validate_read(address, length)
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory.validate_write(address, length)
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read(address, bytes)
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write(address, bytes)
    }
}

impl DosCallAddressSpace for Win16DosAddressSpace<'_> {
    fn caller_id(&self) -> DosCallerId {
        self.caller
    }

    fn resolve_caller_pointer(
        &mut self,
        selector: u16,
        offset: u16,
    ) -> Result<DosFarPointer, DosError> {
        self.current_selector(selector, "resolve protected DOS caller pointer")?;
        Ok(DosFarPointer::protected(self.caller, selector, offset))
    }

    fn validate_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
        _policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        let (selector, offset) =
            self.ensure_pointer(pointer, "validate protected DOS caller range")?;
        self.translated_range(
            selector,
            offset,
            byte_offset,
            length,
            access,
            "validate protected DOS caller range",
        )?;
        Ok(())
    }

    fn read_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        output: &mut [u8],
        _policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        let (selector, offset) = self.ensure_pointer(pointer, "read protected DOS caller range")?;
        self.read_at(
            selector,
            offset,
            byte_offset,
            output,
            "read protected DOS caller range",
        )
    }

    fn write_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        input: &[u8],
        _policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        let (selector, offset) =
            self.ensure_pointer(pointer, "write protected DOS caller range")?;
        self.write_at(
            selector,
            offset,
            byte_offset,
            input,
            "write protected DOS caller range",
        )
    }

    fn read_caller_terminated(
        &mut self,
        pointer: DosFarPointer,
        terminator: u8,
        maximum: usize,
        _policy: DosSpanPolicy,
    ) -> Result<Vec<u8>, DosError> {
        let (selector, offset) =
            self.ensure_pointer(pointer, "read protected DOS caller string")?;
        let mut output = Vec::new();
        for index in 0..maximum {
            let mut byte = [0];
            self.read_at(
                selector,
                offset,
                index,
                &mut byte,
                "read protected DOS caller string",
            )?;
            if byte[0] == terminator {
                return Ok(output);
            }
            output.try_reserve(1).map_err(|error| {
                DosError::caller_address_space(
                    FailureKind::ResourceExhausted,
                    "allocate protected DOS caller string",
                    error,
                )
            })?;
            output.push(byte[0]);
        }
        Err(DosError::MalformedGuestInput(
            "DOS caller string is not terminated within its bound",
        ))
    }

    fn retain_caller_pointer(
        &mut self,
        pointer: DosFarPointer,
    ) -> Result<DosPersistentFarPointer, DosError> {
        let (raw, _) = self.ensure_pointer(pointer, "retain protected DOS caller pointer")?;
        let selector = self.current_selector(raw, "retain protected DOS caller pointer")?;
        self.addresses.retain(self.caller, pointer, selector)
    }

    fn release_caller_pointer(&mut self, pointer: DosPersistentFarPointer) -> Result<(), DosError> {
        self.addresses.release_lease(self.caller, pointer)
    }

    fn validate_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<(), DosError> {
        self.validate_retained_generation(
            pointer,
            byte_offset,
            length,
            access,
            "validate retained protected DOS pointer",
        )?;
        Ok(())
    }

    fn read_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        output: &mut [u8],
    ) -> Result<(), DosError> {
        let (_, address) = self.validate_retained_generation(
            pointer,
            byte_offset,
            output.len(),
            DosPointerAccess::Read,
            "read retained protected DOS pointer",
        )?;
        self.memory
            .backing()
            .read(address, output)
            .map_err(|error| memory_failure("read retained protected DOS pointer", error))
    }

    fn write_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        input: &[u8],
    ) -> Result<(), DosError> {
        let (_, address) = self.validate_retained_generation(
            pointer,
            byte_offset,
            input.len(),
            DosPointerAccess::Write,
            "write retained protected DOS pointer",
        )?;
        self.memory
            .backing_mut()
            .write(address, input)
            .map_err(|error| memory_failure("write retained protected DOS pointer", error))
    }

    fn expose_dos_pointer(
        &mut self,
        segment: u16,
        offset: u16,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<DosFarPointer, DosError> {
        self.expose_alias(segment, offset, length, access)
    }
}
