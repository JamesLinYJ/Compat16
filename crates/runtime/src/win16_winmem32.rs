//! WINMEM32 objects in the process-owned guest heap.
//!
//! The Windows 3.1 SDK publishes the eight far-Pascal WORD entry points, version
//! `0x0100`, and error codes 1 through 5. It requires `wFlags` to be zero. It
//! does not publish a page-granular descriptor format. This runtime keeps each
//! object in the global heap, reserved up to its maximum, and exposes it through
//! the existing tiled selector run: one descriptor covers at most 64 KiB, and
//! the next tile is eight selector values higher. `Global16PointerAlloc` returns
//! a separate data selector whose base is the requested byte, so a window of at
//! most 64 KiB can cross a parent tile. Guest selectors are never host pointers.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use win16_abi::{
    Access, AccessRights, AllocationFlags, GlobalHandle, GuestMemoryOwner, SegmentedPointer,
    SelectorRef, WINMEM32_INSUFFICIENT_MEMORY, WINMEM32_INSUFFICIENT_SELECTORS,
    WINMEM32_INVALID_ARGUMENT, WINMEM32_INVALID_FLAGS, WINMEM32_MAX_16BIT_ALIAS_BYTES,
    WINMEM32_MAX_OBJECT_BYTES, WINMEM32_VERSION_1_00, Win16Error, Win16Winmem32Request,
};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

#[derive(Default)]
pub(crate) struct Win16Winmem32State {
    objects: BTreeMap<u16, Object>,
}

struct Object {
    handle: GlobalHandle,
    selector: SelectorRef,
    max_size: u32,
    size: u32,
    aliases: Vec<Alias>,
}

struct Alias {
    selector: SelectorRef,
    /// Exclusive end offset inside the object at the time the alias was created.
    end: u32,
    /// Exact 16:16 value returned for a data alias. Code aliases have none.
    pointer: Option<u32>,
}

impl Win16State {
    pub(super) fn winmem32_api(
        &mut self,
        request: Win16Winmem32Request,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        use Win16Winmem32Request as Request;
        match request {
            Request::GetVersion => Ok(u32::from(WINMEM32_VERSION_1_00)),
            Request::Global32Alloc {
                size,
                selector_output,
                max_size,
                flags,
            } => self.winmem32_alloc(size, selector_output, max_size, flags, memory),
            Request::Global32Realloc {
                selector,
                new_size,
                flags,
            } => self.winmem32_realloc(selector, new_size, flags, memory),
            Request::Global32Free { selector, flags } => {
                self.winmem32_free(selector, flags, memory)
            }
            Request::Global16PointerAlloc {
                selector,
                offset,
                alias_output,
                size,
                flags,
            } => self.winmem32_pointer_alloc(selector, offset, alias_output, size, flags, memory),
            Request::Global16PointerFree {
                selector,
                alias,
                flags,
            } => self.winmem32_pointer_free(selector, alias, flags),
            Request::Global32CodeAlias {
                selector,
                alias_output,
                flags,
            } => self.winmem32_code_alias(selector, alias_output, flags, memory),
            Request::Global32CodeAliasFree {
                selector,
                alias,
                flags,
            } => self.winmem32_code_alias_free(selector, alias, flags),
        }
    }

    fn winmem32_alloc(
        &mut self,
        size: u32,
        selector_output: u32,
        max_size: u32,
        flags: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        if !object_limit(size) || !object_limit(max_size) || size > max_size {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        }
        let output = match self.writable_guest(selector_output, 2, memory) {
            Ok(output) => output,
            Err(status) => return Ok(code(status)),
        };
        let owner = self.tasks.current().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WINMEM32 allocation has no current task",
            )
        })?;
        let task = self.current_task_handle()?;
        let handle =
            match self
                .heap
                .alloc_reserved(memory, owner, size, max_size, AllocationFlags::fixed())
            {
                Ok(handle) => handle,
                Err(error) => return alloc_status(error),
            };
        if let Err(error) = self
            .heap
            .set_guest_owner(handle, GuestMemoryOwner::from_raw(task))
        {
            self.abandon_winmem32(handle, None)?;
            return Err(crate::runtime_error(error).with_context("WINMEM32 guest owner"));
        }
        let base = match self.heap.info(handle) {
            Ok(info) => info.base,
            Err(error) => {
                self.abandon_winmem32(handle, None)?;
                return Err(crate::runtime_error(error).with_context("WINMEM32 allocation base"));
            }
        };
        let selector =
            match self
                .selectors
                .alloc_block(base, size, AccessRights::read_write(), memory)
            {
                Ok(selector) => selector,
                Err(error) => {
                    self.abandon_winmem32(handle, None)?;
                    return alloc_status(error);
                }
            };
        let raw = selector.raw().0;
        if raw == 0
            || self.winmem32.objects.contains_key(&raw)
            || self.global_handles.contains_key(&raw)
            || self.dos_global_blocks.contains_key(&raw)
        {
            self.abandon_winmem32(handle, Some(selector))?;
            return Ok(code(WINMEM32_INSUFFICIENT_SELECTORS));
        }
        self.winmem32.objects.insert(
            raw,
            Object {
                handle,
                selector,
                max_size,
                size,
                aliases: Vec::new(),
            },
        );
        if let Err(error) = self.selectors.write(memory, output, &raw.to_le_bytes()) {
            self.destroy_winmem32(raw)?;
            return Err(crate::runtime_error(error).with_context("WINMEM32 selector output"));
        }
        Ok(0)
    }

    fn winmem32_realloc(
        &mut self,
        selector: u16,
        new_size: u32,
        flags: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        let Some(snapshot) = self.winmem32.objects.get(&selector).map(|object| {
            (
                object.handle,
                object.selector,
                object.max_size,
                object.size,
                object.aliases.iter().any(|alias| alias.end > new_size),
            )
        }) else {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        };
        let (handle, selector_ref, max_size, size, alias_past_end) = snapshot;
        if !object_limit(new_size) || new_size > max_size || alias_past_end {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        }
        if new_size == size {
            return Ok(0);
        }
        let base = self
            .heap
            .info(handle)
            .map_err(|error| crate::runtime_error(error).with_context("WINMEM32 realloc base"))?
            .base;
        let capacity = self.heap.reserved_capacity(handle).map_err(|error| {
            crate::runtime_error(error).with_context("WINMEM32 realloc capacity")
        })?;
        if new_size > capacity {
            return Ok(code(WINMEM32_INSUFFICIENT_MEMORY));
        }
        let updated = match self.selectors.rebind(
            selector_ref,
            base,
            new_size,
            AccessRights::read_write(),
            memory,
        ) {
            Ok(updated) => updated,
            Err(Win16Error::SelectorTableFull) => return Ok(code(WINMEM32_INSUFFICIENT_SELECTORS)),
            Err(Win16Error::OutOfMemory) => return Ok(code(WINMEM32_INSUFFICIENT_MEMORY)),
            Err(error) => {
                return Err(crate::runtime_error(error).with_context("WINMEM32 realloc"));
            }
        };
        let object = self.winmem32.objects.get_mut(&selector).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WINMEM32 object disappeared during realloc",
            )
        })?;
        object.selector = updated;
        object.size = new_size;
        Ok(0)
    }

    fn winmem32_free(
        &mut self,
        selector: u16,
        flags: u16,
        _memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        if !self.winmem32.objects.contains_key(&selector) {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        }
        self.destroy_winmem32(selector)?;
        Ok(0)
    }

    fn winmem32_pointer_alloc(
        &mut self,
        selector: u16,
        offset: u32,
        alias_output: u32,
        size: u32,
        flags: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        let Some(object_size) = self
            .winmem32
            .objects
            .get(&selector)
            .map(|object| object.size)
        else {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        };
        let Some(end) = offset.checked_add(size) else {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        };
        if size == 0 || size > WINMEM32_MAX_16BIT_ALIAS_BYTES || end > object_size {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        }
        let output = match self.writable_guest(alias_output, 4, memory) {
            Ok(output) => output,
            Err(status) => return Ok(code(status)),
        };
        let object_selector = self
            .winmem32
            .objects
            .get(&selector)
            .ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "WINMEM32 object disappeared")
            })?
            .selector;
        let base = self
            .selectors
            .describe(object_selector)
            .map_err(|error| crate::runtime_error(error).with_context("WINMEM32 alias base"))?;
        let alias_base = base.base.0.checked_add(offset).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "WINMEM32 alias offset overflowed")
        })?;
        let alias = match self.selectors.alloc_fixed_selector_descriptor(
            guest_core::PhysAddr(alias_base),
            size,
            AccessRights::read_write(),
            memory,
        ) {
            Ok(alias) => alias,
            Err(error) => return alloc_status(error),
        };
        let raw = alias.raw().0;
        let pointer = u32::from(raw) << 16;
        if let Err(error) = self.selectors.write(memory, output, &pointer.to_le_bytes()) {
            return self.rollback_alias(alias, error, "WINMEM32 alias output");
        }
        self.winmem32
            .objects
            .get_mut(&selector)
            .ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "WINMEM32 object disappeared")
            })?
            .aliases
            .push(Alias {
                selector: alias,
                end,
                pointer: Some(pointer),
            });
        Ok(0)
    }

    fn winmem32_pointer_free(
        &mut self,
        selector: u16,
        alias: u32,
        flags: u16,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        self.free_alias(selector, |entry| entry.pointer == Some(alias))
    }

    fn winmem32_code_alias(
        &mut self,
        selector: u16,
        alias_output: u32,
        flags: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        let Some(size) = self
            .winmem32
            .objects
            .get(&selector)
            .map(|object| object.size)
        else {
            return Ok(code(WINMEM32_INVALID_ARGUMENT));
        };
        let output = match self.writable_guest(alias_output, 2, memory) {
            Ok(output) => output,
            Err(status) => return Ok(code(status)),
        };
        let object_selector = self
            .winmem32
            .objects
            .get(&selector)
            .ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "WINMEM32 object disappeared")
            })?
            .selector;
        let base = self
            .selectors
            .describe(object_selector)
            .map_err(|error| crate::runtime_error(error).with_context("WINMEM32 code alias base"))?
            .base;
        let alias = match self
            .selectors
            .alloc_block(base, size, AccessRights::code(), memory)
        {
            Ok(alias) => alias,
            Err(error) => return alloc_status(error),
        };
        let raw = alias.raw().0;
        if let Err(error) = self.selectors.write(memory, output, &raw.to_le_bytes()) {
            return self.rollback_alias(alias, error, "WINMEM32 code alias output");
        }
        self.winmem32
            .objects
            .get_mut(&selector)
            .ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "WINMEM32 object disappeared")
            })?
            .aliases
            .push(Alias {
                selector: alias,
                end: size,
                pointer: None,
            });
        Ok(0)
    }

    fn winmem32_code_alias_free(
        &mut self,
        selector: u16,
        alias: u16,
        flags: u16,
    ) -> Result<u32, RuntimeError> {
        if flags != 0 {
            return Ok(code(WINMEM32_INVALID_FLAGS));
        }
        self.free_alias(selector, |entry| {
            entry.pointer.is_none() && entry.selector.raw().0 == alias
        })
    }

    fn free_alias(
        &mut self,
        selector: u16,
        matches: impl Fn(&Alias) -> bool,
    ) -> Result<u32, RuntimeError> {
        let removed = {
            let Some(object) = self.winmem32.objects.get_mut(&selector) else {
                return Ok(code(WINMEM32_INVALID_ARGUMENT));
            };
            let Some(index) = object.aliases.iter().position(&matches) else {
                return Ok(code(WINMEM32_INVALID_ARGUMENT));
            };
            (index, object.aliases.remove(index))
        };
        let (index, alias) = removed;
        if let Err(error) = self.selectors.free_block(alias.selector) {
            self.winmem32
                .objects
                .get_mut(&selector)
                .ok_or_else(|| {
                    RuntimeError::new(Kind::InternalInvariant, "WINMEM32 object disappeared")
                })?
                .aliases
                .insert(index, alias);
            return Err(crate::runtime_error(error).with_context("WINMEM32 alias free"));
        }
        Ok(0)
    }

    fn rollback_alias(
        &mut self,
        alias: SelectorRef,
        error: Win16Error,
        context: &'static str,
    ) -> Result<u32, RuntimeError> {
        if let Err(rollback) = self.selectors.free_block(alias) {
            return Err(crate::runtime_error(error).with_cleanup(
                "rolling back a WINMEM32 alias",
                crate::runtime_error(rollback),
            ));
        }
        Err(crate::runtime_error(error).with_context(context))
    }

    fn writable_guest(
        &self,
        far: u32,
        length: usize,
        memory: &Memory,
    ) -> Result<SegmentedPointer, u16> {
        if far == 0 {
            return Err(WINMEM32_INVALID_ARGUMENT);
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|_| WINMEM32_INVALID_ARGUMENT)?;
        self.selectors
            .translate(pointer, Access::Write, length, memory)
            .map_err(|_| WINMEM32_INVALID_ARGUMENT)?;
        Ok(pointer)
    }

    fn abandon_winmem32(
        &mut self,
        handle: GlobalHandle,
        selector: Option<SelectorRef>,
    ) -> Result<(), RuntimeError> {
        if let Some(selector) = selector {
            self.selectors.free_block(selector).map_err(|error| {
                crate::runtime_error(error).with_context("WINMEM32 selector rollback")
            })?;
        }
        self.heap
            .free(handle, &mut self.selectors)
            .map_err(|error| crate::runtime_error(error).with_context("WINMEM32 heap rollback"))?;
        Ok(())
    }

    fn destroy_winmem32(&mut self, raw: u16) -> Result<(), RuntimeError> {
        let mut object = self.winmem32.objects.remove(&raw).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "WINMEM32 object is not tracked")
        })?;
        while let Some(alias) = object.aliases.pop() {
            if let Err(error) = self.selectors.free_block(alias.selector) {
                object.aliases.push(alias);
                self.winmem32.objects.insert(raw, object);
                return Err(crate::runtime_error(error).with_context("WINMEM32 alias release"));
            }
        }
        if let Err(error) = self.selectors.free_block(object.selector) {
            self.winmem32.objects.insert(raw, object);
            return Err(crate::runtime_error(error).with_context("WINMEM32 selector release"));
        }
        self.heap
            .free(object.handle, &mut self.selectors)
            .map_err(|error| crate::runtime_error(error).with_context("WINMEM32 heap release"))?;
        Ok(())
    }
}

fn object_limit(size: u32) -> bool {
    size > 0 && size <= WINMEM32_MAX_OBJECT_BYTES
}

fn code(status: u16) -> u32 {
    u32::from(status)
}

fn alloc_status(error: Win16Error) -> Result<u32, RuntimeError> {
    match error {
        Win16Error::SelectorTableFull => Ok(code(WINMEM32_INSUFFICIENT_SELECTORS)),
        Win16Error::OutOfMemory | Win16Error::HandleTableFull | Win16Error::InvalidSize => {
            Ok(code(WINMEM32_INSUFFICIENT_MEMORY))
        }
        other => Err(crate::runtime_error(other).with_context("WINMEM32 allocation")),
    }
}

#[cfg(test)]
#[path = "win16_winmem32_tests.rs"]
mod tests;
