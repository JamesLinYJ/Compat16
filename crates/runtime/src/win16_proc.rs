//! Guest-resident Win16 instance procedure thunks.
//!
//! A procedure instance is executable guest code that loads the module data
//! selector into AX before jumping to the original far procedure. No thunk
//! address is a host pointer or a host executable memory allocation.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use guest_core::{OwnerId, Selector};
use win16_abi::{Access, AllocationFlags, GlobalHandle};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

const INSTANCE_THUNK_BYTES: u32 = 8;
const MOV_AX_IMMEDIATE: u8 = 0xB8;
const JMP_FAR_IMMEDIATE: u8 = 0xEA;
// NE segment flag: movable segment handles are selector - 1.
const NE_SEGMENT_MOVEABLE: u16 = 0x0010;

pub(super) struct ProcInstances {
    allocations: BTreeMap<u32, (GlobalHandle, u32, u16)>,
}

impl ProcInstances {
    pub(super) fn new() -> Self {
        Self {
            allocations: BTreeMap::new(),
        }
    }
}

impl Win16State {
    pub(super) fn make_proc_instance(
        &mut self,
        procedure: u32,
        instance: u16,
        calling_ds: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if procedure >> 16 == 0 {
            return Ok(0);
        }
        let Ok(target) = self.selectors.pointer_from_far(procedure) else {
            return Ok(0);
        };
        if self
            .selectors
            .translate(target, Access::Execute, 1, memory)
            .is_err()
        {
            return Ok(0);
        }
        // Win16's instance handle identifies the automatic data segment. A
        // movable segment's handle is selector - 1; callers may also pass its
        // selector directly. Zero and -1 historically request the current DS.
        let instance_selector = if instance == 0 || instance == u16::MAX {
            calling_ds
        } else {
            let Some(module_handle) = self.module_handle_for_instance(instance) else {
                return Ok(0);
            };
            let Some(record) = self.modules.records.get(&module_handle) else {
                return Ok(0);
            };
            let Some(definition) = record.definition.as_ref() else {
                return Ok(0);
            };
            let data_segment_number = definition.header.automatic_data_segment;
            if data_segment_number == 0 {
                // An explicit module instance must identify a data segment to
                // bind. The current-DS behavior is reserved for the documented
                // null/-1 forms handled above.
                return Ok(0);
            }
            let Some(loaded) = record.loaded.as_ref() else {
                return Ok(0);
            };
            let Some(data_selector) = loaded.segment_selector(data_segment_number) else {
                return Ok(0);
            };
            let Some(segment) = definition
                .segments
                .iter()
                .find(|segment| segment.number == data_segment_number)
            else {
                return Ok(0);
            };
            let data_handle = if segment.flags & NE_SEGMENT_MOVEABLE != 0 {
                let Some(handle) = data_selector.0.checked_sub(1) else {
                    return Ok(0);
                };
                handle
            } else {
                data_selector.0
            };
            if instance != record.instance && instance != data_selector.0 && instance != data_handle
            {
                return Ok(0);
            }
            data_selector.0
        };
        let Ok(data) = self.selectors.reference(Selector(instance_selector)) else {
            return Ok(0);
        };
        if self
            .selectors
            .translate(
                win16_abi::SegmentedPointer::new(data, 0),
                Access::Read,
                1,
                memory,
            )
            .is_err()
        {
            return Ok(0);
        }

        let allocation = match self.heap.alloc(
            memory,
            OwnerId(1),
            INSTANCE_THUNK_BYTES,
            AllocationFlags::fixed().with_execute(),
        ) {
            Ok(handle) => handle,
            Err(win16_abi::Win16Error::OutOfMemory | win16_abi::Win16Error::HandleTableFull) => {
                return Ok(0);
            }
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let entry = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => {
                self.heap
                    .free(allocation, &mut self.selectors)
                    .map_err(crate::runtime_error)?;
                return match error {
                    win16_abi::Win16Error::OutOfMemory
                    | win16_abi::Win16Error::SelectorTableFull => Ok(0),
                    other => Err(crate::runtime_error(other)),
                };
            }
        };
        let mut code = [0_u8; INSTANCE_THUNK_BYTES as usize];
        code[0] = MOV_AX_IMMEDIATE;
        code[1..3].copy_from_slice(&instance_selector.to_le_bytes());
        code[3] = JMP_FAR_IMMEDIATE;
        code[4..8].copy_from_slice(&procedure.to_le_bytes());
        let write_result = self.selectors.write(memory, entry, &code);
        let unlock_result = self.heap.unlock(allocation, &mut self.selectors);
        if let Err(error) = write_result {
            let _ = unlock_result;
            self.heap
                .free(allocation, &mut self.selectors)
                .map_err(crate::runtime_error)?;
            return Err(crate::runtime_error(error));
        }
        unlock_result.map_err(crate::runtime_error)?;
        let address = entry.far_value();
        if self
            .proc_instances
            .allocations
            .insert(address, (allocation, procedure, instance_selector))
            .is_some()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 procedure thunk selector was allocated twice",
            ));
        }
        Ok(address)
    }

    pub(super) fn free_proc_instance(&mut self, procedure: u32) -> Result<(), RuntimeError> {
        let Some((allocation, _, _)) = self.proc_instances.allocations.get(&procedure).copied()
        else {
            return Ok(());
        };
        self.heap
            .free(allocation, &mut self.selectors)
            .map_err(crate::runtime_error)?;
        self.proc_instances.allocations.remove(&procedure);
        Ok(())
    }

    /// Resolve only procedure-instance thunks owned by this runtime. Callers
    /// may fall back to interpreting an unowned FARPROC as its original guest
    /// code address; thunk bytes are never guessed from guest memory.
    pub(super) fn proc_instance_target(&self, procedure: u32) -> Option<u32> {
        self.proc_instances
            .allocations
            .get(&procedure)
            .map(|(_, target, _)| *target)
    }

    pub(super) fn proc_code_references(&self) -> Vec<u32> {
        self.proc_instances
            .allocations
            .iter()
            .flat_map(|(&thunk, &(_, target, _))| [target, thunk])
            .collect()
    }

    pub(super) fn proc_global_blocks(&self) -> impl Iterator<Item = (u16, GlobalHandle, u16)> + '_ {
        self.proc_instances
            .allocations
            .iter()
            .map(|(&entry, &(identity, _, owner_ds))| ((entry >> 16) as u16, identity, owner_ds))
    }

    pub(super) fn proc_owner_modules(&self) -> Vec<u16> {
        self.proc_instances
            .allocations
            .values()
            .filter_map(|&(_, _, data_selector)| {
                self.modules.retained_owner(data_selector, &self.selectors)
            })
            .collect()
    }
}
