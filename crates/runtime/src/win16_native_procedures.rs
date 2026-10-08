//! Stable guest FAR gates for native USER window procedures.
//!
//! Native procedure identities remain opaque host tokens. The guest sees a
//! checked executable selector and a never-reused offset in a runtime-owned
//! fixed code allocation; the interpreter traps that exact address before
//! fetching its `INT 3` guard byte and routes the call back to the host.

use guest_core::{OwnerId, PhysAddr, Selector, memory::Memory};
use win16_abi::{
    AllocationFlags, ArgumentKind, GlobalHandle, ReturnAddressWidth, SelectorRef, Win16Argument,
    Win16CallFrame, Win16CallingConvention,
};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostProcedure};

const GATE_BLOCK_BYTES: u32 = 4096;
const GATE_TRAP_BYTE: u8 = 0xcc;
// Reserved for runtime-owned module/gate allocations. Task termination must
// not reclaim these while retained native procedure tokens remain callable.
const GATE_ALLOCATION_OWNER: OwnerId = OwnerId(u32::MAX);

fn canonical_selector(selector: u16) -> u16 {
    // SelectorTable resolves descriptors by raw >> 3; the low three bits are
    // RPL/TI attributes and do not identify a different descriptor.
    selector & !0x7
}

fn canonical_far(address: u32) -> u32 {
    (u32::from(canonical_selector((address >> 16) as u16)) << 16) | (address & 0xffff)
}

#[derive(Debug)]
struct NativeProcedureGateBlock {
    allocation: GlobalHandle,
    base: PhysAddr,
    /// The GlobalHeap's permanently pinned RW selector keeps its fixed
    /// allocation alive. Guest FAR gates use the separate RX selector below.
    pin_selector: SelectorRef,
    gate_selector: SelectorRef,
    next_offset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeProcedureGateTarget {
    WindowProcedure(Win16HostProcedure),
    Ole1ClientCallback,
    /// One public OLEOBJECT method on a checked runtime proxy. This identity
    /// is neither a guest FAR value nor a native COM pointer.
    Ole1ObjectMethod {
        object_proxy_id: u64,
        slot: u8,
    },
}

/// Append-only mapping between host procedure tokens and guest FAR entries.
/// The selector table and GlobalHeap own the actual guest backing.
#[derive(Debug, Default)]
pub(super) struct NativeProcedureGates {
    blocks: Vec<NativeProcedureGateBlock>,
    by_token: Vec<(NativeProcedureGateTarget, u32)>,
    by_address: Vec<(u32, NativeProcedureGateTarget)>,
}

impl NativeProcedureGates {
    fn address_for_target(&self, target: NativeProcedureGateTarget) -> Option<u32> {
        self.by_token
            .iter()
            .find_map(|(current, address)| (*current == target).then_some(*address))
    }

    fn target_for_address(&self, address: u32) -> Option<NativeProcedureGateTarget> {
        let address = canonical_far(address);
        self.by_address
            .iter()
            .find_map(|(current, target)| (*current == address).then_some(*target))
    }

    fn block_for_gate_selector(&self, selector: u16) -> Option<&NativeProcedureGateBlock> {
        let selector = canonical_selector(selector);
        self.blocks
            .iter()
            .find(|block| canonical_selector(block.gate_selector.raw().0) == selector)
    }

    /// True for both the published RX selector and its private GlobalHeap pin
    /// selector. Runtime selector mutators use this to protect both identities.
    fn owns_selector(&self, selector: u16) -> bool {
        let selector = canonical_selector(selector);
        self.blocks.iter().any(|block| {
            canonical_selector(block.gate_selector.raw().0) == selector
                || canonical_selector(block.pin_selector.raw().0) == selector
        })
    }

    fn validate_block(
        &self,
        block: &NativeProcedureGateBlock,
        heap: &win16_abi::GlobalHeap,
        selectors: &win16_abi::SelectorTable,
    ) -> bool {
        let Ok(info) = heap.info(block.allocation) else {
            return false;
        };
        let Ok(pin_count) = heap.internal_pin_count(block.allocation) else {
            return false;
        };
        let Ok(pin_current) = selectors.reference(block.pin_selector.raw()) else {
            return false;
        };
        let Ok(gate_current) = selectors.reference(block.gate_selector.raw()) else {
            return false;
        };
        let Ok(pin_descriptor) = selectors.describe(block.pin_selector) else {
            return false;
        };
        let Ok(gate_descriptor) = selectors.describe(block.gate_selector) else {
            return false;
        };

        info.base == block.base
            && info.size == GATE_BLOCK_BYTES
            && info.owner == GATE_ALLOCATION_OWNER
            && !info.executable
            && !info.movable
            && !info.discarded
            && pin_count > 0
            && pin_current == block.pin_selector
            && gate_current == block.gate_selector
            && canonical_selector(block.pin_selector.raw().0)
                != canonical_selector(block.gate_selector.raw().0)
            && pin_descriptor.present
            && pin_descriptor.base == block.base
            && pin_descriptor.limit == GATE_BLOCK_BYTES - 1
            && pin_descriptor.rights.readable()
            && pin_descriptor.rights.writable()
            && !pin_descriptor.rights.executable()
            && gate_descriptor.present
            && gate_descriptor.base == block.base
            && gate_descriptor.limit == GATE_BLOCK_BYTES - 1
            && gate_descriptor.rights.readable()
            && gate_descriptor.rights.executable()
            && !gate_descriptor.rights.writable()
    }

    fn allocate_block(
        &mut self,
        heap: &mut win16_abi::GlobalHeap,
        selectors: &mut win16_abi::SelectorTable,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        self.blocks.try_reserve(1).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native WndProc gate metadata cannot grow",
            )
        })?;
        let mut trap_bytes = Vec::new();
        trap_bytes
            .try_reserve_exact(GATE_BLOCK_BYTES as usize)
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "native WndProc gate backing cannot grow",
                )
            })?;
        trap_bytes.resize(GATE_BLOCK_BYTES as usize, GATE_TRAP_BYTE);

        let allocation = heap
            .alloc(
                memory,
                GATE_ALLOCATION_OWNER,
                GATE_BLOCK_BYTES,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("allocating native WndProc gate backing"))?;
        let pin_pointer = match heap.lock(allocation, selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => {
                heap.free(allocation, selectors)
                    .map_err(crate::runtime_error)?;
                return Err(
                    crate::runtime_error(error).with_context("pinning native WndProc gate backing")
                );
            }
        };
        let pin_selector = pin_pointer.selector();
        let base = match heap.info(allocation) {
            Ok(info) => info.base,
            Err(error) => {
                Self::rollback_allocation(heap, selectors, allocation)?;
                return Err(crate::runtime_error(error)
                    .with_context("reading native WndProc gate allocation"));
            }
        };
        if let Err(error) = selectors.write(memory, pin_pointer, &trap_bytes) {
            Self::rollback_allocation(heap, selectors, allocation)?;
            return Err(crate::runtime_error(error)
                .with_context("initializing native WndProc gate trap bytes"));
        }
        let gate_selector = match selectors.alloc_block(
            base,
            GATE_BLOCK_BYTES,
            win16_abi::AccessRights::code(),
            memory,
        ) {
            Ok(selector) => selector,
            Err(error) => {
                Self::rollback_allocation(heap, selectors, allocation)?;
                return Err(crate::runtime_error(error)
                    .with_context("allocating native WndProc executable selector"));
            }
        };
        self.blocks.push(NativeProcedureGateBlock {
            allocation,
            base,
            pin_selector,
            gate_selector,
            next_offset: 0,
        });
        Ok(())
    }

    fn rollback_allocation(
        heap: &mut win16_abi::GlobalHeap,
        selectors: &mut win16_abi::SelectorTable,
        allocation: GlobalHandle,
    ) -> Result<(), RuntimeError> {
        if heap.internal_pin_count(allocation).unwrap_or(0) != 0 {
            heap.unlock(allocation, selectors)
                .map_err(crate::runtime_error)?;
        }
        heap.free(allocation, selectors)
            .map_err(crate::runtime_error)
    }

    fn insert(
        &mut self,
        target: NativeProcedureGateTarget,
        heap: &mut win16_abi::GlobalHeap,
        selectors: &mut win16_abi::SelectorTable,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if let Some(address) = self.address_for_target(target) {
            let selector = (address >> 16) as u16;
            let Some(block) = self.block_for_gate_selector(selector) else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native WndProc gate token has no backing block",
                ));
            };
            if !self.validate_block(block, heap, selectors) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "published native WndProc gate backing changed",
                ));
            }
            return Ok(address);
        }

        // Reserve lookup metadata before allocating guest-visible backing, so
        // metadata pressure cannot leave an unreachable published gate.
        self.by_token.try_reserve(1).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native WndProc token table cannot grow",
            )
        })?;
        self.by_address.try_reserve(1).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native WndProc address table cannot grow",
            )
        })?;

        if self
            .blocks
            .last()
            .map_or(true, |block| block.next_offset >= GATE_BLOCK_BYTES)
        {
            self.allocate_block(heap, selectors, memory)?;
        }
        let block = self.blocks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "native WndProc gate allocation produced no block",
            )
        })?;
        let offset = u16::try_from(block.next_offset).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native WndProc gate block offsets are exhausted",
            )
        })?;
        let address =
            canonical_far((u32::from(block.gate_selector.raw().0) << 16) | u32::from(offset));
        if self.target_for_address(address).is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native WndProc gate address was already published",
            ));
        }
        let block = self.blocks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "native WndProc gate block disappeared",
            )
        })?;
        block.next_offset += 1;
        self.by_token.push((target, address));
        self.by_address.push((address, target));
        Ok(address)
    }

    /// Make a consecutive group of new gate insertions allocation-free after
    /// this call. OLE publishes a full 39-slot client table as one guest object,
    /// so
    /// resource exhaustion must be detected before any of its gates become
    /// visible in the append-only token map.
    fn reserve_slots(
        &mut self,
        count: usize,
        heap: &mut win16_abi::GlobalHeap,
        selectors: &mut win16_abi::SelectorTable,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if count == 0 || count > GATE_BLOCK_BYTES as usize {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native procedure gate reservation has an invalid slot count",
            ));
        }
        self.by_token.try_reserve(count).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native procedure token table cannot reserve an OLE vtable",
            )
        })?;
        self.by_address.try_reserve(count).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native procedure address table cannot reserve an OLE vtable",
            )
        })?;

        let fits_current = self.blocks.last().is_some_and(|block| {
            block
                .next_offset
                .checked_add(count as u32)
                .is_some_and(|end| end <= GATE_BLOCK_BYTES)
        });
        if !fits_current {
            self.blocks.try_reserve(1).map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "native procedure backing table cannot reserve an OLE vtable",
                )
            })?;
            self.allocate_block(heap, selectors, memory)?;
        }
        Ok(())
    }

    fn validate_address(
        &self,
        address: u32,
        heap: &win16_abi::GlobalHeap,
        selectors: &win16_abi::SelectorTable,
    ) -> Option<NativeProcedureGateTarget> {
        let target = self.target_for_address(address)?;
        let block = self.block_for_gate_selector((address >> 16) as u16)?;
        self.validate_block(block, heap, selectors)
            .then_some(target)
    }

    fn has_gate_selector(&self, selector: u16) -> bool {
        self.block_for_gate_selector(selector).is_some()
    }
}

impl Win16State {
    /// Return a stable guest FAR entry for one host WNDPROC token. Each
    /// 4-KiB code block supplies 4096 one-byte guarded slots; a new fixed block
    /// is allocated when the current one fills.
    pub(super) fn native_procedure_gate(
        &mut self,
        procedure: Win16HostProcedure,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        match self.native_procedures.insert(
            NativeProcedureGateTarget::WindowProcedure(procedure),
            &mut self.heap,
            &mut self.selectors,
            memory,
        ) {
            Err(error) if error.kind() == Kind::ResourceExhausted => Ok(0),
            result => result,
        }
    }

    /// Resolve a guest FAR gate only while its retained selector generation,
    /// executable descriptor and fixed GlobalHeap backing still agree.
    pub(super) fn native_procedure_for_address(&self, address: u32) -> Option<Win16HostProcedure> {
        match self
            .native_procedures
            .validate_address(address, &self.heap, &self.selectors)?
        {
            NativeProcedureGateTarget::WindowProcedure(procedure) => Some(procedure),
            NativeProcedureGateTarget::Ole1ClientCallback
            | NativeProcedureGateTarget::Ole1ObjectMethod { .. } => None,
        }
    }

    pub(super) fn ole1_client_callback_gate(
        &mut self,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        self.native_procedures.insert(
            NativeProcedureGateTarget::Ole1ClientCallback,
            &mut self.heap,
            &mut self.selectors,
            memory,
        )
    }

    /// Return a checked gate for one of the 39 client OLE.H object slots.
    /// ChangeData is internal-only but physically occupies the final slot.
    pub(super) fn ole1_object_method_gate(
        &mut self,
        object_proxy_id: u64,
        slot: u8,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if object_proxy_id == 0 || u32::from(slot) >= 39 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "invalid runtime OLE1 object-proxy gate identity or slot",
            ));
        }
        self.native_procedures.insert(
            NativeProcedureGateTarget::Ole1ObjectMethod {
                object_proxy_id,
                slot,
            },
            &mut self.heap,
            &mut self.selectors,
            memory,
        )
    }

    pub(super) fn reserve_ole1_object_method_gates(
        &mut self,
        count: usize,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        self.native_procedures
            .reserve_slots(count, &mut self.heap, &mut self.selectors, memory)
    }

    pub(super) fn ole1_object_method_gate_address(
        &self,
        object_proxy_id: u64,
        slot: u8,
    ) -> Option<u32> {
        self.native_procedures
            .address_for_target(NativeProcedureGateTarget::Ole1ObjectMethod {
                object_proxy_id,
                slot,
            })
    }

    fn native_procedure_gate_target_for_address(
        &self,
        address: u32,
    ) -> Option<NativeProcedureGateTarget> {
        self.native_procedures
            .validate_address(address, &self.heap, &self.selectors)
    }

    /// The executor traps this selector before the CPU fetches its `INT 3`
    /// guard. A selector with an unpublished slot is rejected by dispatch.
    pub(super) fn is_native_procedure_gate(&self, selector: u16) -> bool {
        self.native_procedures.has_gate_selector(selector)
    }

    /// True for the published gate selector and its private fixed-block pin
    /// selector; selector-mutating kernel APIs must reject either raw word.
    pub(super) fn owns_native_procedure_selector(&self, selector: u16) -> bool {
        self.native_procedures.owns_selector(selector)
    }

    /// Decode a direct guest FAR call to a native window procedure. Win16
    /// WNDPROC takes ten stack bytes and returns with `RETF 10`.
    pub(super) fn dispatch_native_procedure(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u8>, RuntimeError> {
        let address = (u32::from(cpu.regs.cs) << 16) | u32::from(cpu.regs.ip());
        let target = self
            .native_procedure_gate_target_for_address(address)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "guest entered an invalid or stale native procedure gate",
                )
            })?;
        let procedure = match target {
            NativeProcedureGateTarget::WindowProcedure(procedure) => procedure,
            NativeProcedureGateTarget::Ole1ClientCallback => {
                return self.begin_ole1_client_proxy_callback(cpu, dos, memory);
            }
            NativeProcedureGateTarget::Ole1ObjectMethod {
                object_proxy_id,
                slot,
            } => {
                return self.begin_ole1_object_proxy_method(
                    cpu,
                    dos,
                    memory,
                    host,
                    object_proxy_id,
                    slot,
                );
            }
        };
        let stack_entry = self
            .selectors
            .pointer_from_raw(Selector(cpu.regs.ss), cpu.regs.sp())
            .map_err(crate::runtime_error)?;
        let frame = Win16CallFrame::new(stack_entry, ReturnAddressWidth::Far);
        let convention = Win16CallingConvention::Pascal;
        let signature = [
            ArgumentKind::Word,
            ArgumentKind::Word,
            ArgumentKind::Word,
            ArgumentKind::Dword,
        ];
        let arguments = frame
            .decode_arguments(&self.selectors, memory, convention, &signature)
            .map_err(crate::runtime_error)?;
        let cleanup = frame
            .cleanup(convention, &signature)
            .map_err(crate::runtime_error)?;
        let return_to = self.far_return(&cpu.regs, memory, cleanup.callee_pop_bytes)?;
        let (window, message, w_param, l_param) = match arguments.as_slice() {
            [
                Win16Argument::Word(window),
                Win16Argument::Word(message),
                Win16Argument::Word(w_param),
                Win16Argument::Dword(l_param),
            ] => (*window, *message, *w_param, *l_param),
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native WndProc stack decoder returned an unexpected signature",
                ));
            }
        };
        self.begin_native_window_proc(
            &mut cpu.regs,
            memory,
            host,
            procedure,
            window,
            message,
            w_param,
            l_param,
            return_to,
        )
    }
}
