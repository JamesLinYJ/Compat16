//! Fixed-width TOOLHELP structures beyond the global-arena records.
//!
//! Private byte-aligned wire records encode the Win16 layouts with explicit
//! little-endian fields. Their offsets were transcribed from the TOOLHELP
//! declarations tracked by this repository's export inventory; the reference
//! checkout is not a production dependency.

use super::wire::{
    ClassEntry16Wire, LocalEntry16Wire, LocalInfo16Wire, MemManInfo16Wire, ModuleEntry16Wire,
    StackTraceEntry16Wire, SystemHeapInfo16Wire, TaskEntry16Wire, TimerInfo16Wire, encode_wire,
    read_wire,
};
use zerocopy::byteorder::little_endian::{U16, U32};

pub const LOCALINFO16_SIZE: usize = 6;
pub const LOCALENTRY16_SIZE: usize = 22;
pub const LOCAL32INFO16_SIZE: usize = 24;
pub const LOCAL32ENTRY16_SIZE: usize = 30;
pub const MODULEENTRY16_NAME_BYTES: usize = 10;
pub const MODULEENTRY16_PATH_BYTES: usize = 256;
pub const MODULEENTRY16_SIZE: usize = 276;
pub const TASKENTRY16_NAME_BYTES: usize = 10;
pub const TASKENTRY16_SIZE: usize = 40;
pub const SYSHEAPINFO16_SIZE: usize = 12;
pub const MEMMANINFO16_SIZE: usize = 42;
pub const TIMERINFO16_SIZE: usize = 12;
pub const CLASSENTRY16_NAME_BYTES: usize = 256;
pub const CLASSENTRY16_SIZE: usize = 264;
// Win16 STACKTRACEENTRY is DWORD dwSize followed by eight WORD fields.
// Source: the packed Win16 declaration in the repository's development-only
// ToolHelp header (`toolhelp/toolhelp.h`); the wire size is 20 bytes.
pub const STACKTRACEENTRY16_SIZE: usize = 20;

pub mod localentry16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const HANDLE: usize = 4;
    pub const ADDRESS: usize = 6;
    pub const BLOCK_SIZE: usize = 8;
    pub const FLAGS: usize = 10;
    pub const LOCK_COUNT: usize = 12;
    pub const BLOCK_TYPE: usize = 14;
    pub const HEAP: usize = 16;
    pub const HEAP_TYPE: usize = 18;
    pub const NEXT: usize = 20;
}

pub mod moduleentry16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const MODULE_NAME: usize = 4;
    pub const MODULE_HANDLE: usize = 14;
    pub const USAGE_COUNT: usize = 16;
    pub const EXECUTABLE_PATH: usize = 18;
    pub const NEXT: usize = 274;
}

pub mod classentry16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const INSTANCE: usize = 4;
    pub const CLASS_NAME: usize = 6;
    pub const NEXT: usize = 262;
}

pub mod taskentry16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const TASK: usize = 4;
    pub const PARENT_TASK: usize = 6;
    pub const INSTANCE: usize = 8;
    pub const MODULE: usize = 10;
    pub const STACK_SEGMENT: usize = 12;
    pub const STACK_POINTER: usize = 14;
    pub const STACK_TOP: usize = 16;
    pub const STACK_MINIMUM: usize = 18;
    pub const STACK_BOTTOM: usize = 20;
    pub const EVENT_COUNT: usize = 22;
    pub const QUEUE: usize = 24;
    pub const MODULE_NAME: usize = 26;
    pub const PSP_OFFSET: usize = 36;
    pub const NEXT: usize = 38;
}

pub mod memmaninfo16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const LARGEST_FREE_BLOCK: usize = 4;
    pub const MAX_PAGES_AVAILABLE: usize = 8;
    pub const MAX_PAGES_LOCKABLE: usize = 12;
    pub const TOTAL_LINEAR_SPACE: usize = 16;
    pub const TOTAL_UNLOCKED_PAGES: usize = 20;
    pub const FREE_PAGES: usize = 24;
    pub const TOTAL_PAGES: usize = 28;
    pub const FREE_LINEAR_SPACE: usize = 32;
    pub const SWAP_FILE_PAGES: usize = 36;
    pub const PAGE_SIZE: usize = 40;
}

pub mod stacktraceentry16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const TASK: usize = 4;
    pub const STACK_SEGMENT: usize = 6;
    pub const BASE_POINTER: usize = 8;
    pub const CODE_SEGMENT: usize = 10;
    pub const INSTRUCTION_POINTER: usize = 12;
    pub const MODULE: usize = 14;
    pub const SEGMENT: usize = 16;
    pub const FLAGS: usize = 18;
}

/// `LOCALINFO` prefix, preserving the caller's `dwSize`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct LocalInfo16 {
    pub items: u16,
}

impl LocalInfo16 {
    pub const SIZE: usize = LOCALINFO16_SIZE;

    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(LocalInfo16Wire {
            dw_size: U32::new(dw_size),
            items: U16::new(self.items),
        })
    }
}

/// One fixed-width `LOCALENTRY`; `next` is an opaque same-heap cursor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct LocalEntry16 {
    pub handle: u16,
    pub address: u16,
    pub block_size: u16,
    pub flags: u16,
    pub lock_count: u16,
    pub block_type: u16,
    pub heap: u16,
    pub heap_type: u16,
    pub next: u16,
}

impl LocalEntry16 {
    pub const SIZE: usize = LOCALENTRY16_SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> (u32, Self) {
        let wire = read_wire::<LocalEntry16Wire>(bytes);
        (
            wire.dw_size.get(),
            Self {
                handle: wire.handle.get(),
                address: wire.address.get(),
                block_size: wire.block_size.get(),
                flags: wire.flags.get(),
                lock_count: wire.lock_count.get(),
                block_type: wire.block_type.get(),
                heap: wire.heap.get(),
                heap_type: wire.heap_type.get(),
                next: wire.next.get(),
            },
        )
    }

    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(LocalEntry16Wire {
            dw_size: U32::new(dw_size),
            handle: U16::new(self.handle),
            address: U16::new(self.address),
            block_size: U16::new(self.block_size),
            flags: U16::new(self.flags),
            lock_count: U16::new(self.lock_count),
            block_type: U16::new(self.block_type),
            heap: U16::new(self.heap),
            heap_type: U16::new(self.heap_type),
            next: U16::new(self.next),
        })
    }
}

/// One fixed-width `MODULEENTRY` with ANSI module/path fields.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ModuleEntry16 {
    pub module_name: [u8; MODULEENTRY16_NAME_BYTES],
    pub module_handle: u16,
    pub usage_count: u16,
    pub executable_path: [u8; MODULEENTRY16_PATH_BYTES],
    pub next: u16,
}

impl Default for ModuleEntry16 {
    fn default() -> Self {
        Self {
            module_name: [0; MODULEENTRY16_NAME_BYTES],
            module_handle: 0,
            usage_count: 0,
            executable_path: [0; MODULEENTRY16_PATH_BYTES],
            next: 0,
        }
    }
}

impl ModuleEntry16 {
    pub const SIZE: usize = MODULEENTRY16_SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> (u32, Self) {
        let wire = read_wire::<ModuleEntry16Wire>(bytes);
        (
            wire.dw_size.get(),
            Self {
                module_name: wire.module_name,
                module_handle: wire.module_handle.get(),
                usage_count: wire.usage_count.get(),
                executable_path: wire.executable_path,
                next: wire.next.get(),
            },
        )
    }

    pub fn encode_with_size(&self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(ModuleEntry16Wire {
            dw_size: U32::new(dw_size),
            module_name: self.module_name,
            module_handle: U16::new(self.module_handle),
            usage_count: U16::new(self.usage_count),
            executable_path: self.executable_path,
            next: U16::new(self.next),
        })
    }
}

/// One fixed-width `CLASSENTRY`; the continuation word contains the next
/// guest atom in the current registration-order snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClassEntry16 {
    pub instance: u16,
    pub class_name: [u8; CLASSENTRY16_NAME_BYTES],
    pub next: u16,
}

impl Default for ClassEntry16 {
    fn default() -> Self {
        Self {
            instance: 0,
            class_name: [0; CLASSENTRY16_NAME_BYTES],
            next: 0,
        }
    }
}

impl ClassEntry16 {
    pub const SIZE: usize = CLASSENTRY16_SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> (u32, Self) {
        let wire = read_wire::<ClassEntry16Wire>(bytes);
        (
            wire.dw_size.get(),
            Self {
                instance: wire.instance.get(),
                class_name: wire.class_name,
                next: wire.next.get(),
            },
        )
    }

    pub fn encode_with_size(&self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(ClassEntry16Wire {
            dw_size: U32::new(dw_size),
            instance: U16::new(self.instance),
            class_name: self.class_name,
            next: U16::new(self.next),
        })
    }
}

/// One fixed-width `TASKENTRY`; task handles remain guest WORD identities.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TaskEntry16 {
    pub task: u16,
    pub parent_task: u16,
    pub instance: u16,
    pub module: u16,
    pub stack_segment: u16,
    pub stack_pointer: u16,
    pub stack_top: u16,
    pub stack_minimum: u16,
    pub stack_bottom: u16,
    pub event_count: u16,
    pub queue: u16,
    pub module_name: [u8; TASKENTRY16_NAME_BYTES],
    pub psp_offset: u16,
    pub next: u16,
}

impl Default for TaskEntry16 {
    fn default() -> Self {
        Self {
            task: 0,
            parent_task: 0,
            instance: 0,
            module: 0,
            stack_segment: 0,
            stack_pointer: 0,
            stack_top: 0,
            stack_minimum: 0,
            stack_bottom: 0,
            event_count: 0,
            queue: 0,
            module_name: [0; TASKENTRY16_NAME_BYTES],
            psp_offset: 0,
            next: 0,
        }
    }
}

impl TaskEntry16 {
    pub const SIZE: usize = TASKENTRY16_SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> (u32, Self) {
        let wire = read_wire::<TaskEntry16Wire>(bytes);
        (
            wire.dw_size.get(),
            Self {
                task: wire.task.get(),
                parent_task: wire.parent_task.get(),
                instance: wire.instance.get(),
                module: wire.module.get(),
                stack_segment: wire.stack_segment.get(),
                stack_pointer: wire.stack_pointer.get(),
                stack_top: wire.stack_top.get(),
                stack_minimum: wire.stack_minimum.get(),
                stack_bottom: wire.stack_bottom.get(),
                event_count: wire.event_count.get(),
                queue: wire.queue.get(),
                module_name: wire.module_name,
                psp_offset: wire.psp_offset.get(),
                next: wire.next.get(),
            },
        )
    }

    pub fn encode_with_size(&self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(TaskEntry16Wire {
            dw_size: U32::new(dw_size),
            task: U16::new(self.task),
            parent_task: U16::new(self.parent_task),
            instance: U16::new(self.instance),
            module: U16::new(self.module),
            stack_segment: U16::new(self.stack_segment),
            stack_pointer: U16::new(self.stack_pointer),
            stack_top: U16::new(self.stack_top),
            stack_minimum: U16::new(self.stack_minimum),
            stack_bottom: U16::new(self.stack_bottom),
            event_count: U16::new(self.event_count),
            queue: U16::new(self.queue),
            module_name: self.module_name,
            psp_offset: U16::new(self.psp_offset),
            next: U16::new(self.next),
        })
    }
}

/// Fixed-width output for the Win16 `TIMERINFO` query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct TimerInfo16 {
    pub milliseconds_since_start: u32,
    pub milliseconds_this_vm: u32,
}

impl TimerInfo16 {
    pub const SIZE: usize = TIMERINFO16_SIZE;
    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(TimerInfo16Wire {
            dw_size: U32::new(dw_size),
            milliseconds_since_start: U32::new(self.milliseconds_since_start),
            milliseconds_this_vm: U32::new(self.milliseconds_this_vm),
        })
    }
}

/// Fixed-width output for Win16 `SYSTEMHEAPINFO`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct SystemHeapInfo16 {
    pub user_free_percent: u16,
    pub gdi_free_percent: u16,
    pub user_segment: u16,
    pub gdi_segment: u16,
}

impl SystemHeapInfo16 {
    pub const SIZE: usize = SYSHEAPINFO16_SIZE;
    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(SystemHeapInfo16Wire {
            dw_size: U32::new(dw_size),
            user_free_percent: U16::new(self.user_free_percent),
            gdi_free_percent: U16::new(self.gdi_free_percent),
            user_segment: U16::new(self.user_segment),
            gdi_segment: U16::new(self.gdi_segment),
        })
    }
}

/// Fixed-width output for Win16 `MEMMANINFO`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct MemManInfo16 {
    pub largest_free_block: u32,
    pub max_pages_available: u32,
    pub max_pages_lockable: u32,
    pub total_linear_space: u32,
    pub total_unlocked_pages: u32,
    pub free_pages: u32,
    pub total_pages: u32,
    pub free_linear_space: u32,
    pub swap_file_pages: u32,
    pub page_size: u16,
}

impl MemManInfo16 {
    pub const SIZE: usize = MEMMANINFO16_SIZE;
    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(MemManInfo16Wire {
            dw_size: U32::new(dw_size),
            largest_free_block: U32::new(self.largest_free_block),
            max_pages_available: U32::new(self.max_pages_available),
            max_pages_lockable: U32::new(self.max_pages_lockable),
            total_linear_space: U32::new(self.total_linear_space),
            total_unlocked_pages: U32::new(self.total_unlocked_pages),
            free_pages: U32::new(self.free_pages),
            total_pages: U32::new(self.total_pages),
            free_linear_space: U32::new(self.free_linear_space),
            swap_file_pages: U32::new(self.swap_file_pages),
            page_size: U16::new(self.page_size),
        })
    }
}

/// Fixed-width output for the Win16 `STACKTRACEENTRY` record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct StackTraceEntry16 {
    pub task: u16,
    pub stack_segment: u16,
    pub base_pointer: u16,
    pub code_segment: u16,
    pub instruction_pointer: u16,
    pub module: u16,
    pub segment: u16,
    pub flags: u16,
}

impl StackTraceEntry16 {
    pub const SIZE: usize = STACKTRACEENTRY16_SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> (u32, Self) {
        let wire = read_wire::<StackTraceEntry16Wire>(bytes);
        (
            wire.dw_size.get(),
            Self {
                task: wire.task.get(),
                stack_segment: wire.stack_segment.get(),
                base_pointer: wire.base_pointer.get(),
                code_segment: wire.code_segment.get(),
                instruction_pointer: wire.instruction_pointer.get(),
                module: wire.module.get(),
                segment: wire.segment.get(),
                flags: wire.flags.get(),
            },
        )
    }

    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(StackTraceEntry16Wire {
            dw_size: U32::new(dw_size),
            task: U16::new(self.task),
            stack_segment: U16::new(self.stack_segment),
            base_pointer: U16::new(self.base_pointer),
            code_segment: U16::new(self.code_segment),
            instruction_pointer: U16::new(self.instruction_pointer),
            module: U16::new(self.module),
            segment: U16::new(self.segment),
            flags: U16::new(self.flags),
        })
    }
}
