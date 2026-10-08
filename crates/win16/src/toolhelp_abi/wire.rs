//! Private byte-layout records for fixed Win16 TOOLHELP structures.
//!
//! The logical DTOs stay public and checked selector access remains outside
//! this module. These byte-aligned `zerocopy` records replace repeated offset
//! slicing while keeping Win16 little-endian widths independent of host ABI.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::enumeration::{
    CLASSENTRY16_NAME_BYTES, MEMMANINFO16_SIZE, MODULEENTRY16_NAME_BYTES, MODULEENTRY16_PATH_BYTES,
    STACKTRACEENTRY16_SIZE, SYSHEAPINFO16_SIZE, TASKENTRY16_NAME_BYTES, TIMERINFO16_SIZE,
    classentry16_offsets as class, localentry16_offsets as local_entry,
    memmaninfo16_offsets as memman, moduleentry16_offsets as module,
    stacktraceentry16_offsets as stack, taskentry16_offsets as task,
};
use super::{
    GLOBALENTRY16_SIZE, GLOBALINFO16_SIZE, LOCALENTRY16_SIZE, LOCALINFO16_SIZE,
    globalentry16_offsets as global, globalinfo16_offsets as global_info,
};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct GlobalEntry16Wire {
    pub(super) dw_size: U32,
    pub(super) address: U32,
    pub(super) block_size: U32,
    pub(super) block_handle: U16,
    pub(super) lock_count: U16,
    pub(super) page_lock_count: U16,
    pub(super) flags: U16,
    pub(super) heap_present: U16,
    pub(super) owner: U16,
    pub(super) block_type: U16,
    pub(super) data: U16,
    pub(super) next: U32,
    pub(super) next_alt: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct GlobalInfo16Wire {
    pub(super) dw_size: U32,
    pub(super) items: U16,
    pub(super) free_items: U16,
    pub(super) lru_items: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct LocalInfo16Wire {
    pub(super) dw_size: U32,
    pub(super) items: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct LocalEntry16Wire {
    pub(super) dw_size: U32,
    pub(super) handle: U16,
    pub(super) address: U16,
    pub(super) block_size: U16,
    pub(super) flags: U16,
    pub(super) lock_count: U16,
    pub(super) block_type: U16,
    pub(super) heap: U16,
    pub(super) heap_type: U16,
    pub(super) next: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct ModuleEntry16Wire {
    pub(super) dw_size: U32,
    pub(super) module_name: [u8; MODULEENTRY16_NAME_BYTES],
    pub(super) module_handle: U16,
    pub(super) usage_count: U16,
    pub(super) executable_path: [u8; MODULEENTRY16_PATH_BYTES],
    pub(super) next: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct ClassEntry16Wire {
    pub(super) dw_size: U32,
    pub(super) instance: U16,
    pub(super) class_name: [u8; CLASSENTRY16_NAME_BYTES],
    pub(super) next: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct TaskEntry16Wire {
    pub(super) dw_size: U32,
    pub(super) task: U16,
    pub(super) parent_task: U16,
    pub(super) instance: U16,
    pub(super) module: U16,
    pub(super) stack_segment: U16,
    pub(super) stack_pointer: U16,
    pub(super) stack_top: U16,
    pub(super) stack_minimum: U16,
    pub(super) stack_bottom: U16,
    pub(super) event_count: U16,
    pub(super) queue: U16,
    pub(super) module_name: [u8; TASKENTRY16_NAME_BYTES],
    pub(super) psp_offset: U16,
    pub(super) next: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct TimerInfo16Wire {
    pub(super) dw_size: U32,
    pub(super) milliseconds_since_start: U32,
    pub(super) milliseconds_this_vm: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct SystemHeapInfo16Wire {
    pub(super) dw_size: U32,
    pub(super) user_free_percent: U16,
    pub(super) gdi_free_percent: U16,
    pub(super) user_segment: U16,
    pub(super) gdi_segment: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct MemManInfo16Wire {
    pub(super) dw_size: U32,
    pub(super) largest_free_block: U32,
    pub(super) max_pages_available: U32,
    pub(super) max_pages_lockable: U32,
    pub(super) total_linear_space: U32,
    pub(super) total_unlocked_pages: U32,
    pub(super) free_pages: U32,
    pub(super) total_pages: U32,
    pub(super) free_linear_space: U32,
    pub(super) swap_file_pages: U32,
    pub(super) page_size: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct StackTraceEntry16Wire {
    pub(super) dw_size: U32,
    pub(super) task: U16,
    pub(super) stack_segment: U16,
    pub(super) base_pointer: U16,
    pub(super) code_segment: U16,
    pub(super) instruction_pointer: U16,
    pub(super) module: U16,
    pub(super) segment: U16,
    pub(super) flags: U16,
}

pub(super) fn read_wire<T>(bytes: &[u8]) -> T
where
    T: FromBytes + KnownLayout + Immutable + Unaligned,
{
    T::read_from_bytes(bytes)
        .unwrap_or_else(|_| unreachable!("fixed TOOLHELP byte array matches asserted wire size"))
}

pub(super) fn encode_wire<const N: usize, T: IntoBytes + Immutable>(value: T) -> [u8; N] {
    value
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!("TOOLHELP wire size is compile-time asserted"))
}

macro_rules! assert_wire_layout {
    ($wire:ty, $size:expr, {$($field:ident => $offset:expr),+ $(,)?}) => {
        const _: () = {
            assert!(core::mem::size_of::<$wire>() == $size);
            assert!(core::mem::align_of::<$wire>() == 1);
            $(assert!(core::mem::offset_of!($wire, $field) == $offset);)+
        };
    };
}

assert_wire_layout!(GlobalEntry16Wire, GLOBALENTRY16_SIZE, {
    dw_size => global::DW_SIZE, address => global::ADDRESS,
    block_size => global::BLOCK_SIZE, block_handle => global::BLOCK_HANDLE,
    lock_count => global::LOCK_COUNT, page_lock_count => global::PAGE_LOCK_COUNT,
    flags => global::FLAGS, heap_present => global::HEAP_PRESENT,
    owner => global::OWNER, block_type => global::BLOCK_TYPE, data => global::DATA,
    next => global::NEXT, next_alt => global::NEXT_ALT,
});
assert_wire_layout!(GlobalInfo16Wire, GLOBALINFO16_SIZE, {
    dw_size => global_info::DW_SIZE, items => global_info::ITEMS,
    free_items => global_info::FREE_ITEMS, lru_items => global_info::LRU_ITEMS,
});
assert_wire_layout!(LocalInfo16Wire, LOCALINFO16_SIZE, {
    dw_size => 0, items => 4,
});
assert_wire_layout!(LocalEntry16Wire, LOCALENTRY16_SIZE, {
    dw_size => local_entry::DW_SIZE, handle => local_entry::HANDLE,
    address => local_entry::ADDRESS, block_size => local_entry::BLOCK_SIZE,
    flags => local_entry::FLAGS, lock_count => local_entry::LOCK_COUNT,
    block_type => local_entry::BLOCK_TYPE, heap => local_entry::HEAP,
    heap_type => local_entry::HEAP_TYPE, next => local_entry::NEXT,
});
assert_wire_layout!(ModuleEntry16Wire, super::enumeration::MODULEENTRY16_SIZE, {
    dw_size => module::DW_SIZE, module_name => module::MODULE_NAME,
    module_handle => module::MODULE_HANDLE, usage_count => module::USAGE_COUNT,
    executable_path => module::EXECUTABLE_PATH, next => module::NEXT,
});
assert_wire_layout!(ClassEntry16Wire, super::enumeration::CLASSENTRY16_SIZE, {
    dw_size => class::DW_SIZE, instance => class::INSTANCE,
    class_name => class::CLASS_NAME, next => class::NEXT,
});
assert_wire_layout!(TaskEntry16Wire, super::enumeration::TASKENTRY16_SIZE, {
    dw_size => task::DW_SIZE, task => task::TASK, parent_task => task::PARENT_TASK,
    instance => task::INSTANCE, module => task::MODULE,
    stack_segment => task::STACK_SEGMENT, stack_pointer => task::STACK_POINTER,
    stack_top => task::STACK_TOP, stack_minimum => task::STACK_MINIMUM,
    stack_bottom => task::STACK_BOTTOM, event_count => task::EVENT_COUNT,
    queue => task::QUEUE, module_name => task::MODULE_NAME,
    psp_offset => task::PSP_OFFSET, next => task::NEXT,
});
assert_wire_layout!(TimerInfo16Wire, TIMERINFO16_SIZE, {
    dw_size => 0, milliseconds_since_start => 4, milliseconds_this_vm => 8,
});
assert_wire_layout!(SystemHeapInfo16Wire, SYSHEAPINFO16_SIZE, {
    dw_size => 0, user_free_percent => 4, gdi_free_percent => 6,
    user_segment => 8, gdi_segment => 10,
});
assert_wire_layout!(MemManInfo16Wire, MEMMANINFO16_SIZE, {
    dw_size => memman::DW_SIZE, largest_free_block => memman::LARGEST_FREE_BLOCK,
    max_pages_available => memman::MAX_PAGES_AVAILABLE,
    max_pages_lockable => memman::MAX_PAGES_LOCKABLE,
    total_linear_space => memman::TOTAL_LINEAR_SPACE,
    total_unlocked_pages => memman::TOTAL_UNLOCKED_PAGES,
    free_pages => memman::FREE_PAGES, total_pages => memman::TOTAL_PAGES,
    free_linear_space => memman::FREE_LINEAR_SPACE,
    swap_file_pages => memman::SWAP_FILE_PAGES, page_size => memman::PAGE_SIZE,
});
assert_wire_layout!(StackTraceEntry16Wire, STACKTRACEENTRY16_SIZE, {
    dw_size => stack::DW_SIZE, task => stack::TASK,
    stack_segment => stack::STACK_SEGMENT, base_pointer => stack::BASE_POINTER,
    code_segment => stack::CODE_SEGMENT, instruction_pointer => stack::INSTRUCTION_POINTER,
    module => stack::MODULE, segment => stack::SEGMENT, flags => stack::FLAGS,
});
