//! Typed KERNEL global-heap API arguments.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelGlobalHeapRequest {
    GlobalFreeAll { owner: u16 },
    GlobalReAlloc { handle: u16, size: u32, flags: u16 },
    GlobalFlags { handle: u16 },
    GlobalCompact { minimum_free: u32 },
    GlobalFix { handle: u16 },
    GlobalUnfix { handle: u16 },
    GlobalPageLock { handle: u16 },
    GlobalPageUnlock { handle: u16 },
    FarSetOwner { handle: u16, owner: u16 },
    FarGetOwner { handle: u16 },
    GlobalLruOldest { handle: u16 },
    GlobalLruNewest { handle: u16 },
    GlobalDosAlloc { size: u32 },
    GlobalDosFree { selector: u16 },
    GlobalMasterHandle,
    GlobalChangeLockCount { handle: u16, delta: i16 },
    GlobalWire { handle: u16 },
    GlobalUnWire { handle: u16 },
    LockSegment { segment: u16 },
    UnlockSegment { segment: u16 },
    GetFreeSpace { flags: u16 },
}
