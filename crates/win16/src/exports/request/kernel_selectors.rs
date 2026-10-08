//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelSelectorsRequest {
    /// Allocate an independent selector descriptor, copying a valid source
    /// selector or reserving an uninitialized descriptor for a null source.
    AllocSelector { source_selector: u16 },

    /// Allocate a guest selector alias with data access for the supplied code
    /// selector. The source remains a guest selector ID, never a host pointer.
    AllocCStoDSAlias { source_selector: u16 },

    /// Allocate an executable alias of a checked fixed data segment.
    AllocDStoCSAlias { source_selector: u16 },

    /// Historical spelling of AllocCStoDSAlias (KERNEL.172).
    AllocAlias { source_selector: u16 },

    /// Release a runtime-owned temporary guest selector after validating its
    /// handle and allocation state. This value is not a host pointer.
    FreeSelector { selector: u16 },

    /// Convert the destination guest selector to the opposite code/data kind
    /// while preserving the source selector's guest descriptor. Selector
    /// values remain guest IDs and are validated by the runtime; they are not
    /// host pointers.
    PrestoChangoSelector {
        source_selector: u16,
        destination_selector: u16,
    },

    GetSelectorBase { selector: u16 },
    SetSelectorBase { selector: u16, base: u32 },
    GetSelectorLimit { selector: u16 },
    SetSelectorLimit { selector: u16, limit: u32 },
    SelectorAccessRights { selector: u16, operation: u16, access: u16 },
    AllocSelectorArray { count: u16 },
    LongPtrAdd { far_pointer: u32, amount: u32 },
    IsSharedSelector { selector: u16 },
    MapSL { far_pointer: u32 },
    MapLS { guest_linear: u32 },
    UnMapLS { far_pointer: u32 },
}
