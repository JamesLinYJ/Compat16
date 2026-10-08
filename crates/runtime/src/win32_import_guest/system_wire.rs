//! Fixed PE32 SYSTEM_INFO wire layout, independent of native pointer width.

use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};
use zerocopy::byteorder::{LittleEndian, U16, U32};

// These are the Windows SDK processor identifiers, not CPU model numbers.
pub(super) const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
pub(super) const PROCESSOR_INTEL_486: u32 = 486;
pub(super) const PROCESSOR_INTEL_PENTIUM: u32 = 586;

#[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct SystemInfo32 {
    pub(super) architecture: U16<LittleEndian>,
    pub(super) reserved: U16<LittleEndian>,
    pub(super) page_size: U32<LittleEndian>,
    pub(super) minimum_address: U32<LittleEndian>,
    pub(super) maximum_address: U32<LittleEndian>,
    pub(super) active_processor_mask: U32<LittleEndian>,
    pub(super) processor_count: U32<LittleEndian>,
    pub(super) processor_type: U32<LittleEndian>,
    pub(super) allocation_granularity: U32<LittleEndian>,
    pub(super) processor_level: U16<LittleEndian>,
    pub(super) processor_revision: U16<LittleEndian>,
}

impl SystemInfo32 {
    pub(super) const BYTE_LEN: usize = core::mem::size_of::<Self>();
}

const _: () = {
    assert!(SystemInfo32::BYTE_LEN == 36);
    assert!(core::mem::align_of::<SystemInfo32>() == 1);
    assert!(core::mem::offset_of!(SystemInfo32, architecture) == 0);
    assert!(core::mem::offset_of!(SystemInfo32, reserved) == 2);
    assert!(core::mem::offset_of!(SystemInfo32, page_size) == 4);
    assert!(core::mem::offset_of!(SystemInfo32, minimum_address) == 8);
    assert!(core::mem::offset_of!(SystemInfo32, maximum_address) == 12);
    assert!(core::mem::offset_of!(SystemInfo32, active_processor_mask) == 16);
    assert!(core::mem::offset_of!(SystemInfo32, processor_count) == 20);
    assert!(core::mem::offset_of!(SystemInfo32, processor_type) == 24);
    assert!(core::mem::offset_of!(SystemInfo32, allocation_granularity) == 28);
    assert!(core::mem::offset_of!(SystemInfo32, processor_level) == 32);
    assert!(core::mem::offset_of!(SystemInfo32, processor_revision) == 34);
};
