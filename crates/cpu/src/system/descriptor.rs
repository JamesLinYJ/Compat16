use guest_core::LinearAddr;

use super::CpuFault;

/// A cached view of an IA-32 segment descriptor's architected fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentDescriptor {
    pub(crate) base: u32,
    pub(crate) limit: u32,
    pub(crate) dpl: u8,
    pub(crate) present: bool,
    pub(crate) default_big: bool,
    pub(crate) granularity: bool,
    pub(crate) available: bool,
    pub(crate) long_mode: bool,
    pub(crate) descriptor_type: DescriptorType,
}

/// Code/data type bits are decoded explicitly; system descriptors retain their
/// type nibble for callers that implement gates, TSS, or LDT state later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DescriptorType {
    Data {
        writable: bool,
        expand_down: bool,
        accessed: bool,
    },
    Code {
        readable: bool,
        conforming: bool,
        accessed: bool,
    },
    System {
        system_type: u8,
    },
}

/// The operation being checked against a cached segment descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SegmentAccess {
    InstructionFetch,
    Read,
    Write,
    StackRead,
    StackWrite,
}

/// GDTR/LDTR-compatible table bounds. The base is a guest linear address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SegmentTableRegister {
    pub(crate) base: LinearAddr,
    /// Effective byte limit; an LDT descriptor can supply all 20 bits.
    pub(crate) limit: u32,
}

impl SegmentTableRegister {
    /// Resolve a selector to the linear address of its eight-byte descriptor.
    ///
    /// The caller selects the GDT or LDT first and handles null selectors
    /// according to the segment register being loaded.
    pub(crate) fn descriptor_address(&self, selector: u16) -> Result<LinearAddr, CpuFault> {
        let offset = u32::from(selector & 0xfff8);
        let end = offset + 7;
        if end > self.limit {
            return Err(CpuFault::general_protection(selector_error_code(selector)));
        }
        let address = self
            .base
            .0
            .checked_add(offset)
            .map(LinearAddr)
            .ok_or_else(|| CpuFault::general_protection(selector_error_code(selector)))?;
        address
            .0
            .checked_add(7)
            .map(LinearAddr)
            .ok_or_else(|| CpuFault::general_protection(selector_error_code(selector)))?;
        Ok(address)
    }
}

impl SegmentDescriptor {
    /// Decode one little-endian 64-bit code/data or system descriptor.
    pub(crate) fn parse(raw: u64) -> Self {
        let encoded_limit = ((raw & 0xffff) | (((raw >> 48) & 0x0f) << 16)) as u32;
        let granularity = raw & (1 << 55) != 0;
        let limit = if granularity {
            (encoded_limit << 12) | 0x0fff
        } else {
            encoded_limit
        };
        let base = (((raw >> 16) & 0xffff) as u32)
            | ((((raw >> 32) & 0xff) as u32) << 16)
            | ((((raw >> 56) & 0xff) as u32) << 24);
        let access = ((raw >> 40) & 0xff) as u8;
        let access_type = access & 0x0f;
        let system = access & 0x10 == 0;
        let descriptor_type = if system {
            DescriptorType::System {
                system_type: access_type,
            }
        } else if access_type & 0x08 == 0 {
            DescriptorType::Data {
                writable: access_type & 0x02 != 0,
                expand_down: access_type & 0x04 != 0,
                accessed: access_type & 0x01 != 0,
            }
        } else {
            DescriptorType::Code {
                conforming: access_type & 0x04 != 0,
                readable: access_type & 0x02 != 0,
                accessed: access_type & 0x01 != 0,
            }
        };

        Self {
            base,
            limit,
            dpl: (access >> 5) & 0x03,
            present: access & 0x80 != 0,
            default_big: raw & (1 << 54) != 0,
            granularity,
            available: raw & (1 << 52) != 0,
            long_mode: raw & (1 << 53) != 0,
            descriptor_type,
        }
    }

    /// Build the cached fields supplied by a machine owner at an explicit
    /// mode boundary. `limit` is already expanded when the descriptor used
    /// page granularity; no host pointer or packed compiler layout is involved.
    pub(crate) fn from_cache_fields(base: u32, limit: u32, access: u8, flags: u8) -> Option<Self> {
        let system = access & 0x10 == 0;
        let kind = access & 0x0f;
        let descriptor_type = if system {
            DescriptorType::System { system_type: kind }
        } else if kind & 0x08 == 0 {
            DescriptorType::Data {
                writable: kind & 0x02 != 0,
                expand_down: kind & 0x04 != 0,
                accessed: kind & 0x01 != 0,
            }
        } else {
            DescriptorType::Code {
                readable: kind & 0x02 != 0,
                conforming: kind & 0x04 != 0,
                accessed: kind & 0x01 != 0,
            }
        };
        Some(Self {
            base,
            limit,
            dpl: (access >> 5) & 3,
            present: access & 0x80 != 0,
            default_big: flags & 0x40 != 0,
            granularity: flags & 0x80 != 0,
            available: flags & 0x10 != 0,
            long_mode: flags & 0x20 != 0,
            descriptor_type,
        })
    }

    pub(crate) fn cache_fields(self) -> (u8, u8) {
        let kind = match self.descriptor_type {
            DescriptorType::Data {
                writable,
                expand_down,
                accessed,
            } => u8::from(writable) << 1 | u8::from(expand_down) << 2 | u8::from(accessed),
            DescriptorType::Code {
                readable,
                conforming,
                accessed,
            } => 0x08 | u8::from(readable) << 1 | u8::from(conforming) << 2 | u8::from(accessed),
            DescriptorType::System { system_type } => system_type & 0x0f,
        };
        let system = !matches!(
            self.descriptor_type,
            DescriptorType::Data { .. } | DescriptorType::Code { .. }
        );
        let access = kind
            | if system { 0 } else { 0x10 }
            | (self.dpl & 3) << 5
            | if self.present { 0x80 } else { 0 };
        let flags = if self.granularity { 0x80 } else { 0 }
            | if self.default_big { 0x40 } else { 0 }
            | if self.long_mode { 0x20 } else { 0 }
            | if self.available { 0x10 } else { 0 };
        (access, flags)
    }

    /// Validate type, privilege, presence, and the complete byte range.
    ///
    /// `cpl` and `rpl` are privilege levels in the range 0 through 3. The
    /// caller supplies the effective offset after address-size wrapping. This
    /// function checks every byte of a multi-byte access without translating
    /// any linear addresses; callers must still resolve each covered page.
    pub(crate) fn check_access(
        &self,
        selector: u16,
        access: SegmentAccess,
        cpl: u8,
        rpl: u8,
        offset: u32,
        size: usize,
    ) -> Result<(), CpuFault> {
        let error_code = selector_error_code(selector);
        // A usable real-mode hidden cache can retain selector zero across a
        // CR0.PE transition. NULL rejection belongs to selector-load/query
        // operations, not to access through an already-loaded cache.
        if cpl > 3 || rpl > 3 {
            return Err(CpuFault::general_protection(error_code));
        }

        self.check_type_and_privilege(access, cpl, rpl, error_code)?;
        if !self.present {
            return Err(match access {
                SegmentAccess::StackRead | SegmentAccess::StackWrite => {
                    CpuFault::stack_segment(error_code)
                }
                _ => CpuFault::segment_not_present(error_code),
            });
        }
        self.check_range(access, offset, size)
    }

    pub(crate) fn validate_data_load(&self, selector: u16, cpl: u8) -> Result<(), CpuFault> {
        let error_code = selector_error_code(selector);
        let privilege_ok = match self.descriptor_type {
            DescriptorType::Data { .. } => cpl.max((selector & 3) as u8) <= self.dpl,
            DescriptorType::Code {
                readable: true,
                conforming: false,
                ..
            } => cpl.max((selector & 3) as u8) <= self.dpl,
            DescriptorType::Code {
                readable: true,
                conforming: true,
                ..
            } => true,
            _ => false,
        };
        if !privilege_ok {
            return Err(CpuFault::general_protection(error_code));
        }
        if !self.present {
            return Err(CpuFault::segment_not_present(error_code));
        }
        Ok(())
    }

    pub(crate) fn validate_stack_load(&self, selector: u16, cpl: u8) -> Result<(), CpuFault> {
        let error_code = selector_error_code(selector);
        if selector & 3 != u16::from(cpl)
            || self.dpl != cpl
            || !matches!(
                self.descriptor_type,
                DescriptorType::Data { writable: true, .. }
            )
        {
            return Err(CpuFault::general_protection(error_code));
        }
        if !self.present {
            return Err(CpuFault::stack_segment(error_code));
        }
        Ok(())
    }

    /// Validate a non-gate far transfer to code without changing privilege.
    pub(crate) fn validate_direct_code_transfer(
        &self,
        selector: u16,
        cpl: u8,
    ) -> Result<u8, CpuFault> {
        let error_code = selector_error_code(selector);
        let DescriptorType::Code { conforming, .. } = self.descriptor_type else {
            return Err(CpuFault::general_protection(error_code));
        };
        let rpl = (selector & 3) as u8;
        if conforming {
            if self.dpl > cpl {
                return Err(CpuFault::general_protection(error_code));
            }
        } else if self.dpl != cpl || rpl > cpl {
            return Err(CpuFault::general_protection(error_code));
        }
        if !self.present {
            return Err(CpuFault::segment_not_present(error_code));
        }
        Ok(cpl)
    }

    pub(crate) fn validate_code_return(&self, selector: u16, cpl: u8) -> Result<u8, CpuFault> {
        let error_code = selector_error_code(selector);
        let DescriptorType::Code { conforming, .. } = self.descriptor_type else {
            return Err(CpuFault::general_protection(error_code));
        };
        let rpl = (selector & 3) as u8;
        if rpl < cpl || (conforming && self.dpl > rpl) || (!conforming && self.dpl != rpl) {
            return Err(CpuFault::general_protection(error_code));
        }
        if !self.present {
            return Err(CpuFault::segment_not_present(error_code));
        }
        Ok(rpl)
    }

    pub(crate) fn permits_selector_query(&self, selector: u16, cpl: u8) -> bool {
        let rpl = (selector & 3) as u8;
        match self.descriptor_type {
            // LAR/LSL exempt conforming code from selector DPL/RPL checks,
            // regardless of whether the descriptor is readable. Data access
            // and CS execution use their separate privilege checks.
            DescriptorType::Code { conforming: true, .. } => true,
            _ => cpl.max(rpl) <= self.dpl,
        }
    }

    pub(crate) fn is_readable_segment(&self) -> bool {
        matches!(
            self.descriptor_type,
            DescriptorType::Data { .. } | DescriptorType::Code { readable: true, .. }
        )
    }

    pub(crate) fn is_writable_data(&self) -> bool {
        matches!(
            self.descriptor_type,
            DescriptorType::Data { writable: true, .. }
        )
    }

    fn check_type_and_privilege(
        &self,
        access: SegmentAccess,
        cpl: u8,
        rpl: u8,
        error_code: u32,
    ) -> Result<(), CpuFault> {
        use DescriptorType::{Code, Data};
        use SegmentAccess::{InstructionFetch, Read, StackRead, StackWrite, Write};

        let privilege_violation = match (access, self.descriptor_type) {
            (
                InstructionFetch,
                Code {
                    conforming: true, ..
                },
            ) => false,
            (
                InstructionFetch,
                Code {
                    conforming: false, ..
                },
            ) => self.dpl != cpl || rpl > cpl,
            (Read | Write, Data { .. }) => self.dpl < cpl.max(rpl),
            (
                Read,
                Code {
                    conforming: true, ..
                },
            ) => false,
            (
                Read,
                Code {
                    conforming: false, ..
                },
            ) => self.dpl < cpl.max(rpl),
            (StackRead | StackWrite, Data { .. }) => self.dpl != cpl || rpl != cpl,
            _ => true,
        };
        if privilege_violation {
            return Err(CpuFault::general_protection(error_code));
        }

        let type_allowed = match (access, self.descriptor_type) {
            (InstructionFetch, Code { .. }) => true,
            (Read, Data { .. }) => true,
            (Read, Code { readable: true, .. }) => true,
            (Write, Data { writable: true, .. }) => true,
            (StackRead, Data { writable: true, .. }) => true,
            (StackWrite, Data { writable: true, .. }) => true,
            _ => false,
        };
        if !type_allowed {
            return Err(CpuFault::general_protection(error_code));
        }
        Ok(())
    }

    fn check_range(&self, access: SegmentAccess, offset: u32, size: usize) -> Result<(), CpuFault> {
        let end_exclusive = u64::from(offset)
            .checked_add(u64::try_from(size).unwrap_or(u64::MAX))
            .filter(|end| *end <= u64::from(u32::MAX) + 1);
        let Some(end_exclusive) = end_exclusive else {
            return Err(self.range_fault(access));
        };

        let expand_down = matches!(
            self.descriptor_type,
            DescriptorType::Data {
                expand_down: true,
                ..
            }
        );
        if expand_down {
            let lower = u64::from(self.limit) + 1;
            let upper = if self.default_big {
                u64::from(u32::MAX)
            } else {
                u64::from(u16::MAX)
            };
            if u64::from(offset) < lower || end_exclusive > upper + 1 {
                return Err(self.range_fault(access));
            }
        } else if end_exclusive > u64::from(self.limit) + 1 {
            return Err(self.range_fault(access));
        }
        Ok(())
    }

    fn range_fault(&self, access: SegmentAccess) -> CpuFault {
        match access {
            SegmentAccess::StackRead | SegmentAccess::StackWrite => CpuFault::stack_segment(0),
            _ => CpuFault::general_protection(0),
        }
    }
}

fn selector_error_code(selector: u16) -> u32 {
    if selector & 0xfffc == 0 {
        0
    } else {
        u32::from(selector & 0xfffc)
    }
}
