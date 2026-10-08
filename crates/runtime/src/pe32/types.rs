//! PE32 guest identities, module metadata, and staged-operation results.

use super::identity::{Pe32ModuleIdentity, Pe32ProcedureToken, Pe32TypedHostServiceId};

/// Opaque transaction identity for a set of images linked before publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Pe32LoadGroupId(pub(super) u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32GuestAddress(pub(crate) u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32GuestImage {
    /// Identifies the allocator instance in addition to its local allocation
    /// id and generation; a different PE32 arena can never satisfy retirement.
    pub(super) arena_id: u64,
    pub(crate) base: Pe32GuestAddress,
    pub(crate) size: u32,
    /// The allocator's identity is retained so a reused range cannot satisfy
    /// retirement of an older mapping.
    pub(crate) allocation_id: u64,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32RvaRange {
    pub(crate) start: u32,
    pub(crate) size: u32,
    pub(crate) executable: bool,
}

/// PE section protection metadata retained for a later CPU/Memory permission
/// layer. Current execution confines fetches to executable ranges but does
/// not claim per-section read/write page enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32SectionProtection {
    pub(super) rva: u32,
    pub(super) size: u32,
    pub(super) characteristics: u32,
    pub(super) read: bool,
    pub(super) write: bool,
    pub(super) execute: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Pe32ImportSymbol {
    Name { hint: u16, name: Vec<u8> },
    Ordinal(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pe32ImportSite {
    pub(super) iat_rva: u32,
    pub(super) module: Vec<u8>,
    pub(super) symbol: Pe32ImportSymbol,
    pub(super) delayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Pe32ExportTarget {
    Rva(u32),
    Forwarder {
        module: Vec<u8>,
        symbol: Pe32ImportSymbol,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pe32ExportRecord {
    pub(super) ordinal: u32,
    pub(super) names: Vec<Vec<u8>>,
    pub(super) target: Pe32ExportTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pe32ModuleSpec {
    pub(super) name: Vec<u8>,
    pub(super) image: Pe32GuestImage,
    pub(super) is_dll: bool,
    pub(super) entry_rva: Option<u32>,
    pub(super) has_tls: bool,
    pub(super) loader_directories: Vec<Pe32LoaderDirectory>,
    pub(super) sections: Vec<Pe32SectionProtection>,
    pub(super) executable_ranges: Vec<Pe32RvaRange>,
    pub(super) imports: Vec<Pe32ImportSite>,
    pub(super) exports: Vec<Pe32ExportRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32ModuleStage {
    Prepared,
    Mapped,
    Linked,
    Initializing,
    Initialized,
    Published,
    Retiring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32CallReason {
    Export,
    ProcessAttach,
    ProcessDetach,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Pe32LoaderDirectoryKind {
    Export,
    Import,
    Resource,
    Exception,
    Security,
    BaseRelocation,
    Debug,
    Architecture,
    GlobalPointer,
    Tls,
    LoadConfig,
    BoundImport,
    Iat,
    DelayImport,
    ClrRuntimeHeader,
    Reserved,
    Other(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32LoaderDirectoryAddressKind {
    ImageRva,
    FileOffset,
}

/// Runtime-owned metadata lets each loader requirement stay explicit without
/// retaining formats-library objects past the validation adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32LoaderDirectory {
    pub(super) kind: Pe32LoaderDirectoryKind,
    pub(super) address_kind: Pe32LoaderDirectoryAddressKind,
    pub(super) address: u32,
    pub(super) size: u32,
}

/// Executable targets for guest call leases. System services use the distinct
/// `Pe32ImportTarget::TypedHostService` gate route and never become call frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32CallableTarget {
    GuestCode {
        address: Pe32GuestAddress,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Pe32ExportKey {
    Name(Vec<u8>),
    Ordinal(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Pe32SymbolResult {
    /// Runtime identity only; callers must not expose it as an x86 code pointer
    /// until a guest thunk/address bridge exists.
    Procedure(Pe32ProcedureToken),
    Data {
        module: Pe32ModuleIdentity,
        address: Pe32GuestAddress,
    },
    Forwarder {
        module: Vec<u8>,
        symbol: Pe32ImportSymbol,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32ImportTarget {
    Procedure(Pe32ProcedureToken),
    Data {
        module: Pe32ModuleIdentity,
        address: Pe32GuestAddress,
    },
    /// A runtime-owned UD2 service gate. The address is checked against the
    /// task gate table before each instruction fetch; it is never native code.
    TypedHostService {
        service_id: Pe32TypedHostServiceId,
        address: Pe32GuestAddress,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32ImportBinding<'a> {
    pub(super) site: &'a Pe32ImportSite,
    pub(super) target: Pe32ImportTarget,
}

impl<'a> Pe32ImportBinding<'a> {
    pub(crate) const fn new(site: &'a Pe32ImportSite, target: Pe32ImportTarget) -> Self {
        Self { site, target }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pe32IatWrite {
    pub(super) rva: u32,
    pub(super) value: u32,
}

impl Pe32IatWrite {
    pub(crate) const fn rva(&self) -> u32 {
        self.rva
    }
    pub(crate) const fn value(&self) -> u32 {
        self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pe32LinkPlan {
    pub(super) module: Pe32ModuleIdentity,
    pub(super) dependencies: Vec<Pe32ModuleIdentity>,
    pub(super) writes: Vec<Pe32IatWrite>,
}

impl Pe32LinkPlan {
    pub(crate) const fn module(&self) -> Pe32ModuleIdentity {
        self.module
    }
    pub(crate) fn dependencies(&self) -> &[Pe32ModuleIdentity] {
        &self.dependencies
    }
    pub(crate) fn writes(&self) -> &[Pe32IatWrite] {
        &self.writes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32RetirementInfo {
    pub(super) module: Pe32ModuleIdentity,
    pub(super) image: Pe32GuestImage,
    pub(super) mapped: bool,
}

impl Pe32RetirementInfo {
    pub(crate) const fn module(self) -> Pe32ModuleIdentity {
        self.module
    }
    pub(crate) const fn image(self) -> Pe32GuestImage {
        self.image
    }
}
