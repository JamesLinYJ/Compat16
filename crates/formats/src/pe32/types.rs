use core::fmt;

/// Failure to parse or construct a bounded PE32 guest image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pe32Error {
    /// The image violates a checked PE or guest-image invariant.
    InvalidImage(&'static str),
    /// The image uses a valid PE feature this guest loader does not implement.
    Unsupported(&'static str),
    /// The PE machine is not 32-bit x86.
    UnsupportedMachine(u16),
    /// A fallible allocation failed while owning image metadata or bytes.
    OutOfMemory(&'static str),
    /// The image exceeds the caller's explicit memory budget.
    ImageTooLarge { size: u32, maximum: u32 },
    /// The selected base cannot represent the image in the PE32 address space.
    InvalidLoadBase(&'static str),
    /// The image needs rebasing but has no usable base-relocation entries.
    RelocationsUnavailable,
    /// Rebasing requires a relocation operation outside the implemented set.
    UnsupportedRelocation {
        /// PE base-relocation type code.
        kind: u16,
        /// Relocation target RVA.
        target_rva: u32,
    },
}

impl fmt::Display for Pe32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidImage(context) => write!(f, "invalid PE32 image: {context}"),
            Self::Unsupported(context) => write!(f, "unsupported PE32 feature: {context}"),
            Self::UnsupportedMachine(machine) => {
                write!(f, "unsupported PE32 machine {machine:#06x}; expected I386")
            }
            Self::OutOfMemory(context) => write!(f, "allocation failed while {context}"),
            Self::ImageTooLarge { size, maximum } => {
                write!(f, "PE32 image size {size:#x} exceeds limit {maximum:#x}")
            }
            Self::InvalidLoadBase(context) => write!(f, "invalid PE32 load base: {context}"),
            Self::RelocationsUnavailable => {
                f.write_str("PE32 image cannot be rebased without base relocations")
            }
            Self::UnsupportedRelocation { kind, target_rva } => write!(
                f,
                "unsupported PE32 relocation kind {kind} at RVA {target_rva:#x}"
            ),
        }
    }
}

impl std::error::Error for Pe32Error {}

/// An owned PE32 image parsed from a file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32Image {
    pub(super) machine: u16,
    pub(super) preferred_base: u32,
    pub(super) image_size: u32,
    pub(super) header_size: u32,
    pub(super) section_alignment: u32,
    pub(super) entry_rva: Option<u32>,
    pub(super) is_dll: bool,
    pub(super) subsystem: u16,
    pub(super) sections: Vec<Pe32Section>,
    pub(super) header_bytes: Vec<u8>,
    pub(super) imports: Vec<Pe32ImportModule>,
    pub(super) exports: Vec<Pe32Export>,
    pub(super) data_directories: Vec<Pe32DataDirectory>,
    pub(super) relocations: Vec<Pe32Relocation>,
    pub(super) has_relocation_directory: bool,
    pub(super) relocations_stripped: bool,
    pub(super) tls: Option<Pe32TlsMetadata>,
}

impl Pe32Image {
    /// COFF machine code. This reader accepts only I386 (`0x014c`).
    pub fn machine(&self) -> u16 {
        self.machine
    }

    /// Preferred 32-bit image base from the optional header.
    pub fn preferred_base(&self) -> u32 {
        self.preferred_base
    }

    /// Declared guest image size, including headers and zero-filled section tails.
    pub fn image_size(&self) -> u32 {
        self.image_size
    }

    /// Section alignment used by the image.
    pub fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    /// Entry-point RVA, or `None` when the optional header declares zero.
    pub fn entry_rva(&self) -> Option<u32> {
        self.entry_rva
    }

    /// Whether the COFF characteristics identify a DLL image.
    pub fn is_dll(&self) -> bool {
        self.is_dll
    }

    /// PE subsystem value, preserved without interpreting newer values.
    pub fn subsystem(&self) -> u16 {
        self.subsystem
    }

    /// Owned section metadata and raw bytes.
    pub fn sections(&self) -> &[Pe32Section] {
        &self.sections
    }

    /// Unresolved regular and delay-load import descriptors.
    pub fn imports(&self) -> &[Pe32ImportModule] {
        &self.imports
    }

    /// Export address table entries. PE does not identify function versus data exports.
    pub fn exports(&self) -> &[Pe32Export] {
        &self.exports
    }

    /// All populated data directories, including metadata whose loader semantics
    /// the current runtime has not implemented.
    pub fn data_directories(&self) -> &[Pe32DataDirectory] {
        &self.data_directories
    }

    /// Base-relocation entries retained from the image.
    pub fn relocations(&self) -> &[Pe32Relocation] {
        &self.relocations
    }

    /// TLS directory metadata, if present. Addresses retain their documented RVA/VA identity.
    pub fn tls(&self) -> Option<&Pe32TlsMetadata> {
        self.tls.as_ref()
    }
}

/// One section's owned file bytes and validated virtual range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32Section {
    pub(super) name: Vec<u8>,
    pub(super) rva: u32,
    pub(super) virtual_size: u32,
    pub(super) raw_file_offset: u32,
    pub(super) raw_size: u32,
    pub(super) characteristics: u32,
    pub(super) raw_data: Vec<u8>,
}

impl Pe32Section {
    /// The section name with trailing NUL padding removed.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Section start RVA.
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Declared in-memory section size; its remainder beyond raw bytes is zero-filled.
    pub fn virtual_size(&self) -> u32 {
        self.virtual_size
    }

    /// File offset of this section's raw bytes.
    pub fn raw_file_offset(&self) -> u32 {
        self.raw_file_offset
    }

    /// Declared raw-data byte count.
    pub fn raw_size(&self) -> u32 {
        self.raw_size
    }

    /// PE section characteristics, including unknown bits.
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    /// The exact bytes in the section's validated file range.
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Whether the section is marked executable by the PE section characteristics.
    pub fn is_executable(&self) -> bool {
        self.characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE.0 != 0
    }
}

/// Import descriptor kind and delay-import pointer metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pe32ImportKind {
    /// An `IMAGE_DIRECTORY_ENTRY_IMPORT` descriptor.
    Normal,
    /// A delay-load descriptor. Its table addresses are normalized to RVAs.
    Delay(Pe32DelayImportMetadata),
}

/// Additional delay-load descriptor values needed by a later guest linker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32DelayImportMetadata {
    pub(super) attributes: u32,
    pub(super) module_handle_rva: Option<u32>,
    pub(super) bound_iat_rva: Option<u32>,
    pub(super) unload_iat_rva: Option<u32>,
    pub(super) timestamp: u32,
}

impl Pe32DelayImportMetadata {
    /// Original delay-load attribute bits.
    pub fn attributes(&self) -> u32 {
        self.attributes
    }

    /// Module-handle storage RVA, if present.
    pub fn module_handle_rva(&self) -> Option<u32> {
        self.module_handle_rva
    }

    /// Optional bound IAT RVA.
    pub fn bound_iat_rva(&self) -> Option<u32> {
        self.bound_iat_rva
    }

    /// Optional unload IAT RVA.
    pub fn unload_iat_rva(&self) -> Option<u32> {
        self.unload_iat_rva
    }

    /// Delay-import timestamp, preserved as stored.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

/// One imported module and its unresolved symbols.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32ImportModule {
    pub(super) kind: Pe32ImportKind,
    pub(super) name: Vec<u8>,
    pub(super) symbols: Vec<Pe32ImportSymbol>,
}

impl Pe32ImportModule {
    /// Normal or delay-load descriptor kind.
    pub fn kind(&self) -> &Pe32ImportKind {
        &self.kind
    }

    /// DLL module name as NUL-free bytes from the file.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Imported symbols and their IAT slot RVAs.
    pub fn symbols(&self) -> &[Pe32ImportSymbol] {
        &self.symbols
    }
}

/// One unresolved import and the guest IAT slot that will receive its address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32ImportSymbol {
    pub(super) iat_rva: u32,
    pub(super) target: Pe32ImportTarget,
}

impl Pe32ImportSymbol {
    /// IAT slot RVA.
    pub fn iat_rva(&self) -> u32 {
        self.iat_rva
    }

    /// Import-by-name or import-by-ordinal identity.
    pub fn target(&self) -> &Pe32ImportTarget {
        &self.target
    }
}

/// An unresolved PE import identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pe32ImportTarget {
    /// Import by name and hint.
    Name {
        /// Export-name hint from `IMAGE_IMPORT_BY_NAME`.
        hint: u16,
        /// NUL-free symbol-name bytes.
        name: Vec<u8>,
    },
    /// Import by ordinal.
    Ordinal(u16),
}

/// One non-hole export address-table entry, grouped with every associated name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32Export {
    pub(super) ordinal: u16,
    pub(super) names: Vec<Vec<u8>>,
    pub(super) target: Pe32ExportTarget,
}

impl Pe32Export {
    /// Export ordinal.
    pub fn ordinal(&self) -> u16 {
        self.ordinal
    }

    /// All name aliases associated with the ordinal; empty means ordinal-only.
    pub fn names(&self) -> &[Vec<u8>] {
        &self.names
    }

    /// Local image RVA or forwarder identity.
    pub fn target(&self) -> &Pe32ExportTarget {
        &self.target
    }
}

/// An export's address-table target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pe32ExportTarget {
    /// Address within this image. It is not classified as function or data.
    ImageRva(u32),
    /// Forwarded to another module's name or ordinal.
    Forwarder {
        /// NUL-free module-name bytes.
        module: Vec<u8>,
        /// The forwarded name or ordinal.
        target: Pe32ForwardTarget,
    },
}

/// A forwarder's target symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pe32ForwardTarget {
    /// Forward to a name in the target module.
    Name(Vec<u8>),
    /// Forward to a numeric ordinal in the target module.
    Ordinal(u16),
}

/// Address interpretation for a populated PE data-directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pe32DirectoryAddressKind {
    /// The address is an RVA within the loaded image.
    Rva,
    /// The address is a file offset, as used by the certificate directory.
    FileOffset,
}

/// Standard PE data-directory identity or an unrecognized directory index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pe32DataDirectoryKind {
    /// Export address/name table.
    Export,
    /// Normal import descriptors.
    Import,
    /// Resource tree.
    Resource,
    /// Platform exception metadata.
    Exception,
    /// Certificate table, whose address is a file offset.
    Security,
    /// Base-relocation blocks.
    BaseRelocation,
    /// Debug records.
    Debug,
    /// Architecture-specific data.
    Architecture,
    /// Global pointer value.
    GlobalPointer,
    /// Thread-local storage directory.
    Tls,
    /// Loader configuration, including mitigation and control-flow metadata.
    LoadConfig,
    /// Bound import descriptors.
    BoundImport,
    /// Import address table.
    Iat,
    /// Delay-load import descriptors.
    DelayImport,
    /// CLR runtime header.
    ClrRuntimeHeader,
    /// Reserved directory slot.
    Reserved,
    /// Directory index not named by the PE specification used here.
    Other(u32),
}

/// Address and size of one populated data-directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pe32DataDirectory {
    pub(super) kind: Pe32DataDirectoryKind,
    pub(super) address_kind: Pe32DirectoryAddressKind,
    pub(super) address: u32,
    pub(super) size: u32,
}

impl Pe32DataDirectory {
    /// Directory identity, including unknown numeric indices.
    pub fn kind(self) -> Pe32DataDirectoryKind {
        self.kind
    }

    /// Whether `address` is an RVA or a file offset.
    pub fn address_kind(self) -> Pe32DirectoryAddressKind {
        self.address_kind
    }

    /// Stored address in its declared address space.
    pub fn address(self) -> u32 {
        self.address
    }

    /// Directory size in bytes.
    pub fn size(self) -> u32 {
        self.size
    }
}

/// Base-relocation operation and target RVA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pe32Relocation {
    pub(super) kind: u16,
    pub(super) target_rva: u32,
    pub(super) highadj_adjustment: Option<u16>,
}

impl Pe32Relocation {
    /// PE base-relocation kind. `0` is the `ABSOLUTE` padding entry.
    pub fn kind(self) -> u16 {
        self.kind
    }

    /// Relocation target RVA.
    pub fn target_rva(self) -> u32 {
        self.target_rva
    }

    /// Raw paired adjustment WORD for `HIGHADJ`; rebasing does not apply it yet.
    pub fn highadj_adjustment(self) -> Option<u16> {
        self.highadj_adjustment
    }
}

/// TLS directory data with both source VAs and normalized image RVAs.
///
/// The source VA fields are preferred-base addresses as stored in the PE file.
/// The normalized RVAs are checked against the image and are safe for a later
/// guest lifecycle to translate using its selected load base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32TlsMetadata {
    pub(super) directory_rva: u32,
    pub(super) start_address_of_raw_data_va: u32,
    pub(super) end_address_of_raw_data_va: u32,
    pub(super) address_of_index_va: u32,
    pub(super) address_of_callbacks_va: u32,
    pub(super) template_rva: Option<u32>,
    pub(super) template_size: u32,
    pub(super) index_rva: Option<u32>,
    pub(super) callback_table_rva: Option<u32>,
    pub(super) callback_rvas: Vec<u32>,
    pub(super) size_of_zero_fill: u32,
    pub(super) characteristics: u32,
}

impl Pe32TlsMetadata {
    /// TLS directory RVA.
    pub fn directory_rva(&self) -> u32 {
        self.directory_rva
    }

    /// Source preferred-image VA for template start.
    pub fn start_address_of_raw_data_va(&self) -> u32 {
        self.start_address_of_raw_data_va
    }

    /// Source preferred-image VA for template end.
    pub fn end_address_of_raw_data_va(&self) -> u32 {
        self.end_address_of_raw_data_va
    }

    /// Source preferred-image VA for the TLS index storage.
    pub fn address_of_index_va(&self) -> u32 {
        self.address_of_index_va
    }

    /// Source preferred-image VA for the callback pointer array.
    pub fn address_of_callbacks_va(&self) -> u32 {
        self.address_of_callbacks_va
    }

    /// TLS template start RVA, if the directory contains a template.
    pub fn template_rva(&self) -> Option<u32> {
        self.template_rva
    }

    /// TLS template byte length.
    pub fn template_size(&self) -> u32 {
        self.template_size
    }

    /// TLS index storage RVA, if present.
    pub fn index_rva(&self) -> Option<u32> {
        self.index_rva
    }

    /// Callback pointer-array RVA, if present.
    pub fn callback_table_rva(&self) -> Option<u32> {
        self.callback_table_rva
    }

    /// Callback target RVAs in source order. They are metadata only; no callback runs here.
    pub fn callback_rvas(&self) -> &[u32] {
        &self.callback_rvas
    }

    /// Number of zero-initialized bytes after the template.
    pub fn size_of_zero_fill(&self) -> u32 {
        self.size_of_zero_fill
    }

    /// TLS characteristics as stored in the directory.
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }
}

/// Section information retained by a guest load plan after file bytes are mapped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32LoadSection {
    pub(super) name: Vec<u8>,
    pub(super) rva: u32,
    pub(super) virtual_size: u32,
    pub(super) characteristics: u32,
}

impl Pe32LoadSection {
    /// Section name with trailing NUL padding removed.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Section start RVA.
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Section virtual size.
    pub fn virtual_size(&self) -> u32 {
        self.virtual_size
    }

    /// Raw section characteristics.
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    /// Whether the section is marked executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE.0 != 0
    }
}
