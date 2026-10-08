use core::ops::Range;

use super::pe32_types::{
    Pe32DataDirectory, Pe32Error, Pe32Export, Pe32Image, Pe32ImportModule, Pe32LoadSection,
    Pe32TlsMetadata,
};

/// Caller-selected placement and hard allocation budget for one PE32 image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pe32LoadOptions {
    /// Guest linear address selected for the image base.
    pub load_base: u32,
    /// Maximum image bytes this caller is willing to map.
    pub max_image_size: u32,
}

/// A fully owned, validated image mapping plan.
///
/// Fields remain private so consumers receive the validation performed by
/// [`plan_pe32_load`] and cannot accidentally change the mapped base/size pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe32LoadPlan {
    load_base: u32,
    preferred_base: u32,
    image_size: u32,
    entry_rva: Option<u32>,
    is_dll: bool,
    subsystem: u16,
    mapped_image: Vec<u8>,
    sections: Vec<Pe32LoadSection>,
    imports: Vec<Pe32ImportModule>,
    exports: Vec<Pe32Export>,
    data_directories: Vec<Pe32DataDirectory>,
    tls: Option<Pe32TlsMetadata>,
}

impl Pe32LoadPlan {
    /// Guest linear base selected by the caller.
    pub fn load_base(&self) -> u32 {
        self.load_base
    }

    /// Original preferred image base.
    pub fn preferred_base(&self) -> u32 {
        self.preferred_base
    }

    /// Mapped image size in bytes.
    pub fn image_size(&self) -> u32 {
        self.image_size
    }

    /// Exclusive guest image end as a 64-bit value, allowing the 4-GiB boundary.
    pub fn image_end(&self) -> u64 {
        u64::from(self.load_base) + u64::from(self.image_size)
    }

    /// Entry-point RVA, or `None` for a zero entry point.
    pub fn entry_rva(&self) -> Option<u32> {
        self.entry_rva
    }

    /// Checked absolute guest entry-point address, if the image declares one.
    pub fn entry_address(&self) -> Option<u32> {
        self.entry_rva
            .and_then(|rva| self.load_base.checked_add(rva))
    }

    /// Whether the image is a DLL.
    pub fn is_dll(&self) -> bool {
        self.is_dll
    }

    /// PE subsystem value, preserved without interpreting newer values.
    pub fn subsystem(&self) -> u16 {
        self.subsystem
    }

    /// Fully mapped image bytes, including zero-filled section tails and applied relocations.
    pub fn mapped_image(&self) -> &[u8] {
        &self.mapped_image
    }

    /// Validated sections, useful for guest page permissions and executable ranges.
    pub fn sections(&self) -> &[Pe32LoadSection] {
        &self.sections
    }

    /// Absolute executable guest ranges, using an exclusive 64-bit end address.
    pub fn executable_guest_ranges(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        let base = u64::from(self.load_base);
        self.sections.iter().filter_map(move |section| {
            if !section.is_executable() || section.virtual_size() == 0 {
                return None;
            }
            let start = base.checked_add(u64::from(section.rva()))?;
            let end = start.checked_add(u64::from(section.virtual_size()))?;
            Some(start..end)
        })
    }

    /// Unresolved imports, retained for the runtime's guest linker.
    pub fn imports(&self) -> &[Pe32ImportModule] {
        &self.imports
    }

    /// Export address table entries, including names, aliases, and forwarders.
    pub fn exports(&self) -> &[Pe32Export] {
        &self.exports
    }

    /// All populated directories, including loader features the runtime may reject.
    pub fn data_directories(&self) -> &[Pe32DataDirectory] {
        &self.data_directories
    }

    /// TLS data as checked RVAs plus original preferred-base VA fields.
    ///
    /// Presence does not indicate that TLS storage or callbacks were initialized.
    pub fn tls(&self) -> Option<&Pe32TlsMetadata> {
        self.tls.as_ref()
    }
}

/// Build a checked guest mapping and apply supported base relocations.
pub fn plan_pe32_load(
    image: Pe32Image,
    options: Pe32LoadOptions,
) -> Result<Pe32LoadPlan, Pe32Error> {
    if image.image_size > options.max_image_size {
        return Err(Pe32Error::ImageTooLarge {
            size: image.image_size,
            maximum: options.max_image_size,
        });
    }
    if options.load_base == 0 {
        return Err(Pe32Error::InvalidLoadBase(
            "zero is reserved as a null address",
        ));
    }
    if options.load_base % image.section_alignment != 0 {
        return Err(Pe32Error::InvalidLoadBase(
            "base does not satisfy SectionAlignment",
        ));
    }
    let end = u64::from(options.load_base) + u64::from(image.image_size);
    if end > (u64::from(u32::MAX) + 1) {
        return Err(Pe32Error::InvalidLoadBase(
            "image crosses the PE32 4-GiB address boundary",
        ));
    }
    let mapped_size = usize::try_from(image.image_size).map_err(|_| Pe32Error::ImageTooLarge {
        size: image.image_size,
        maximum: options.max_image_size,
    })?;
    let mut mapped_image = Vec::new();
    mapped_image
        .try_reserve_exact(mapped_size)
        .map_err(|_| Pe32Error::OutOfMemory("allocating the guest PE image"))?;
    mapped_image.resize(mapped_size, 0);

    let header_size = usize::try_from(image.header_size)
        .map_err(|_| Pe32Error::InvalidImage("SizeOfHeaders does not fit host size"))?;
    let header_target = mapped_image
        .get_mut(..header_size)
        .ok_or(Pe32Error::InvalidImage("headers exceed mapped image"))?;
    if image.header_bytes.len() != header_size {
        return Err(Pe32Error::InvalidImage("owned PE header length changed"));
    }
    header_target.copy_from_slice(&image.header_bytes);

    for section in &image.sections {
        let target_start = usize::try_from(section.rva)
            .map_err(|_| Pe32Error::InvalidImage("section RVA does not fit host size"))?;
        let raw_data_length = u32::try_from(section.raw_data.len())
            .map_err(|_| Pe32Error::InvalidImage("section raw bytes exceed PE32 size"))?;
        if raw_data_length != section.raw_size {
            return Err(Pe32Error::InvalidImage(
                "section raw bytes do not match header",
            ));
        }
        let copy_length = section.virtual_size.min(section.raw_size);
        let copy_length = usize::try_from(copy_length)
            .map_err(|_| Pe32Error::InvalidImage("section copy size does not fit host size"))?;
        let target_end = target_start
            .checked_add(copy_length)
            .ok_or(Pe32Error::InvalidImage("mapped section range overflows"))?;
        let source = section
            .raw_data
            .get(..copy_length)
            .ok_or(Pe32Error::InvalidImage("section raw bytes are incomplete"))?;
        let target = mapped_image
            .get_mut(target_start..target_end)
            .ok_or(Pe32Error::InvalidImage("section exceeds mapped image"))?;
        target.copy_from_slice(source);
    }

    apply_relocations(&image, options.load_base, &mut mapped_image)?;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(image.sections.len())
        .map_err(|_| Pe32Error::OutOfMemory("building guest section metadata"))?;
    for section in image.sections {
        sections.push(Pe32LoadSection {
            name: section.name,
            rva: section.rva,
            virtual_size: section.virtual_size,
            characteristics: section.characteristics,
        });
    }

    Ok(Pe32LoadPlan {
        load_base: options.load_base,
        preferred_base: image.preferred_base,
        image_size: image.image_size,
        entry_rva: image.entry_rva,
        is_dll: image.is_dll,
        subsystem: image.subsystem,
        mapped_image,
        sections,
        imports: image.imports,
        exports: image.exports,
        data_directories: image.data_directories,
        tls: image.tls,
    })
}

fn apply_relocations(
    image: &Pe32Image,
    load_base: u32,
    mapped_image: &mut [u8],
) -> Result<(), Pe32Error> {
    if load_base == image.preferred_base {
        return Ok(());
    }
    if image.relocations_stripped || !image.has_relocation_directory {
        return Err(Pe32Error::RelocationsUnavailable);
    }
    let delta = load_base.wrapping_sub(image.preferred_base);
    // The object reader decodes relocation records but does not place a guest
    // image. Apply I386 HIGHLOW as PE/COFF specifies; keep ABSOLUTE padding and
    // reject other kinds when a nonpreferred guest base actually needs them.
    for relocation in &image.relocations {
        match relocation.kind {
            0 => {}
            3 => {
                let start = usize::try_from(relocation.target_rva).map_err(|_| {
                    Pe32Error::InvalidImage("relocation RVA does not fit host size")
                })?;
                let end = start
                    .checked_add(4)
                    .ok_or(Pe32Error::InvalidImage("relocation range overflows"))?;
                let slot = mapped_image
                    .get_mut(start..end)
                    .ok_or(Pe32Error::InvalidImage("relocation target exceeds image"))?;
                let old_value = u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
                slot.copy_from_slice(&old_value.wrapping_add(delta).to_le_bytes());
            }
            kind => {
                return Err(Pe32Error::UnsupportedRelocation {
                    kind,
                    target_rva: relocation.target_rva,
                });
            }
        }
    }
    Ok(())
}
