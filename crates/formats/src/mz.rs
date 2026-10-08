use crate::{ensure_memory_range, read_u16, FormatError, ImageKind, LoadedImage};
use guest_core::{real_address, GuestMemory, PhysAddr, Registers};

const DOS_HEADER_MIN_SIZE: usize = 0x1c;
const PSP_SIZE: u32 = 0x100;
const COM_LOAD_OFFSET: u32 = 0x100;
const COM_MAX_SIZE: usize = 0x1_0000 - COM_LOAD_OFFSET as usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MzHeader {
    pub bytes_on_last_page: u16,
    pub page_count: u16,
    pub relocation_count: u16,
    pub header_paragraphs: u16,
    pub min_extra_paragraphs: u16,
    pub max_extra_paragraphs: u16,
    pub initial_ss: u16,
    pub initial_sp: u16,
    pub initial_ip: u16,
    pub initial_cs: u16,
    pub relocation_table_offset: u16,
    pub overlay_number: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MzRelocation {
    pub offset: u16,
    pub segment: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MzImage {
    pub header: MzHeader,
    pub declared_file_size: usize,
    pub image_offset: usize,
    pub image: Vec<u8>,
    pub relocations: Vec<MzRelocation>,
}

/// Parse the DOS MZ header, image, and relocation table without mutating memory.
pub fn parse_mz(bytes: &[u8]) -> Result<MzImage, FormatError> {
    if bytes.get(0..2) != Some(b"MZ".as_slice()) {
        return Err(FormatError::InvalidSignature { expected: "MZ" });
    }
    let header = MzHeader {
        bytes_on_last_page: read_u16(bytes, 0x02, "MZ bytes-on-last-page")?,
        page_count: read_u16(bytes, 0x04, "MZ page count")?,
        relocation_count: read_u16(bytes, 0x06, "MZ relocation count")?,
        header_paragraphs: read_u16(bytes, 0x08, "MZ header paragraphs")?,
        min_extra_paragraphs: read_u16(bytes, 0x0a, "MZ minimum allocation")?,
        max_extra_paragraphs: read_u16(bytes, 0x0c, "MZ maximum allocation")?,
        initial_ss: read_u16(bytes, 0x0e, "MZ initial SS")?,
        initial_sp: read_u16(bytes, 0x10, "MZ initial SP")?,
        initial_ip: read_u16(bytes, 0x14, "MZ initial IP")?,
        initial_cs: read_u16(bytes, 0x16, "MZ initial CS")?,
        relocation_table_offset: read_u16(bytes, 0x18, "MZ relocation table offset")?,
        overlay_number: read_u16(bytes, 0x1a, "MZ overlay number")?,
    };

    if bytes.len() < DOS_HEADER_MIN_SIZE {
        return Err(FormatError::Truncated { context: "MZ fixed header", offset: 0, needed: DOS_HEADER_MIN_SIZE });
    }
    if header.page_count == 0 {
        return Err(FormatError::InvalidMzHeader("page count is zero"));
    }
    if header.bytes_on_last_page > 511 {
        return Err(FormatError::InvalidMzHeader("last-page byte count exceeds 511"));
    }
    if header.max_extra_paragraphs != 0xffff
        && header.max_extra_paragraphs < header.min_extra_paragraphs
    {
        return Err(FormatError::InvalidMzHeader("maximum allocation is below minimum allocation"));
    }

    let declared_file_size = if header.bytes_on_last_page == 0 {
        usize::from(header.page_count).checked_mul(512).ok_or(FormatError::ArithmeticOverflow)?
    } else {
        usize::from(header.page_count - 1)
            .checked_mul(512)
            .and_then(|previous_pages| previous_pages.checked_add(usize::from(header.bytes_on_last_page)))
            .ok_or(FormatError::ArithmeticOverflow)?
    };
    let image_offset = usize::from(header.header_paragraphs)
        .checked_mul(16)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if image_offset < DOS_HEADER_MIN_SIZE {
        return Err(FormatError::InvalidMzHeader("header is smaller than its fixed fields"));
    }
    if image_offset > declared_file_size {
        return Err(FormatError::InvalidMzHeader("header extends past the declared file size"));
    }
    if declared_file_size > bytes.len() {
        return Err(FormatError::Truncated { context: "MZ declared file", offset: 0, needed: declared_file_size });
    }

    let relocation_bytes = usize::from(header.relocation_count)
        .checked_mul(4)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let relocation_offset = usize::from(header.relocation_table_offset);
    if header.relocation_count != 0 {
        if relocation_offset < DOS_HEADER_MIN_SIZE {
            return Err(FormatError::InvalidMzHeader("relocation table overlaps the fixed header"));
        }
        let relocation_end = relocation_offset.checked_add(relocation_bytes).ok_or(FormatError::ArithmeticOverflow)?;
        if relocation_end > image_offset {
            return Err(FormatError::InvalidMzHeader("relocation table is outside the MZ header"));
        }
    }

    let image_size = declared_file_size.checked_sub(image_offset).ok_or(FormatError::ArithmeticOverflow)?;
    if image_size == 0 {
        return Err(FormatError::InvalidMzHeader("loaded image is empty"));
    }
    let image_end = image_offset.checked_add(image_size).ok_or(FormatError::ArithmeticOverflow)?;
    let image_slice = bytes.get(image_offset..image_end).ok_or(FormatError::Truncated {
        context: "MZ image", offset: image_offset, needed: image_size,
    })?;
    let image = image_slice.to_vec();

    let mut relocations = Vec::with_capacity(usize::from(header.relocation_count));
    for index in 0..usize::from(header.relocation_count) {
        let entry_offset = relocation_offset
            .checked_add(index.checked_mul(4).ok_or(FormatError::ArithmeticOverflow)?)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let offset = read_u16(bytes, entry_offset, "MZ relocation offset")?;
        let segment_offset = entry_offset.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        let segment = read_u16(bytes, segment_offset, "MZ relocation segment")?;
        let target = usize::from(segment)
            .checked_mul(16)
            .and_then(|base| base.checked_add(usize::from(offset)))
            .ok_or(FormatError::ArithmeticOverflow)?;
        let target_end = target.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        if target_end > image.len() {
            return Err(FormatError::InvalidMzHeader("relocation target is outside the loaded image"));
        }
        relocations.push(MzRelocation { offset, segment });
    }

    Ok(MzImage { header, declared_file_size, image_offset, image, relocations })
}

/// Copy a COM image at PSP:0100 and return its initial DOS register state.
/// PSP construction and the return word at PSP:FFFE are owned by the DOS layer.
pub fn load_com(
    bytes: &[u8],
    psp_segment: u16,
    memory: &mut impl GuestMemory,
) -> Result<LoadedImage, FormatError> {
    if bytes.is_empty() {
        return Err(FormatError::InvalidCom("image is empty"));
    }
    if bytes.len() > COM_MAX_SIZE {
        return Err(FormatError::InvalidCom("image exceeds its PSP segment"));
    }
    let psp_base = real_address(psp_segment, 0).0;
    let load_address = psp_base.checked_add(COM_LOAD_OFFSET).ok_or(FormatError::ArithmeticOverflow)?;
    let stack_address = psp_base.checked_add(0xfffe).ok_or(FormatError::ArithmeticOverflow)?;
    ensure_memory_range(memory.len(), psp_base, usize::try_from(PSP_SIZE).map_err(|_| FormatError::ArithmeticOverflow)?)?;
    ensure_memory_range(memory.len(), load_address, bytes.len())?;
    ensure_memory_range(memory.len(), stack_address, 2)?;
    memory.write(PhysAddr(load_address), bytes)?;

    let mut registers = Registers::default();
    registers.cs = psp_segment;
    registers.ds = psp_segment;
    registers.es = psp_segment;
    registers.ss = psp_segment;
    registers.set_ip(COM_LOAD_OFFSET as u16);
    registers.set_sp(0xfffe);
    Ok(LoadedImage {
        kind: ImageKind::Com,
        load_address: PhysAddr(load_address),
        image_size: u32::try_from(bytes.len()).map_err(|_| FormatError::ArithmeticOverflow)?,
        registers,
    })
}

/// Parse, relocate, and copy an MZ executable after the caller's 256-byte PSP.
pub fn load_mz(
    bytes: &[u8],
    psp_segment: u16,
    memory: &mut impl GuestMemory,
) -> Result<LoadedImage, FormatError> {
    let mut parsed = parse_mz(bytes)?;
    if parsed.header.overlay_number != 0 {
        return Err(FormatError::UnsupportedExecutable("MZ overlay"));
    }
    let psp_base = real_address(psp_segment, 0).0;
    let load_segment_u32 = u32::from(psp_segment).checked_add(0x10).ok_or(FormatError::ArithmeticOverflow)?;
    let load_segment = u16::try_from(load_segment_u32)
        .map_err(|_| FormatError::InvalidMzHeader("PSP leaves no representable MZ load segment"))?;
    let load_address = real_address(load_segment, 0).0;
    let psp_end = psp_base.checked_add(PSP_SIZE).ok_or(FormatError::ArithmeticOverflow)?;
    if psp_end > memory.len() {
        return Err(FormatError::AddressOutOfRange { address: psp_base, length: PSP_SIZE as usize, memory_len: memory.len() });
    }
    let available_load = memory.len().checked_sub(psp_end).ok_or(FormatError::ArithmeticOverflow)?;
    let image_size = u32::try_from(parsed.image.len()).map_err(|_| FormatError::ArithmeticOverflow)?;
    let available_extra = available_load.checked_sub(image_size)
        .ok_or(FormatError::InvalidMzHeader("image does not fit guest memory"))?;
    let min_extra = u32::from(parsed.header.min_extra_paragraphs)
        .checked_mul(16)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let max_extra = if parsed.header.max_extra_paragraphs == 0xffff {
        available_extra
    } else {
        u32::from(parsed.header.max_extra_paragraphs)
            .checked_mul(16)
            .ok_or(FormatError::ArithmeticOverflow)?
    };
    if max_extra < min_extra {
        return Err(FormatError::InvalidMzHeader("maximum extra allocation is below minimum"));
    }
    if available_extra < min_extra {
        return Err(FormatError::InvalidMzHeader("minimum extra allocation does not fit guest memory"));
    }
    let allocation_size = image_size
        .checked_add(max_extra.min(available_extra))
        .ok_or(FormatError::ArithmeticOverflow)?;
    if allocation_size > available_load {
        return Err(FormatError::InvalidMzHeader("declared allocation exceeds guest memory"));
    }

    // DOS adds the load segment to the 16-bit CS and SS fields. The result is
    // stored in 16-bit registers, so each addition wraps modulo 0x10000.
    let cs = load_segment.wrapping_add(parsed.header.initial_cs);
    let ss = load_segment.wrapping_add(parsed.header.initial_ss);
    let image_end = load_address.checked_add(image_size).ok_or(FormatError::ArithmeticOverflow)?;
    let entry_address = real_address(cs, parsed.header.initial_ip).0;
    if entry_address < load_address || entry_address >= image_end {
        return Err(FormatError::InvalidMzHeader("entry point is outside the loaded image"));
    }
    let allocation_end = load_address.checked_add(allocation_size).ok_or(FormatError::ArithmeticOverflow)?;
    let stack_address = real_address(ss, parsed.header.initial_sp).0;
    if stack_address < load_address || stack_address > allocation_end {
        return Err(FormatError::InvalidMzHeader("initial stack is outside the allocated image"));
    }
    if stack_address > memory.len() {
        return Err(FormatError::InvalidMzHeader("initial stack address is outside guest memory"));
    }

    for relocation in &parsed.relocations {
        let target = usize::from(relocation.segment)
            .checked_mul(16)
            .and_then(|value| value.checked_add(usize::from(relocation.offset)))
            .ok_or(FormatError::ArithmeticOverflow)?;
        let target_end = target.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        let word = parsed.image.get_mut(target..target_end)
            .ok_or(FormatError::InvalidMzHeader("relocation target is outside the loaded image"))?;
        let lo = *word.first().ok_or(FormatError::InvalidMzHeader("relocation target is truncated"))?;
        let hi = *word.get(1).ok_or(FormatError::InvalidMzHeader("relocation target is truncated"))?;
        let relocated = u16::from_le_bytes([lo, hi]).wrapping_add(load_segment);
        word.copy_from_slice(&relocated.to_le_bytes());
    }

    ensure_memory_range(memory.len(), load_address, parsed.image.len())?;
    memory.write(PhysAddr(load_address), &parsed.image)?;

    let mut registers = Registers::default();
    registers.cs = cs;
    registers.ds = psp_segment;
    registers.es = psp_segment;
    registers.ss = ss;
    registers.set_ip(parsed.header.initial_ip);
    registers.set_sp(parsed.header.initial_sp);
    Ok(LoadedImage {
        kind: ImageKind::Mz,
        load_address: PhysAddr(load_address),
        image_size,
        registers,
    })
}
