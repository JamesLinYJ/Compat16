//! Checked Win16 WFX and ACM structure wire projections.

use guest_core::GuestMemory;
use super::*;
use zerocopy::FromBytes;
use zerocopy::byteorder::little_endian::{U16, U32};

pub(super) struct TagFields {
    pub(super) tag_index: u32,
    pub(super) tag: u32,
    pub(super) data_bytes: u32,
    pub(super) support: u32,
    pub(super) standard_count: u32,
    pub(super) name: [u8; 48],
}

pub(super) struct ItemFields {
    pub(super) index: u32,
    pub(super) tag: u32,
    pub(super) support: u32,
    pub(super) data_far: u32,
    pub(super) data_bytes: u32,
    pub(super) name: [u8; 128],
}

pub(super) struct ChooseFields {
    pub(super) style: u32,
    pub(super) owner_window: u16,
    pub(super) data_far: u32,
    pub(super) data_bytes: u32,
    pub(super) title_far: u32,
    pub(super) tag_name: [u8; 48],
    pub(super) item_name: [u8; 128],
    pub(super) saved_name_far: u32,
    pub(super) saved_name_chars: u32,
    pub(super) enum_flags: u32,
    pub(super) enum_data_far: u32,
    pub(super) instance: u16,
    pub(super) template_name_far: u32,
    pub(super) custom_data: u32,
    pub(super) hook_far: u32,
}

pub(super) fn read_tag_wire(bytes: &[u8]) -> Result<TagFields, RuntimeError> {
    let wire = win16_abi::msacm_abi::AcmTagDetails16Wire::read_from_bytes(bytes)
        .map_err(|_| acm_invariant("invalid Win16 ACM tag-details wire record"))?;
    Ok(TagFields {
        tag_index: wire.tag_index.get(), tag: wire.tag.get(),
        data_bytes: wire.format_or_filter_bytes.get(), support: wire.support.get(),
        standard_count: wire.standard_count.get(), name: wire.tag_name,
    })
}

pub(super) fn read_item_wire(bytes: &[u8]) -> Result<ItemFields, RuntimeError> {
    let wire = win16_abi::msacm_abi::AcmItemDetails16Wire::read_from_bytes(bytes)
        .map_err(|_| acm_invariant("invalid Win16 ACM item-details wire record"))?;
    Ok(ItemFields { index: wire.index.get(), tag: wire.tag.get(),
        support: wire.support.get(), data_far: wire.data_far.get(),
        data_bytes: wire.data_bytes.get(), name: wire.name })
}

pub(super) fn read_choose_wire(bytes: &[u8]) -> Result<ChooseFields, RuntimeError> {
    let wire = win16_abi::msacm_abi::AcmChoose16Wire::read_from_bytes(bytes)
        .map_err(|_| acm_invariant("invalid Win16 ACM choose wire record"))?;
    Ok(ChooseFields {
        style: wire.style.get(), owner_window: wire.owner_window.get(),
        data_far: wire.data_far.get(), data_bytes: wire.data_bytes.get(),
        title_far: wire.title_far.get(), tag_name: wire.tag_name,
        item_name: wire.item_name, saved_name_far: wire.saved_name_far.get(),
        saved_name_chars: wire.saved_name_chars.get(), enum_flags: wire.enum_flags.get(),
        enum_data_far: wire.enum_data_far.get(), instance: wire.instance.get(),
        template_name_far: wire.template_name_far.get(), custom_data: wire.custom_data.get(),
        hook_far: wire.hook_far.get(),
    })
}

pub(super) fn tag_query(
    flags: u32,
    index: u32,
    tag: u32,
) -> Result<Win16HostAcmDetailQuery, RuntimeError> {
    match flags {
        ACM_FORMATTAGDETAILSF_INDEX => Ok(Win16HostAcmDetailQuery::Index { index, tag }),
        ACM_FORMATTAGDETAILSF_FORMATTAG => Ok(Win16HostAcmDetailQuery::Tag(tag)),
        ACM_FORMATTAGDETAILSF_LARGESTSIZE => Ok(Win16HostAcmDetailQuery::Largest { tag }),
        _ => Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 ACM tag-details query flags are invalid")),
    }
}

pub(super) fn item_query(
    flags: u32,
    index: u32,
    tag: u32,
) -> Result<Win16HostAcmDetailQuery, RuntimeError> {
    match flags {
        ACM_FORMATDETAILSF_INDEX => Ok(Win16HostAcmDetailQuery::Index { index, tag }),
        ACM_FORMATDETAILSF_FORMAT => Ok(Win16HostAcmDetailQuery::Tag(tag)),
        _ => Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 ACM format/filter-details query flags are invalid")),
    }
}

pub(super) fn encode_tag_wire(
    details: Win16HostAcmTagDetails,
) -> win16_abi::msacm_abi::AcmTagDetails16Wire {
    win16_abi::msacm_abi::AcmTagDetails16Wire {
        structure_bytes: U32::new(TAG_BYTES as u32),
        tag_index: U32::new(details.index), tag: U32::new(details.tag),
        format_or_filter_bytes: U32::new(details.data_bytes),
        support: U32::new(details.support), standard_count: U32::new(details.standard_count),
        tag_name: details.name,
    }
}

pub(super) fn encode_item_wire(
    details: &Win16HostAcmItemDetails,
    data_far: u32,
    capacity: u32,
) -> win16_abi::msacm_abi::AcmItemDetails16Wire {
    win16_abi::msacm_abi::AcmItemDetails16Wire {
        structure_bytes: U32::new(ITEM_BYTES as u32), index: U32::new(details.index),
        tag: U32::new(details.tag), support: U32::new(details.support),
        data_far: U32::new(data_far), data_bytes: U32::new(capacity), name: details.name,
    }
}

pub(super) fn encode_choose_wire(
    old: &ChooseFields,
    tag_name: [u8; 48],
    item_name: [u8; 128],
    data_bytes: u32,
) -> win16_abi::msacm_abi::AcmChoose16Wire {
    win16_abi::msacm_abi::AcmChoose16Wire {
        structure_bytes: U32::new(CHOOSE_BYTES as u32), style: U32::new(old.style),
        owner_window: U16::new(old.owner_window), data_far: U32::new(old.data_far),
        data_bytes: U32::new(data_bytes), title_far: U32::new(old.title_far),
        tag_name, item_name, saved_name_far: U32::new(old.saved_name_far),
        saved_name_chars: U32::new(old.saved_name_chars), enum_flags: U32::new(old.enum_flags),
        enum_data_far: U32::new(old.enum_data_far), instance: U16::new(old.instance),
        template_name_far: U32::new(old.template_name_far),
        custom_data: U32::new(old.custom_data), hook_far: U32::new(old.hook_far),
    }
}

pub(super) fn read_waveformat(
    state: &Win16State,
    far: u32,
    capacity: u32,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    // Guest ACM capacities are DWORDs; convert with a checked host-index width
    // before comparing them with usize wire lengths.
    let capacity = usize::try_from(capacity).map_err(|error| RuntimeError::with_source(
        Kind::InvalidInput, "Win16 ACM format capacity exceeds host index range", error))?;
    const PCM_TAG: u16 = 1;
    if capacity < 2 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 ACM format buffer is smaller than its tag"));
    }
    let tag_pointer = acm_pointer(state, far, 2, memory)?;
    let tag_bytes = acm_read(state, tag_pointer, 2, memory)?;
    if u16::from_le_bytes([tag_bytes[0], tag_bytes[1]]) == PCM_TAG {
        if capacity < 16 {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "Win16 PCMFORMAT is smaller than its 16-byte prefix"));
        }
        let prefix = acm_pointer(state, far, 16, memory)?;
        let pcwfx = acm_read(state, prefix, 16, memory)?;
        // Win16 PCMFORMAT is 16 bytes. Host adapters add WAVEFORMATEX.cbSize
        // in separate owned storage; do not claim two guest output bytes here.
        return Ok(pcwfx);
    }
    if capacity < WAVEFORMATEX_FIXED {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 WAVEFORMATEX is smaller than its fixed prefix"));
    }
    let pointer = acm_pointer(state, far, WAVEFORMATEX_FIXED, memory)?;
    let fixed = acm_read(state, pointer, WAVEFORMATEX_FIXED, memory)?;
    let extra = u16::from_le_bytes([fixed[16], fixed[17]]) as usize;
    let size = WAVEFORMATEX_FIXED.checked_add(extra).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "Win16 WAVEFORMATEX size overflow"))?;
    if size > capacity {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 WAVEFORMATEX extension exceeds the declared ACM buffer"));
    }
    acm_read(state, pointer, size, memory)
}

pub(super) fn read_guest_field(
    state: &Win16State,
    far: u32,
    offset: usize,
    length: usize,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    let offset = u32::try_from(offset).map_err(|error| RuntimeError::with_source(
        Kind::InternalInvariant, "Win16 ACM field offset exceeds DWORD", error))?;
    let field = state.selectors.add_bytes(pointer, offset).map_err(crate::runtime_error)?;
    let checked = state.selectors.translate(field, win16_abi::Access::Read,
        length, memory).map_err(crate::runtime_error)?;
    let mut bytes = zeroed(length)?;
    memory.read(checked, &mut bytes).map_err(crate::runtime_error)?;
    Ok(bytes)
}

pub(super) fn copy_format_enum_fields(
    state: &Win16State,
    far: u32,
    flags: u32,
    destination: &mut [u8],
    memory: &Memory,
) -> Result<(), RuntimeError> {
    copy_format_fields(state, far, flags, destination, memory, [
        (ACM_FORMATENUMF_WFORMATTAG, 0, 2),
        (ACM_FORMATENUMF_NCHANNELS, 2, 2),
        (ACM_FORMATENUMF_NSAMPLESPERSEC, 4, 4),
        (ACM_FORMATENUMF_WBITSPERSAMPLE, 14, 2),
    ])
}

pub(super) fn copy_format_suggest_fields(
    state: &Win16State,
    far: u32,
    flags: u32,
    destination: &mut [u8],
    memory: &Memory,
) -> Result<(), RuntimeError> {
    copy_format_fields(state, far, flags, destination, memory, [
        (ACM_FORMATSUGGESTF_WFORMATTAG, 0, 2),
        (ACM_FORMATSUGGESTF_NCHANNELS, 2, 2),
        (ACM_FORMATSUGGESTF_NSAMPLESPERSEC, 4, 4),
        (ACM_FORMATSUGGESTF_WBITSPERSAMPLE, 14, 2),
    ])
}

fn copy_format_fields(
    state: &Win16State,
    far: u32,
    flags: u32,
    destination: &mut [u8],
    memory: &Memory,
    fields: [(u32, usize, usize); 4],
) -> Result<(), RuntimeError> {
    // ACM treats only flag-selected WFX members as input. Unselected bytes and
    // cbSize may be uninitialized, so copy only the fields the caller marked.
    for (flag, offset, length) in fields {
        if flags & flag == 0 { continue; }
        let end = offset.checked_add(length).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "ACM WAVEFORMATEX field range overflow"))?;
        let target = destination.get_mut(offset..end).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "ACM WAVEFORMATEX field exceeds host buffer"))?;
        target.copy_from_slice(&read_guest_field(state, far, offset, length, memory)?);
    }
    Ok(())
}

pub(super) fn read_wavefilter(
    state: &Win16State,
    far: u32,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let pointer = acm_pointer(state, far, WAVEFILTER_FIXED, memory)?;
    let fixed = acm_read(state, pointer, WAVEFILTER_FIXED, memory)?;
    let declared = u32::from_le_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
    let size = usize::try_from(declared).map_err(|error| RuntimeError::with_source(
        Kind::InvalidInput, "Win16 WAVEFILTER size exceeds host address width", error))?;
    if size < WAVEFILTER_FIXED {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 WAVEFILTER is smaller than its fixed prefix"));
    }
    acm_read(state, pointer, size, memory)
}

pub(super) fn zeroed(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 ACM buffer", error))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
