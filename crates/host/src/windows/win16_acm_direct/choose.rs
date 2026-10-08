use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostAcmChooseKind, Win16HostAcmResult as ResultValue,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Media::Audio::{
    ACMERR_NOTPOSSIBLE, ACMFILTERCHOOSE_STYLEF_ENABLEHOOK, ACMFILTERCHOOSE_STYLEF_ENABLETEMPLATE,
    ACMFILTERCHOOSE_STYLEF_ENABLETEMPLATEHANDLE, ACMFILTERCHOOSE_STYLEF_INITTOFILTERSTRUCT,
    ACMFILTERCHOOSEW, ACMFORMATCHOOSE_STYLEF_ENABLEHOOK, ACMFORMATCHOOSE_STYLEF_ENABLETEMPLATE,
    ACMFORMATCHOOSE_STYLEF_ENABLETEMPLATEHANDLE, ACMFORMATCHOOSE_STYLEF_INITTOWFXSTRUCT,
    ACMFORMATCHOOSEW, acmFilterChooseW, acmFormatChooseW,
};
use windows_sys::Win32::Media::{MMSYSERR_INVALPARAM, MMSYSERR_NOERROR, MMSYSERR_NOTSUPPORTED};

use super::super::guest_text::GuestTextCodec;
use super::format::{WAVEFILTER_BYTES, WFX_BYTES, filter_size, normalize_wfx, wave_size, zeroed};
use super::text::{
    guest_fixed_to_wide, optional_guest_string_to_wide_z, wide_fixed_to_guest, wide_to_guest_buffer,
};

const PCMWAVEFORMAT_BYTES: usize = 16;

pub(super) fn choose(
    codec: GuestTextCodec,
    kind: Win16HostAcmChooseKind,
    owner: Option<runtime::Win16HostWindow>,
    style: u32,
    mut data: Vec<u8>,
    data_capacity: u32,
    title: Option<Vec<u8>>,
    tag_name: [u8; 48],
    item_name: [u8; 128],
    saved_name: Option<Vec<u8>>,
    saved_name_capacity: u32,
    enum_flags: u32,
    mut enum_data: Vec<u8>,
) -> Result<ResultValue, RuntimeError> {
    let (minimum, initialize) = match kind {
        Win16HostAcmChooseKind::Format => (
            PCMWAVEFORMAT_BYTES,
            style & ACMFORMATCHOOSE_STYLEF_INITTOWFXSTRUCT as u32 != 0,
        ),
        Win16HostAcmChooseKind::Filter => (
            WAVEFILTER_BYTES,
            style & ACMFILTERCHOOSE_STYLEF_INITTOFILTERSTRUCT as u32 != 0,
        ),
    };
    let style_unsupported = match kind {
        Win16HostAcmChooseKind::Format => {
            style
                & ((ACMFORMATCHOOSE_STYLEF_ENABLEHOOK
                    | ACMFORMATCHOOSE_STYLEF_ENABLETEMPLATE
                    | ACMFORMATCHOOSE_STYLEF_ENABLETEMPLATEHANDLE) as u32)
                != 0
        }
        Win16HostAcmChooseKind::Filter => {
            style
                & ((ACMFILTERCHOOSE_STYLEF_ENABLEHOOK
                    | ACMFILTERCHOOSE_STYLEF_ENABLETEMPLATE
                    | ACMFILTERCHOOSE_STYLEF_ENABLETEMPLATEHANDLE) as u32)
                != 0
        }
    };
    if owner.is_some() || style_unsupported {
        return Ok(chosen_result(
            MMSYSERR_NOTSUPPORTED,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }

    let capacity = data_capacity as usize;
    if data.len() > capacity {
        return Ok(chosen_result(
            MMSYSERR_INVALPARAM,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }
    let pcm_guest_layout = kind == Win16HostAcmChooseKind::Format
        && initialize
        && (PCMWAVEFORMAT_BYTES..WFX_BYTES).contains(&capacity)
        && data.len() >= PCMWAVEFORMAT_BYTES
        && data[..2] == [1, 0];
    if kind == Win16HostAcmChooseKind::Format && capacity < WFX_BYTES && !pcm_guest_layout {
        return Ok(chosen_result(
            MMSYSERR_INVALPARAM,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }
    // Win16 PCMWAVEFORMAT omits WAVEFORMATEX.cbSize. Only the validated
    // initialized 16/17-byte PCM representation gets an 18-byte native extent.
    let native_format_capacity = if pcm_guest_layout {
        WFX_BYTES as u32
    } else {
        data_capacity
    };
    let mut native_data = if initialize {
        if capacity < minimum || data.len() < minimum {
            return Ok(chosen_result(
                MMSYSERR_INVALPARAM,
                Vec::new(),
                data_capacity,
                tag_name,
                item_name,
                saved_name,
            ));
        }
        match kind {
            Win16HostAcmChooseKind::Format => {
                let Some(normalized) = normalize_wfx(std::mem::take(&mut data))? else {
                    return Ok(chosen_result(
                        MMSYSERR_INVALPARAM,
                        Vec::new(),
                        data_capacity,
                        tag_name,
                        item_name,
                        saved_name,
                    ));
                };
                if guest_wave_size(&normalized, capacity).is_none() {
                    return Ok(chosen_result(
                        MMSYSERR_INVALPARAM,
                        Vec::new(),
                        data_capacity,
                        tag_name,
                        item_name,
                        saved_name,
                    ));
                }
                let mut buffer = zeroed(capacity.max(WFX_BYTES))?;
                buffer[..normalized.len()].copy_from_slice(&normalized);
                buffer
            }
            Win16HostAcmChooseKind::Filter => {
                if filter_size(&data, capacity).is_none() {
                    return Ok(chosen_result(
                        MMSYSERR_INVALPARAM,
                        Vec::new(),
                        data_capacity,
                        tag_name,
                        item_name,
                        saved_name,
                    ));
                }
                let mut buffer = zeroed(capacity)?;
                buffer[..data.len()].copy_from_slice(&data);
                buffer
            }
        }
    } else {
        // Without INITTO*, ACM must decide from the style and available
        // capacity; do not interpret or normalize the guest's buffer bytes.
        let native_minimum = match kind {
            Win16HostAcmChooseKind::Format => WFX_BYTES,
            Win16HostAcmChooseKind::Filter => minimum,
        };
        let mut buffer = zeroed(capacity.max(native_minimum))?;
        buffer[..data.len()].copy_from_slice(&data);
        buffer
    };

    if enum_data.len() > u32::MAX as usize
        || saved_name
            .as_ref()
            .is_some_and(|_| saved_name_capacity > 1_048_576)
    {
        return Ok(chosen_result(
            MMSYSERR_INVALPARAM,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }
    if saved_name
        .as_ref()
        .is_some_and(|buffer| buffer.is_empty() || buffer.len() != saved_name_capacity as usize)
    {
        return Ok(chosen_result(
            MMSYSERR_INVALPARAM,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }
    if !enum_data.is_empty() && enum_data.len() < minimum {
        return Ok(chosen_result(
            MMSYSERR_INVALPARAM,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }
    if !enum_data.is_empty() {
        match kind {
            Win16HostAcmChooseKind::Format => {
                let Some(normalized) = normalize_wfx(std::mem::take(&mut enum_data))? else {
                    return Ok(chosen_result(
                        MMSYSERR_INVALPARAM,
                        Vec::new(),
                        data_capacity,
                        tag_name,
                        item_name,
                        saved_name,
                    ));
                };
                enum_data = normalized;
            }
            Win16HostAcmChooseKind::Filter => {
                if filter_size(&enum_data, enum_data.len()).is_none() {
                    return Ok(chosen_result(
                        MMSYSERR_INVALPARAM,
                        Vec::new(),
                        data_capacity,
                        tag_name,
                        item_name,
                        saved_name,
                    ));
                }
            }
        }
    }

    if title.as_ref().is_some_and(|title| title.contains(&0)) {
        return Ok(chosen_result(
            MMSYSERR_INVALPARAM,
            Vec::new(),
            data_capacity,
            tag_name,
            item_name,
            saved_name,
        ));
    }
    let has_title = title.is_some();
    let title_buffer =
        optional_guest_string_to_wide_z(codec, title.as_deref())?.unwrap_or_default();
    let has_saved_name = saved_name.is_some();
    let guest_saved_name = saved_name.unwrap_or_default();
    let mut chosen_name = if has_saved_name {
        // pszName is a C string in a caller-owned capacity buffer. Its unused
        // tail is not text and may contain arbitrary uninitialized bytes.
        let end = guest_saved_name.iter().position(|byte| *byte == 0);
        let decoded = codec.to_wide(&guest_saved_name[..end.unwrap_or(guest_saved_name.len())])?;
        let terminated = end.is_some();
        let native_capacity = if terminated {
            (saved_name_capacity as usize).max(128)
        } else {
            decoded.len()
        };
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(native_capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native ACM name buffer",
                error,
            )
        })?;
        buffer.resize(native_capacity, 0);
        if decoded.len() > native_capacity {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "guest ACM name does not fit its native UTF-16 buffer",
            ));
        }
        buffer[..decoded.len()].copy_from_slice(&decoded);
        buffer
    } else {
        Vec::new()
    };
    let name_ptr = if has_saved_name {
        chosen_name.as_mut_ptr()
    } else {
        ptr::null_mut()
    };
    // ACM cchName is measured in native UTF-16 characters. Guest output is
    // separately clipped to saved_name_capacity bytes below.
    let name_capacity = if name_ptr.is_null() {
        0
    } else {
        chosen_name.len() as u32
    };
    let title_ptr = if has_title {
        title_buffer.as_ptr()
    } else {
        ptr::null()
    };
    let tag = guest_fixed_to_wide(codec, &tag_name)?;
    let item = guest_fixed_to_wide(codec, &item_name)?;
    let enum_ptr = if enum_data.is_empty() {
        ptr::null_mut()
    } else {
        enum_data.as_mut_ptr()
    };
    let (mut result, selected_tag, selected_item, mut data_bytes) = match kind {
        Win16HostAcmChooseKind::Format => {
            let mut native = ACMFORMATCHOOSEW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct)
                    .write_unaligned(std::mem::size_of::<ACMFORMATCHOOSEW>() as u32);
                ptr::addr_of_mut!(native.fdwStyle).write_unaligned(style);
                ptr::addr_of_mut!(native.hwndOwner)
                    .write_unaligned(ptr::null_mut::<core::ffi::c_void>() as HWND);
                ptr::addr_of_mut!(native.pwfx).write_unaligned(native_data.as_mut_ptr().cast());
                // The guest PCM wire can be 16 bytes; native WAVEFORMATEX
                // needs its separate 18-byte backing extent even then.
                ptr::addr_of_mut!(native.cbwfx).write_unaligned(native_format_capacity);
                ptr::addr_of_mut!(native.pszTitle).write_unaligned(title_ptr);
                ptr::addr_of_mut!(native.szFormatTag).write_unaligned(tag);
                ptr::addr_of_mut!(native.szFormat).write_unaligned(item);
                ptr::addr_of_mut!(native.pszName).write_unaligned(name_ptr);
                ptr::addr_of_mut!(native.cchName).write_unaligned(name_capacity);
                ptr::addr_of_mut!(native.fdwEnum).write_unaligned(enum_flags);
                ptr::addr_of_mut!(native.pwfxEnum).write_unaligned(enum_ptr.cast());
            }
            // SAFETY: all pointers are host-owned and live through this
            // synchronous call; guest callbacks, templates, and owners are not passed.
            let result = unsafe { acmFormatChooseW(&mut native) };
            let selected_tag = unsafe { ptr::addr_of!(native.szFormatTag).read_unaligned() };
            let selected_item = unsafe { ptr::addr_of!(native.szFormat).read_unaligned() };
            let data_bytes = unsafe { ptr::addr_of!(native.cbwfx).read_unaligned() };
            (result, selected_tag, selected_item, data_bytes)
        }
        Win16HostAcmChooseKind::Filter => {
            let mut native = ACMFILTERCHOOSEW::default();
            unsafe {
                ptr::addr_of_mut!(native.cbStruct)
                    .write_unaligned(std::mem::size_of::<ACMFILTERCHOOSEW>() as u32);
                ptr::addr_of_mut!(native.fdwStyle).write_unaligned(style);
                ptr::addr_of_mut!(native.hwndOwner)
                    .write_unaligned(ptr::null_mut::<core::ffi::c_void>() as HWND);
                ptr::addr_of_mut!(native.pwfltr).write_unaligned(native_data.as_mut_ptr().cast());
                ptr::addr_of_mut!(native.cbwfltr).write_unaligned(data_capacity);
                ptr::addr_of_mut!(native.pszTitle).write_unaligned(title_ptr);
                ptr::addr_of_mut!(native.szFilterTag).write_unaligned(tag);
                ptr::addr_of_mut!(native.szFilter).write_unaligned(item);
                ptr::addr_of_mut!(native.pszName).write_unaligned(name_ptr);
                ptr::addr_of_mut!(native.cchName).write_unaligned(name_capacity);
                ptr::addr_of_mut!(native.fdwEnum).write_unaligned(enum_flags);
                ptr::addr_of_mut!(native.pwfltrEnum).write_unaligned(enum_ptr.cast());
            }
            // SAFETY: all pointers are host-owned and live through this
            // synchronous call; guest callbacks, templates, and owners are not passed.
            let result = unsafe { acmFilterChooseW(&mut native) };
            let selected_tag = unsafe { ptr::addr_of!(native.szFilterTag).read_unaligned() };
            let selected_item = unsafe { ptr::addr_of!(native.szFilter).read_unaligned() };
            let data_bytes = unsafe { ptr::addr_of!(native.cbwfltr).read_unaligned() };
            (result, selected_tag, selected_item, data_bytes)
        }
    };

    if result == ACMERR_NOTPOSSIBLE {
        native_data.clear();
    } else if result == MMSYSERR_NOERROR {
        let actual_size = match kind {
            Win16HostAcmChooseKind::Format => wave_size(&native_data, native_data.len()),
            Win16HostAcmChooseKind::Filter => filter_size(&native_data, capacity),
        };
        let guest_format_size = if kind == Win16HostAcmChooseKind::Format && actual_size.is_some() {
            guest_wave_size(&native_data, usize::MAX)
        } else {
            None
        };
        let output_size = match (kind, actual_size) {
            (Win16HostAcmChooseKind::Format, Some(_)) => guest_format_size
                .filter(|size| {
                    let reported = data_bytes as usize;
                    let standard_pcm = *size == PCMWAVEFORMAT_BYTES
                        && native_data.len() >= WFX_BYTES
                        && u16::from_le_bytes([native_data[0], native_data[1]]) == 1
                        && native_data[16..18] == [0, 0];
                    if standard_pcm {
                        capacity >= PCMWAVEFORMAT_BYTES
                            && (PCMWAVEFORMAT_BYTES..=WFX_BYTES).contains(&reported)
                    } else {
                        *size <= reported && reported <= capacity
                    }
                })
                .filter(|size| *size <= capacity),
            (Win16HostAcmChooseKind::Filter, Some(size)) => (size <= data_bytes as usize
                && data_bytes as usize <= capacity)
                .then_some(data_bytes as usize),
            _ => None,
        };
        if let Some(size) = output_size {
            native_data.truncate(size);
            data_bytes = size as u32;
        } else if kind == Win16HostAcmChooseKind::Format
            && (data_bytes as usize > capacity
                || guest_format_size.is_some_and(|size| size > capacity))
        {
            // The native API documents ACMERR_NOTPOSSIBLE for a selection
            // larger than cbwfx. Preserve that guest capacity result instead
            // of turning a successful dialog into MMSYSERR_INVALPARAM.
            if let Some(required) = guest_format_size {
                data_bytes = required as u32;
            }
            result = ACMERR_NOTPOSSIBLE;
            native_data.clear();
        } else {
            result = MMSYSERR_INVALPARAM;
            native_data.clear();
        }
    } else {
        native_data.clear();
    }
    let saved_name = if has_saved_name {
        Some(wide_to_guest_buffer(
            codec,
            &chosen_name,
            saved_name_capacity as usize,
        )?)
    } else {
        None
    };
    Ok(ResultValue::Chosen {
        result,
        data: native_data,
        data_bytes,
        tag_name: wide_fixed_to_guest(codec, &selected_tag)?,
        item_name: wide_fixed_to_guest(codec, &selected_item)?,
        saved_name,
    })
}

fn guest_wave_size(bytes: &[u8], capacity: usize) -> Option<usize> {
    if bytes.len() < WFX_BYTES {
        return None;
    }
    let pcm = u16::from_le_bytes([bytes[0], bytes[1]]) == 1 && bytes[16..18] == [0, 0];
    if pcm {
        return (capacity >= PCMWAVEFORMAT_BYTES).then_some(PCMWAVEFORMAT_BYTES);
    }
    let size = wave_size(bytes, bytes.len())?;
    (size <= capacity).then_some(size)
}

fn chosen_result(
    result: u32,
    data: Vec<u8>,
    data_bytes: u32,
    tag_name: [u8; 48],
    item_name: [u8; 128],
    saved_name: Option<Vec<u8>>,
) -> ResultValue {
    ResultValue::Chosen {
        result,
        data,
        data_bytes,
        tag_name,
        item_name,
        saved_name,
    }
}
