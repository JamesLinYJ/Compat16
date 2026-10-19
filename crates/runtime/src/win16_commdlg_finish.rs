//! Validated common-dialog results and transactional guest writeback.

use guest_core::memory::Memory;
use win16_abi::{
    commdlg_abi::{ChooseColor16, ChooseFont16, OpenFileName16, PrintDlg16},
    Win16ReturnKind,
};

use super::{
    finish_guest_failure, ranges::commit_guest_writes,
    support::{encode_devmode16, guest_log_font, validate_dev_names},
    Win16CommonDialogContinuation, Win16CommonDialogOutput, Win16State,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCommonDialogResult};

const FNERR_BUFFERTOOSMALL: u32 = 0x0000_3003;

pub(super) fn finish_common_dialog(
    state: &mut Win16State,
    continuation: Win16CommonDialogContinuation,
    result: Win16HostCommonDialogResult,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    let request_id = continuation.find_replace_request_id();
    let return_kind = continuation.return_kind;
    let finished = finish_result(state, continuation, result, memory, host);
    match (finished, request_id) {
        (Err(primary), Some(request_id)) => match state.cancel_find_replace(request_id) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(RuntimeError::with_source(Kind::InternalInvariant,
                format!("{primary}; Find/Replace completion cleanup failed"), cleanup)),
        },
        (result, _) => result.map(|value| (value, return_kind)),
    }
}

fn finish_result(
    state: &mut Win16State,
    continuation: Win16CommonDialogContinuation,
    result: Win16HostCommonDialogResult,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    let guest_failure_value = continuation.guest_failure_value;
    match (continuation.output, result) {
        (Win16CommonDialogOutput::PrinterMode { output },
            Win16HostCommonDialogResult::PrinterMode(result)) =>
            super::printer::finish(state, memory, output, result),
        (Win16CommonDialogOutput::File {
            structure, file, file_far, file_capacity,
            file_title, file_title_far, file_title_capacity,
            custom_filter, custom_filter_far, custom_filter_capacity,
        }, Win16HostCommonDialogResult::File {
            accepted, extended_error, flags, filter_index, file: file_bytes,
            file_title: title_bytes, file_offset, file_extension,
            custom_filter: custom_bytes, required_size,
        }) => {
            state.common_dialog_state.last_extended_error =
                if accepted { 0 } else { extended_error };
            if accepted {
                if file_bytes.len() > file_capacity || !file_bytes.contains(&0) {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "common dialog returned an invalid Win16 file-buffer result"));
                }
                let mut record = match read_open_file_record(state, memory, &structure) {
                    Ok(record) => record,
                    Err(error) => return finish_guest_failure(error, guest_failure_value),
                };
                if !open_file_bindings_match(&record, file_far, file_capacity,
                    file_title_far, file_title_capacity, custom_filter_far,
                    custom_filter_capacity)
                {
                    return Ok(0);
                }
                let mut writes = vec![(file, file_bytes)];
                if let (Some(range), Some(bytes)) = (file_title, title_bytes) {
                    if bytes.len() > range.length() || !bytes.contains(&0) {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "common dialog returned an invalid Win16 file-title result"));
                    }
                    writes.push((range, bytes));
                }
                if let (Some(range), Some(bytes)) = (custom_filter, custom_bytes) {
                    if bytes.len() > range.length() || !bytes.contains(&0) {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "common dialog returned an invalid Win16 custom-filter result"));
                    }
                    writes.push((range, bytes));
                }
                record.flags = flags;
                record.filter_index = filter_index;
                record.file_offset = file_offset;
                record.file_extension = file_extension;
                writes.push((structure, record.encode().to_vec()));
                match commit_guest_writes(state, memory, writes) {
                    Ok(()) => Ok(1),
                    Err(error) => finish_guest_failure(error, guest_failure_value),
                }
            } else {
                if extended_error != FNERR_BUFFERTOOSMALL { return Ok(0); }
                let Some(required_size) = required_size else { return Ok(0); };
                if file_capacity < 2 { return Ok(0); }
                let record = match read_open_file_record(state, memory, &structure) {
                    Ok(record) => record,
                    Err(error) => return finish_guest_failure(error, guest_failure_value),
                };
                if !open_file_bindings_match(&record, file_far, file_capacity,
                    file_title_far, file_title_capacity, custom_filter_far,
                    custom_filter_capacity)
                {
                    return Ok(0);
                }
                match commit_guest_writes(state, memory,
                    vec![(file, required_size.to_le_bytes().to_vec())])
                {
                    Ok(()) => Ok(0),
                    Err(error) => finish_guest_failure(error, guest_failure_value),
                }
            }
        }
        (Win16CommonDialogOutput::Color { structure, custom_colors, custom_colors_far },
            Win16HostCommonDialogResult::Color {
                accepted, extended_error, color, custom_colors: palette,
            }) => {
            state.common_dialog_state.last_extended_error =
                if accepted { 0 } else { extended_error };
            if !accepted { return Ok(0); }
            let mut record = match read_color_record(state, memory, &structure) {
                Ok(record) => record,
                Err(error) => return finish_guest_failure(error, guest_failure_value),
            };
            if record.custom_colors != custom_colors_far { return Ok(0); }
            let mut bytes = [0u8; 64];
            for (index, color) in palette.into_iter().enumerate() {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&color.to_le_bytes());
            }
            record.initial_color = color;
            match commit_guest_writes(state, memory, vec![
                (custom_colors, bytes.to_vec()), (structure, record.encode().to_vec()),
            ]) {
                Ok(()) => Ok(1),
                Err(error) => finish_guest_failure(error, guest_failure_value),
            }
        }
        (Win16CommonDialogOutput::FindReplace { request_id },
            Win16HostCommonDialogResult::FindReplaceCreated {
                request_id: returned_id, window, find_message, extended_error,
            }) => {
            if returned_id != request_id {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native Find/Replace result has a different request identity"));
            }
            state.common_dialog_state.last_extended_error =
                if window.is_some() { 0 } else { extended_error };
            match window {
                None => {
                    state.cancel_find_replace(request_id)?;
                    Ok(0)
                }
                Some(window) => {
                    if !state.bind_find_replace_result(request_id, Some(window), find_message)? {
                        state.cancel_find_replace(request_id)?;
                        return Ok(0);
                    }
                    match state.map_window_handle(window, true) {
                        Ok(guest) => Ok(u32::from(guest)),
                        Err(error) => {
                            state.cancel_find_replace(request_id)?;
                            Err(error)
                        }
                    }
                }
            }
        }
        (Win16CommonDialogOutput::Font {
            structure, log_font, log_font_far, style, style_far,
        }, Win16HostCommonDialogResult::Font {
            accepted, extended_error, log_font: font, point_size, color,
            flags, style: style_bytes, font_type,
        }) => {
            state.common_dialog_state.last_extended_error =
                if accepted { 0 } else { extended_error };
            if !accepted { return Ok(0); }
            if style_bytes.len() > 32 || !style_bytes.contains(&0) {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "CHOOSEFONT returned a style string outside the Win16 32-byte buffer"));
            }
            let mut record = match read_font_record(state, memory, &structure) {
                Ok(record) => record,
                Err(error) => return finish_guest_failure(error, guest_failure_value),
            };
            if record.log_font != log_font_far || record.style != style_far { return Ok(0); }
            let mut writes = vec![(log_font, guest_log_font(font).encode().to_vec())];
            if let Some(range) = style {
                if style_bytes.len() > range.length() { return Err(RuntimeError::new(
                    Kind::HostFailure, "CHOOSEFONT style exceeds the captured Win16 range")); }
                writes.push((range, style_bytes));
            }
            record.point_size = point_size;
            record.flags = flags;
            record.color = color;
            record.font_type = font_type;
            writes.push((structure, record.encode().to_vec()));
            match commit_guest_writes(state, memory, writes) {
                Ok(()) => Ok(1),
                Err(error) => finish_guest_failure(error, guest_failure_value),
            }
        }
        (Win16CommonDialogOutput::Print {
            structure, input_dev_mode, dev_mode_capture,
            input_dev_names, dev_names_capture,
        }, Win16HostCommonDialogResult::Print {
            accepted, extended_error, dev_mode, dev_names, dc, flags,
            from_page, to_page, min_page, max_page, copies,
        }) => {
            state.common_dialog_state.last_extended_error =
                if accepted { 0 } else { extended_error };
            if !accepted { return Ok(0); }
            let mut record = match read_print_record(state, memory, &structure) {
                Ok(record) => record,
                Err(error) => return finish_guest_failure(error, guest_failure_value),
            };
            if record.dev_mode != input_dev_mode || record.dev_names != input_dev_names {
                return Ok(0);
            }
            if let Some(capture) = &dev_mode_capture {
                if capture.guest_handle() != input_dev_mode {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "PRINTDLG DEVMODE capture belongs to a different guest handle"));
                }
                if let Err(error) = capture.is_live(state, memory) {
                    return finish_guest_failure(error, guest_failure_value);
                }
            }
            if let Some(capture) = &dev_names_capture {
                if capture.guest_handle() != input_dev_names {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "PRINTDLG DEVNAMES capture belongs to a different guest handle"));
                }
                if let Err(error) = capture.is_live(state, memory) {
                    return finish_guest_failure(error, guest_failure_value);
                }
            }
            let dev_mode_bytes = dev_mode.as_ref().map(encode_devmode16).transpose()?;
            if let Some(bytes) = &dev_names { validate_dev_names(bytes)?; }
            let guest_dev_mode = match dev_mode_bytes {
                Some(bytes) => state.write_guest_global(input_dev_mode,
                    dev_mode_capture.as_ref().map(|block| block.identity()),
                    &bytes, memory, host)?,
                // A successful PrintDlg with no DEVMODE returns a null HGLOBAL.
                None => 0,
            };
            let guest_dev_names = match dev_names {
                Some(bytes) => state.write_guest_global(input_dev_names,
                    dev_names_capture.as_ref().map(|block| block.identity()),
                    &bytes, memory, host)?,
                None => 0,
            };
            let guest_dc = match dc {
                Some(dc) => state.guest_gdi.allocate_dc(dc).ok_or_else(|| RuntimeError::new(
                    Kind::ResourceExhausted, "Win16 HDC table is full after PRINTDLG"))?,
                None => 0,
            };
            record.dev_mode = guest_dev_mode;
            record.dev_names = guest_dev_names;
            record.dc = guest_dc;
            record.flags = flags;
            record.from_page = from_page;
            record.to_page = to_page;
            record.min_page = min_page;
            record.max_page = max_page;
            record.copies = copies;
            match commit_guest_writes(state, memory, vec![(structure, record.encode().to_vec())]) {
                Ok(()) => Ok(1),
                Err(error) => finish_guest_failure(error, guest_failure_value),
            }
        }
        (Win16CommonDialogOutput::FileTitle { output },
            Win16HostCommonDialogResult::FileTitle { status, title }) => {
            if let Some(range) = output {
                if title.len() > range.length() {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "GetFileTitle host output exceeds the captured Win16 capacity"));
                }
                if let Err(error) = commit_guest_writes(state, memory, vec![(range, title)]) {
                    return finish_guest_failure(error, guest_failure_value);
                }
            }
            Ok(status as u16 as u32)
        }
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "common-dialog worker returned a mismatched result variant")),
    }
}

fn read_open_file_record(
    state: &Win16State,
    memory: &Memory,
    range: &super::ranges::GuestOutputRange,
) -> Result<OpenFileName16, RuntimeError> {
    let bytes = range.read(state, memory)?;
    let raw: [u8; OpenFileName16::SIZE] = bytes.try_into().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "captured OPENFILENAME record has an invalid size"))?;
    Ok(OpenFileName16::decode(&raw))
}

fn open_file_bindings_match(
    record: &OpenFileName16,
    file_far: u32,
    file_capacity: usize,
    title_far: u32,
    title_capacity: u32,
    custom_far: u32,
    custom_capacity: u32,
) -> bool {
    record.file == file_far
        && usize::try_from(record.max_file).ok() == Some(file_capacity)
        && record.file_title == title_far
        && record.max_file_title == title_capacity
        && record.custom_filter == custom_far
        && record.max_custom_filter == custom_capacity
}

fn read_color_record(
    state: &Win16State,
    memory: &Memory,
    range: &super::ranges::GuestOutputRange,
) -> Result<ChooseColor16, RuntimeError> {
    let bytes = range.read(state, memory)?;
    let raw: [u8; ChooseColor16::SIZE] = bytes.try_into().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "captured CHOOSECOLOR record has an invalid size"))?;
    Ok(ChooseColor16::decode(&raw))
}

fn read_font_record(
    state: &Win16State,
    memory: &Memory,
    range: &super::ranges::GuestOutputRange,
) -> Result<ChooseFont16, RuntimeError> {
    let bytes = range.read(state, memory)?;
    let raw: [u8; ChooseFont16::SIZE] = bytes.try_into().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "captured CHOOSEFONT record has an invalid size"))?;
    Ok(ChooseFont16::decode(&raw))
}

fn read_print_record(
    state: &Win16State,
    memory: &Memory,
    range: &super::ranges::GuestOutputRange,
) -> Result<PrintDlg16, RuntimeError> {
    let bytes = range.read(state, memory)?;
    let raw: [u8; PrintDlg16::SIZE] = bytes.try_into().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant, "captured PRINTDLG record has an invalid size"))?;
    Ok(PrintDlg16::decode(&raw))
}
