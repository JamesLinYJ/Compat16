//! Win16 ACM format, filter, enumeration, suggestion, and choose exports.

use guest_core::{Registers, memory::Memory};
use win16_abi::Win16ReturnKind;
use zerocopy::IntoBytes;

use super::{
    Win16State, acm_copy, acm_dword, acm_far, acm_invariant, acm_output_range,
    acm_pointer, acm_read, acm_read_ansi_z, acm_validate_callback, acm_word, acm_wire_size,
    acm_warn_unsupported, acm_commit_output, MMSYSERR_INVALHANDLE,
    MMSYSERR_INVALFLAG, MMSYSERR_INVALPARAM, MMSYSERR_NOTSUPPORTED,
    ACMERR_NOTPOSSIBLE,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAcmChooseKind,
    Win16HostAcmDetailQuery, Win16HostAcmItemDetails, Win16HostAcmOperation,
    Win16HostAcmResult, Win16HostAcmTagDetails, Win16HostAcmTagKind,
};
use super::super::guest_ranges::commit_guest_writes;

macro_rules! guest_input {
    ($state:expr, $registers:expr, $return_to:expr, $code:expr, $kind:expr, $value:expr) => {
        match $value {
            Ok(value) => value,
            Err(error) => return $state.finish_acm_input_error(
                $registers, $return_to, error, $code, $kind),
        }
    };
}

const TAG_BYTES: usize = win16_abi::msacm_abi::ACMFORMATTAGDETAILS16_BYTES;
const ITEM_BYTES: usize = win16_abi::msacm_abi::ACMFORMATDETAILS16_BYTES;
const CHOOSE_BYTES: usize = win16_abi::msacm_abi::ACMFORMATCHOOSE16_BYTES;
const WAVEFORMATEX_FIXED: usize = win16_abi::msacm_abi::WAVEFORMATEX16_FIXED_BYTES;
const WAVEFILTER_FIXED: usize = win16_abi::msacm_abi::WAVEFILTER16_BYTES;
const ACM_FORMATDETAILSF_INDEX: u32 = 0;
const ACM_FORMATDETAILSF_FORMAT: u32 = 1;
const ACM_FORMATTAGDETAILSF_INDEX: u32 = 0;
const ACM_FORMATTAGDETAILSF_FORMATTAG: u32 = 1;
const ACM_FORMATTAGDETAILSF_LARGESTSIZE: u32 = 2;
const ACM_FORMATENUMF_WFORMATTAG: u32 = 0x0001_0000;
const ACM_FORMATENUMF_NCHANNELS: u32 = 0x0002_0000;
const ACM_FORMATENUMF_NSAMPLESPERSEC: u32 = 0x0004_0000;
const ACM_FORMATENUMF_WBITSPERSAMPLE: u32 = 0x0008_0000;
const ACM_FORMATENUMF_CONVERT: u32 = 0x0010_0000;
const ACM_FORMATENUMF_SUGGEST: u32 = 0x0020_0000;
const ACM_FILTERENUMF_DWFILTERTAG: u32 = 1;
const ACM_FORMATSUGGESTF_WFORMATTAG: u32 = 0x0001_0000;
const ACM_FORMATSUGGESTF_NCHANNELS: u32 = 0x0002_0000;
const ACM_FORMATSUGGESTF_NSAMPLESPERSEC: u32 = 0x0004_0000;
const ACM_FORMATSUGGESTF_WBITSPERSAMPLE: u32 = 0x0008_0000;
const ACM_CHOOSE_STYLEF_ENABLEHOOK: u32 = 0x0008;
const ACM_CHOOSE_STYLEF_ENABLETEMPLATE: u32 = 0x0010;
const ACM_CHOOSE_STYLEF_ENABLETEMPLATEHANDLE: u32 = 0x0020;
const ACM_FORMATCHOOSE_STYLEF_INITTOWFXSTRUCT: u32 = 0x0040;
const ACM_FILTERCHOOSE_STYLEF_INITTOFILTERSTRUCT: u32 = 0x0040;

#[path = "win16_acm_format_wire.rs"]
mod wire;
use wire::{copy_format_enum_fields, copy_format_suggest_fields,
    encode_choose_wire, encode_item_wire, encode_tag_wire, item_query, read_choose_wire,
    read_guest_field, read_item_wire, read_tag_wire, read_wavefilter, read_waveformat,
    tag_query, zeroed};

impl Win16State {
    pub(super) fn acm_format_export(
        &mut self,
        call: win16_abi::Win16MultimediaCall,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match call.ordinal {
            30 | 50 => self.acm_tag_details(&call, &mut cpu.regs, memory, host,
                return_to, return_kind),
            31 | 51 => self.acm_tag_enum(&call, cpu, dos, memory, host, return_to),
            40 | 60 => self.acm_choose(&call, &mut cpu.regs, memory, host,
                return_to, return_kind),
            41 | 61 => self.acm_item_details(&call, &mut cpu.regs, memory, host,
                return_to, return_kind),
            42 | 62 => self.acm_item_enum(&call, cpu, dos, memory, host, return_to),
            45 => self.acm_format_suggest(&call, &mut cpu.regs, memory, host,
                return_to, return_kind),
            _ => Err(acm_invariant("non-format export reached MSACM format dispatcher")),
        }
    }

    fn acm_tag_details(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest_driver = acm_word(call, 0)?;
        let kind = tag_kind(call.ordinal);
        let far = acm_far(call, 1)?;
        let (_, size) = match acm_wire_size(self, far, TAG_BYTES, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let output = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            acm_output_range(self, far, size, memory));
        let input = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            (|| { let pointer = acm_pointer(self, far, TAG_BYTES, memory)?;
                acm_read(self, pointer, TAG_BYTES, memory) })());
        let original = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind, read_tag_wire(&input));
        let flags = acm_dword(call, 2)?;
        let query = match tag_query(flags, original.tag_index, original.tag) {
            Ok(query) => query,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALFLAG), return_kind),
        };
        let driver = if guest_driver == 0 {
            None
        } else {
            match self.acm.object(guest_driver) {
                Some((kind @ (crate::Win16HostAcmObjectKind::Driver
                    | crate::Win16HostAcmObjectKind::DriverId), handle))
                    if kind == crate::Win16HostAcmObjectKind::Driver
                        || matches!(query, Win16HostAcmDetailQuery::Index { .. }) =>
                {
                    Some((kind, handle))
                }
                _ => return self.finish_acm(registers, return_to,
                    u32::from(MMSYSERR_INVALHANDLE), return_kind),
            }
        };
        let initial = Win16HostAcmTagDetails {
            index: original.tag_index,
            tag: original.tag,
            data_bytes: original.data_bytes,
            support: original.support,
            standard_count: original.standard_count,
            name: original.name,
        };
        let reply = host.win16_acm(Win16HostAcmOperation::TagDetails {
            kind, driver, query, initial,
        })?;
        let (result, details) = match reply {
            Win16HostAcmResult::TagDetails { result, details } => (result, details),
            _ => return Err(acm_invariant("ACM tag-details returned the wrong host result")),
        };
        if result == 0 {
            let wire = encode_tag_wire(details);
            acm_commit_output(self, memory, output, acm_copy(wire.as_bytes())?)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_tag_enum(
        &mut self, call: &win16_abi::Win16MultimediaCall, cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let registers = &mut cpu.regs;
        let guest_driver = acm_word(call, 0)?;
        let kind = tag_kind(call.ordinal);
        let driver = match self.acm_driver_optional(guest_driver) {
            Ok(value) => value,
            Err(code) => return self.complete_return(registers, return_to.0,
                return_to.1, return_to.2, code, Win16ReturnKind::Word),
        };
        let far = acm_far(call, 1)?;
        let (_, size) = match acm_wire_size(self, far, TAG_BYTES, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word),
        };
        let _template_range = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
            acm_output_range(self, far, size, memory));
        let input = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
            (|| { let pointer = acm_pointer(self, far, TAG_BYTES, memory)?;
                acm_read(self, pointer, TAG_BYTES, memory) })());
        let template = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word, read_tag_wire(&input));
        let callback = acm_far(call, 2)?;
        if let Err(error) = acm_validate_callback(self, callback, memory) {
            return self.finish_acm_input_error(registers, return_to, error,
                u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word);
        }
        let instance = acm_dword(call, 3)?;
        let flags = acm_dword(call, 4)?;
        self.retry_orphaned_acm_enumeration(host)?;
        let reply = host.win16_acm(Win16HostAcmOperation::TagEnum {
            kind, driver, template: Win16HostAcmTagDetails {
                index: template.tag_index, tag: template.tag,
                data_bytes: template.data_bytes, support: template.support,
                standard_count: template.standard_count, name: template.name,
            }, instance, flags,
        })?;
        let (result, records) = match reply {
            Win16HostAcmResult::Enumerated { result, records } => (result, records),
            _ => return Err(acm_invariant("ACM tag-enum returned the wrong host result")),
        };
        self.begin_acm_enumeration(cpu, dos, memory, host, return_to,
            Win16ReturnKind::Word, callback, instance, result, records)
    }

    fn acm_item_details(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest_driver = acm_word(call, 0)?;
        let kind = item_kind(call.ordinal);
        let driver = match self.acm_driver_optional(guest_driver) {
            Ok(value) => value,
            Err(code) => return self.finish_acm(registers, return_to, code, return_kind),
        };
        let far = acm_far(call, 1)?;
        let (_, size) = match acm_wire_size(self, far, ITEM_BYTES, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let output = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            acm_output_range(self, far, size, memory));
        let input = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            (|| { let pointer = acm_pointer(self, far, ITEM_BYTES, memory)?;
                acm_read(self, pointer, ITEM_BYTES, memory) })());
        let original = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind, read_item_wire(&input));
        let capacity = original.data_bytes;
        let nested_far = original.data_far;
        let nested = match acm_output_range(self, nested_far, capacity as usize, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let flags = acm_dword(call, 2)?;
        let query = match item_query(flags, original.index, original.tag) {
            Ok(query) => query,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALFLAG), return_kind),
        };
        let initial_data = if query == Win16HostAcmDetailQuery::Tag(original.tag)
            && kind == Win16HostAcmTagKind::Format
        {
            guest_input!(self, registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind,
                read_waveformat(self, nested_far, capacity, memory))
        } else if query == Win16HostAcmDetailQuery::Tag(original.tag)
            && kind == Win16HostAcmTagKind::Filter
        {
            guest_input!(self, registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind,
                (|| { let pointer = acm_pointer(self, nested_far,
                        capacity as usize, memory)?;
                    acm_read(self, pointer, capacity as usize, memory) })())
        } else {
            zeroed(capacity as usize)?
        };
        let initial = Win16HostAcmItemDetails {
            index: original.index, tag: original.tag, support: original.support,
            name: original.name, data: initial_data,
        };
        let mut writes = Vec::new();
        writes.try_reserve(2).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve ACM item-details output transaction", error))?;
        let mut wire_output = Vec::new();
        wire_output.try_reserve_exact(ITEM_BYTES).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM item-details wire output", error))?;
        let reply = host.win16_acm(Win16HostAcmOperation::ItemDetails {
            kind, driver, query, initial, capacity,
        })?;
        let (result, details) = match reply {
            Win16HostAcmResult::ItemDetails { result, details } => (result, details),
            _ => return Err(acm_invariant("ACM item-details returned the wrong host result")),
        };
        if result == 0 {
            if details.data.len() > capacity as usize {
                return Err(acm_invariant("ACM item-details exceeded its guest data buffer"));
            }
            let wire = encode_item_wire(&details, nested_far, capacity);
            wire_output.extend_from_slice(wire.as_bytes());
            writes.push((nested, details.data));
            writes.push((output, wire_output));
            commit_guest_writes(self, memory, writes)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_item_enum(
        &mut self, call: &win16_abi::Win16MultimediaCall, cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let registers = &mut cpu.regs;
        let guest_driver = acm_word(call, 0)?;
        let kind = item_kind(call.ordinal);
        let driver = match self.acm_driver_optional(guest_driver) {
            Ok(value) => value,
            Err(code) => return self.complete_return(registers, return_to.0,
                return_to.1, return_to.2, code, Win16ReturnKind::Word),
        };
        let far = acm_far(call, 1)?;
        let (_, size) = match acm_wire_size(self, far, ITEM_BYTES, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word),
        };
        let _template_range = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
            acm_output_range(self, far, size, memory));
        let input = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
            (|| { let pointer = acm_pointer(self, far, ITEM_BYTES, memory)?;
                acm_read(self, pointer, ITEM_BYTES, memory) })());
        let template = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word, read_item_wire(&input));
        let capacity = template.data_bytes;
        let nested_far = template.data_far;
        let callback = acm_far(call, 2)?;
        if let Err(error) = acm_validate_callback(self, callback, memory) {
            return self.finish_acm_input_error(registers, return_to, error,
                u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word);
        }
        let instance = acm_dword(call, 3)?;
        let flags = acm_dword(call, 4)?;
        if nested_far == 0 || capacity == 0 {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word);
        }
        let _template_range = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
            acm_output_range(self, nested_far, capacity as usize, memory));
        let data = if item_kind(call.ordinal) == Win16HostAcmTagKind::Format {
            if (capacity as usize) < WAVEFORMATEX_FIXED {
                return self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word);
            }
            let mut data = zeroed(capacity as usize)?;
            let full_format = flags & (ACM_FORMATENUMF_CONVERT | ACM_FORMATENUMF_SUGGEST) != 0;
            if full_format {
                let input = guest_input!(self, registers, return_to,
                    u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
                    read_waveformat(self, nested_far, capacity, memory));
                data[..input.len()].copy_from_slice(&input);
            } else {
                guest_input!(self, registers, return_to,
                    u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
                    copy_format_enum_fields(self, nested_far, flags, &mut data, memory));
            }
            data
        } else {
            if (capacity as usize) < WAVEFILTER_FIXED {
                return self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word);
            }
            let mut data = zeroed(capacity as usize)?;
            if flags & ACM_FILTERENUMF_DWFILTERTAG != 0 {
                let tag = guest_input!(self, registers, return_to,
                    u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word,
                    read_guest_field(self, nested_far, 4, 4, memory));
                data[4..8].copy_from_slice(&tag);
            }
            data
        };
        self.retry_orphaned_acm_enumeration(host)?;
        let reply = host.win16_acm(Win16HostAcmOperation::ItemEnum {
            kind, driver, template: Win16HostAcmItemDetails {
                index: template.index, tag: template.tag, support: template.support,
                name: template.name, data,
            }, capacity, instance, flags,
        })?;
        let (result, records) = match reply {
            Win16HostAcmResult::Enumerated { result, records } => (result, records),
            _ => return Err(acm_invariant("ACM item-enum returned the wrong host result")),
        };
        self.begin_acm_enumeration(cpu, dos, memory, host, return_to,
            Win16ReturnKind::Word, callback, instance, result, records)
    }

    fn acm_format_suggest(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest_driver = acm_word(call, 0)?;
        let driver = match self.acm_driver_optional(guest_driver) {
            Ok(value) => value,
            Err(code) => return self.finish_acm(registers, return_to, code, return_kind),
        };
        let source_far = acm_far(call, 1)?;
        let destination_far = acm_far(call, 2)?;
        let capacity = acm_dword(call, 3)?;
        let flags = acm_dword(call, 4)?;
        let destination = match acm_output_range(self, destination_far, capacity as usize, memory) {
            Ok(range) => range,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let source = match read_waveformat(self, source_far, u32::MAX, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        if (capacity as usize) < WAVEFORMATEX_FIXED {
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind);
        }
        let mut destination_data = zeroed(capacity as usize)?;
        guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            copy_format_suggest_fields(self, destination_far, flags,
                &mut destination_data, memory));
        let reply = host.win16_acm(Win16HostAcmOperation::FormatSuggest {
            driver, source, destination: destination_data, flags,
        })?;
        let (result, data) = match reply {
            Win16HostAcmResult::FormatSuggest { result, destination } => (result, destination),
            _ => return Err(acm_invariant("acmFormatSuggest returned the wrong host result")),
        };
        if result == 0 {
            if data.len() > capacity as usize {
                return Err(acm_invariant("acmFormatSuggest exceeded its guest destination buffer"));
            }
            acm_commit_output(self, memory, destination, data)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_choose(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let choose_far = acm_far(call, 0)?;
        let (_, size) = match acm_wire_size(self, choose_far, CHOOSE_BYTES, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let choose_output = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            acm_output_range(self, choose_far, size, memory));
        let input_bytes = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind,
            (|| { let pointer = acm_pointer(self, choose_far, CHOOSE_BYTES, memory)?;
                acm_read(self, pointer, CHOOSE_BYTES, memory) })());
        let initial = guest_input!(self, registers, return_to,
            u32::from(MMSYSERR_INVALPARAM), return_kind, read_choose_wire(&input_bytes));
        let kind = if call.ordinal == 40 {
            Win16HostAcmChooseKind::Format
        } else { Win16HostAcmChooseKind::Filter };
        if initial.style & (ACM_CHOOSE_STYLEF_ENABLEHOOK
            | ACM_CHOOSE_STYLEF_ENABLETEMPLATE
            | ACM_CHOOSE_STYLEF_ENABLETEMPLATEHANDLE) != 0
        {
            acm_warn_unsupported(self, host, call.ordinal,
                "custom Win16 choose hooks/templates have no proven guest callback or module-resource thunk");
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_NOTSUPPORTED), return_kind);
        }
        let owner = if initial.owner_window == 0 {
            None
        } else {
            let Some(owner) = self.window_handles.get(&initial.owner_window).copied() else {
                return self.finish_acm(registers, return_to,
                    u32::from(MMSYSERR_INVALHANDLE), return_kind);
            };
            Some(owner)
        };
        let data_far = initial.data_far;
        let data_capacity = initial.data_bytes;
        let format_initialized = kind == Win16HostAcmChooseKind::Format
            && initial.style & ACM_FORMATCHOOSE_STYLEF_INITTOWFXSTRUCT != 0;
        if kind == Win16HostAcmChooseKind::Format
            && data_capacity < WAVEFORMATEX_FIXED as u32
            && !format_initialized
        {
            // With INIT absent the guest bytes are undefined, so they cannot
            // establish the 16-byte PCMWAVEFORMAT to 18-byte WAVEFORMATEX map.
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind);
        }
        let data_output = match acm_output_range(self, data_far, data_capacity as usize, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let initial_style = if kind == Win16HostAcmChooseKind::Format {
            ACM_FORMATCHOOSE_STYLEF_INITTOWFXSTRUCT
        } else {
            ACM_FILTERCHOOSE_STYLEF_INITTOFILTERSTRUCT
        };
        let mut data = zeroed(data_capacity as usize)?;
        if initial.style & initial_style != 0 {
            let initial_data = if kind == Win16HostAcmChooseKind::Format {
                match read_waveformat(self, data_far, data_capacity, memory) {
                    Ok(value) => value,
                    Err(error) => return self.finish_acm_input_error(registers,
                        return_to, error, u32::from(MMSYSERR_INVALPARAM), return_kind),
                }
            } else {
                if (data_capacity as usize) < WAVEFILTER_FIXED {
                    return self.finish_acm(registers, return_to,
                        u32::from(MMSYSERR_INVALPARAM), return_kind);
                }
                let value = guest_input!(self, registers, return_to,
                    u32::from(MMSYSERR_INVALPARAM), return_kind,
                    read_wavefilter(self, data_far, memory));
                if value.len() > data_capacity as usize {
                    return self.finish_acm(registers, return_to,
                        u32::from(MMSYSERR_INVALPARAM), return_kind);
                }
                value
            };
            data[..initial_data.len()].copy_from_slice(&initial_data);
        }
        let title = if initial.title_far == 0 { None } else {
            match acm_read_ansi_z(self, initial.title_far, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let saved_name_capacity = initial.saved_name_chars;
        let saved_name_output = if initial.saved_name_far == 0 || saved_name_capacity == 0 {
            None
        } else {
            match acm_output_range(self, initial.saved_name_far,
                saved_name_capacity as usize, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let saved_name = match saved_name_output.as_ref() {
            Some(output) => match output.read(self, memory) {
                Ok(value) => Some(value),
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            },
            None => None,
        };
        let enum_data = if initial.enum_flags == 0 {
            Vec::new()
        } else if initial.enum_data_far == 0 {
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_INVALPARAM), return_kind);
        } else if kind == Win16HostAcmChooseKind::Format {
            let full_format = initial.enum_flags
                & (ACM_FORMATENUMF_CONVERT | ACM_FORMATENUMF_SUGGEST) != 0;
            if full_format {
                // CONVERT and SUGGEST require an initialized complete format,
                // including any cbSize extension bytes.
                match read_waveformat(self, initial.enum_data_far, u32::MAX, memory) {
                    Ok(value) => value,
                    Err(error) => return self.finish_acm_input_error(registers, return_to,
                        error, u32::from(MMSYSERR_INVALPARAM), return_kind),
                }
            } else {
                // The chooser flags select individual WAVEFORMATEX fields.
                // Keep other bytes, especially cbSize, uninspected.
                let mut data = zeroed(WAVEFORMATEX_FIXED)?;
                if let Err(error) = copy_format_enum_fields(
                    self, initial.enum_data_far, initial.enum_flags, &mut data, memory,
                ) {
                    return self.finish_acm_input_error(registers, return_to,
                        error, u32::from(MMSYSERR_INVALPARAM), return_kind);
                }
                data
            }
        } else {
            match read_wavefilter(self, initial.enum_data_far, memory) {
                Ok(value) => value,
                Err(error) => return self.finish_acm_input_error(registers, return_to,
                    error, u32::from(MMSYSERR_INVALPARAM), return_kind),
            }
        };
        let mut writes = Vec::new();
        writes.try_reserve(3).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve ACM choose output transaction", error))?;
        let mut choose_wire = Vec::new();
        choose_wire.try_reserve_exact(CHOOSE_BYTES).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ACM choose structure output", error))?;
        let reply = host.win16_acm(Win16HostAcmOperation::Choose {
            kind, owner, style: initial.style, data, data_capacity, title,
            tag_name: initial.tag_name, item_name: initial.item_name,
            saved_name, saved_name_capacity, enum_flags: initial.enum_flags,
            enum_data,
        })?;
        let (result, data, data_bytes, tag_name, item_name, saved_name) = match reply {
            Win16HostAcmResult::Chosen { result, data, data_bytes, tag_name,
                item_name, saved_name } =>
                (result, data, data_bytes, tag_name, item_name, saved_name),
            _ => return Err(acm_invariant("ACM choose returned the wrong host result")),
        };
        if result == u32::from(MMSYSERR_NOTSUPPORTED) && owner.is_some() {
            acm_warn_unsupported(self, host, call.ordinal,
                "owner HWND belongs to the isolated USER worker and cannot be passed to the native ACM chooser");
        }
        if result == 0 {
            if data.len() > data_capacity as usize
                || data_bytes > data_capacity
                || data_bytes as usize != data.len()
                || saved_name.as_ref().is_some_and(|value|
                    value.len() != saved_name_capacity as usize)
            {
                return Err(acm_invariant("ACM choose returned more bytes than the guest buffers"));
            }
            if saved_name_output.is_some() && saved_name.is_none() {
                return Err(acm_invariant("ACM choose omitted a requested saved-name result"));
            }
            let wire = encode_choose_wire(&initial, tag_name, item_name, data_bytes);
            choose_wire.extend_from_slice(wire.as_bytes());
            writes.push((data_output, data));
            if let (Some(output), Some(saved_name)) = (saved_name_output, saved_name) {
                writes.push((output, saved_name));
            }
            writes.push((choose_output, choose_wire));
            commit_guest_writes(self, memory, writes)?;
        } else if result == ACMERR_NOTPOSSIBLE {
            let wire = encode_choose_wire(&initial, initial.tag_name, initial.item_name, data_bytes);
            choose_wire.extend_from_slice(wire.as_bytes());
            writes.push((choose_output, choose_wire));
            commit_guest_writes(self, memory, writes)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_optional(
        &self, guest: u16,
    ) -> Result<Option<crate::Win16HostAcmHandle>, u32> {
        if guest == 0 { return Ok(None); }
        self.acm.handle(guest, crate::Win16HostAcmObjectKind::Driver)
            .map(Some).ok_or(u32::from(MMSYSERR_INVALHANDLE))
    }

}

fn tag_kind(ordinal: u16) -> Win16HostAcmTagKind {
    if ordinal == 50 || ordinal == 51 { Win16HostAcmTagKind::Filter }
    else { Win16HostAcmTagKind::Format }
}

fn item_kind(ordinal: u16) -> Win16HostAcmTagKind {
    if ordinal == 61 || ordinal == 62 { Win16HostAcmTagKind::Filter }
    else { Win16HostAcmTagKind::Format }
}
