//! Direct MSACM metrics and driver-object exports.

use std::{error::Error, fmt};

use guest_core::{Registers, memory::Memory};
use win16_abi::Win16ReturnKind;
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U16, U32};

use super::{
    Win16State, acm_dword, acm_far, acm_output_range, acm_read_ansi_z, acm_word,
    acm_validate_callback, acm_wire_size, AcmU16Write, acm_invariant, acm_warn_unsupported,
    MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOMEM, MMSYSERR_NOTSUPPORTED,
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAcmDriverDetails,
    Win16HostAcmObjectKind, Win16HostAcmOperation, Win16HostAcmResult,
    Win16HostIcon,
};

const ACM_DRIVERADDF_TYPEMASK: u32 = 0x0007;
const ACM_DRIVERADDF_NAME: u32 = 0x0001;
const DRIVER_DETAILS_BYTES: usize = win16_abi::msacm_abi::ACMDRIVERDETAILS16_BYTES;

#[derive(Debug)]
struct AcmIconReleaseFailure {
    guest_result: u32,
    cleanup: RuntimeError,
}

impl fmt::Display for AcmIconReleaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "guest MMRESULT {:#x}; copied host icon release failed: {}",
            self.guest_result, self.cleanup)
    }
}

impl Error for AcmIconReleaseFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.cleanup) }
}

impl Win16State {
    pub(super) fn acm_driver_export(
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
            8 => self.acm_metrics(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            10 => self.acm_driver_enum(&call, cpu, dos, memory, host, return_to),
            11 => self.acm_driver_details(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            12 => self.acm_driver_add(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            13 => self.acm_driver_remove(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            14 => self.acm_driver_open(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            15 => self.acm_driver_close(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            16 => self.acm_driver_message(&call, &mut cpu.regs, host, return_to, return_kind),
            17 => self.acm_driver_id(&call, &mut cpu.regs, memory, host, return_to, return_kind),
            18 => self.acm_driver_priority(&call, &mut cpu.regs, host, return_to, return_kind),
            _ => Err(acm_invariant("non-driver export reached MSACM driver dispatcher")),
        }
    }

    fn acm_metrics(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let _ = (call, memory);
        acm_warn_unsupported(self, host, 8,
            "the local Win16 SDK contract does not establish acmMetrics argument order");
        self.finish_acm(registers, return_to, u32::from(MMSYSERR_NOTSUPPORTED), return_kind)
    }

    fn acm_driver_enum(
        &mut self, call: &win16_abi::Win16MultimediaCall, cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let callback = acm_far(call, 0)?;
        if let Err(error) = acm_validate_callback(self, callback, memory) {
            return self.finish_acm_input_error(&mut cpu.regs, return_to, error,
                u32::from(MMSYSERR_INVALPARAM), Win16ReturnKind::Word);
        }
        let instance = acm_dword(call, 1)?;
        let flags = acm_dword(call, 2)?;
        // Do not start another borrowed-identity batch while an earlier
        // cleanup failure still owns tokens that must be retried.
        self.retry_orphaned_acm_enumeration(host)?;
        let reply = host.win16_acm(Win16HostAcmOperation::DriverEnum { instance, flags })?;
        let (result, records) = match reply {
            Win16HostAcmResult::Enumerated { result, records } => (result, records),
            _ => return Err(acm_invariant("acmDriverEnum returned the wrong host result")),
        };
        self.begin_acm_enumeration(cpu, dos, memory, host, return_to,
            Win16ReturnKind::Word, callback, instance, result, records)
    }

    fn acm_driver_details(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let driver_id = acm_word(call, 0)?;
        let Some(driver) = self.acm.handle(driver_id, Win16HostAcmObjectKind::DriverId) else {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let far = acm_far(call, 1)?;
        let (_, size) = match acm_wire_size(self, far, DRIVER_DETAILS_BYTES, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let output = match acm_output_range(self, far, size, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let flags = acm_dword(call, 2)?;
        // If publication later fails, retain a preallocated retry slot for the
        // exact copied host icon before the native call can create that token.
        self.acm.reserve_orphan_icon_slot()?;
        let reply = host.win16_acm(Win16HostAcmOperation::DriverDetails {
            driver_id: driver, flags,
        })?;
        let (result, details) = match reply {
            Win16HostAcmResult::DriverDetails { result, details } => (result, details),
            _ => return Err(acm_invariant("acmDriverDetails returned the wrong host result")),
        };
        if result == 0 {
            let (icon, unpublished) = match details.icon {
                None => (0, None),
                Some(value) => match self.guest_images.allocate_icon(value) {
                    Some((handle, is_new)) => (handle, is_new.then_some((handle, value))),
                    None => {
                        self.release_unpublished_acm_icon(value, u32::from(MMSYSERR_NOMEM), host);
                        return self.finish_acm(registers, return_to,
                            u32::from(MMSYSERR_NOMEM), return_kind);
                    }
                },
            };
            let wire = driver_details_wire(details, icon);
            let data = match super::acm_copy(wire.as_bytes()) {
                Ok(data) => data,
                Err(primary) => return Err(self.rollback_unpublished_acm_icon(
                    unpublished, primary, host)),
            };
            if let Err(primary) = super::acm_commit_output(self, memory, output, data) {
                return Err(self.rollback_unpublished_acm_icon(unpublished, primary, host));
            }
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn rollback_unpublished_acm_icon(
        &mut self,
        unpublished: Option<(u16, Win16HostIcon)>,
        primary: RuntimeError,
        host: &mut impl RuntimeHost,
    ) -> RuntimeError {
        let Some((handle, value)) = unpublished else { return primary; };
        if !self.guest_images.take_unpublished_icon(handle, value) {
            // Keep the host token owned by the image table when the exact
            // provisional guest entry cannot be proven removed.
            return super::combine_acm_failures(primary,
                acm_invariant("unpublished ACM icon identity changed before rollback"),
                "ACM driver-details output failed and its provisional icon owner changed");
        }
        match host.win16_release_icon(value) {
            Ok(()) => primary,
            Err(cleanup) => {
                self.acm.orphaned_icons.push(value);
                super::combine_acm_failures(primary, cleanup,
                    "ACM driver-details output failed and its copied icon could not be released")
            }
        }
    }

    fn release_unpublished_acm_icon(
        &mut self,
        icon: Win16HostIcon,
        guest_result: u32,
        host: &mut impl RuntimeHost,
    ) {
        if let Err(cleanup) = host.win16_release_icon(icon) {
            self.acm.orphaned_icons.push(icon);
            host.report_diagnostic(&Diagnostic::warning(Kind::ResourceExhausted,
                "ACM driver details returned MMSYSERR_NOMEM after guest icon aliases were exhausted")
                .with_cause(AcmIconReleaseFailure { guest_result, cleanup }));
        }
    }

    fn acm_driver_add(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let output = match acm_output_range(self, acm_far(call, 0)?, 2, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let output = AcmU16Write::reserve(output)?;
        let module_instance = acm_word(call, 1)?;
        let parameter = acm_dword(call, 2)?;
        let priority = acm_dword(call, 3)?;
        let flags = acm_dword(call, 4)?;
        if flags & ACM_DRIVERADDF_TYPEMASK != ACM_DRIVERADDF_NAME || module_instance != 0 {
            acm_warn_unsupported(self, host, 12,
                "FUNCTION and NOTIFYHWND driver-add forms need Win16 procedure/window mapping");
            return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_NOTSUPPORTED), return_kind);
        }
        let name = match acm_read_ansi_z(self, parameter, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let alias = match self.acm.reserve_handle_alias()? {
            Some(alias) => alias,
            None => return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_NOMEM), return_kind),
        };
        let reply = host.win16_acm(Win16HostAcmOperation::DriverAdd {
            module_instance, name: Some(name), priority, flags,
        })?;
        let (result, handle) = match reply {
            Win16HostAcmResult::Handle { result, handle } => (result, handle),
            _ => return Err(acm_invariant("acmDriverAdd returned the wrong host result")),
        };
        if result == 0 {
            let Some(handle) = handle else {
                return Err(acm_invariant("successful acmDriverAdd returned no driver identity"));
            };
            let guest = self.acm.store_reserved_handle(
                Win16HostAcmObjectKind::DriverId, handle, alias)?;
            self.acm.added_driver_ids.insert(guest);
            output.commit(self, memory, guest)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_remove(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        _memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest = acm_word(call, 0)?;
        let Some(driver_id) = self.acm.handle(guest, Win16HostAcmObjectKind::DriverId) else {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let flags = acm_dword(call, 1)?;
        let result = scalar(host.win16_acm(Win16HostAcmOperation::DriverRemove {
            driver_id, flags,
        })?)?;
        if result == 0 {
            self.acm.handles.remove(&guest);
            self.acm.added_driver_ids.remove(&guest);
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_open(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let output = match acm_output_range(self, acm_far(call, 0)?, 2, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let output = AcmU16Write::reserve(output)?;
        let guest_id = acm_word(call, 1)?;
        let Some(driver_id) = self.acm.handle(guest_id, Win16HostAcmObjectKind::DriverId) else {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let flags = acm_dword(call, 2)?;
        let alias = match self.acm.reserve_handle_alias()? {
            Some(alias) => alias,
            None => return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_NOMEM), return_kind),
        };
        let reply = host.win16_acm(Win16HostAcmOperation::DriverOpen { driver_id, flags })?;
        let (result, handle) = match reply {
            Win16HostAcmResult::Handle { result, handle } => (result, handle),
            _ => return Err(acm_invariant("acmDriverOpen returned the wrong host result")),
        };
        if result == 0 {
            let Some(handle) = handle else {
                return Err(acm_invariant("successful acmDriverOpen returned no driver handle"));
            };
            let guest = self.acm.store_reserved_handle(
                Win16HostAcmObjectKind::Driver, handle, alias)?;
            output.commit(self, memory, guest)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_close(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        _memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest = acm_word(call, 0)?;
        let Some(driver) = self.acm.handle(guest, Win16HostAcmObjectKind::Driver) else {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let flags = acm_dword(call, 1)?;
        let result = scalar(host.win16_acm(Win16HostAcmOperation::DriverClose {
            driver, flags,
        })?)?;
        if result == 0 { self.acm.handles.remove(&guest); }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_message(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest = acm_word(call, 0)?;
        if self.acm.handle(guest, Win16HostAcmObjectKind::Driver).is_none() {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        }
        let message = acm_word(call, 1)?;
        let param1 = acm_dword(call, 2)?;
        let param2 = acm_dword(call, 3)?;
        acm_warn_unsupported(self, host, 16,
            "driver-specific message parameters are not safely classifiable as scalar ABI values");
        let _ = (message, param1, param2);
        self.finish_acm(registers, return_to,
            u32::from(MMSYSERR_NOTSUPPORTED), return_kind)
    }

    fn acm_driver_id(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32), return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest_object = acm_word(call, 0)?;
        let Some((object_kind, object)) = self.acm.object(guest_object) else {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let output = match acm_output_range(self, acm_far(call, 1)?, 2, memory) {
            Ok(value) => value,
            Err(error) => return self.finish_acm_input_error(registers, return_to,
                error, u32::from(MMSYSERR_INVALPARAM), return_kind),
        };
        let output = AcmU16Write::reserve(output)?;
        let flags = acm_dword(call, 2)?;
        let alias = match self.acm.reserve_handle_alias()? {
            Some(alias) => alias,
            None => return self.finish_acm(registers, return_to,
                u32::from(MMSYSERR_NOMEM), return_kind),
        };
        let reply = host.win16_acm(Win16HostAcmOperation::DriverId {
            object_kind, object, flags,
        })?;
        let (result, handle) = match reply {
            Win16HostAcmResult::Handle { result, handle } => (result, handle),
            _ => return Err(acm_invariant("acmDriverID returned the wrong host result")),
        };
        if result == 0 {
            let Some(handle) = handle else {
                return Err(acm_invariant("successful acmDriverID returned no identity"));
            };
            let guest = self.acm.store_reserved_handle(
                Win16HostAcmObjectKind::DriverId, handle, alias)?;
            output.commit(self, memory, guest)?;
        }
        self.finish_acm(registers, return_to, result, return_kind)
    }

    fn acm_driver_priority(
        &mut self, call: &win16_abi::Win16MultimediaCall, registers: &mut Registers,
        host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let guest = acm_word(call, 0)?;
        let Some(driver_id) = self.acm.handle(guest, Win16HostAcmObjectKind::DriverId) else {
            return self.finish_acm(registers, return_to, u32::from(MMSYSERR_INVALHANDLE), return_kind);
        };
        let priority = acm_dword(call, 1)?;
        let flags = acm_dword(call, 2)?;
        let result = scalar(host.win16_acm(Win16HostAcmOperation::DriverPriority {
            driver_id, priority, flags,
        })?)?;
        self.finish_acm(registers, return_to, result, return_kind)
    }
}

fn scalar(result: Win16HostAcmResult) -> Result<u32, RuntimeError> {
    match result {
        Win16HostAcmResult::Scalar(value) => Ok(value),
        _ => Err(acm_invariant("MSACM host operation returned a non-scalar result")),
    }
}

fn driver_details_wire(details: Win16HostAcmDriverDetails, icon_handle: u16)
    -> win16_abi::msacm_abi::AcmDriverDetails16Wire {
    win16_abi::msacm_abi::AcmDriverDetails16Wire {
        structure_bytes: U32::new(DRIVER_DETAILS_BYTES as u32),
        type_fourcc: U32::new(details.type_fourcc),
        compression_fourcc: U32::new(details.compression_fourcc),
        manufacturer_id: U16::new(details.manufacturer_id),
        product_id: U16::new(details.product_id),
        acm_version: U32::new(details.acm_version),
        driver_version: U32::new(details.driver_version),
        support: U32::new(details.support),
        format_tag_count: U32::new(details.format_tag_count),
        filter_tag_count: U32::new(details.filter_tag_count),
        icon_handle: U16::new(icon_handle),
        short_name: details.short_name,
        long_name: details.long_name,
        copyright: details.copyright,
        licensing: details.licensing,
        features: details.features,
    }
}
