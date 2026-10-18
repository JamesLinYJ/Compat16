//! Resumable ExtDeviceMode and generation-checked variable-length writeback.
use super::{
    GuestOutputRange, Win16CommonDialogContinuation, Win16CommonDialogOutput, Win16State,
    WindowReturn,
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCommonDialogOperation,
    Win16HostPrinterMode, Win16HostPrinterModeResult, Win16WindowOperation,
};
use guest_core::{Registers, memory::Memory};
use win16_abi::{Win16PrinterRequest, Win16ReturnKind};

impl Win16State {
    pub(in crate::win16_runtime) fn begin_ext_device_mode(
        &mut self,
        request: Win16PrinterRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let Win16PrinterRequest::ExtDeviceMode {
            owner,
            driver_instance: _,
            output,
            device,
            port,
            input,
            profile,
            mode,
        } = request
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "wrong printer request route",
            ));
        };
        let prepared: Result<_, RuntimeError> = (|| {
            let owner = self.common_dialog_owner(owner)?;
            let input = if mode & 8 != 0 && input != 0 {
                Some(self.decode_guest_devmode(input, memory)?.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InvalidInput,
                        "malformed ExtDeviceMode input structure",
                    )
                })?)
            } else {
                None
            };
            if input
                .as_ref()
                .is_some_and(|value| !value.has_mapped_fields())
            {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "unsupported ExtDeviceMode input layout",
                ));
            }
            let output = if mode & 2 != 0 && output != 0 {
                let pointer = self
                    .selectors
                    .pointer_from_far(output)
                    .map_err(crate::runtime_error)?;
                let (_, base, size) = self
                    .selectors
                    .allocation_range(pointer.selector())
                    .map_err(crate::runtime_error)?;
                let descriptor = self
                    .selectors
                    .describe(pointer.selector())
                    .map_err(crate::runtime_error)?;
                let start = u64::from(descriptor.base.0) + u64::from(pointer.offset());
                let end = u64::from(base.0) + u64::from(size);
                let capacity = end
                    .checked_sub(start)
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|n| *n != 0)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::GuestFault,
                            "ExtDeviceMode output lies outside its owning allocation",
                        )
                    })?
                    .min(usize::from(u16::MAX));
                Some(GuestOutputRange::capture(self, memory, pointer, capacity)?)
            } else {
                None
            };
            let operation = Win16HostPrinterMode {
                owner,
                device,
                port,
                input,
                profile,
                mode,
                output_capacity: output.as_ref().map(GuestOutputRange::length),
            };
            Ok((operation, output))
        })();
        let (operation, output) = match prepared {
            Ok(value) => value,
            Err(error)
                if matches!(
                    error.kind(),
                    Kind::GuestFault
                        | Kind::InvalidInput
                        | Kind::CompatibilityGap
                        | Kind::ResourceExhausted
                ) =>
            {
                host.report_diagnostic(
                    &Diagnostic::warning(
                        error.kind(),
                        "ExtDeviceMode rejected guest input before native execution",
                    )
                    .with_cause(error),
                );
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u16::MAX.into(),
                    return_kind,
                );
            }
            Err(error) => return Err(error),
        };
        // This API does not change CommDlgExtendedError. The existing window
        // operation owns callbacks and a replay-safe completion journal.
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::CommonDialog(Win16HostCommonDialogOperation::PrinterMode(
                operation,
            )),
            WindowReturn::CommonDialog(Win16CommonDialogContinuation {
                return_kind,
                guest_failure_value: u16::MAX.into(),
                output: Win16CommonDialogOutput::PrinterMode { output },
            }),
            return_to,
        )
    }
}

pub(super) fn finish(
    state: &Win16State,
    memory: &mut Memory,
    output: Option<GuestOutputRange>,
    result: Win16HostPrinterModeResult,
) -> Result<u32, RuntimeError> {
    if result.value == 1 {
        if let Some(value) = result.output {
            let Some(output) = output else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "unexpected ExtDeviceMode output",
                ));
            };
            let bytes = super::support::encode_devmode16(&value)?;
            if bytes.len() > output.length() {
                return Ok(u16::MAX.into());
            }
            if let Err(error) = super::ranges::commit_guest_output(state, memory, &output, &bytes) {
                return super::finish_guest_failure(error, u16::MAX.into());
            }
        } else if output.is_some() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "IDOK ExtDeviceMode omitted requested data",
            ));
        }
    } else if result.output.is_some() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "unsuccessful ExtDeviceMode supplied output",
        ));
    }
    Ok(result.value as u16 as u32)
}

#[cfg(test)]
#[path = "win16_commdlg_printer_tests.rs"]
mod tests;
