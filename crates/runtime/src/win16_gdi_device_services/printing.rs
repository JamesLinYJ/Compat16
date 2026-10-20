//! GDI printing services used by the Win16 device request decoder.

use super::*;

impl Win16State {
    pub(super) fn reset_dc(
        &mut self,
        guest_dc: u16,
        devmode_far: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let devmode =
            if devmode_far == 0 {
                None
            } else {
                let Some(mode) = self.decode_guest_devmode(devmode_far, memory)? else {
                    return Ok(0);
                };
                if !mode.has_mapped_fields() {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 ResetDC selects fields without a verified native value conversion")
                    .with_context("Win16 GDI ResetDC"));
                    return Ok(0);
                }
                Some(mode)
            };
        match host.win16_gdi_device(Operation::ResetDc { dc, devmode })? {
            HostResult::Dc(Some(returned)) if returned == dc => Ok(u32::from(guest_dc)),
            HostResult::Dc(Some(_)) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native ResetDC changed the opaque Win16 device-context identity",
            )),
            HostResult::Dc(None) => Ok(0),
            _ => Err(wrong_device_result("ResetDC")),
        }
    }

    pub(super) fn start_doc(
        &mut self,
        guest_dc: u16,
        doc_info: Option<DocInfo16>,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(SP_ERROR16);
        };
        let Some(info) = doc_info else {
            return Ok(SP_ERROR16);
        };
        match host.win16_gdi_device(Operation::StartDoc {
            dc,
            document_name: info.document_name,
            output: info.output,
        })? {
            HostResult::Count(value) => {
                let status = value as u16 as u32;
                if positive_spool_status(status) {
                    self.guest_gdi.set_print_document_open(guest_dc, true);
                }
                Ok(status)
            }
            _ => Err(wrong_device_result("StartDoc")),
        }
    }

    /// `AbortDoc` for a document `StartDoc` already opened. A DC with no open
    /// document is left unchanged.
    pub(in super::super) fn abort_print_document_if_open(
        &mut self,
        guest_dc: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.guest_gdi.print_document_open(guest_dc) {
            self.print(PrintOperation::AbortDocument, guest_dc, host)?;
        }
        Ok(())
    }

    pub(super) fn print(
        &mut self,
        operation: PrintOperation,
        guest_dc: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(SP_ERROR16);
        };
        let operation = match operation {
            PrintOperation::EndDocument => Win16PrintOperation::EndDocument,
            PrintOperation::StartPage => Win16PrintOperation::StartPage,
            PrintOperation::EndPage => Win16PrintOperation::EndPage,
            PrintOperation::AbortDocument => Win16PrintOperation::AbortDocument,
        };
        match host.win16_gdi_device(Operation::Print { operation, dc })? {
            HostResult::Count(value) => {
                let status = value as u16 as u32;
                if positive_spool_status(status)
                    && matches!(
                        operation,
                        Win16PrintOperation::EndDocument | Win16PrintOperation::AbortDocument
                    )
                {
                    self.guest_gdi.set_print_document_open(guest_dc, false);
                }
                Ok(status)
            }
            _ => Err(wrong_device_result("print lifecycle")),
        }
    }
}

fn positive_spool_status(status: u32) -> bool {
    i16::try_from(status).ok().is_some_and(|value| value > 0)
}
