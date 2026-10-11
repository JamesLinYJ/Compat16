//! Win16 GDI device-context creation and selected-font queries.

use guest_core::memory::Memory;
use win16_abi::gdi_abi::{
    decode_devmode16, DevMode16Error, TextMetric16, DEVMODE16_DRIVER_EXTRA_OFFSET,
    DEVMODE16_HEADER_SIZE, DEVMODE16_SIZE_OFFSET, DEVMODE16_SUPPORTED_FIELDS,
    TEXTMETRIC16_SIZE,
};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDevMode};

impl Win16State {
    pub(super) fn create_dc(
        &mut self,
        driver: Option<Vec<u8>>,
        device: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
        init_data: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.create_device_context(driver, device, output, init_data, memory, host, false)
    }

    pub(super) fn create_ic(
        &mut self,
        driver: Option<Vec<u8>>,
        device: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
        init_data: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.create_device_context(driver, device, output, init_data, memory, host, true)
    }

    fn create_device_context(
        &mut self,
        driver: Option<Vec<u8>>,
        device: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
        init_data: u32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        information_context: bool,
    ) -> Result<u16, RuntimeError> {
        let devmode = if init_data == 0 {
            None
        } else {
            let Some(mode) = self.decode_guest_devmode(init_data, memory)? else {
                // Malformed DEVMODE values produce the GDI API's ordinary
                // NULL result, while invalid guest memory remains a guest fault.
                return Ok(0);
            };
            Some(mode)
        };
        if let Some(mode) = devmode.as_ref() {
            let unsupported_fields = mode.fields & !DEVMODE16_SUPPORTED_FIELDS;
            if unsupported_fields != 0 {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 DEVMODE selects fields without a verified native value conversion")
                    .with_context("Win16 GDI CreateDC/CreateIC"));
                return Ok(0);
            }
        }
        let driver = driver.as_deref();
        let device = device.as_deref();
        let output = output.as_deref();
        let native = if information_context {
            host.win16_create_ic(driver, device, output, devmode.as_ref())?
        } else {
            host.win16_create_dc(driver, device, output, devmode.as_ref())?
        };
        let Some(native) = native else { return Ok(0); };
        match self.guest_gdi.allocate_dc(native) {
            Some(handle) => Ok(handle),
            None => {
                let _ = host.win16_delete_dc(native)?;
                Ok(0)
            }
        }
    }

    pub(super) fn decode_guest_devmode(
        &self,
        far_pointer: u32,
        memory: &Memory,
    ) -> Result<Option<Win16HostDevMode>, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(far_pointer)
            .map_err(crate::runtime_error)?;
        // dmSize and dmDriverExtra are inside the fixed 40-byte DEVMODE header.
        let header = self.read_text_bytes(memory, pointer, DEVMODE16_HEADER_SIZE)?;
        let public_size = u16::from_le_bytes([
            header[DEVMODE16_SIZE_OFFSET], header[DEVMODE16_SIZE_OFFSET + 1],
        ]);
        let extra_size = u16::from_le_bytes([
            header[DEVMODE16_DRIVER_EXTRA_OFFSET],
            header[DEVMODE16_DRIVER_EXTRA_OFFSET + 1],
        ]);
        let Some(total_size) = usize::from(public_size).checked_add(usize::from(extra_size))
        else {
            return Ok(None);
        };
        if usize::from(public_size) < DEVMODE16_HEADER_SIZE {
            return Ok(None);
        }
        // Copy the entire declared structure and private tail through checked
        // selectors before converting it; never pass the guest FAR pointer on.
        let bytes = self.read_text_bytes(memory, pointer, total_size)?;
        match decode_devmode16(&bytes) {
            Ok(mode) => Ok(Some(mode.into())),
            Err(DevMode16Error::AllocationFailed) => Err(RuntimeError::new(
                Kind::ResourceExhausted, "Win16 DEVMODE private data could not be copied")),
            Err(DevMode16Error::InvalidPublicSize | DevMode16Error::IncompleteBytes) => Ok(None),
        }
    }

    pub(super) fn get_text_metrics(
        &self,
        dc: u16,
        output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(native) = self.guest_gdi.dc(dc) else { return Ok(0); };
        let destination = self.selectors.pointer_from_far(output)
            .map_err(crate::runtime_error)?;
        self.preflight_text_write(memory, destination, TEXTMETRIC16_SIZE)?;
        let Some(metric) = host.win16_get_text_metrics(native)? else { return Ok(0); };
        let encoded = TextMetric16::from_host(
            metric.dimensions, metric.styles, metric.extra,
        ).encode();
        self.write_text_bytes(memory, destination, &encoded)?;
        host.observe_win16_io(&crate::Win16IoEvent::TextMetrics {
            dc,
            dimensions: &metric.dimensions,
        });
        Ok(1)
    }

    pub(super) fn get_text_face(
        &self,
        dc: u16,
        count: i16,
        output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<i16, RuntimeError> {
        let Some(native) = self.guest_gdi.dc(dc) else { return Ok(0); };
        // A negative count with a non-NULL output buffer has no valid Win32
        // buffer contract; return the API's normal failure without exposing
        // a host pointer to an unbounded signed-to-unsigned length.
        if count < 0 && output != 0 { return Ok(0); }
        let (destination, buffer) = if output == 0 {
            (None, None)
        } else if count > 0 {
            let pointer = self.selectors.pointer_from_far(output)
                .map_err(crate::runtime_error)?;
            let capacity = count as usize;
            self.preflight_text_write(memory, pointer, capacity)?;
            let prior = self.read_text_bytes(memory, pointer, capacity)?;
            (Some(pointer), Some(prior))
        } else {
            // For nCount == 0, keep the guest's non-NULL pointer identity at
            // the host boundary without validating or exposing guest memory.
            (None, Some(Vec::new()))
        };

        let Some(face) = host.win16_get_text_face(native, count, buffer)? else {
            return Ok(0);
        };
        let expected_size = if destination.is_some() { count as usize } else { 0 };
        if face.bytes.len() != expected_size {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host font-face buffer length changed across the native call"));
        }
        if let Some(pointer) = destination {
            if !face.bytes.is_empty() {
                self.write_text_bytes(memory, pointer, &face.bytes)?;
            }
        }
        Ok(face.result as i16)
    }
}

impl Win16State {
    pub(super) fn get_outline_text_metrics(
        &self,
        dc: u16,
        count: u16,
        output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        use super::guest_ranges::{GuestOutputRange, commit_guest_output};
        let Some(native) = self.guest_gdi.dc(dc) else { return Ok(0); };
        // The original far-pointer NULL test examines the selector only.
        let query = output >> 16 == 0;
        let destination = if !query && count != 0 {
            if usize::from(output as u16) + usize::from(count) > 0x1_0000 {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 outline text metrics output crosses a FAR segment"));
            }
            let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
            // Conservative safety policy: the declared capacity must be valid,
            // even when the eventual prefix is shorter. Capture before host work.
            Some(GuestOutputRange::capture(self, memory, pointer, usize::from(count))?)
        } else {
            None
        };
        let Some(metric) = host.win16_get_outline_text_metrics(native)? else { return Ok(0); };
        let Some((required, stored_size)) = outline_metrics_sizes(&metric.names) else {
            return Ok(0);
        };
        if query { return Ok(required); }
        if count == 0 { return Ok(1); }
        let mut fixed = metric.fixed;
        fixed[..2].copy_from_slice(&stored_size.to_le_bytes());
        let length = if count <= 106 { usize::from(count) }
            else { usize::from(count.min(required)) };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(usize::from(required)).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 outline text metrics", error))?;
        bytes.extend_from_slice(&fixed);
        if count > 106 {
            bytes.resize(114, 0);
            for (index, name) in metric.names.iter().enumerate() {
                let offset = bytes.len() as u16; // validated by outline_metrics_sizes
                bytes[106 + index * 2..108 + index * 2].copy_from_slice(&offset.to_le_bytes());
                // Original GDI308 uses the low byte of each UTF-16 word, not
                // the process ANSI codec. A partial output gets no added NUL.
                bytes.extend(name.iter().map(|word| *word as u8));
                bytes.push(0);
            }
        }
        bytes.truncate(length);
        if let Some(destination) = destination {
            commit_guest_output(self, memory, &destination, &bytes)?;
        }
        Ok(1)
    }
}

fn outline_metrics_sizes(names: &[Vec<u16>; 4]) -> Option<(u16, u16)> {
    let mut required = 114_usize;
    for name in names {
        // Native names are copied without terminators. Embedded full-word NUL
        // indicates a malformed host result; low-byte NUL is intentionally valid.
        if name.contains(&0) { return None; }
        required = required.checked_add(name.len().checked_add(1)?)?;
    }
    let stored = required.checked_add(1)? & !1;
    Some((u16::try_from(required).ok()?, u16::try_from(stored).ok()?))
}

#[cfg(test)]
#[path = "win16_outline_text_metrics_tests.rs"]
mod outline_text_metrics_tests;
