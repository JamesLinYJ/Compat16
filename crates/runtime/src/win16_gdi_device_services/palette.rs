//! GDI palette services used by the Win16 device request decoder.

use super::*;

impl Win16State {
    pub(super) fn create_palette(
        &mut self,
        version: u16,
        entries: Vec<PaletteEntry16>,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // Windows 3.1 LOGPALETTE uses version 0x0300. Reject malformed guest
        // input as GDI does; do not normalize it into a successful palette.
        if version != 0x0300 {
            return Ok(0);
        }
        let host_entries = palette_entries_to_host(entries)?;
        let result = host.win16_gdi_device(Operation::CreatePalette {
            version,
            entries: host_entries,
        })?;
        match result {
            HostResult::Object(Some(object)) => {
                self.allocate_guest_gdi_object(object, host).map(u32::from)
            }
            HostResult::Object(None) => Ok(0),
            _ => Err(wrong_device_result("CreatePalette")),
        }
    }

    pub(super) fn create_halftone_palette(
        &mut self,
        dc: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        let result = host.win16_gdi_device(Operation::CreateHalftonePalette { dc })?;
        match result {
            HostResult::Object(Some(object)) => {
                self.allocate_guest_gdi_object(object, host).map(u32::from)
            }
            HostResult::Object(None) => Ok(0),
            _ => Err(wrong_device_result("CreateHalftonePalette")),
        }
    }

    pub(super) fn create_wing_halftone_palette(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let result = host.win16_gdi_device(Operation::CreateWinGHalftonePalette)?;
        match result {
            HostResult::Object(Some(object)) => self.allocate_guest_gdi_object(object, host),
            HostResult::Object(None) => Ok(0),
            _ => Err(wrong_device_result("WinGCreateHalfTonePalette")),
        }
    }

    pub(super) fn select_palette(
        &mut self,
        dc: u16,
        palette: u16,
        force_background: bool,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let (Some(dc), Some(palette)) = (self.guest_gdi.dc(dc), self.guest_gdi.object(palette))
        else {
            return Ok(0);
        };
        let result = host.win16_gdi_device(Operation::SelectPalette {
            dc,
            palette,
            force_background,
        })?;
        match result {
            HostResult::Object(Some(previous)) => {
                if let Some(handle) = self.guest_gdi.existing_object(previous) {
                    return Ok(u32::from(handle));
                }
                Ok(u32::from(
                    self.guest_gdi.allocate_object(previous).unwrap_or(0),
                ))
            }
            HostResult::Object(None) => Ok(0),
            _ => Err(wrong_device_result("SelectPalette")),
        }
    }

    pub(super) fn realize_palette(
        &mut self,
        dc: u16,
        default_palette: bool,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        let operation = if default_palette {
            Operation::RealizeDefaultPalette { dc }
        } else {
            Operation::RealizePalette { dc }
        };
        match host.win16_gdi_device(operation)? {
            HostResult::Count(count) => Ok(count as u16 as u32),
            _ => Err(wrong_device_result("RealizePalette")),
        }
    }

    pub(super) fn update_colors(
        &mut self,
        dc: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        match host.win16_gdi_device(Operation::UpdateColors { dc })? {
            HostResult::Bool(value) => Ok(u32::from(value)),
            _ => Err(wrong_device_result("UpdateColors")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn palette_entries(
        &mut self,
        memory: &mut Memory,
        kind: PaletteTransferKind,
        palette: u16,
        start: u16,
        count: u16,
        entries: Option<Vec<PaletteEntry16>>,
        output: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(palette) = self.guest_gdi.object(palette) else {
            return Ok(0);
        };
        let kind = match kind {
            PaletteTransferKind::Get => Win16PaletteTransferKind::Get,
            PaletteTransferKind::Set => Win16PaletteTransferKind::Set,
            PaletteTransferKind::Animate => Win16PaletteTransferKind::Animate,
        };
        let write = if kind == Win16PaletteTransferKind::Get && count != 0 {
            let pointer = self
                .selectors
                .pointer_from_far(output)
                .map_err(crate::runtime_error)?;
            let bytes = usize::from(count).checked_mul(4).ok_or_else(|| {
                RuntimeError::new(Kind::InvalidInput, "Win16 palette output length overflowed")
            })?;
            Some(self.prepare_text_write(memory, pointer, bytes)?)
        } else {
            None
        };
        let entries = entries.map(palette_entries_to_host).transpose()?;
        let result = host.win16_gdi_device(Operation::PaletteEntries {
            kind,
            palette,
            start,
            count,
            entries,
        })?;
        match (kind, result) {
            (
                Win16PaletteTransferKind::Get,
                HostResult::PaletteEntries {
                    count: copied,
                    entries,
                },
            ) => {
                if copied < 0 || copied > i32::from(count) || entries.len() < copied as usize {
                    return Err(wrong_device_result("GetPaletteEntries"));
                }
                let bytes = encode_palette_entries(&entries[..copied as usize])?;
                if let Some(write) = write {
                    write.commit(memory, &bytes)?;
                }
                Ok(copied as u16 as u32)
            }
            // Windows 3.1 declares AnimatePalette as void. The native Win32
            // binding returns a BOOL, but that host-only result is not part
            // of the guest API and must not leak through the 16-bit slot.
            (Win16PaletteTransferKind::Animate, HostResult::Count(_)) => Ok(0),
            (Win16PaletteTransferKind::Set, HostResult::Count(result)) => Ok(result as u16 as u32),
            _ => Err(wrong_device_result("palette entry transfer")),
        }
    }

    pub(super) fn resize_palette(
        &mut self,
        palette: u16,
        count: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(palette) = self.guest_gdi.object(palette) else {
            return Ok(0);
        };
        match host.win16_gdi_device(Operation::ResizePalette { palette, count })? {
            HostResult::Bool(value) => Ok(u32::from(value)),
            _ => Err(wrong_device_result("ResizePalette")),
        }
    }

    pub(super) fn nearest_palette_index(
        &mut self,
        palette: u16,
        color: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(palette) = self.guest_gdi.object(palette) else {
            return Ok(u16::MAX.into());
        };
        match host.win16_gdi_device(Operation::GetNearestPaletteIndex { palette, color })? {
            HostResult::Count(index) => Ok(index as u16 as u32),
            _ => Err(wrong_device_result("GetNearestPaletteIndex")),
        }
    }

    pub(in crate::win16_runtime) fn system_palette_use(
        &mut self,
        dc: u16,
        use_mode: Option<u16>,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        // Windows 3.1 `WINDOWS.H` defines SYSPAL_STATIC (1) and SYSPAL_NOSTATIC
        // (2). SYSPAL_NOSTATIC256 (3) is a later value. Learn returns
        // SYSPAL_ERROR (0) when SetSystemPaletteUse fails.
        let Some(use_mode) = use_mode else {
            return match host.win16_gdi_device(Operation::GetSystemPaletteUse { dc })? {
                HostResult::Count(value) if matches!(value, 1 | 2) => Ok(value as u32),
                HostResult::Count(_) => Ok(0),
                _ => Err(wrong_device_result("GetSystemPaletteUse")),
            };
        };
        if !matches!(use_mode, 1 | 2) {
            return Ok(0);
        }
        match host.win16_gdi_device(Operation::SetSystemPaletteUse { dc, use_mode })? {
            HostResult::Count(previous) if matches!(previous, 1 | 2) => Ok(previous as u32),
            HostResult::Count(0) => Ok(0),
            // The host named a previous use this API cannot return. Put that
            // use back so the error leaves the palette unchanged.
            HostResult::Count(previous) => {
                let Some(restore) = u16::try_from(previous).ok() else {
                    return Ok(0);
                };
                match host.win16_gdi_device(Operation::SetSystemPaletteUse {
                    dc,
                    use_mode: restore,
                })? {
                    HostResult::Count(_) => Ok(0),
                    _ => Err(wrong_device_result("SetSystemPaletteUse")),
                }
            }
            _ => Err(wrong_device_result("SetSystemPaletteUse")),
        }
    }

    pub(super) fn system_palette_entries(
        &mut self,
        memory: &mut Memory,
        dc: u16,
        start: u16,
        count: u16,
        output: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        let capacity = usize::from(count).checked_mul(4).ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 system palette output length overflowed",
            )
        })?;
        let write = if capacity == 0 {
            None
        } else {
            let pointer = self
                .selectors
                .pointer_from_far(output)
                .map_err(crate::runtime_error)?;
            Some(self.prepare_text_write(memory, pointer, capacity)?)
        };
        let result =
            host.win16_gdi_device(Operation::GetSystemPaletteEntries { dc, start, count })?;
        let HostResult::PaletteEntries {
            count: copied,
            entries,
        } = result
        else {
            return Err(wrong_device_result("GetSystemPaletteEntries"));
        };
        if copied < 0 || copied > i32::from(count) || entries.len() < copied as usize {
            return Err(wrong_device_result("GetSystemPaletteEntries"));
        }
        let bytes = encode_palette_entries(&entries[..copied as usize])?;
        if let Some(write) = write {
            write.commit(memory, &bytes)?;
        }
        Ok(copied as u16 as u32)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn dib_color_table(
        &mut self,
        memory: &mut Memory,
        kind: DibColorTableKind,
        dc: u16,
        start: u16,
        count: u16,
        entries: Option<Vec<DibRgbQuad16>>,
        output: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        let kind = match kind {
            DibColorTableKind::Get => Win16DibColorTableKind::Get,
            DibColorTableKind::Set => Win16DibColorTableKind::Set,
        };
        let write = if kind == Win16DibColorTableKind::Get && count != 0 {
            let pointer = self
                .selectors
                .pointer_from_far(output)
                .map_err(crate::runtime_error)?;
            let bytes = usize::from(count).checked_mul(4).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "Win16 DIB color-table output length overflowed",
                )
            })?;
            Some(self.prepare_text_write(memory, pointer, bytes)?)
        } else {
            None
        };
        let result = host.win16_gdi_device(Operation::DibColorTable {
            kind,
            dc,
            start,
            count,
            entries: entries.map(dib_rgbquads_to_host).transpose()?,
        })?;
        match (kind, result) {
            (
                Win16DibColorTableKind::Get,
                HostResult::PaletteEntries {
                    count: copied,
                    entries,
                },
            ) => {
                if copied < 0 || copied > i32::from(count) || entries.len() < copied as usize {
                    return Err(wrong_device_result("GetDIBColorTable"));
                }
                let bytes = encode_rgbquads(&entries[..copied as usize])?;
                if let Some(write) = write {
                    write.commit(memory, &bytes)?;
                }
                Ok(copied as u16 as u32)
            }
            (Win16DibColorTableKind::Set, HostResult::Count(copied)) => Ok(copied as u16 as u32),
            _ => Err(wrong_device_result("DIB color-table transfer")),
        }
    }
}
fn palette_entries_to_host(entries: Vec<PaletteEntry16>) -> Result<Vec<[u8; 4]>, RuntimeError> {
    let mut result = Vec::new();
    result.try_reserve_exact(entries.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 palette entries",
            error,
        )
    })?;
    result.extend(
        entries
            .into_iter()
            .map(|entry| [entry.red, entry.green, entry.blue, entry.flags]),
    );
    Ok(result)
}

fn encode_palette_entries(entries: &[[u8; 4]]) -> Result<Vec<u8>, RuntimeError> {
    let length = entries.len().checked_mul(4).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 palette result length overflowed",
        )
    })?;
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 palette result bytes",
            error,
        )
    })?;
    for entry in entries {
        result.extend_from_slice(entry);
    }
    Ok(result)
}

fn dib_rgbquads_to_host(entries: Vec<DibRgbQuad16>) -> Result<Vec<[u8; 4]>, RuntimeError> {
    let mut result = Vec::new();
    result.try_reserve_exact(entries.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 DIB color-table entries",
            error,
        )
    })?;
    result.extend(
        entries
            .into_iter()
            .map(|entry| [entry.red, entry.green, entry.blue, entry.reserved]),
    );
    Ok(result)
}

fn encode_rgbquads(entries: &[[u8; 4]]) -> Result<Vec<u8>, RuntimeError> {
    let length = entries.len().checked_mul(4).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 DIB color-table result length overflowed",
        )
    })?;
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 DIB color-table result bytes",
            error,
        )
    })?;
    for [red, green, blue, reserved] in entries {
        result.extend_from_slice(&[*blue, *green, *red, *reserved]);
    }
    Ok(result)
}
