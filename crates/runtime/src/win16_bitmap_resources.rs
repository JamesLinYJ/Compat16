//! Resource-backed USER/COMMCTRL bitmap creation through the guest GDI table.

use guest_core::{memory::Memory, GuestMemory};
use zerocopy::byteorder::little_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};
use win16_abi::{Access, SegmentedPointer, Win16ResourceName, gdi_dib::{
    DibHeader16, DIB_RGB_COLORS16, core_to_info_header, packed_dib_layout,
}};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16GdiObjectOperation, Win16HostDc, Win16HostDib, Win16HostGdiObject};

const CBM_INIT: u32 = 0x0004;
const RT_BITMAP: u16 = 2;
const COLOR_BTNTEXT: i32 = 18;
const COLOR_BTNSHADOW: i32 = 16;
const COLOR_BTNFACE: i32 = 15;
const COLOR_BTNHIGHLIGHT: i32 = 20;

#[derive(Clone, Copy)]
struct ColorMapEntry { from: u32, to: u32 }

#[repr(C)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
struct ColorMap16Wire { from: U32, to: U32 }

const _: () = assert!(core::mem::size_of::<ColorMap16Wire>() == 8);

impl Win16State {
    pub(super) fn load_bitmap(
        &mut self, instance: u16, name: Win16ResourceName, host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        // SDK 3.1 WINDOWS.H: LoadBitmap(HINSTANCE, LPCSTR). NULL instance
        // selects native OEM bitmaps; a guest module requires its own NE bytes.
        if instance == 0 {
            let Win16ResourceName::Id(resource_id) = name else { return Ok(0); };
            let Some(object) = host.win16_create_gdi_object(
                Win16GdiObjectOperation::LoadSystemBitmap { resource_id },
            )? else { return Ok(0); };
            return self.allocate_guest_gdi_object(object, host);
        }
        self.create_resource_bitmap(instance, &name, None, host)
    }

    pub(super) fn read_toolbar_bitmap(
        &self,
        instance: u16,
        resource_id: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16HostDib>, RuntimeError> {
        let resource = self.find_resource(instance,
            &Win16ResourceName::Id(resource_id), &Win16ResourceName::Id(RT_BITMAP), host)?;
        if resource == 0 { return Ok(None); }
        let Some(metadata) = self.resource_metadata(instance, resource) else { return Ok(None); };
        let Some(record) = self.modules.records.get(&metadata.key.module) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "toolbar bitmap module disappeared after resource lookup"));
        };
        let end = metadata.offset.checked_add(metadata.length).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant, "toolbar bitmap resource extent overflow"))?;
        let Some(packed) = record.image.get(metadata.offset..end) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "parsed toolbar bitmap exceeds its module image"));
        };
        let Ok(layout) = packed_dib_layout(packed, DIB_RGB_COLORS16) else { return Ok(None); };
        if !matches!(layout.header, DibHeader16::Info { .. }) { return Ok(None); }
        let info = copy_bytes(&packed[..layout.bits_offset],
            "copy toolbar bitmap information")?;
        let bits = copy_bytes(&packed[layout.bits_offset..layout.total_bytes],
            "copy toolbar bitmap pixels")?;
        Ok(Some(Win16HostDib { info, bits }))
    }

    pub(super) fn create_mapped_bitmap(
        &mut self,
        memory: &Memory,
        instance: u16,
        resource_id: u16,
        flags: u16,
        color_map_far: u32,
        color_map_count: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        // SDK 3.1 declares this BOOL `bDiscardable`. Resource bytes stay in
        // the module image here, so there is no temporary guest resource
        // allocation whose discardability could be changed by this flag.
        let _discardable = flags != 0;
        let maps = if color_map_far == 0 {
            default_color_map(host)?
        } else {
            let count = color_map_count as i16;
            if count < 0 {
                host.report_diagnostic(&Diagnostic::warning(Kind::InvalidInput,
                    "CreateMappedBitmap received a negative color-map count"));
                return Ok(0);
            }
            read_color_map(self, memory, color_map_far, count)?
        };
        self.create_resource_bitmap(instance, &Win16ResourceName::Id(resource_id),
            Some(&maps), host)
    }

    fn create_resource_bitmap(
        &mut self, instance: u16, name: &Win16ResourceName,
        maps: Option<&[ColorMapEntry]>, host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let resource = self.find_resource(
            instance,
            name,
            &Win16ResourceName::Id(RT_BITMAP),
            host,
        )?;
        if resource == 0 { return Ok(0); }
        let Some(metadata) = self.resource_metadata(instance, resource) else {
            return Ok(0);
        };
        let Some(record) = self.modules.records.get(&metadata.key.module) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "bitmap resource module disappeared after lookup"));
        };
        let Some(resource_end) = metadata.offset.checked_add(metadata.length) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "bitmap resource extent overflowed its parsed module"));
        };
        let Some(packed) = record.image.get(metadata.offset..resource_end) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "parsed bitmap resource exceeds its module image"));
        };
        let Ok(layout) = packed_dib_layout(packed, DIB_RGB_COLORS16) else {
            return Ok(0);
        };
        // Mapping rewrites RGBQUAD entries. Unmapped LoadBitmap also accepts
        // CORE resources: the existing codec widens only the creation header,
        // leaving the native initialization info's RGBTRIPLE table intact.
        if maps.is_some() && !matches!(layout.header, DibHeader16::Info { .. }) {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "CreateMappedBitmap CORE color-table mapping is unavailable"));
            return Ok(0);
        }

        let mut info = copy_bytes(&packed[..layout.bits_offset],
            "copy bitmap resource information")?;
        if let Some(maps) = maps {
            apply_color_map(&mut info, layout.color_table_offset,
                layout.color_table_bytes, maps)?;
        }
        let bits = copy_bytes(&packed[layout.bits_offset..layout.total_bytes],
            "copy bitmap resource pixels")?;
        let header_end = layout.header_bytes.min(info.len());
        let header = match layout.header {
            DibHeader16::Core { .. } => {
                let converted = core_to_info_header(&info).map_err(|error|
                    RuntimeError::with_source(Kind::InternalInvariant,
                        "validated bitmap CORE creation header could not be widened", error))?;
                copy_bytes(&converted, "copy widened bitmap creation header")?
            }
            DibHeader16::Info { .. } => copy_bytes(&info[..header_end],
                "copy bitmap resource creation header")?,
        };
        let Some(reserved) = self.guest_gdi.reserve_object() else {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 GDI handle table cannot reserve bitmap resource result"));
        };
        let dc = match host.win16_acquire_screen_dc(false) {
            Ok(Some(dc)) => dc,
            Ok(None) => {
                self.cancel_reserved_bitmap(reserved)?;
                return Ok(0);
            }
            Err(error) => return Err(match self.cancel_reserved_bitmap(reserved) {
                Ok(()) => error,
                Err(cleanup) => collect_cleanup(error, [Some(cleanup), None]),
            }),
        };
        let result = host.win16_create_gdi_object(Win16GdiObjectOperation::CreateDibitmap {
            dc,
            header: Some(header),
            init_flags: CBM_INIT,
            bits: Some(bits),
            info: Some(info),
            color_usage: u32::from(DIB_RGB_COLORS16),
        });
        match result {
            Err(error) => {
                let cancel = self.cancel_reserved_bitmap(reserved);
                let release = release_dc(host, dc);
                Err(collect_cleanup(error, [cancel.err(), release.err()]))
            }
            Ok(None) => {
                let cancel = self.cancel_reserved_bitmap(reserved);
                let release = release_dc(host, dc);
                match (cancel, release) {
                    (Ok(()), Ok(())) => Ok(0),
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                    (Err(primary), Err(cleanup)) =>
                        Err(collect_cleanup(primary, [Some(cleanup), None])),
                }
            }
            Ok(Some(object)) => {
                if let Err(error) = release_dc(host, dc) {
                    return Err(self.rollback_created_bitmap(reserved, object, host, error));
                }
                if self.guest_gdi.bind_object(reserved, object) {
                    Ok(reserved)
                } else {
                    let primary = RuntimeError::new(Kind::InternalInvariant,
                        "Win16 bitmap resource reservation changed before bind");
                    Err(self.rollback_created_bitmap(reserved, object, host, primary))
                }
            }
        }
    }

    fn cancel_reserved_bitmap(&mut self, handle: u16) -> Result<(), RuntimeError> {
        if self.guest_gdi.cancel_object(handle) { Ok(()) } else {
            Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 bitmap resource reservation could not be retired"))
        }
    }

    fn rollback_created_bitmap(
        &mut self,
        handle: u16,
        object: Win16HostGdiObject,
        host: &mut impl RuntimeHost,
        primary: RuntimeError,
    ) -> RuntimeError {
        let delete = match host.win16_delete_object(object) {
            Ok(true) => None,
            Ok(false) => Some(RuntimeError::new(Kind::HostFailure,
                "DeleteObject failed while rolling back bitmap resource creation")),
            Err(error) => Some(error),
        };
        let cancel = self.cancel_reserved_bitmap(handle).err();
        collect_cleanup(primary, [delete, cancel])
    }
}

fn read_color_map(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    signed_count: i16,
) -> Result<Vec<ColorMapEntry>, RuntimeError> {
    let count = usize::try_from(signed_count).map_err(|error| RuntimeError::with_source(
        Kind::InvalidInput, "convert COMMCTRL color-map count", error))?;
    let bytes_len = count.checked_mul(8).ok_or_else(|| RuntimeError::new(
        Kind::GuestFault, "COMMCTRL color-map byte length overflow"))?;
    if bytes_len == 0 { return Ok(Vec::new()); }
    let bytes = read_single_far(state, memory, far, bytes_len)?;
    let mut maps = Vec::new();
    maps.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate COMMCTRL color map", error))?;
    for entry in bytes.chunks_exact(8) {
        let wire = ColorMap16Wire::read_from_bytes(entry).map_err(|_|
            RuntimeError::new(Kind::InternalInvariant,
                "captured COMMCTRL color-map entry has an invalid fixed wire layout"))?;
        maps.push(ColorMapEntry { from: wire.from.get(), to: wire.to.get() });
    }
    Ok(maps)
}

fn default_color_map(host: &mut impl RuntimeHost) -> Result<Vec<ColorMapEntry>, RuntimeError> {
    // These four replacements are the legacy toolbar colors described by the
    // Win16 COMMCTRL implementation and use the host's current system palette.
    let from = [0x0000_0000, 0x0080_8080, 0x00c0_c0c0, 0x00ff_ffff];
    let indices = [COLOR_BTNTEXT, COLOR_BTNSHADOW, COLOR_BTNFACE, COLOR_BTNHIGHLIGHT];
    let mut maps = Vec::new();
    maps.try_reserve_exact(4).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate default COMMCTRL color map", error))?;
    for (from, index) in from.into_iter().zip(indices) {
        maps.push(ColorMapEntry { from, to: host.win16_get_sys_color(index)? });
    }
    Ok(maps)
}

fn apply_color_map(
    info: &mut [u8],
    table_offset: usize,
    table_bytes: usize,
    maps: &[ColorMapEntry],
) -> Result<(), RuntimeError> {
    if table_bytes % 4 != 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "CreateMappedBitmap RGBQUAD table has a partial entry"));
    }
    let end = table_offset.checked_add(table_bytes).ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "CreateMappedBitmap color table extent overflow"))?;
    let Some(table) = info.get_mut(table_offset..end) else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "CreateMappedBitmap color table exceeds its captured info bytes"));
    };
    for color in table.chunks_exact_mut(4) {
        let color_ref = u32::from(color[2]) | (u32::from(color[1]) << 8)
            | (u32::from(color[0]) << 16);
        if let Some(map) = maps.iter().find(|map| map.from == color_ref) {
            color[0] = (map.to >> 16) as u8;
            color[1] = (map.to >> 8) as u8;
            color[2] = map.to as u8;
        }
    }
    Ok(())
}

fn read_single_far(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    length: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let pointer: SegmentedPointer = state.selectors.pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    let descriptor = state.selectors.describe(pointer.selector())
        .map_err(crate::runtime_error)?;
    let end = u32::from(pointer.offset()).checked_add(u32::try_from(length).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "COMMCTRL far buffer exceeds selector width", error))?)
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
            "COMMCTRL far buffer extent overflow"))?;
    if length != 0 && end > descriptor.limit.saturating_add(1) {
        return Err(RuntimeError::new(Kind::GuestFault,
            "COMMCTRL ordinary FAR buffer crosses its selector boundary"));
    }
    let address = state.selectors.translate(pointer, Access::Read, length, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy COMMCTRL ordinary FAR buffer", error))?;
    bytes.resize(length, 0);
    memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
    Ok(bytes)
}

fn copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, context, error))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn release_dc(host: &mut impl RuntimeHost, dc: Win16HostDc) -> Result<(), RuntimeError> {
    match host.win16_release_screen_dc(dc)? {
        true => Ok(()),
        false => Err(RuntimeError::new(Kind::HostFailure,
            "ReleaseDC failed after bitmap resource creation")),
    }
}

fn collect_cleanup(
    primary: RuntimeError,
    cleanup: [Option<RuntimeError>; 2],
) -> RuntimeError {
    let mut errors = cleanup.into_iter().flatten();
    let Some(first) = errors.next() else { return primary; };
    let second = errors.next();
    RuntimeError::with_source(Kind::HostFailure,
        "bitmap resource creation failed during native cleanup",
        BitmapCleanupFailure { primary, first, second })
}

#[derive(Debug)]
struct BitmapCleanupFailure {
    primary: RuntimeError,
    first: RuntimeError,
    second: Option<RuntimeError>,
}

impl std::fmt::Display for BitmapCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; cleanup also failed: {}", self.primary, self.first)?;
        if let Some(second) = &self.second { write!(f, "; additional cleanup failed: {second}")?; }
        Ok(())
    }
}

impl std::error::Error for BitmapCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.primary) }
}
