//! WinG DIB-section aliases backed by the shared guest/native bitmap storage.

use std::rc::Rc;

use guest_core::{
    OwnerId, PhysAddr,
    memory::{DeviceMappingHandle, Memory, MemoryMappedDevice},
};
use win16_abi::{
    AccessRights, AllocationFlags, GlobalHandle, SelectorAllocationView, SelectorRef, Win16Error,
    gdi_dib::DibHeader16,
};

use super::Win16State;
use super::global_memory::GlobalTeardownResult;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16GdiDeviceOperation as Operation,
    Win16GdiDeviceResult as HostResult, Win16HostDibSection, Win16HostGdiObject,
};

#[derive(Default)]
pub(super) struct Win16WingBitmapState {
    pub(super) records: Vec<Win16WingBitmap>,
    pub(super) warned_partial_selector_view: bool,
}

pub(super) enum SelectorRetirement {
    Suspended {
        views: Vec<SelectorAllocationView>,
        owned_blocks: Vec<SelectorRef>,
    },
    Retired {
        reservations: Vec<SelectorRef>,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Phase {
    Provisioning,
    Live,
    Hidden,
    NativeDeleted,
}

#[derive(Clone)]
pub(super) struct Win16WingBitmap {
    pub(super) object: Win16HostGdiObject,
    pub(super) guest_handle: Option<u16>,
    pub(super) owner: OwnerId,
    pub(super) allocation: Option<GlobalHandle>,
    pub(super) base: Option<PhysAddr>,
    pub(super) selector: Option<SelectorRef>,
    pub(super) mapping: Option<DeviceMappingHandle>,
    pub(super) extent: u32,
    pub(super) device: Rc<dyn MemoryMappedDevice>,
    pub(super) header: [u8; 40],
    pub(super) phase: Phase,
    pub(super) selector_retirement: Option<Rc<SelectorRetirement>>,
}

impl Win16State {
    pub(super) fn recommend_win_g_dib_format(
        &self,
        memory: &mut Memory,
        info_far: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if info_far == 0 {
            return Ok(0);
        }
        let pointer = self
            .selectors
            .pointer_from_far(info_far)
            .map_err(crate::runtime_error)?;
        let output = self.prepare_text_write(memory, pointer, 40)?;
        let header = match host.win16_gdi_device(Operation::RecommendWinGDibFormat)? {
            HostResult::DibHeader(Some(header)) => header,
            HostResult::DibHeader(None) => return Ok(0),
            _ => return Err(wrong_result("WinGRecommendDIBFormat")),
        };
        output.commit(memory, &header)?;
        Ok(1)
    }

    pub(super) fn create_win_g_bitmap(
        &mut self,
        guest_dc: u16,
        info_far: u32,
        bits_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let Some(info) = self.copy_dib_info(memory, info_far, 0)? else {
            return Ok(0);
        };
        let owner = self.tasks.current().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WinG bitmap creation has no current task owner",
            )
        })?;
        let image_extent = u32::try_from(info.layout.bits_bytes).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "WinG DIB image extent exceeds the guest allocation range",
                error,
            )
        })?;
        if image_extent == 0 {
            return Ok(0);
        }
        let output = if bits_output == 0 {
            None
        } else {
            let pointer = self
                .selectors
                .pointer_from_far(bits_output)
                .map_err(crate::runtime_error)?;
            Some(self.prepare_text_write(memory, pointer, 4)?)
        };
        self.wing_bitmaps.records.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WinG bitmap lifetime record",
                error,
            )
        })?;

        let section = match host.win16_gdi_device(Operation::CreateWinGDibSection {
            dc,
            info: info.bytes,
            image_bytes: image_extent,
        })? {
            HostResult::DibSection(Some(section)) => section,
            HostResult::DibSection(None) => return Ok(0),
            _ => return Err(wrong_result("WinGCreateBitmap")),
        };
        if self.guest_gdi.existing_object(section.object).is_some()
            || self
                .wing_bitmaps
                .records
                .iter()
                .any(|record| record.object == section.object)
        {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "WinG host reused a live guest GDI bitmap identity",
            );
            return Err(delete_unregistered_section(section, host, primary));
        }
        let index = self.wing_bitmaps.records.len();
        self.wing_bitmaps.records.push(Win16WingBitmap {
            object: section.object,
            guest_handle: None,
            owner,
            allocation: None,
            base: None,
            selector: None,
            mapping: None,
            extent: section.extent,
            device: Rc::clone(&section.memory),
            header: section.header,
            phase: Phase::Provisioning,
            selector_retirement: None,
        });

        if section.extent != image_extent || !header_matches(&section.header, &info.layout.header) {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "WinG host DIB extent or header differs from the checked guest format",
            );
            return Err(self.rollback_created(index, memory, host, primary));
        }

        let allocation =
            match self
                .heap
                .alloc(memory, owner, section.extent, AllocationFlags::fixed())
            {
                Ok(allocation) => allocation,
                Err(
                    Win16Error::OutOfMemory | Win16Error::HandleTableFull | Win16Error::InvalidSize,
                ) => {
                    return self.fail_create_normally(index, memory, host);
                }
                Err(error) => {
                    return Err(self.rollback_created(
                        index,
                        memory,
                        host,
                        crate::runtime_error(error),
                    ));
                }
            };
        let base = match self.heap.info(allocation) {
            Ok(block) if block.owner == owner && block.size == section.extent => block.base,
            Ok(_) => {
                let primary = RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG global allocation returned unexpected owner or extent",
                );
                return Err(
                    self.rollback_created_with_allocation(index, allocation, memory, host, primary)
                );
            }
            Err(error) => {
                return Err(self.rollback_created_with_allocation(
                    index,
                    allocation,
                    memory,
                    host,
                    crate::runtime_error(error),
                ));
            }
        };
        self.wing_bitmaps.records[index].allocation = Some(allocation);
        self.wing_bitmaps.records[index].base = Some(base);

        let mapping =
            match memory.map_device_scoped(base, section.extent, Rc::clone(&section.memory)) {
                Ok(mapping) => mapping,
                Err(error) => {
                    return Err(self.rollback_created(
                        index,
                        memory,
                        host,
                        crate::runtime_error(error),
                    ));
                }
            };
        self.wing_bitmaps.records[index].mapping = Some(mapping);

        let selector = match self.selectors.alloc_block(
            base,
            section.extent,
            AccessRights::read_write(),
            memory,
        ) {
            Ok(selector) => selector,
            Err(Win16Error::SelectorTableFull | Win16Error::OutOfMemory) => {
                return self.fail_create_normally(index, memory, host);
            }
            Err(error) => {
                return Err(self.rollback_created(
                    index,
                    memory,
                    host,
                    crate::runtime_error(error),
                ));
            }
        };
        self.wing_bitmaps.records[index].selector = Some(selector);

        let Some(guest_handle) = self.guest_gdi.allocate_object(section.object) else {
            return self.fail_create_normally(index, memory, host);
        };
        self.wing_bitmaps.records[index].guest_handle = Some(guest_handle);
        self.wing_bitmaps.records[index].phase = Phase::Live;
        if let Some(output) = output {
            let far = u32::from(selector.raw().0) << 16;
            if let Err(primary) = output.commit(memory, &far.to_le_bytes()) {
                return Err(self.rollback_created(index, memory, host, primary));
            }
        }
        Ok(u32::from(guest_handle))
    }

    pub(super) fn get_win_g_dib_pointer(
        &self,
        guest_bitmap: u16,
        info_far: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(object) = self.guest_gdi.object(guest_bitmap) else {
            return Ok(0);
        };
        let Some(record) = self.wing_bitmaps.records.iter().find(|record| {
            record.object == object
                && record.guest_handle == Some(guest_bitmap)
                && record.phase == Phase::Live
        }) else {
            return Ok(0);
        };
        let output = if info_far == 0 {
            None
        } else {
            let pointer = self
                .selectors
                .pointer_from_far(info_far)
                .map_err(crate::runtime_error)?;
            Some(self.prepare_text_write(memory, pointer, 40)?)
        };
        if let Some(output) = output {
            output.commit(memory, &record.header)?;
        }
        let selector = record.selector.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "live WinG bitmap has no selector alias",
            )
        })?;
        Ok(u32::from(selector.raw().0) << 16)
    }

    pub(super) fn delete_wing_bitmap(
        &mut self,
        guest_handle: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u16>, RuntimeError> {
        let Some(object) = self.guest_gdi.object(guest_handle) else {
            return Ok(None);
        };
        let Some(index) = self.wing_bitmaps.records.iter().position(|record| {
            record.object == object && record.guest_handle == Some(guest_handle)
        }) else {
            return Ok(None);
        };
        self.retire_wing_bitmap(index, true, memory, host).map(Some)
    }

    pub(super) fn close_wing_bitmaps(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        while let Some(object) = self
            .wing_bitmaps
            .records
            .first()
            .map(|record| record.object)
        {
            let index = self
                .wing_bitmaps
                .records
                .iter()
                .position(|record| record.object == object)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "WinG bitmap close lost its owner record",
                    )
                })?;
            if self.retire_wing_bitmap(index, false, memory, host)? == 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "WinG bitmap could not be deleted during GDI shutdown",
                ));
            }
        }
        Ok(())
    }

    fn fail_create_normally(
        &mut self,
        index: usize,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let object = self
            .wing_bitmaps
            .records
            .get(index)
            .map(|record| record.object)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG create rollback lost its owner record",
                )
            })?;
        if self.retire_wing_bitmap(index, false, memory, host)? == 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "WinG resource allocation failed and its unpublished bitmap is still live",
            )
            .with_context(format!("host object {}", object.0)));
        }
        Ok(0)
    }

    fn rollback_created(
        &mut self,
        index: usize,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        primary: RuntimeError,
    ) -> RuntimeError {
        match self.retire_wing_bitmap(index, false, memory, host) {
            Ok(1) => primary,
            Ok(0) => combine(
                primary,
                RuntimeError::new(
                    Kind::HostFailure,
                    "DeleteObject returned FALSE while rolling back WinG bitmap creation",
                ),
            ),
            Ok(_) => combine(
                primary,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG bitmap rollback returned an invalid BOOL",
                ),
            ),
            Err(cleanup) => combine(primary, cleanup),
        }
    }

    fn rollback_created_with_allocation(
        &mut self,
        index: usize,
        allocation: GlobalHandle,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        primary: RuntimeError,
    ) -> RuntimeError {
        self.wing_bitmaps.records[index].allocation = Some(allocation);
        self.rollback_created(index, memory, host, primary)
    }

    fn retire_wing_bitmap(
        &mut self,
        index: usize,
        restore_on_false: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let snapshot = self
            .wing_bitmaps
            .records
            .get(index)
            .cloned()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinG bitmap owner record is missing",
                )
            })?;
        self.preflight_wing_bitmap(&snapshot, memory)?;
        if snapshot.phase == Phase::Live || snapshot.phase == Phase::Provisioning {
            if !self.hide_wing_bitmap_selector(index, &snapshot, host)? {
                return Ok(0);
            }
        }
        let snapshot = self
            .wing_bitmaps
            .records
            .get(index)
            .cloned()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "hidden WinG bitmap owner record is missing",
                )
            })?;

        if snapshot.phase != Phase::NativeDeleted {
            if !host.win16_delete_object(snapshot.object)? {
                if restore_on_false && snapshot.guest_handle.is_some() {
                    self.restore_wing_bitmap_selector(index, &snapshot)?;
                }
                return Ok(0);
            }
            self.wing_bitmaps.records[index].phase = Phase::NativeDeleted;
        }
        self.retire_wing_bitmap_guest_alias(index, &snapshot)?;
        self.retire_wing_bitmap_mapping(index, &snapshot, memory)?;
        self.retire_wing_bitmap_selector(index, &snapshot)?;
        self.retire_wing_bitmap_allocation(index, &snapshot)?;
        self.wing_bitmaps.records.remove(index);
        Ok(1)
    }

    fn retire_wing_bitmap_guest_alias(
        &mut self,
        index: usize,
        record: &Win16WingBitmap,
    ) -> Result<(), RuntimeError> {
        let Some(guest) = record.guest_handle else {
            return Ok(());
        };
        if self.guest_gdi.forget_object(guest, record.object)
            || self.guest_gdi.object(guest).is_none()
        {
            self.wing_bitmaps.records[index].guest_handle = None;
            return Ok(());
        }
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "deleted WinG bitmap still has a conflicting guest GDI handle",
        ))
    }

    fn retire_wing_bitmap_mapping(
        &mut self,
        index: usize,
        record: &Win16WingBitmap,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let Some(mapping) = &record.mapping else {
            return Ok(());
        };
        let base = record.base.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WinG device mapping has no heap base",
            )
        })?;
        if !memory.device_mapping_matches(mapping, base, record.extent, &record.device) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG bitmap exact device mapping disappeared before unmap",
            ));
        }
        let unmapped = memory.unmap_device(mapping).map_err(crate::runtime_error)?;
        self.wing_bitmaps.records[index].mapping = None;
        if !Rc::ptr_eq(&unmapped, &record.device) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WinG bitmap unmap returned a different process-owned device",
            ));
        }
        Ok(())
    }

    fn retire_wing_bitmap_allocation(
        &mut self,
        index: usize,
        record: &Win16WingBitmap,
    ) -> Result<(), RuntimeError> {
        let Some(allocation) = record.allocation else {
            return Ok(());
        };
        match self.free_runtime_global_on_teardown(allocation)? {
            GlobalTeardownResult::Freed => {}
            retained @ GlobalTeardownResult::Retained { .. } => {
                return Err(retained.retained_error("WinG DIB allocation")
                    .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "WinG DIB teardown lost its retained allocation cause")));
            }
        }
        self.wing_bitmaps.records[index].allocation = None;
        self.wing_bitmaps.records[index].base = None;
        Ok(())
    }
}

fn header_matches(header: &[u8; 40], expected: &DibHeader16) -> bool {
    let width = i32::from_le_bytes(header[4..8].try_into().unwrap_or_default());
    let height = i32::from_le_bytes(header[8..12].try_into().unwrap_or_default());
    let planes = u16::from_le_bytes(header[12..14].try_into().unwrap_or_default());
    let bit_count = u16::from_le_bytes(header[14..16].try_into().unwrap_or_default());
    let compression = u32::from_le_bytes(header[16..20].try_into().unwrap_or_default());
    match expected {
        DibHeader16::Info {
            width: w,
            height: h,
            planes: p,
            bits_per_pixel,
            compression: c,
            ..
        } => {
            width == *w
                && height == *h
                && planes == *p
                && bit_count == *bits_per_pixel
                && compression == *c
        }
        DibHeader16::Core { .. } => false,
    }
}

fn delete_unregistered_section(
    section: Win16HostDibSection,
    host: &mut impl RuntimeHost,
    primary: RuntimeError,
) -> RuntimeError {
    match host.win16_delete_object(section.object) {
        Ok(true) => primary,
        Ok(false) => combine(
            primary,
            RuntimeError::new(
                Kind::HostFailure,
                "DeleteObject returned FALSE for an unregistered WinG DIB section",
            ),
        ),
        Err(cleanup) => combine(primary, cleanup),
    }
}

fn wrong_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("WinG {operation} returned the wrong host result"),
    )
}

fn combine(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        "WinG bitmap operation and cleanup both failed",
        WingCleanupFailure { primary, cleanup },
    )
}

#[derive(Debug)]
struct WingCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for WingCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for WingCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
