//! Flat guest32 segment maps for the currently owned PE images.

use guest_core::{GuestMemory, memory::Memory};

use crate::{DiagnosticKind as Kind, RuntimeError};

use crate::pe32_call::{
    Pe32GuestCodeRange, Pe32GuestExecutionEnvironment, Pe32GuestStackRange, Pe32SegmentAccess,
    Pe32SegmentMapping,
};

use crate::win32_import_state::Win32ImportState;

use super::{PE32_GATE_PAGE_BYTES, PE32_STACK_BYTES, Pe32ThunkDispatcher};

const CODE_SELECTOR: u16 = 0x0008;
const STACK_SELECTOR: u16 = 0x0010;
const DATA_SELECTOR: u16 = 0x0018;

pub(super) fn for_call(
    dispatcher: &Pe32ThunkDispatcher,
    imports: &Win32ImportState,
    memory: &Memory,
    stack_top: u32,
    target_module: Option<crate::pe32::Pe32ModuleIdentity>,
) -> Result<Pe32GuestExecutionEnvironment, RuntimeError> {
    let memory_end = memory.len();
    let limit = memory_end
        .checked_sub(1)
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "PE32 guest memory is empty"))?;
    let executable = executable_ranges(dispatcher, imports, target_module)?;
    let support_base = dispatcher.support.base();
    let stack_end = support_base.checked_add(PE32_STACK_BYTES).ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant, "PE32 support stack overflows")
    })?;
    let gate = stack_end;
    if support_base
        .checked_add(PE32_STACK_BYTES + PE32_GATE_PAGE_BYTES)
        .is_none_or(|end| end > memory_end)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "PE32 support lease is outside guest RAM",
        ));
    }
    if stack_top <= support_base || stack_top > stack_end || stack_top & 3 != 0 {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "PE32 nested stack top is outside the owned support stack",
        ));
    }
    let mut segments = Vec::new();
    segments.try_reserve_exact(3).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve PE32 flat segment map",
            error,
        )
    })?;
    segments.push(Pe32SegmentMapping::new(
        CODE_SELECTOR,
        0,
        limit,
        Pe32SegmentAccess::new(true, false, true),
    ));
    segments.push(Pe32SegmentMapping::new(
        STACK_SELECTOR,
        0,
        limit,
        Pe32SegmentAccess::new(true, true, false),
    ));
    segments.push(Pe32SegmentMapping::new(
        DATA_SELECTOR,
        0,
        limit,
        Pe32SegmentAccess::new(true, true, false),
    ));
    // FS/GS are intentionally absent: a flat zero-base alias would falsely
    // claim a TEB/TLS environment that this runtime has not allocated.
    Ok(Pe32GuestExecutionEnvironment::new(
        segments,
        executable,
        CODE_SELECTOR,
        STACK_SELECTOR,
        DATA_SELECTOR,
        Some(DATA_SELECTOR),
        None,
        None,
        Pe32GuestStackRange::new(support_base, stack_end, stack_top),
        gate,
    ))
}

/// Snapshot only published images, the exact active attach group visible to
/// this paused caller, and owners pinned by an executing frame. This is rebuilt
/// after each successful service so newly loaded code becomes fetchable while
/// retired generations disappear before the caller resumes.
pub(super) fn executable_ranges(
    dispatcher: &Pe32ThunkDispatcher,
    imports: &Win32ImportState,
    target_module: Option<crate::pe32::Pe32ModuleIdentity>,
) -> Result<Vec<Pe32GuestCodeRange>, RuntimeError> {
    let visible_group = dispatcher.active_load_group.as_ref().and_then(|group| {
        let paused_owner = dispatcher
            .active
            .last()
            .filter(|active| active.paused_at_service)
            .and_then(|active| active.module);
        let caller_in_group = paused_owner.is_some_and(|module| {
            dispatcher.registry.load_group(module).ok() == Some(Some(group.id))
        });
        let target_in_group = target_module.is_some_and(|module| {
            dispatcher.registry.load_group(module).ok() == Some(Some(group.id))
        });
        (caller_in_group || target_in_group).then_some(group.id)
    });
    let active_owner = |identity| {
        dispatcher
            .active
            .iter()
            .any(|frame| frame.module == Some(identity))
    };
    let mut range_count = imports.service_gate_guard_addresses().count();
    for module in &dispatcher.modules {
        let identity = module.transaction.module();
        if module.image_released {
            continue;
        }
        if dispatcher.registry.identity(identity.token()) != Some(identity) {
            if active_owner(identity) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "executing PE32 frame lost its exact image generation",
                ));
            }
            continue;
        }
        let Some(stage) = dispatcher.registry.stage(identity.token()) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "live PE32 image owner has no registry stage",
            ));
        };
        let published = stage == crate::pe32::Pe32ModuleStage::Published;
        let group_visible = visible_group.is_some_and(|group| {
            dispatcher.registry.load_group(identity).ok() == Some(Some(group))
                && matches!(
                    stage,
                    crate::pe32::Pe32ModuleStage::Mapped
                        | crate::pe32::Pe32ModuleStage::Linked
                        | crate::pe32::Pe32ModuleStage::Initializing
                        | crate::pe32::Pe32ModuleStage::Initialized
                )
        });
        if published || group_visible || active_owner(identity) {
            range_count = range_count
                .checked_add(module.executable_ranges.len())
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "PE32 executable range count overflowed",
                    )
                })?;
        }
    }
    let mut executable = Vec::new();
    executable.try_reserve_exact(range_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve PE32 executable map",
            error,
        )
    })?;
    for module in &dispatcher.modules {
        let identity = module.transaction.module();
        if module.image_released || dispatcher.registry.identity(identity.token()) != Some(identity)
        {
            continue;
        }
        let stage = dispatcher.registry.stage(identity.token()).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "live PE32 image owner has no stage",
            )
        })?;
        let group_visible = visible_group.is_some_and(|group| {
            dispatcher.registry.load_group(identity).ok() == Some(Some(group))
                && matches!(
                    stage,
                    crate::pe32::Pe32ModuleStage::Mapped
                        | crate::pe32::Pe32ModuleStage::Linked
                        | crate::pe32::Pe32ModuleStage::Initializing
                        | crate::pe32::Pe32ModuleStage::Initialized
                )
        });
        if stage == crate::pe32::Pe32ModuleStage::Published
            || group_visible
            || active_owner(identity)
        {
            executable.extend_from_slice(&module.executable_ranges);
        }
    }
    for address in imports.service_gate_guard_addresses() {
        let end = address.checked_add(2).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 service gate range overflowed",
            )
        })?;
        executable.push(Pe32GuestCodeRange::from_linear_range(
            u64::from(address)..u64::from(end),
        ));
    }
    if executable.is_empty() {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "PE32 execution has no mapped executable image",
        ));
    }
    Ok(executable)
}
