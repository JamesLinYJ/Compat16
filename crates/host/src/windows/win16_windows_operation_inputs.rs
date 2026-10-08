//! Guest handle leases and native input identities for USER operations.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostGdiObject, Win16MenuItemContent,
    Win16MenuOperation, Win16WindowOperation,
};

use super::{Win16Objects, Win16RegionLease};

pub(super) fn update_region_output(
    operation: &Win16WindowOperation,
) -> Option<Win16HostGdiObject> {
    use runtime::Win16HostUpdateOperation as Update;
    match operation {
        Win16WindowOperation::UpdateRegion(Update::GetUpdateRgn { region, .. }) => Some(*region),
        Win16WindowOperation::UpdateRegion(Update::ScrollWindowEx { update_region, .. }) => {
            *update_region
        }
        _ => None,
    }
}

pub(super) fn commit_update_region(
    objects: &Win16Objects,
    token: Win16HostGdiObject,
    region: &Win16RegionLease,
    result: &mut runtime::Win16WindowResult,
) -> Result<(), RuntimeError> {
    use runtime::{Win16HostUpdateResult as UpdateResult, Win16WindowResult};
    let value = match result {
        Win16WindowResult::UpdateRegion(UpdateResult::Word(value))
        | Win16WindowResult::UpdateRegion(UpdateResult::Rect { value, .. }) => *value,
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 region output has an unexpected native completion",
            ));
        }
    };
    if value == 0 {
        return Ok(());
    }
    // The worker has left its native call before Complete. Copy into the
    // exact original object identity, never a recycled guest handle. A guest
    // callback may have deleted that identity; then it has no output target.
    if objects.commit_region(token, region)? == Some(false) {
        match result {
            Win16WindowResult::UpdateRegion(UpdateResult::Word(value)) => *value = 0,
            Win16WindowResult::UpdateRegion(UpdateResult::Rect { value, rect }) => {
                *value = 0;
                *rect = None;
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 region completion changed during output transfer",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn update_region_tokens(
    operation: &Win16WindowOperation,
) -> std::collections::BTreeSet<Win16HostGdiObject> {
    use runtime::Win16HostUpdateOperation as Update;
    let Win16WindowOperation::UpdateRegion(update) = operation else {
        return Default::default();
    };
    match update {
        Update::InvalidateRgn { region, .. }
        | Update::ValidateRgn { region, .. }
        | Update::RedrawWindow { region, .. } => region.iter().copied().collect(),
        Update::GetUpdateRgn { region, .. } => [*region].into_iter().collect(),
        Update::ScrollWindowEx { update_region, .. } => update_region.iter().copied().collect(),
        _ => Default::default(),
    }
}

pub(super) fn native_bitmap_tokens(
    operation: &Win16WindowOperation,
) -> std::collections::BTreeSet<Win16HostGdiObject> {
    match operation {
        Win16WindowOperation::Menu(operation) => match operation {
            Win16MenuOperation::InsertMenu { item, .. }
            | Win16MenuOperation::AppendMenu { item, .. }
            | Win16MenuOperation::ModifyMenu { item, .. } => match &item.content {
                Win16MenuItemContent::Bitmap(Some(bitmap)) => [*bitmap].into_iter().collect(),
                _ => std::collections::BTreeSet::new(),
            },
            Win16MenuOperation::SetMenuItemBitmaps {
                unchecked, checked, ..
            } => unchecked.iter().chain(checked.iter()).copied().collect(),
            _ => std::collections::BTreeSet::new(),
        },
        _ => std::collections::BTreeSet::new(),
    }
}

pub(super) fn toolbar_bitmap_tokens(
    operation: &Win16WindowOperation,
) -> std::collections::BTreeSet<Win16HostGdiObject> {
    match operation {
        Win16WindowOperation::CommonControls(
            runtime::Win16HostCommonControlsOperation::CreateToolbar {
                bitmap: runtime::Win16HostToolbarBitmap::GuestObject(bitmap),
                ..
            },
        ) => [*bitmap].into_iter().collect(),
        _ => std::collections::BTreeSet::new(),
    }
}
