//! Generic extraction from checked NE group-icon resources.
//!
//! This path reads a copied file only. It never loads or initializes a guest
//! module; PE and ICO handling remains with the native host shell APIs.

use formats::{FormatError, NeIconResourceTable, NeResourceId};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostIcon,
    Win16HostIconSize, Win16HostShellIconResult,
};

const RT_GROUP_ICON: u16 = 14;

struct NeIconSource {
    groups: Vec<NeResourceId>,
    resources: NeIconResourceTable,
}

struct SelectedGroup {
    directory: Vec<u8>,
}

enum NeIconRead {
    NotNe,
    Malformed,
    Ready(NeIconSource),
}

/// Return `None` when the host path is missing or does not contain an NE image,
/// allowing PE/ICO formats to continue through the host shell implementation.
pub(super) fn extract_icon(
    host: &mut impl RuntimeHost,
    path: &[u8],
    application_path: &[u8],
    index: i16,
) -> Result<Option<Win16HostShellIconResult>, RuntimeError> {
    let source = match read_ne_source(host, path, application_path)? {
        NeIconRead::NotNe => return Ok(None),
        NeIconRead::Malformed if index == -1 => {
            return Ok(Some(Win16HostShellIconResult::IconCount { count: 0 }));
        }
        NeIconRead::Malformed => {
            return Ok(Some(Win16HostShellIconResult::Icon { icon: None }));
        }
        NeIconRead::Ready(source) => source,
    };
    if index == -1 {
        let count = u32::try_from(source.groups.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "NE group-icon count exceeds SHELL.34 result width",
                error,
            )
        })?;
        return Ok(Some(Win16HostShellIconResult::IconCount { count }));
    }

    // SHELL.34's ordinal is a WORD. FFFF is the sole count query; other high
    // values remain large unsigned ordinals instead of signed resource IDs.
    let ordinal = usize::from(index as u16);
    let Some(id) = source.groups.get(ordinal) else {
        return Ok(Some(Win16HostShellIconResult::Icon { icon: None }));
    };
    let Some(group) = selected_group(host, &source, id)? else {
        return Ok(Some(Win16HostShellIconResult::Icon { icon: None }));
    };
    let icon = create_icon_for_group(host, &source.resources, &group, Win16HostIconSize::Large)?;
    Ok(Some(Win16HostShellIconResult::Icon { icon }))
}

/// Extract group icons for SHELL.39/SHELL.40 while preserving the native
/// signed-index convention used by those entry points.
pub(super) fn extract_icon_ex(
    host: &mut impl RuntimeHost,
    path: &[u8],
    application_path: &[u8],
    index: i16,
    requested_count: u16,
    large: bool,
    small: bool,
    count_query: bool,
) -> Result<Option<Win16HostShellIconResult>, RuntimeError> {
    let source = match read_ne_source(host, path, application_path)? {
        NeIconRead::NotNe => return Ok(None),
        NeIconRead::Malformed => {
            return Ok(Some(Win16HostShellIconResult::Extracted {
                failed: true,
                count: 0,
                large: Vec::new(),
                small: Vec::new(),
            }));
        }
        NeIconRead::Ready(source) => source,
    };
    if count_query {
        let count = u16::try_from(source.groups.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "NE group-icon count exceeds SHELL.40 result width",
                error,
            )
        })?;
        return Ok(Some(Win16HostShellIconResult::Extracted {
            failed: false,
            count,
            large: Vec::new(),
            small: Vec::new(),
        }));
    }
    if requested_count == 0 || (!large && !small) {
        return Ok(Some(Win16HostShellIconResult::Extracted {
            failed: false,
            count: 0,
            large: Vec::new(),
            small: Vec::new(),
        }));
    }

    let groups = select_groups(host, &source, index, requested_count)?;
    let mut large_icons = Vec::new();
    let mut small_icons = Vec::new();
    if large {
        reserve_icons(&mut large_icons, groups.len())?;
    }
    if small {
        reserve_icons(&mut small_icons, groups.len())?;
    }

    for group in &groups {
        let large_icon = if large {
            match create_icon_for_group(host, &source.resources, group, Win16HostIconSize::Large) {
                Ok(icon) => icon,
                Err(error) => {
                    return Err(release_partial(
                        host,
                        error,
                        &large_icons,
                        &small_icons,
                        None,
                    ));
                }
            }
        } else {
            None
        };
        let small_icon = if small {
            match create_icon_for_group(host, &source.resources, group, Win16HostIconSize::Small) {
                Ok(icon) => icon,
                Err(error) => {
                    return Err(release_partial(
                        host,
                        error,
                        &large_icons,
                        &small_icons,
                        large_icon,
                    ));
                }
            }
        } else {
            None
        };
        if large_icon.is_none() && small_icon.is_none() {
            break;
        }
        if large {
            large_icons.push(large_icon);
        }
        if small {
            small_icons.push(small_icon);
        }
    }

    // The native one-group dual-size call reports individual created icons;
    // multi-group calls report the successful group prefix instead.
    let successful = if requested_count == 1 && large && small {
        large_icons.iter().chain(&small_icons).flatten().count()
    } else if large {
        large_icons.len()
    } else {
        small_icons.len()
    };
    let count = u16::try_from(successful)
    .map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "successful NE icon count exceeds its WORD request",
            error,
        )
    })?;
    Ok(Some(Win16HostShellIconResult::Extracted {
        failed: false,
        count,
        large: large_icons,
        small: small_icons,
    }))
}

fn read_ne_source(
    host: &mut impl RuntimeHost,
    path: &[u8],
    application_path: &[u8],
) -> Result<NeIconRead, RuntimeError> {
    let file = match host.win16_read_module(path, application_path)? {
        Ok(file) => file,
        Err(_) => return Ok(NeIconRead::NotNe),
    };
    if !has_ne_header(&file.image) {
        return Ok(NeIconRead::NotNe);
    }

    // Reuse the checked NE module definition and resource table. The module
    // stays a passive byte image and is never initialized or executed here.
    let definition = match formats::parse_ne(&file.image) {
        Ok(definition) => definition,
        Err(error) => {
            report_format_problem(
                host,
                error,
                "SHELL icon extraction skipped a malformed NE image",
            )?;
            return Ok(NeIconRead::Malformed);
        }
    };
    let resources = match NeIconResourceTable::from_module(&file.image, &definition) {
        Ok(resources) => resources,
        Err(error) => {
            report_format_problem(
                host,
                error,
                "SHELL icon extraction skipped malformed NE resources",
            )?;
            return Ok(NeIconRead::Malformed);
        }
    };
    let count = definition
        .resource_types
        .iter()
        .filter(|resource_type| resource_type.id == NeResourceId::Numeric(RT_GROUP_ICON))
        .try_fold(0usize, |total, resource_type| {
            total.checked_add(resource_type.resources.len())
        })
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "NE group-icon table length overflow",
            )
        })?;
    let mut groups = Vec::new();
    groups.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "could not index NE group-icon resources",
            error,
        )
    })?;
    for resource_type in &definition.resource_types {
        if resource_type.id == NeResourceId::Numeric(RT_GROUP_ICON) {
            groups.extend(
                resource_type
                    .resources
                    .iter()
                    .map(|resource| resource.id.clone()),
            );
        }
    }
    Ok(NeIconRead::Ready(NeIconSource { groups, resources }))
}

fn has_ne_header(image: &[u8]) -> bool {
    if image.get(0..2) != Some(b"MZ".as_slice()) {
        return false;
    }
    let Some(offset_bytes) = image.get(0x3c..0x40) else {
        return false;
    };
    let Ok(offset) = usize::try_from(u32::from_le_bytes([
        offset_bytes[0],
        offset_bytes[1],
        offset_bytes[2],
        offset_bytes[3],
    ])) else {
        return false;
    };
    let Some(end) = offset.checked_add(2) else {
        return false;
    };
    image.get(offset..end) == Some(b"NE".as_slice())
}

fn selected_group(
    host: &mut impl RuntimeHost,
    source: &NeIconSource,
    id: &NeResourceId,
) -> Result<Option<SelectedGroup>, RuntimeError> {
    match source.resources.group_icon(id) {
        Ok(Some(directory)) => Ok(Some(SelectedGroup { directory })),
        Ok(None) => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::InvalidInput,
                "SHELL icon extraction found a missing NE group-icon resource",
            ));
            Ok(None)
        }
        Err(error) => {
            report_format_problem(
                host,
                error,
                "SHELL icon extraction skipped a malformed NE group icon",
            )?;
            Ok(None)
        }
    }
}

fn select_groups(
    host: &mut impl RuntimeHost,
    source: &NeIconSource,
    index: i16,
    requested_count: u16,
) -> Result<Vec<SelectedGroup>, RuntimeError> {
    let mut selected = Vec::new();
    let start = if index < 0 {
        // A negative index identifies the starting resource, not a limit of
        // one group. The requested count still bounds consecutive extraction.
        let id = NeResourceId::Numeric(index.unsigned_abs());
        let Some(start) = source.groups.iter().position(|candidate| candidate == &id) else {
            return Ok(selected);
        };
        start
    } else {
        usize::from(index as u16)
    };
    let ids = source
        .groups
        .iter()
        .skip(start)
        .take(usize::from(requested_count));
    let count = ids.clone().count();
    selected.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "could not reserve selected NE group icons",
            error,
        )
    })?;
    for id in ids {
        let Some(group) = selected_group(host, source, id)? else {
            break;
        };
        selected.push(group);
    }
    Ok(selected)
}

fn create_icon_for_group(
    host: &mut impl RuntimeHost,
    resources: &NeIconResourceTable,
    group: &SelectedGroup,
    size: Win16HostIconSize,
) -> Result<Option<Win16HostIcon>, RuntimeError> {
    let Some(image_id) = host.win16_select_icon_image_sized(&group.directory, size)? else {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::InvalidInput,
            "SHELL icon extraction could not select an NE icon image",
        ));
        return Ok(None);
    };
    let image = match resources.icon_image(image_id) {
        Ok(Some(image)) => image,
        Ok(None) => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::InvalidInput,
                "SHELL icon extraction found a missing NE icon image",
            ));
            return Ok(None);
        }
        Err(error) => {
            report_format_problem(
                host,
                error,
                "SHELL icon extraction skipped a malformed NE icon image",
            )?;
            return Ok(None);
        }
    };
    let icon = host.win16_create_icon_sized(&image, size)?;
    if icon.is_none() {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::InvalidInput,
            "SHELL icon extraction could not create an NE icon image",
        ));
    }
    Ok(icon)
}

fn report_format_problem(
    host: &mut impl RuntimeHost,
    error: FormatError,
    message: &'static str,
) -> Result<(), RuntimeError> {
    if matches!(&error, FormatError::AllocationFailed) {
        return Err(crate::runtime_error(error));
    }
    host.report_diagnostic(&Diagnostic::warning(Kind::InvalidInput, message).with_cause(error));
    Ok(())
}

fn reserve_icons(icons: &mut Vec<Option<Win16HostIcon>>, count: usize) -> Result<(), RuntimeError> {
    icons.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "could not reserve extracted NE icon handles",
            error,
        )
    })
}

fn release_partial(
    host: &mut impl RuntimeHost,
    original_error: RuntimeError,
    large: &[Option<Win16HostIcon>],
    small: &[Option<Win16HostIcon>],
    pending: Option<Win16HostIcon>,
) -> RuntimeError {
    let mut first_release_error = None;
    for icon in large.iter().chain(small).flatten().copied().chain(pending) {
        if let Err(error) = host.win16_release_icon(icon) {
            if first_release_error.is_none() {
                first_release_error = Some(error);
            }
        }
    }
    match first_release_error {
        Some(release_error) => RuntimeError::with_source(
            Kind::InternalInvariant,
            "failed to release partial NE icon extraction",
            release_error,
        )
        .with_context(format!("original extraction failure: {original_error}")),
        None => original_error,
    }
}

#[cfg(test)]
mod tests {
    use super::has_ne_header;

    #[test]
    fn identifies_only_mz_images_with_ne_at_the_declared_offset() {
        let mut image = vec![0_u8; 0x82];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x82].copy_from_slice(b"NE");
        assert!(has_ne_header(&image));

        image[0x80..0x82].copy_from_slice(b"PE");
        assert!(!has_ne_header(&image));
        image[0..2].copy_from_slice(b"NE");
        assert!(!has_ne_header(&image));
    }
}
