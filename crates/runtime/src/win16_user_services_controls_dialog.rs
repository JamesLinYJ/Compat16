//! Owned class identities for custom classes embedded in dialog templates.

use super::*;

pub(super) fn guest_class_routes(
    template: &crate::Win16HostDialogTemplate,
) -> Result<Vec<GuestDialogClassRoute>, RuntimeError> {
    let count = usize::from(matches!(
        &template.class,
        crate::Win16HostDialogAtom::GuestClass(_)
    ))
    .checked_add(
        template
            .items
            .iter()
            .filter(|item| matches!(&item.class, crate::Win16HostDialogAtom::GuestClass(_)))
            .count(),
    )
    .ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 dialog class-route count overflow",
        )
    })?;
    let mut routes = Vec::new();
    routes.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 dialog class routes",
            error,
        )
    })?;
    if let crate::Win16HostDialogAtom::GuestClass(host_class) = &template.class {
        let name = template.guest_class_name.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "resolved dialog root class lost its guest identity",
            )
        })?;
        routes.push(GuestDialogClassRoute {
            root: true,
            control_id: None,
            host_class: *host_class,
            guest_class_name: copy_host_class_name(name)?,
        });
    }
    for item in &template.items {
        let crate::Win16HostDialogAtom::GuestClass(host_class) = &item.class else {
            continue;
        };
        let name = item.guest_class_name.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "resolved dialog item class lost its guest identity",
            )
        })?;
        routes.push(GuestDialogClassRoute {
            root: false,
            control_id: Some(item.id),
            host_class: *host_class,
            guest_class_name: copy_host_class_name(name)?,
        });
    }
    Ok(routes)
}

fn copy_host_class_name(
    name: &crate::Win16HostClassName,
) -> Result<crate::Win16HostClassName, RuntimeError> {
    match name {
        crate::Win16HostClassName::Atom(atom) => Ok(crate::Win16HostClassName::Atom(*atom)),
        crate::Win16HostClassName::Name(bytes) => {
            let mut copy = Vec::new();
            copy.try_reserve_exact(bytes.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy Win16 guest dialog class name",
                    error,
                )
            })?;
            copy.extend_from_slice(bytes);
            Ok(crate::Win16HostClassName::Name(copy))
        }
    }
}

pub(super) fn standard_dialog_control_ordinal(name: &[u8]) -> Option<u16> {
    let ordinal = if name.eq_ignore_ascii_case(b"BUTTON") {
        0x80
    } else if name.eq_ignore_ascii_case(b"EDIT") {
        0x81
    } else if name.eq_ignore_ascii_case(b"STATIC") {
        0x82
    } else if name.eq_ignore_ascii_case(b"LISTBOX") {
        0x83
    } else if name.eq_ignore_ascii_case(b"SCROLLBAR") {
        0x84
    } else if name.eq_ignore_ascii_case(b"COMBOBOX") {
        0x85
    } else {
        return None;
    };
    Some(ordinal)
}
