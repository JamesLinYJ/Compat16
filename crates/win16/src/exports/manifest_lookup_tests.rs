//! Public resolver contracts retained when physical catalog groups change.

use super::*;

#[test]
fn explicit_name_collisions_keep_the_legacy_target() {
    // These names collide with later declarations. The selected ordinal is an
    // explicit catalog decision, not whichever TOML group is traversed first.
    assert!(declarations::NAME_RESOLUTIONS.iter().any(|&(module, name, ordinal)| {
        module == "USER" && name.eq_ignore_ascii_case("OLDEXITWINDOWS") && ordinal == 2
    }));
    for &(module, name, ordinal) in declarations::NAME_RESOLUTIONS {
        let expected = lookup_export_metadata(module.as_bytes(), ExportLookupTarget::Ordinal(ordinal));
        assert!(expected.is_some(), "missing chosen declaration {module}!{ordinal}");
        for spelling in [name.to_ascii_lowercase(), name.to_ascii_uppercase()] {
            assert_eq!(lookup_export_metadata(module.as_bytes(), ExportLookupTarget::Name(spelling.as_bytes())), expected);
            assert_eq!(lookup_export(module.as_bytes(), ExportLookupTarget::Name(spelling.as_bytes())),
                lookup_export(module.as_bytes(), ExportLookupTarget::Ordinal(ordinal)));
        }
    }
}

#[test]
fn generated_export_aliases_preserve_canonical_resolution() {
    for (module, ordinal, name) in [("GDI", 104, "RectVisibleOld"), ("GDI", 181, "RectInRegionOld")] {
        assert!(declarations::EXPORT_ALIASES.contains(&(module, ordinal, name)));
    }
    for &(module, ordinal, alias) in declarations::EXPORT_ALIASES {
        // A colliding alias is resolved by the same explicit policy as an
        // exported name; do not accidentally bypass NAME_RESOLUTIONS here.
        let ordinal = declarations::NAME_RESOLUTIONS.iter()
            .find(|&&(candidate, name, _)| candidate == module && name.eq_ignore_ascii_case(alias))
            .map_or(ordinal, |&(_, _, selected)| selected);
        assert_eq!(resolve_export(module.as_bytes(), ExportLookupTarget::Name(alias.to_ascii_lowercase().as_bytes())),
            resolve_export(module.as_bytes(), ExportLookupTarget::Ordinal(ordinal)));
    }
}

#[test]
fn generated_module_aliases_accept_case_and_single_suffix_normalization() {
    for &(module, alias) in declarations::MODULE_ALIASES {
        let entry = WIN16_EXPORTS.iter().flat_map(|group| group.iter())
            .find(|entry| entry.module == module && entry.architecture == ExportArchitecture::Win16)
            .expect("module alias must identify an active declaration");
        let target = ExportLookupTarget::Ordinal(entry.ordinal);
        let expected = resolve_export(module.as_bytes(), target);
        for spelling in [alias.to_ascii_lowercase(), alias.to_ascii_uppercase()] {
            assert_eq!(resolve_export(spelling.as_bytes(), target), expected);
        }
    }
    let target = ExportLookupTarget::Ordinal(1);
    for module in ["kernel", "krnl386", "KrNl386.ExE", "KERNEL.DLL", "kernel.drv", "kernel.MOD"] {
        assert_eq!(resolve_export(module.as_bytes(), target), resolve_export(b"KERNEL", target));
    }
    assert!(lookup_export_metadata(b"KERNEL.DLL.DLL", target).is_none());
    assert!(lookup_export_metadata(b"unknown_module", target).is_none());
}

#[test]
fn generated_decoder_keys_match_stable_descriptor_identities() {
    assert_eq!(WIN16_DECODER_KEYS.len(), export_descriptors().len());
    for (descriptor, &(id, key)) in export_descriptors().iter().zip(WIN16_DECODER_KEYS) {
        assert_eq!(descriptor.id, id);
        assert_eq!(format!("{id:?}"), key);
        assert_eq!(lookup_export(id.module().as_bytes(), ExportLookupTarget::Ordinal(id.ordinal())), Some(descriptor));
    }
}
