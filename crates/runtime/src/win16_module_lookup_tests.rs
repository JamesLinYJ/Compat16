//! Resident names, complete filenames and loader aliases are distinct contracts.

use super::*;
use crate::win16_runtime::test_support::tiny_ne_executable;

fn module(handle: u16, name: &[u8], path: &[u8]) -> ModuleRecord {
    let image = tiny_ne_executable();
    let mut definition = formats::parse_ne(&image).unwrap();
    definition.resident_names = vec![formats::NeNamedEntry {
        name: name.to_vec(),
        ordinal: 0,
    }];
    ModuleRecord {
        handle,
        instance: handle,
        path: path.to_vec(),
        name: name.to_vec(),
        builtin: false,
        pinned: false,
        explicit_refs: 0,
        continuation_owner_refs: 0,
        state: ModuleState::Ready,
        deps: Vec::new(),
        definition: Some(definition),
        loaded: None,
        image,
        allocations: Vec::new(),
        builtin_data_selector: None,
        builtin_data_exports: None,
        external_application: None,
        wep_called: false,
        resources_retirement_deferred: false,
    }
}

#[test]
fn module_lookup_bare_dll_import_does_not_bind_same_stem_executable() {
    let registry = ModuleRegistry::new(module(0x80, b"EDITORX", br"C:\APPS\EDITOR.EXE"));
    assert_eq!(registry.by_name(b"EDITOR"), None);
    assert_eq!(registry.by_load_name(b"EDITOR"), None);
    assert_eq!(registry.by_load_name(br"C:\APPS\EDITOR.DLL"), None);
    assert_eq!(registry.by_name(b"editorx"), Some(0x80));
    assert_eq!(registry.by_name(b"EDITOR.EXE"), Some(0x80));
}

#[test]
fn module_lookup_resident_identity_precedes_unrelated_filename() {
    let mut registry = ModuleRegistry::new(module(0x80, b"RENAMED", b"MATH.DLL"));
    registry
        .records
        .insert(0x88, module(0x88, b"MATH.DLL", b"OTHER.DLL"));
    assert_eq!(registry.by_name(b"MATH.DLL"), Some(0x88));
    assert_eq!(registry.by_load_name(b"MATH.DLL"), Some(0x80));
    registry.records.get_mut(&0x88).unwrap().state = ModuleState::Retired;
    assert_eq!(registry.by_name(b"MATH.DLL"), Some(0x80));
}

#[test]
fn module_lookup_complete_filenames_keep_exe_dll_and_drv_distinct() {
    let mut registry = ModuleRegistry::new(module(0x80, b"EDITORX", b"EDITOR.EXE"));
    registry
        .records
        .insert(0x88, module(0x88, b"EDITOR", b"EDITOR.DLL"));
    registry
        .records
        .insert(0x90, module(0x90, b"DRIVER", b"EDITOR.DRV"));
    for (query, expected) in [
        (b"EDITOR.EXE".as_slice(), 0x80),
        (b"EDITOR.DLL", 0x88),
        (b"EDITOR.DRV", 0x90),
        (b"EDITOR", 0x88),
    ] {
        assert_eq!(registry.by_name(query), Some(expected));
        assert_eq!(registry.by_load_name(query), Some(expected));
    }
}

#[test]
fn module_lookup_loader_fallback_uses_resident_name_without_file_extension() {
    let registry = ModuleRegistry::new(module(0x80, b"HELPER", b"RENAMED.DLL"));
    assert_eq!(registry.by_name(b"HELPER.DLL"), None);
    assert_eq!(registry.by_load_name(b"HELPER.DLL"), Some(0x80));
    assert_eq!(registry.by_load_name(br"C:\APPS\helper.drv"), Some(0x80));
    assert_eq!(registry.by_load_name(b".DLL"), None);
}

#[test]
fn module_lookup_builtin_suffix_aliases_remain_available() {
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], br"C:\APP.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let kernel = state.modules.by_name(b"KERNEL").unwrap();
    for query in [
        b"KERNEL.EXE".as_slice(),
        b"kernel.dll",
        br"C:\WINDOWS\KERNEL.EXE",
    ] {
        assert_eq!(state.modules.by_name(query), Some(kernel));
    }
    assert_eq!(state.modules.by_name(b"KERNEL.UNKNOWN"), None);
    state.modules.records.get_mut(&kernel).unwrap().state = ModuleState::Retired;
    assert_eq!(state.modules.by_load_name(b"KERNEL.EXE"), None);
}

#[test]
fn module_lookup_import_binding_uses_dll_export_and_preserves_missing_symbol() {
    use formats::{FarAddress, NeEntry, NeEntryKind, NeImportValue};
    use guest_core::Selector;
    use win16_abi::Win16ProcReference;
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], br"C:\EDITOR.EXE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state
        .modules
        .records
        .get_mut(&state.modules.main)
        .unwrap()
        .name = b"EDITORX".to_vec();
    state
        .modules
        .records
        .get_mut(&state.modules.main)
        .unwrap()
        .definition
        .as_mut()
        .unwrap()
        .resident_names = vec![formats::NeNamedEntry {
        name: b"EDITORX".to_vec(),
        ordinal: 0,
    }];
    let dll_handle = 0xf000;
    let mut dll = module(dll_handle, b"EDITOR", b"EDITOR.DLL");
    dll.definition.as_mut().unwrap().nonresident_names = vec![formats::NeNamedEntry {
        name: b"RENDER".to_vec(),
        ordinal: 1,
    }];
    let address = NeImportValue::Address(FarAddress {
        selector: Selector(0xf008),
        offset: 42,
    });
    dll.definition.as_mut().unwrap().entries = vec![NeEntry {
        ordinal: 1,
        flags: 1,
        kind: NeEntryKind::Fixed {
            segment: 1,
            offset: 42,
        },
    }];
    dll.loaded = Some(
        formats::plan_ne_segments(
            dll.definition.as_ref().unwrap(),
            &[Selector(0xf008), Selector(0xf010)],
        )
        .unwrap(),
    );
    state.modules.records.insert(dll_handle, dll);
    let owner = state.modules.by_name(b"EDITOR").unwrap();
    assert_eq!(owner, dll_handle);
    assert_eq!(
        state
            .module_import_value(owner, &Win16ProcReference::Name(b"RENDER".to_vec()), true)
            .unwrap(),
        Some(address)
    );
    assert_eq!(
        state
            .module_import_value(owner, &Win16ProcReference::Name(b"ABSENT".to_vec()), true)
            .unwrap(),
        None
    );
}

#[test]
fn module_handle_rejects_a_task_handle_and_a_missing_module_is_null() {
    use win16_abi::Win16ModuleReference;
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], br"C:\APP.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let task = state.first_task_handle;
    let instance = state.instance_handle;
    let main = state.modules.main;
    assert_ne!(task, 0);
    assert_ne!(task, instance);
    assert_ne!(task, main);
    assert_ne!(state.modules.first, 0);
    assert_eq!(
        state.module_handle(&Win16ModuleReference::Handle(task)),
        None
    );
    assert_eq!(
        state.module_handle(&Win16ModuleReference::Handle(instance)),
        Some(main)
    );
    assert_eq!(
        state.module_handle(&Win16ModuleReference::Current),
        Some(main)
    );
    let kernel = state.modules.by_name(b"KERNEL").unwrap();
    assert_eq!(
        state.module_handle(&Win16ModuleReference::Name(b"KERNEL".to_vec())),
        Some(kernel)
    );
    let alien = 1;
    assert_eq!(state.modules.by_handle(alien), None);
    state.task_handles.insert(guest_core::OwnerId(9), alien);
    assert_eq!(
        state.module_handle(&Win16ModuleReference::Handle(alien)),
        None
    );
    assert_eq!(
        state.kernel_get_module_handle(&Win16ModuleReference::Handle(task)),
        0
    );
    assert_eq!(
        state.kernel_get_module_handle(&Win16ModuleReference::Handle(alien)),
        0
    );
    assert_eq!(
        state.kernel_get_module_handle(&Win16ModuleReference::Name(b"NO-SUCH".to_vec())),
        0
    );
    assert_eq!(
        state.kernel_get_module_handle(&Win16ModuleReference::Handle(main)),
        u32::from(main) | (u32::from(state.modules.first) << 16)
    );
}
