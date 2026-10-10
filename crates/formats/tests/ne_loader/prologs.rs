use super::*;

fn prolog_module(code_size: u32) -> NeModule {
    let mut module = two_segment_module(Vec::new());
    module.header.target_os = 2;
    module.header.flags = 0x8001; // Library with one shared automatic data segment.
    module.header.automatic_data_segment = 2;
    module.segments[0].file_size = code_size;
    module.segments[0].memory_size = code_size;
    module.segments[1].file_offset = None;
    module.segments[1].file_size = 0;
    module.segments[1].flags = 1;
    module.entries[0].kind = NeEntryKind::Fixed { segment: 1, offset: 0 };
    module.entries[0].flags = 3;
    module
}

fn loaded_code(module: &NeModule, bytes: &[u8]) -> (Vec<u8>, Selector) {
    let mut memory = TestMemory(vec![0xa5; 0x2_0000]);
    let mut resolver = TestResolver::new();
    let loaded = load_ne_segments(bytes, module, &mut resolver, &mut memory)
        .expect("Windows NE prolog load");
    let code = loaded.segment_selector(1).expect("code selector");
    let data = loaded.segment_selector(2).expect("data selector");
    let length = module.segments[0].memory_size as usize;
    let start = resolver.selector_range(code, 0, length).expect("code mapping").0 as usize;
    (memory.0[start..start + length].to_vec(), data)
}

#[test]
fn shared_data_exports_load_the_final_dgroup_selector() {
    for prefix in [[0x1e, 0x58, 0x90], [0x8c, 0xd8, 0x90]] {
        for movable in [false, true] {
            let mut module = prolog_module(16);
            if movable {
                module.entries[0].kind = NeEntryKind::Movable { segment: 1, offset: 0 };
            }
            let mut bytes = vec![0xcc; 16];
            bytes[..3].copy_from_slice(&prefix);
            let (code, data) = loaded_code(&module, &bytes);
            let [low, high] = data.0.to_le_bytes();
            assert_eq!(&code[..3], &[0xb8, low, high]);
            assert_eq!(&code[3..], &bytes[3..]);
            assert_eq!(&bytes[..3], &prefix, "source file remains immutable");
        }
    }
}

#[test]
fn multiple_data_callbacks_preserve_the_instance_selector_in_ax() {
    for prefix in [[0x1e, 0x58, 0x90], [0x8c, 0xd8, 0x90]] {
        let mut module = prolog_module(16);
        module.header.flags = 2;
        module.entries[0].flags = 1;
        let mut bytes = vec![0xcc; 16];
        bytes[..3].copy_from_slice(&prefix);
        let (code, _) = loaded_code(&module, &bytes);
        assert_eq!(&code[..3], &[0x90; 3]);
        assert_eq!(&code[3..], &bytes[3..]);
    }
}

#[test]
fn ineligible_entries_and_non_windows_modules_keep_original_bytes() {
    for case in 0..9 {
        let mut module = prolog_module(16);
        let mut bytes = vec![0xcc; 16];
        bytes[..3].copy_from_slice(&[0x1e, 0x58, 0x90]);
        match case {
            0 => module.entries[0].flags = 1, // DLL NODATA export.
            1 => { module.header.flags = 2; module.entries[0].flags = 0; }
            2 => module.segments[0].flags = 1, // Exported data, not code.
            3 => module.header.automatic_data_segment = 0,
            4 => module.header.target_os = 1, // OS/2.
            5 => module.header.target_os = 0, // Unspecified target.
            6 => module.header.target_os = 4, // Windows/386 has not been established.
            7 => module.entries[0].kind = NeEntryKind::Constant(0x581e),
            8 => module.entries[0].kind = NeEntryKind::Unused,
            _ => unreachable!(),
        }
        let (code, _) = loaded_code(&module, &bytes);
        assert_eq!(code, bytes, "ineligible case {case}");
    }
}

#[test]
fn arbitrary_and_short_entry_prefixes_are_not_rewritten() {
    for prefix in [[0x1e, 0x58, 0xcb], [0x8c, 0xd8, 0xcb], [0xb8, 0, 0]] {
        let module = prolog_module(16);
        let mut bytes = vec![0xcc; 16];
        bytes[..3].copy_from_slice(&prefix);
        assert_eq!(loaded_code(&module, &bytes).0, bytes);
    }
    let mut module = prolog_module(16);
    module.entries[0].kind = NeEntryKind::Fixed { segment: 1, offset: 14 };
    let mut bytes = vec![0xcc; 16];
    bytes[14..].copy_from_slice(&[0x1e, 0x58]);
    assert_eq!(loaded_code(&module, &bytes).0, bytes);
}

#[test]
fn prologs_use_expanded_images_and_relocations_use_pristine_chain_links() {
    let mut module = prolog_module(0x5820);
    module.segments[0].fixups = vec![fixup_at(0, false, 0x21)];
    let mut bytes = vec![0; 0x5820];
    bytes[..3].copy_from_slice(&[0x1e, 0x58, 0x90]);
    // The same two bytes are a recognized prolog and the first chain link.
    bytes[0x581e..0x5820].copy_from_slice(&0xffff_u16.to_le_bytes());
    let (code, data) = loaded_code(&module, &bytes);
    assert_eq!(&code[..3], &[0x21, 0, data.0.to_le_bytes()[1]]);
    assert_eq!(&code[0x581e..0x5820], &[0x21, 0]);

    let mut module = prolog_module(16);
    module.segments[0].flags = SEGMENT_FLAG_ITERATED;
    module.segments[0].file_size = 7;
    let (code, data) = loaded_code(&module, &[1, 0, 3, 0, 0x1e, 0x58, 0x90]);
    let [low, high] = data.0.to_le_bytes();
    assert_eq!(&code[..3], &[0xb8, low, high]);
}

#[test]
fn failed_commit_rolls_back_patched_code_and_releases_segments() {
    let module = prolog_module(16);
    let mut bytes = vec![0xcc; 16];
    bytes[..3].copy_from_slice(&[0x1e, 0x58, 0x90]);
    let mut memory = FaultMemory {
        inner: TestMemory(vec![0xa5; 0x2_0000]),
        write_count: 0,
        faults: HashMap::from([(2, MemoryError::InvalidMapping)]),
    };
    let before = memory.inner.0.clone();
    let mut resolver = TestResolver::new();
    assert!(load_ne_segments(&bytes, &module, &mut resolver, &mut memory).is_err());
    assert_eq!(memory.inner.0, before);
    assert!(resolver.allocations.is_empty());
    assert_eq!(resolver.released, [Selector(0x108), Selector(0x100)]);
}
