use super::*;

fn fixture() -> (DosKernel, TestHost, TestMemory) {
    let mut host = TestHost::default();
    host.drive = 2;
    (DosKernel::new(0x1000), host, TestMemory::new())
}
fn file(host: &mut TestHost, name: &[u8], attrs: u8) {
    let handle = host.file_create(name, attrs).unwrap();
    host.file_write(handle, b"preserve").unwrap();
    host.file_close(handle).unwrap();
}
fn fields(name: &[u8], page: text_codec::CodePage) -> [u8; 11] {
    let mut result = [0; 11];
    let (_, pattern) = parse_search_spec(
        name,
        &TestHost {
            code_page: Some(page),
            ..Default::default()
        },
    )
    .unwrap();
    result[..8].copy_from_slice(&pattern.name);
    result[8..].copy_from_slice(&pattern.extension);
    result
}
fn input(memory: &mut TestMemory, old: &[u8; 11], new: Option<&[u8; 11]>, attrs: Option<u8>) {
    let mut bytes = [0xcc; 35];
    let skip = if let Some(attrs) = attrs {
        bytes[..7].fill(0);
        bytes[0] = 0xff;
        bytes[6] = attrs;
        7
    } else {
        0
    };
    bytes[skip] = 0;
    bytes[skip + 1..skip + 12].copy_from_slice(old);
    if let Some(new) = new {
        bytes[skip + 17..skip + 28].copy_from_slice(new);
    }
    memory.put(0x10100, &bytes);
}
fn call(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, ah: u8, status: u8) {
    let mut regs = Registers {
        eax: 0x1234_0007 | (u32::from(ah) << 8),
        ebx: 0x2345_1234,
        ecx: 0x3456_2345,
        edx: 0x4567_0100,
        esi: 0x5678_3456,
        edi: 0x6789_4567,
        ds: 0x1000,
        es: 0xffff,
        eflags: 0xad57,
        ..Default::default()
    };
    let mut expected = regs.clone();
    expected.set_al(status);
    let before = memory.0.clone();
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert_eq!(regs, expected);
    assert_eq!(memory.0, before);
}
fn error(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory) -> u16 {
    let mut regs = Registers {
        eax: 0x5900,
        ..Default::default()
    };
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    regs.ax()
}

#[test]
fn fcb_delete_exact_and_wildcard_remove_only_matching_entries_without_changing_fcb_or_dta() {
    let (mut dos, mut host, mut memory) = fixture();
    for name in [b"A.TMP".as_slice(), b"B.TMP", b"KEEP.TXT"] {
        file(&mut host, name, 0x20);
    }
    input(
        &mut memory,
        &fields(b"?.TMP", text_codec::CodePage::Cp437),
        None,
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0);
    assert_eq!(
        host.paths.keys().cloned().collect::<Vec<_>>(),
        [b"KEEP.TXT".to_vec()]
    );
    assert_eq!(host.fcb_delete_calls.len(), 2);
    assert!(host.searches.is_empty());
    assert_eq!(host.search_open_calls.len(), 1);
    assert_eq!(host.search_close_calls.len(), 1);
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 2);
}

#[test]
fn fcb_delete_readonly_hidden_system_and_directory_rules_keep_rejected_entries() {
    let (mut dos, mut host, mut memory) = fixture();
    file(&mut host, b"ONLY.TMP", 1);
    file(&mut host, b"HIDDEN.TMP", 2);
    file(&mut host, b"SYSTEM.TMP", 4);
    host.directories.insert(b"DIR.TMP".to_vec(), ());
    input(
        &mut memory,
        &fields(b"ONLY.TMP", text_codec::CodePage::Cp437),
        None,
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 5);
    assert!(host.fcb_delete_calls.is_empty());
    input(
        &mut memory,
        &fields(b"ONLY.TMP", text_codec::CodePage::Cp437),
        None,
        Some(1),
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0);
    assert_eq!(host.fcb_delete_calls, [(b"ONLY.TMP".to_vec(), true)]);
    input(
        &mut memory,
        &fields(b"*.TMP", text_codec::CodePage::Cp437),
        None,
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 2);
    input(
        &mut memory,
        &fields(b"*.TMP", text_codec::CodePage::Cp437),
        None,
        Some(6),
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0);
    assert!(host.paths.is_empty());
    assert!(host.directories.contains_key(b"DIR.TMP".as_slice()));
    input(
        &mut memory,
        &fields(b"DIR.TMP", text_codec::CodePage::Cp437),
        None,
        Some(0x1f),
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 5);
}

#[test]
fn fcb_delete_skips_locked_files_but_reports_success_if_another_match_was_deleted() {
    let (mut dos, mut host, mut memory) = fixture();
    file(&mut host, b"A.TMP", 0);
    file(&mut host, b"B.TMP", 0);
    let open = host.file_open(b"A.TMP", DosFileAccess::ReadOnly).unwrap();
    input(
        &mut memory,
        &fields(b"?.TMP", text_codec::CodePage::Cp437),
        None,
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0);
    assert!(host.paths.contains_key(b"A.TMP".as_slice()));
    assert!(!host.paths.contains_key(b"B.TMP".as_slice()));
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 5);
    host.file_close(open).unwrap();
    call(&mut dos, &mut host, &mut memory, 0x13, 0);
    assert!(host.paths.is_empty());
}

#[test]
fn fcb_delete_hard_errors_abort_after_prior_success_and_preserve_real_extended_code() {
    let (mut dos, mut host, mut memory) = fixture();
    for name in [b"A.TMP", b"B.TMP", b"C.TMP"] {
        file(&mut host, name, 0);
    }
    host.fcb_delete_errors
        .insert(b"B.TMP".to_vec(), DosErrorCode::WriteProtected);
    input(
        &mut memory,
        &fields(b"?.TMP", text_codec::CodePage::Cp437),
        None,
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 19);
    assert!(!host.paths.contains_key(b"A.TMP".as_slice()));
    assert!(host.paths.contains_key(b"B.TMP".as_slice()));
    assert!(host.paths.contains_key(b"C.TMP".as_slice()));
}

#[test]
fn fcb_rename_substitutes_fixed_fields_and_stops_at_first_duplicate_without_rollback() {
    let (mut dos, mut host, mut memory) = fixture();
    file(&mut host, b"A.OLD", 0);
    file(&mut host, b"B.OLD", 0);
    input(
        &mut memory,
        &fields(b"?.OLD", text_codec::CodePage::Cp437),
        Some(&fields(b"SAME.NEW", text_codec::CodePage::Cp437)),
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x17, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 5);
    assert!(host.paths.contains_key(b"SAME.NEW".as_slice()));
    assert!(!host.paths.contains_key(b"A.OLD".as_slice()));
    assert!(host.paths.contains_key(b"B.OLD".as_slice()));
    assert_eq!(host.rename_calls.len(), 2);
    assert!(host.searches.is_empty());
    input(
        &mut memory,
        &fields(b"B.OLD", text_codec::CodePage::Cp437),
        Some(&fields(b"B.NEW", text_codec::CodePage::Cp437)),
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x17, 0);
    assert!(host.paths.contains_key(b"B.NEW".as_slice()));
    input(
        &mut memory,
        &fields(b"B.NEW", text_codec::CodePage::Cp437),
        Some(&fields(b"B.NEW", text_codec::CodePage::Cp437)),
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x17, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 5);
}

#[test]
fn fcb_rename_extended_attributes_and_reserved_drive_byte_keep_the_source_directory() {
    let (mut dos, mut host, mut memory) = fixture();
    file(&mut host, b"HIDE.OLD", 2);
    file(&mut host, b"READ.OLD", 1);
    input(
        &mut memory,
        &fields(b"HIDE.OLD", text_codec::CodePage::Cp437),
        Some(&fields(b"HIDE.NEW", text_codec::CodePage::Cp437)),
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x17, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 2);
    input(
        &mut memory,
        &fields(b"HIDE.OLD", text_codec::CodePage::Cp437),
        Some(&fields(b"HIDE.NEW", text_codec::CodePage::Cp437)),
        Some(2),
    );
    call(&mut dos, &mut host, &mut memory, 0x17, 0);
    assert_eq!(host.attributes.get(b"HIDE.NEW".as_slice()), Some(&2));
    // DOS 4 and NT demRenameFCB pass readonly source files to the same rename
    // service; the template's offset 10h is reserved, never another drive.
    input(
        &mut memory,
        &fields(b"READ.OLD", text_codec::CodePage::Cp437),
        Some(&fields(b"READ.NEW", text_codec::CodePage::Cp437)),
        None,
    );
    memory.put(0x10110, &[26]);
    call(&mut dos, &mut host, &mut memory, 0x17, 0);
    assert_eq!(host.attributes.get(b"READ.NEW".as_slice()), Some(&1));
}

#[test]
fn fcb_mutation_oem_names_and_question_mark_positions_preserve_dbcs_trail_backslash() {
    for (page, prefix) in [
        (text_codec::CodePage::Cp437, b"\x9a".as_slice()),
        (text_codec::CodePage::Cp936, b"\x81\\"),
    ] {
        let (mut dos, mut host, mut memory) = fixture();
        host.code_page = Some(page);
        let old = [prefix, b"A.OLD"].concat();
        file(&mut host, &old, 0);
        // This legacy mock's parent splitter is ASCII-only; provide owned
        // directory entries for the DOS byte contract. Native COM/NE cases
        // use actual Unicode files and the real Windows path adapter.
        host.search_entries_override = Some(vec![DosDirectoryEntry {
            short_name: old.clone(),
            attributes: 0,
            write_time: 0,
            write_date: 0,
            size: 8,
        }]);
        let mut source = [b' '; 11];
        source[..prefix.len()].copy_from_slice(prefix);
        source[prefix.len()] = b'?';
        source[8..].copy_from_slice(b"OLD");
        let mut destination = [b'?'; 11];
        destination[8..].copy_from_slice(b"NEW");
        input(&mut memory, &source, Some(&destination), None);
        call(&mut dos, &mut host, &mut memory, 0x17, 0);
        let new = [prefix, b"A.NEW"].concat();
        assert!(host.paths.contains_key(&new));
        host.search_entries_override.as_mut().unwrap()[0].short_name = new.clone();
        let source = fields(&new, page);
        input(&mut memory, &source, None, None);
        call(&mut dos, &mut host, &mut memory, 0x13, 0);
        assert!(host.paths.is_empty());
    }
}

#[test]
fn fcb_mutation_close_failure_is_retryable_and_precedes_all_file_changes() {
    let (mut dos, mut host, mut memory) = fixture();
    file(&mut host, b"A.TMP", 0);
    host.search_close_error = Some(DosErrorCode::SharingViolation);
    input(
        &mut memory,
        &fields(b"A.TMP", text_codec::CodePage::Cp437),
        None,
        None,
    );
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(error(&mut dos, &mut host, &mut memory), 32);
    assert!(host.fcb_delete_calls.is_empty());
    assert_eq!(host.searches.len(), 1);
    call(&mut dos, &mut host, &mut memory, 0x13, 0xff);
    assert_eq!(host.search_open_calls.len(), 1);
    host.search_close_error = None;
    call(&mut dos, &mut host, &mut memory, 0x13, 0);
    assert!(host.paths.is_empty());
    assert!(host.searches.is_empty());
}

#[test]
fn fcb_mutation_invalid_fields_and_drive_do_not_enumerate_or_modify_files() {
    for rename in [false, true] {
        let (mut dos, mut host, mut memory) = fixture();
        file(&mut host, b"KEEP.TMP", 0);
        let mut bad = [b' '; 11];
        bad[..2].copy_from_slice(b"A:");
        input(
            &mut memory,
            &fields(b"KEEP.TMP", text_codec::CodePage::Cp437),
            rename.then_some(&bad),
            None,
        );
        if !rename {
            memory.put(0x10100, &[27]);
        }
        call(
            &mut dos,
            &mut host,
            &mut memory,
            if rename { 0x17 } else { 0x13 },
            0xff,
        );
        assert_eq!(error(&mut dos, &mut host, &mut memory), 3);
        assert!(host.search_open_calls.is_empty());
        assert!(host.paths.contains_key(b"KEEP.TMP".as_slice()));
    }
}
