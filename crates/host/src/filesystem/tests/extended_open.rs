use dos_kernel::{
    DosErrorCode, DosFileAccess, DosFileDisposition, DosFileOpenOutcome, DosFileOpenRequest,
    DosFileSharing, DosHostError, DosSeekOrigin,
};

use super::{Filesystem, TestDirectory};

fn request(disposition: DosFileDisposition, access: DosFileAccess) -> DosFileOpenRequest {
    DosFileOpenRequest {
        access,
        sharing: DosFileSharing::DenyNone,
        disposition,
        attributes: 0,
    }
}

#[test]
fn extended_open_native_reports_actions_without_truncation_or_attribute_changes() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let mut create = request(DosFileDisposition::CreateNew, DosFileAccess::ReadWrite);
    create.attributes = 0x06;
    let first = fs.file_extended_open(b"KEEP.DAT", create).unwrap();
    assert_eq!(first.outcome, DosFileOpenOutcome::Created);
    fs.file_write(first.file, b"preserve me").unwrap();
    let attributes = fs.file_get_attributes(b"KEEP.DAT").unwrap();
    assert_eq!(attributes & 0x06, 0x06);
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::OpenOrCreate] {
        let second = fs.file_extended_open(b"keep.dat", request(disposition, DosFileAccess::ReadWrite)).unwrap();
        assert_eq!(second.outcome, DosFileOpenOutcome::Opened);
        assert_ne!(second.file, first.file);
        assert_eq!(fs.file_status(second.file).unwrap().position, 0);
        assert_eq!(fs.file_status(first.file).unwrap().position, 11);
        let mut bytes = [0; 11];
        assert_eq!(fs.file_read(second.file, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"preserve me");
        assert_eq!(fs.file_get_attributes(b"KEEP.DAT").unwrap(), attributes);
        fs.file_close(second.file).unwrap();
    }
    assert_eq!(fs.file_extended_open(b"KEEP.DAT", create).unwrap_err().code, DosErrorCode::FileExists);
    let duplicate = fs.file_duplicate(first.file).unwrap();
    fs.file_close(first.file).unwrap();
    fs.file_seek(duplicate, 0, DosSeekOrigin::Start).unwrap();
    assert_eq!(fs.file_status(duplicate).unwrap().size, 11);
    fs.file_close(duplicate).unwrap();
    assert!(fs.files.is_empty());
    assert_eq!(std::fs::read(directory.0.join("KEEP.DAT")).unwrap(), b"preserve me");
}

#[test]
fn extended_open_native_enforces_requested_access_on_returned_handles() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for disposition in [DosFileDisposition::CreateNew, DosFileDisposition::OpenExisting, DosFileDisposition::OpenOrCreate] {
        for access in [DosFileAccess::ReadOnly, DosFileAccess::WriteOnly, DosFileAccess::ReadWrite] {
            let path = b"ACCESS.DAT";
            if disposition == DosFileDisposition::OpenExisting {
                std::fs::write(directory.0.join("ACCESS.DAT"), b"x").unwrap();
            }
            let result = fs.file_extended_open(path, request(disposition, access));
            let opened = result.unwrap();
            assert_eq!(
                opened.outcome,
                if disposition == DosFileDisposition::OpenExisting {
                    DosFileOpenOutcome::Opened
                } else {
                    DosFileOpenOutcome::Created
                },
            );
            let mut byte = [0];
            let read = fs.file_read(opened.file, &mut byte);
            if access == DosFileAccess::WriteOnly {
                assert_eq!(read.unwrap_err().code, DosErrorCode::AccessDenied);
            } else {
                read.unwrap();
            }
            let write = fs.file_write(opened.file, b"y");
            if access == DosFileAccess::ReadOnly {
                assert_eq!(write.unwrap_err().code, DosErrorCode::AccessDenied);
                assert_eq!(fs.file_set_len(opened.file, 0).unwrap_err().code, DosErrorCode::AccessDenied);
            } else {
                assert_eq!(write.unwrap(), 1);
            }
            let duplicate = fs.file_duplicate(opened.file).unwrap();
            fs.file_close(opened.file).unwrap();
            if access == DosFileAccess::WriteOnly {
                assert_eq!(fs.file_read(duplicate, &mut byte).unwrap_err().code, DosErrorCode::AccessDenied);
            } else if access == DosFileAccess::ReadOnly {
                assert_eq!(fs.file_write(duplicate, b"bad").unwrap_err().code, DosErrorCode::AccessDenied);
                assert_eq!(fs.file_set_len(duplicate, 0).unwrap_err().code, DosErrorCode::AccessDenied);
                assert_eq!(fs.file_status(duplicate).unwrap().size,
                    if disposition == DosFileDisposition::OpenExisting { 1 } else { 0 });
            }
            fs.file_close(duplicate).unwrap();
            std::fs::remove_file(directory.0.join("ACCESS.DAT")).unwrap();
        }
    }
    assert!(fs.files.is_empty());
}

#[test]
fn extended_open_native_read_only_open_or_create_can_open_existing() {
    let directory = TestDirectory::new();
    std::fs::write(directory.0.join("READONLY.DAT"), b"original").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.file_set_attributes(b"READONLY.DAT", 0x01).unwrap();
    let result = fs.file_extended_open(
        b"READONLY.DAT",
        request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadOnly),
    ).unwrap();
    assert_eq!(result.outcome, DosFileOpenOutcome::Opened);
    assert_eq!(fs.file_status(result.file).unwrap().size, 8);
    assert_eq!(fs.file_write(result.file, b"bad").unwrap_err().code, DosErrorCode::AccessDenied);
    fs.file_close(result.file).unwrap();
    assert_eq!(fs.file_extended_open(
        b"READONLY.DAT", request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite),
    ).unwrap_err().code, DosErrorCode::AccessDenied);
    assert_eq!(std::fs::read(directory.0.join("READONLY.DAT")).unwrap(), b"original");
    fs.file_set_attributes(b"READONLY.DAT", 0).unwrap();
}

#[test]
fn extended_open_native_enforces_all_requested_sharing_modes() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for (disposition, existing) in [
        (DosFileDisposition::OpenExisting, true),
        (DosFileDisposition::CreateNew, false),
        (DosFileDisposition::OpenOrCreate, true),
        (DosFileDisposition::OpenOrCreate, false),
    ] {
        for sharing in [
            DosFileSharing::Compatibility,
            DosFileSharing::DenyNone,
            DosFileSharing::DenyAll,
            DosFileSharing::DenyWrite,
            DosFileSharing::DenyRead,
        ] {
            if existing {
                std::fs::write(directory.0.join("SHARING.DAT"), b"keep").unwrap();
            }
            let mut first_request = request(disposition, DosFileAccess::ReadWrite);
            first_request.sharing = sharing;
            let first = fs.file_extended_open(b"SHARING.DAT", first_request).unwrap();
            assert_eq!(first.outcome, if existing { DosFileOpenOutcome::Opened } else { DosFileOpenOutcome::Created });
            for access in [DosFileAccess::ReadOnly, DosFileAccess::WriteOnly] {
                let denied = sharing == DosFileSharing::DenyAll
                    || (sharing == DosFileSharing::DenyWrite && access == DosFileAccess::WriteOnly)
                    || (sharing == DosFileSharing::DenyRead && access == DosFileAccess::ReadOnly);
                let probe = fs.file_extended_open(
                    b"SHARING.DAT", request(DosFileDisposition::OpenOrCreate, access),
                );
                if denied {
                    assert_eq!(probe.unwrap_err().code, DosErrorCode::SharingViolation);
                } else {
                    let probe = probe.unwrap();
                    assert_eq!(probe.outcome, DosFileOpenOutcome::Opened);
                    fs.file_close(probe.file).unwrap();
                }
            }
            fs.file_close(first.file).unwrap();
            assert!(fs.files.is_empty());
            if existing {
                assert_eq!(std::fs::read(directory.0.join("SHARING.DAT")).unwrap(), b"keep");
            }
            std::fs::remove_file(directory.0.join("SHARING.DAT")).unwrap();
        }
    }
}

#[test]
fn extended_open_native_resolves_existing_short_aliases() {
    let directory = TestDirectory::new();
    let native = directory.0.join("Long existing filename.dat");
    std::fs::write(&native, b"existing contents").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    let search = fs.directory_search_open(b".").unwrap();
    let mut alias = None;
    while let Some(entry) = fs.directory_search_next(search).unwrap() {
        if entry.attributes & 0x10 == 0 {
            assert!(alias.is_none());
            alias = Some(entry.short_name);
        }
    }
    fs.directory_search_close(search).unwrap();
    let alias = alias.unwrap();
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::OpenOrCreate] {
        let opened = fs.file_extended_open(&alias, request(disposition, DosFileAccess::ReadWrite)).unwrap();
        assert_eq!(opened.outcome, DosFileOpenOutcome::Opened);
        assert_eq!(fs.file_status(opened.file).unwrap().size, 17);
        fs.file_close(opened.file).unwrap();
    }
    assert_eq!(fs.file_extended_open(
        &alias, request(DosFileDisposition::CreateNew, DosFileAccess::ReadWrite),
    ).unwrap_err().code, DosErrorCode::FileExists);
    assert_eq!(std::fs::read(&native).unwrap(), b"existing contents");
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn extended_open_native_rejects_invalid_attributes_and_exhausted_tokens_before_mutation() {
    let directory = TestDirectory::new();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::CreateNew, DosFileDisposition::OpenOrCreate] {
        for attributes in [0x08, 0x10, 0x40, 0x80, 0xff] {
            let mut invalid = request(disposition, DosFileAccess::ReadWrite);
            invalid.attributes = attributes;
            assert_eq!(fs.file_extended_open(b"INVALID.DAT", invalid).unwrap_err().code, DosErrorCode::InvalidAccess);
        }
    }
    std::fs::write(directory.0.join("KEEP.DAT"), b"keep").unwrap();
    fs.next_file = u64::MAX;
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::CreateNew, DosFileDisposition::OpenOrCreate] {
        for path in [b"NEW.DAT".as_slice(), b"KEEP.DAT".as_slice()] {
            assert_eq!(fs.file_extended_open(path, request(disposition, DosFileAccess::ReadWrite)).unwrap_err().code, DosErrorCode::TooManyOpenFiles);
        }
    }
    assert!(!directory.0.join("INVALID.DAT").exists());
    assert!(!directory.0.join("NEW.DAT").exists());
    assert_eq!(std::fs::read(directory.0.join("KEEP.DAT")).unwrap(), b"keep");
    assert!(fs.files.is_empty());
}

#[test]
fn extended_open_native_preserves_directories_and_missing_parents() {
    let directory = TestDirectory::new();
    std::fs::create_dir(directory.0.join("SUBDIR")).unwrap();
    std::fs::write(directory.0.join("SUBDIR/KEEP.DAT"), b"keep").unwrap();
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::CreateNew, DosFileDisposition::OpenOrCreate] {
        let error = fs.file_extended_open(b"SUBDIR", request(disposition, DosFileAccess::ReadWrite)).unwrap_err();
        assert!(matches!(error.code, DosErrorCode::AccessDenied | DosErrorCode::FileExists));
        let missing = fs.file_extended_open(b"MISSING/NEW.DAT",
            request(disposition, DosFileAccess::ReadWrite)).unwrap_err();
        if disposition != DosFileDisposition::OpenExisting {
            assert_eq!(missing.code, DosErrorCode::PathNotFound);
        }
    }
    assert_eq!(fs.file_extended_open(b"SUBDIR/ABSENT.DAT",
        request(DosFileDisposition::OpenExisting, DosFileAccess::ReadWrite)).unwrap_err().code,
        DosErrorCode::FileNotFound);
    assert_eq!(std::fs::read(directory.0.join("SUBDIR/KEEP.DAT")).unwrap(), b"keep");
    assert!(!directory.0.join("MISSING").exists());
    assert!(fs.files.is_empty());
}

#[test]
fn extended_open_native_concurrent_open_or_create_has_one_created_outcome() {
    let directory = TestDirectory::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2).map(|_| {
        let path = directory.0.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut fs = Filesystem::new_native_directory(&path, 437).unwrap();
            barrier.wait();
            let opened = fs.file_extended_open(
                b"RACE.DAT", request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite),
            ).unwrap();
            if opened.outcome == DosFileOpenOutcome::Created {
                fs.file_write(opened.file, b"winner").unwrap();
            }
            fs.file_close(opened.file).unwrap();
            opened.outcome
        })
    }).collect();
    let outcomes: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|&&outcome| outcome == DosFileOpenOutcome::Created).count(), 1);
    assert_eq!(outcomes.iter().filter(|&&outcome| outcome == DosFileOpenOutcome::Opened).count(), 1);
    assert_eq!(std::fs::read(directory.0.join("RACE.DAT")).unwrap(), b"winner");
}

fn confined_filesystem(directory: &TestDirectory) -> Filesystem {
    let mut fs = Filesystem::new_native_directory(&directory.0, 437).unwrap();
    fs.root = cap_std::fs::Dir::open_ambient_dir(&directory.0, cap_std::ambient_authority()).unwrap();
    fs.canonical_root = std::fs::canonicalize(&directory.0).unwrap();
    fs.current_directory.clear();
    fs
}

#[test]
fn extended_open_native_keeps_dos_paths_in_the_capability_root() {
    let directory = TestDirectory::new();
    let mut fs = confined_filesystem(&directory);
    let opened = fs.file_extended_open(
        b"\\..\\..\\LOCAL.DAT", request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite),
    ).unwrap();
    assert_eq!(opened.outcome, DosFileOpenOutcome::Created);
    fs.file_close(opened.file).unwrap();
    assert!(directory.0.join("LOCAL.DAT").is_file());
    for path in [b"\\\\server\\share\\BAD.DAT".as_slice(), b"\\\\?\\C:\\BAD.DAT", b"LOCAL.DAT:stream", b"NUL"] {
        assert!(fs.file_extended_open(path, request(DosFileDisposition::OpenOrCreate, DosFileAccess::ReadWrite)).is_err());
    }
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    assert!(fs.files.is_empty());
}

fn symlink_file_or_skip(target: &std::path::Path, link: &std::path::Path) -> bool {
    match std::os::windows::fs::symlink_file(target, link) {
        Ok(()) => true,
        Err(error) if error.raw_os_error() == Some(1314) => {
            eprintln!("symlink coverage requires Windows Developer Mode or symlink privilege");
            false
        }
        Err(error) => panic!("cannot create symlink fixture: {error}"),
    }
}

#[test]
fn extended_open_native_does_not_create_through_a_dangling_final_symlink() {
    let directory = TestDirectory::new();
    let target = directory.0.join("ABSENT.DAT");
    let link = directory.0.join("LINK.DAT");
    if !symlink_file_or_skip(std::path::Path::new("ABSENT.DAT"), &link) {
        return;
    }
    let mut fs = confined_filesystem(&directory);
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::CreateNew, DosFileDisposition::OpenOrCreate] {
        let error = fs.file_extended_open(b"LINK.DAT", request(disposition, DosFileAccess::ReadWrite)).unwrap_err();
        if disposition == DosFileDisposition::CreateNew {
            assert_eq!(error.code, DosErrorCode::FileExists);
        }
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(fs.files.is_empty());
    }
}

#[test]
fn extended_open_native_rejects_final_symlinks_outside_the_capability_root() {
    let directory = TestDirectory::new();
    let outside = TestDirectory::new();
    let target = outside.0.join("KEEP.DAT");
    std::fs::write(&target, b"outside contents").unwrap();
    let link = directory.0.join("OUTSIDE.DAT");
    if !symlink_file_or_skip(&target, &link) {
        return;
    }
    let mut fs = confined_filesystem(&directory);
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::CreateNew, DosFileDisposition::OpenOrCreate] {
        let error: DosHostError = fs.file_extended_open(b"OUTSIDE.DAT", request(disposition, DosFileAccess::ReadWrite)).unwrap_err();
        if disposition == DosFileDisposition::CreateNew {
            assert_eq!(error.code, DosErrorCode::FileExists);
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"outside contents");
        assert!(fs.files.is_empty());
    }
}

#[test]
fn extended_open_native_rejects_parent_symlinks_outside_the_capability_root() {
    let directory = TestDirectory::new();
    let outside = TestDirectory::new();
    std::fs::write(outside.0.join("KEEP.DAT"), b"outside contents").unwrap();
    match std::os::windows::fs::symlink_dir(&outside.0, directory.0.join("OUTSIDE")) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(1314) => {
            eprintln!("symlink coverage requires Windows Developer Mode or symlink privilege");
            return;
        }
        Err(error) => panic!("cannot create directory symlink fixture: {error}"),
    }
    let mut fs = confined_filesystem(&directory);
    for disposition in [DosFileDisposition::OpenExisting, DosFileDisposition::CreateNew, DosFileDisposition::OpenOrCreate] {
        for path in [b"OUTSIDE/KEEP.DAT".as_slice(), b"OUTSIDE/NEW.DAT".as_slice()] {
            assert!(fs.file_extended_open(path, request(disposition, DosFileAccess::ReadWrite)).is_err());
            assert!(fs.files.is_empty());
        }
    }
    assert!(!outside.0.join("NEW.DAT").exists());
    assert_eq!(std::fs::read(outside.0.join("KEEP.DAT")).unwrap(), b"outside contents");
}
