//! The optional disk code-page flag is independent of the disposition byte.
use super::{call, fixture};
use crate::{DosErrorCode, DosFileAccess, DosHost, DosSeekOrigin};

#[test]
fn extended_open_disk_code_page_flag_keeps_actions_contents_and_registers() {
    for exists in [false, true] {
        for action in [1, 2, 0x10, 0x11, 0x12] {
            let mut outputs = Vec::new();
            for flag in [0, 0x100] {
                let (mut dos, mut host, mut memory) = fixture();
                let original = exists.then(|| {
                    let file = host.file_create(b"TARGET.DAT", 2).unwrap();
                    host.file_write(file, b"preserve").unwrap();
                    host.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
                    file
                });
                let result = call(&mut dos, &mut host, &mut memory, 2, action | flag, 0x20);
                assert_eq!(host.extended_open_calls.len(), 1);
                assert_eq!(result.dx(), action | flag);
                if let Some(file) = original {
                    assert_eq!(
                        host.file_for(file).unwrap().bytes,
                        if matches!(action, 2 | 0x12) {
                            b"".as_slice()
                        } else {
                            b"preserve"
                        }
                    );
                }
                let mut normalized = result.clone();
                normalized.set_dx(action);
                outputs.push((normalized, host.extended_open_calls[0].clone()));
                dos.close_all_handles_checked(&mut host).unwrap();
            }
            assert_eq!(
                outputs[0], outputs[1],
                "exists={exists} action={action:02x}"
            );
        }
    }
}

#[test]
fn extended_open_disk_code_page_flag_keeps_host_errors_and_slot_cleanup() {
    let (mut dos, mut host, mut memory) = fixture();
    for code in [
        DosErrorCode::FileNotFound,
        DosErrorCode::AccessDenied,
        DosErrorCode::SharingViolation,
    ] {
        host.extended_open_error = Some(code);
        let result = call(&mut dos, &mut host, &mut memory, 0, 0x101, 0xffff);
        assert_eq!(result.ax(), code as u16);
        assert!(result.carry());
        assert_eq!(result.dx(), 0x101);
        assert_eq!(result.cx(), 0xffff);
        assert_eq!(
            host.extended_open_calls.last().unwrap().1.access,
            DosFileAccess::ReadOnly
        );
        assert!(dos.handles.get(&3).is_none());
        assert!(host.paths.is_empty());
    }
    host.extended_open_error = None;
    host.file_create(b"TARGET.DAT", 0).unwrap();
    let result = call(&mut dos, &mut host, &mut memory, 0, 0x101, 0);
    assert!(!result.carry());
    assert_eq!((result.ax(), result.cx()), (3, 1));
    dos.close_all_handles_checked(&mut host).unwrap();
}
