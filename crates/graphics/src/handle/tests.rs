use super::{BitmapHandle, HandleError, HandleTable, WindowHandle};

#[test]
fn removed_handles_are_never_reissued() {
    let mut table = HandleTable::<BitmapHandle, _>::new();
    let stale = table.insert("first").unwrap();
    assert_eq!(table.remove(stale), Some("first"));
    let current = table.insert("second").unwrap();

    assert_ne!(stale, current);
    assert_eq!(table.get(stale), None);
    assert_eq!(table.get(current), Some(&"second"));
}

#[test]
fn handle_types_reject_null_and_do_not_alias() {
    assert!(WindowHandle::from_raw(0).is_none());
    let window = WindowHandle::from_raw(7).unwrap();
    let bitmap = BitmapHandle::from_raw(7).unwrap();
    assert_eq!(window.raw(), bitmap.raw());
    // The distinct Rust types cannot be passed to one another's tables.
    let mut windows = HandleTable::<WindowHandle, _>::new();
    assert!(windows.insert("window").is_ok());
}

#[test]
fn exhausted_table_does_not_wrap_or_reuse() {
    let mut table = HandleTable::<BitmapHandle, _>::new();
    for _ in 0..u16::MAX {
        table.insert(()).unwrap();
    }
    assert_eq!(table.insert(()), Err(HandleError::Exhausted));
    assert_eq!(table.len(), usize::from(u16::MAX));
    assert_eq!(
        HandleError::Exhausted.to_string(),
        "No unused 16-bit object handles remain; valid handles range from 1 through 65,535."
    );
}
