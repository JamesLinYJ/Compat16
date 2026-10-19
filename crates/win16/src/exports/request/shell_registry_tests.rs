use super::*;
use crate::{AccessRights, SegmentedPointer};
use guest_core::{PhysAddr, memory::Memory};

fn source(bytes: &[u8]) -> (Memory, SelectorTable, u32) {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    memory.write(PhysAddr(0x1000), bytes).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors
        .alloc_block(
            PhysAddr(0x1000),
            bytes.len() as u32,
            AccessRights::read_only(),
            &memory,
        )
        .unwrap();
    (
        memory,
        selectors,
        SegmentedPointer::new(selector, 0).far_value(),
    )
}

fn decode(
    memory: &Memory,
    selectors: &SelectorTable,
    far: u32,
    count: u32,
    kind: u32,
    subkey: u32,
) -> Result<Win16ShellRegistryRequest, Win16Error> {
    let args = [1, subkey, kind, far, count].map(Win16Argument::Dword);
    Win16ShellRegistryRequest::decode_export(5, &args, selectors, memory)
}

fn value(request: Win16ShellRegistryRequest) -> Vec<u8> {
    let Win16ShellRegistryRequest::SetValue { value, .. } = request else {
        panic!("SetValue")
    };
    value.expect("Win3.1 string")
}

#[test]
fn registry_set_value_ignores_zero_short_and_oversized_counts_for_dbcs_text() {
    let (memory, selectors, far) = source(b"A\xd6\xd0\0");
    for count in [0, 1, 2, 4, 0x1_0000, u32::MAX] {
        assert_eq!(
            value(decode(&memory, &selectors, far, count, 1, 0).unwrap()),
            b"A\xd6\xd0"
        );
    }
}

#[test]
fn registry_set_value_stops_at_nul_instead_of_copying_counted_suffix() {
    let (memory, selectors, far) = source(b"text\0unrelated");
    assert_eq!(
        value(decode(&memory, &selectors, far, 14, 1, 0).unwrap()),
        b"text"
    );
}

#[test]
fn registry_set_value_null_data_is_the_win31_zero_string() {
    let (memory, selectors, _) = source(b"\0");
    assert_eq!(
        value(decode(&memory, &selectors, 0, u32::MAX, 1, 0).unwrap()),
        b"0"
    );
}

#[test]
fn registry_set_value_empty_string_remains_distinct_from_null_data() {
    let (memory, selectors, far) = source(b"\0");
    assert!(value(decode(&memory, &selectors, far, 0, 1, 0).unwrap()).is_empty());
}

#[test]
fn registry_set_value_rejectable_type_does_not_dereference_either_string() {
    let (memory, selectors, _) = source(b"\0");
    let request = decode(&memory, &selectors, 0xffff_0001, u32::MAX, 4, 0xffff_0001).unwrap();
    assert_eq!(
        request,
        Win16ShellRegistryRequest::SetValue {
            key: 1,
            subkey: Vec::new(),
            value_type: 4,
            value: None,
        }
    );
}

#[test]
fn registry_set_value_ignored_count_does_not_weaken_far_pointer_checks() {
    let (memory, selectors, far) = source(b"unterminated");
    for count in [0, 1, u32::MAX] {
        assert!(decode(&memory, &selectors, far, count, 1, 0).is_err());
        // Selector zero with a nonzero offset is not the NULL FAR pointer.
        assert!(decode(&memory, &selectors, 1, count, 1, 0).is_err());
    }
}

#[test]
fn registry_set_value_kernel32_preserves_null_and_ignores_string_count() {
    let (memory, selectors, far) = source(b"A\xd6\xd0\0");
    for pointer in [0, far] {
        let args = [0x8000_0001, 0, 1, pointer, u32::MAX].map(Win16Argument::Dword);
        let request =
            Win16ShellRegistryRequest::decode_kernel_export(221, &args, &selectors, &memory)
                .unwrap();
        let Win16ShellRegistryRequest::SetValue { value, .. } = request else {
            panic!("SetValue")
        };
        assert_eq!(value, (pointer != 0).then(|| b"A\xd6\xd0".to_vec()));
    }
}

#[test]
fn registry_query_shell_null_length_rejects_before_pointer_access() {
    let (memory, selectors, _) = source(b"\0");
    let arguments = [1, 0xffff_0001, 0xffff_0001, 0].map(Win16Argument::Dword);
    assert_eq!(
        Win16ShellRegistryRequest::decode_export(6, &arguments, &selectors, &memory).unwrap(),
        Win16ShellRegistryRequest::QueryValue {
            key: 1,
            subkey: Vec::new(),
            output: 0xffff_0001,
            byte_count: 0,
            byte_count_output: 0
        }
    );
}

#[test]
fn registry_query_kernel_null_length_keeps_checked_subkey_and_raw_output() {
    let (memory, selectors, far) = source(b"entry\0");
    let arguments = [1, far, 0xffff_0001, 0].map(Win16Argument::Dword);
    assert_eq!(
        Win16ShellRegistryRequest::decode_kernel_export(224, &arguments, &selectors, &memory)
            .unwrap(),
        Win16ShellRegistryRequest::QueryValue {
            key: 1,
            subkey: b"entry".to_vec(),
            output: 0xffff_0001,
            byte_count: 0,
            byte_count_output: 0
        }
    );
    let bad = [1, 0xffff_0001, 0, 0].map(Win16Argument::Dword);
    assert!(
        Win16ShellRegistryRequest::decode_kernel_export(224, &bad, &selectors, &memory).is_err()
    );
}

#[test]
fn registry_query_null_data_does_not_bypass_nonnull_length_pointer_checks() {
    let (memory, selectors, _) = source(b"\0");
    let arguments = [1, 0, 0, 1].map(Win16Argument::Dword);
    assert!(Win16ShellRegistryRequest::decode_export(6, &arguments, &selectors, &memory).is_err());
    assert!(
        Win16ShellRegistryRequest::decode_kernel_export(224, &arguments, &selectors, &memory)
            .is_err()
    );
}

fn decoded_subkey(request: Win16ShellRegistryRequest) -> Vec<u8> {
    match request {
        Win16ShellRegistryRequest::OpenKey { subkey, .. }
        | Win16ShellRegistryRequest::CreateKey { subkey, .. }
        | Win16ShellRegistryRequest::DeleteKey { subkey, .. }
        | Win16ShellRegistryRequest::SetValue { subkey, .. }
        | Win16ShellRegistryRequest::QueryValue { subkey, .. } => subkey,
        _ => panic!("path-based registry request"),
    }
}

#[test]
fn registry_default_root_classes_node_open_create_delete_are_shell_only() {
    let (memory, selectors, far) = source(b".ClAsSeS\0");
    for root in [0, 1, 0x8000_0000] {
        for (shell, kernel) in [(1, 217), (2, 218), (4, 219)] {
            let args = if shell == 4 {
                vec![root, far]
            } else {
                vec![root, far, 0]
            };
            let args: Vec<_> = args.into_iter().map(Win16Argument::Dword).collect();
            let expected = if root == 0 {
                b"".as_slice()
            } else {
                b".ClAsSeS".as_slice()
            };
            assert_eq!(
                decoded_subkey(
                    Win16ShellRegistryRequest::decode_export(shell, &args, &selectors, &memory)
                        .unwrap()
                ),
                expected
            );
            assert_eq!(
                decoded_subkey(
                    Win16ShellRegistryRequest::decode_kernel_export(
                        kernel, &args, &selectors, &memory
                    )
                    .unwrap()
                ),
                b".ClAsSeS"
            );
        }
    }
}

#[test]
fn registry_default_root_classes_node_set_and_query_are_shell_only() {
    let (memory, selectors, far) = source(b".classes\0");
    for root in [0, 1, 0x8000_0000] {
        for (shell, kernel, raw) in [
            (5, 221, vec![root, far, 1, far, 0]),
            (6, 224, vec![root, far, 0, far]),
        ] {
            let args: Vec<_> = raw.into_iter().map(Win16Argument::Dword).collect();
            let expected = if root == 0 {
                b"".as_slice()
            } else {
                b".classes".as_slice()
            };
            assert_eq!(
                decoded_subkey(
                    Win16ShellRegistryRequest::decode_export(shell, &args, &selectors, &memory)
                        .unwrap()
                ),
                expected
            );
            assert_eq!(
                decoded_subkey(
                    Win16ShellRegistryRequest::decode_kernel_export(
                        kernel, &args, &selectors, &memory
                    )
                    .unwrap()
                ),
                b".classes"
            );
        }
    }
}

#[test]
fn registry_default_root_does_not_rewrite_similarly_named_keys() {
    for text in [b".classes2\0".as_slice(), b"x.classes\0", b".classes \0"] {
        let (memory, selectors, far) = source(text);
        let args = [0, far, 0].map(Win16Argument::Dword);
        assert_eq!(
            decoded_subkey(
                Win16ShellRegistryRequest::decode_export(1, &args, &selectors, &memory).unwrap()
            ),
            &text[..text.len() - 1]
        );
    }
}

#[test]
fn registry_close_and_enum_preserve_raw_root_for_api_specific_validation() {
    let (memory, selectors, _) = source(b"\0");
    for root in [0, 1, 0x8000_0000] {
        let close = [root].map(Win16Argument::Dword);
        assert_eq!(
            Win16ShellRegistryRequest::decode_export(3, &close, &selectors, &memory).unwrap(),
            Win16ShellRegistryRequest::CloseKey { key: root }
        );
        let enumerate = [root, 0, 0, 0].map(Win16Argument::Dword);
        assert_eq!(
            Win16ShellRegistryRequest::decode_export(7, &enumerate, &selectors, &memory).unwrap(),
            Win16ShellRegistryRequest::EnumKey {
                key: root,
                index: 0,
                output: 0,
                capacity: 0
            }
        );
    }
}
