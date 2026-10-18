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
