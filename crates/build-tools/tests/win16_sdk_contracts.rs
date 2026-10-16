//! Independent, bounded SDK contract regression; see the fixture's README.
use std::collections::HashSet;

use win16_abi::{ArgumentKind, StackCleanup};
use win16_abi::exports::{
    ExportCallingConvention, ExportLookupTarget, Win16ExportAbiKind, Win16ExportDescriptor,
    Win16ExportStackCleanup, Win16ReturnKind, export_descriptors, lookup_export,
};

const FACTS: &str = include_str!("fixtures/win31-sdk-abi.tsv");
const HEADER: &str = "module\tname\tordinal\theader_line\timport_record_offset\tcalling_convention\tabi_kind\tsource_order_slot_bytes\treturn_kind\tcallee_pop_bytes\tcaller_pop_bytes";

#[derive(Clone, Debug)]
struct SdkContract<'a> {
    module: &'a str,
    name: &'a str,
    ordinal: u16,
    header_line: usize,
    import_record_offset: usize,
    calling_convention: ExportCallingConvention,
    abi_kind: Win16ExportAbiKind,
    slot_bytes: Vec<u16>,
    return_kind: Win16ReturnKind,
    cleanup: StackCleanup,
}

fn contracts() -> Vec<SdkContract<'static>> {
    let mut lines = FACTS.lines();
    assert_eq!(lines.next(), Some(HEADER), "SDK fixture schema changed");
    let rows: Vec<_> = lines
        .enumerate()
        .map(|(index, line)| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 11, "SDK fixture line {}", index + 2);
            assert!(matches!(fields[0], "KERNEL" | "USER" | "GDI"));
            assert!(!fields[1].is_empty());
            let slot_bytes = if fields[7] == "-" {
                Vec::new()
            } else {
                fields[7]
                    .split(',')
                    .map(|value| match value {
                        "2" => 2,
                        "4" => 4,
                        _ => panic!("unsupported SDK slot: {value}"),
                    })
                    .collect()
            };
            let row = SdkContract {
                module: fields[0],
                name: fields[1],
                ordinal: fields[2].parse().expect("SDK ordinal"),
                header_line: fields[3].parse().expect("SDK header line"),
                import_record_offset: usize::from_str_radix(
                    fields[4].strip_prefix("0x").expect("hex SDK record offset"),
                    16,
                )
                .expect("SDK record offset"),
                calling_convention: match fields[5] {
                    "Pascal" => ExportCallingConvention::Pascal,
                    other => panic!("unsupported SDK convention: {other}"),
                },
                abi_kind: match fields[6] {
                    "Stack" => Win16ExportAbiKind::Stack,
                    other => panic!("unsupported SDK ABI: {other}"),
                },
                slot_bytes,
                return_kind: match fields[8] {
                    "Void" => Win16ReturnKind::Void,
                    "Word" => Win16ReturnKind::Word,
                    "Dword" => Win16ReturnKind::Dword,
                    "FarPointer" => Win16ReturnKind::FarPointer,
                    other => panic!("unsupported SDK return: {other}"),
                },
                cleanup: StackCleanup {
                    callee_pop_bytes: fields[9].parse().expect("SDK callee cleanup"),
                    caller_pop_bytes: fields[10].parse().expect("SDK caller cleanup"),
                },
            };
            assert!(row.ordinal > 0 && row.header_line > 0 && row.import_record_offset > 0);
            assert_eq!(row.cleanup.callee_pop_bytes, row.slot_bytes.iter().sum::<u16>());
            assert_eq!(row.cleanup.caller_pop_bytes, 0);
            row
        })
        .collect();
    // Deliberately bounded inventory: deleting rows must not silently reduce coverage.
    assert_eq!(rows.len(), 23);
    let mut names = HashSet::new();
    let mut ordinals = HashSet::new();
    let mut records = HashSet::new();
    for row in &rows {
        assert!(names.insert((row.module, row.name.to_ascii_uppercase())));
        assert!(ordinals.insert((row.module, row.ordinal)));
        assert!(records.insert(row.import_record_offset));
    }
    rows
}

fn differences(expected: &SdkContract<'_>, actual: &Win16ExportDescriptor) -> Vec<&'static str> {
    let mut differences = Vec::new();
    if !expected.module.eq_ignore_ascii_case(actual.module()) {
        differences.push("module");
    }
    if !expected.name.eq_ignore_ascii_case(actual.name()) {
        differences.push("name");
    }
    if expected.ordinal != actual.ordinal() {
        differences.push("ordinal");
    }
    if expected.calling_convention != actual.calling_convention {
        differences.push("calling convention");
    }
    if expected.abi_kind != actual.abi_kind {
        differences.push("ABI kind");
    }
    if expected.slot_bytes.len() != actual.parameter_count() {
        differences.push("parameter count");
    }
    for (width, parameter) in expected.slot_bytes.iter().zip(actual.parameters) {
        let expected_kind = match width {
            2 => ArgumentKind::Word,
            4 => ArgumentKind::Dword,
            _ => unreachable!("fixture parser rejects unsupported widths"),
        };
        if parameter.kind != expected_kind {
            differences.push("parameter kind/slot width");
        }
    }
    if expected.return_kind != actual.return_kind {
        differences.push("return kind");
    }
    if actual.stack_cleanup != Win16ExportStackCleanup::Fixed(expected.cleanup) {
        differences.push("stack cleanup");
    }
    differences
}

fn descriptor(row: &SdkContract<'_>) -> &'static Win16ExportDescriptor {
    let by_name = lookup_export(row.module.as_bytes(), ExportLookupTarget::Name(row.name.as_bytes()))
        .unwrap_or_else(|| panic!("missing SDK export {}!{}", row.module, row.name));
    let by_ordinal = lookup_export(row.module.as_bytes(), ExportLookupTarget::Ordinal(row.ordinal))
        .unwrap_or_else(|| panic!("missing SDK ordinal {}!{}", row.module, row.ordinal));
    assert!(std::ptr::eq(by_name, by_ordinal), "SDK name and ordinal resolved differently: {row:?}");
    for count in [
        export_descriptors().iter().filter(|d| {
            d.module().eq_ignore_ascii_case(row.module) && d.name().eq_ignore_ascii_case(row.name)
        }).count(),
        export_descriptors().iter().filter(|d| {
            d.module().eq_ignore_ascii_case(row.module) && d.ordinal() == row.ordinal
        }).count(),
    ] {
        assert_eq!(count, 1, "SDK identity must be unique: {row:?}");
    }
    by_name
}

#[test]
fn implemented_contracts_match_independent_windows_31_sdk_facts() {
    for row in contracts() {
        assert_eq!(
            differences(&row, descriptor(&row)),
            Vec::<&str>::new(),
            "{}!{}: WINDOWS.H line {}, LIBW.LIB record {:#x}",
            row.module, row.name, row.header_line, row.import_record_offset,
        );
    }
}

#[test]
fn comparator_rejects_changed_return_class() {
    let row = contracts().remove(0);
    let mut changed = *descriptor(&row);
    changed.return_kind = Win16ReturnKind::Word;
    assert_eq!(differences(&row, &changed), ["return kind"]);
}

#[test]
fn comparator_rejects_changed_slot_width_and_same_width_byte_kind() {
    let row = contracts().remove(0);
    let actual = descriptor(&row);
    let mut changed = row.clone();
    changed.slot_bytes[1] = 2;
    assert_eq!(differences(&changed, actual), ["parameter kind/slot width"]);
    // Byte and Word both consume two bytes, but this SDK parameter is a Word.
    let parameters = Box::leak(actual.parameters.to_vec().into_boxed_slice());
    parameters[0].kind = ArgumentKind::Byte;
    let changed = Win16ExportDescriptor { parameters, ..*actual };
    assert_eq!(differences(&row, &changed), ["parameter kind/slot width"]);
}

#[test]
fn comparator_rejects_changed_name_ordinal_and_module() {
    let row = contracts().remove(0);
    let actual = descriptor(&row);
    let mut changed = row.clone();
    changed.name = "SetWindowTextChanged";
    assert_eq!(differences(&changed, actual), ["name"]);
    changed = row.clone();
    changed.ordinal += 1;
    assert_eq!(differences(&changed, actual), ["ordinal"]);
    changed = row;
    changed.module = "GDI";
    assert_eq!(differences(&changed, actual), ["module"]);
}

#[test]
fn comparator_rejects_changed_cleanup_including_caller_and_variable_frames() {
    let row = contracts().remove(0);
    let actual = descriptor(&row);
    for cleanup in [
        Win16ExportStackCleanup::Fixed(StackCleanup { callee_pop_bytes: 4, caller_pop_bytes: 0 }),
        Win16ExportStackCleanup::Fixed(StackCleanup { callee_pop_bytes: 6, caller_pop_bytes: 2 }),
        Win16ExportStackCleanup::Variable,
    ] {
        let changed = Win16ExportDescriptor { stack_cleanup: cleanup, ..*actual };
        assert_eq!(differences(&row, &changed), ["stack cleanup"]);
    }
}

#[test]
fn comparator_rejects_changed_count_convention_and_abi_kind() {
    let row = contracts().remove(0);
    let actual = descriptor(&row);
    let mut changed = *actual;
    changed.parameters = &actual.parameters[..1];
    assert_eq!(differences(&row, &changed), ["parameter count"]);
    changed = *actual;
    changed.calling_convention = ExportCallingConvention::Cdecl;
    assert_eq!(differences(&row, &changed), ["calling convention"]);
    changed = *actual;
    changed.abi_kind = Win16ExportAbiKind::RegisterContext;
    assert_eq!(differences(&row, &changed), ["ABI kind"]);
}
