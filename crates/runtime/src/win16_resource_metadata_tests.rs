//! HRSRC offset lookup agrees with the original checked row-by-row walk.

use super::*;
use formats::{NeResource, NeResourceType};

fn definition(table_offset: u16, counts: &[usize]) -> NeModule {
    let image = super::super::test_support::tiny_ne_executable();
    let mut definition = formats::parse_ne(&image).unwrap();
    definition.header.resource_table_offset = table_offset;
    definition.resource_types = counts.iter().enumerate().map(|(type_index, &count)| {
        NeResourceType {
            id: NeResourceId::Numeric(type_index as u16),
            resources: (0..count).map(|index| NeResource {
                id: NeResourceId::Numeric(index as u16),
                file_offset: type_index * 100_000 + index,
                byte_length: index + 1,
                flags: (type_index + index) as u16,
                handle: 0,
                usage: 0,
            }).collect(),
        }
    }).collect();
    definition
}

fn linear_metadata(definition: &NeModule, info: u16) -> Option<ResourceMetadata> {
    let mut row_offset = NE_RESOURCE_ALIGNMENT_SHIFT_BYTES;
    let table_offset = usize::from(definition.header.resource_table_offset);
    for (type_index, entry) in definition.resource_types.iter().enumerate() {
        row_offset = row_offset.checked_add(NE_RESOURCE_TYPEINFO_BYTES)?;
        for resource in &entry.resources {
            let header_relative = table_offset.checked_add(row_offset)?;
            if u16::try_from(header_relative).ok()? == info {
                return Some(ResourceMetadata {
                    key: ResourceKey { module: 7, info },
                    type_index,
                    offset: resource.file_offset,
                    length: resource.byte_length,
                    flags: resource.flags,
                });
            }
            row_offset = row_offset.checked_add(NE_RESOURCE_NAMEINFO_BYTES)?;
        }
    }
    None
}

#[test]
fn resource_metadata_matches_linear_lookup_for_all_word_handles() {
    for (table_offset, counts) in [
        (0, vec![]),
        (0x80, vec![0, 3, 0, 2, 0]),
        (u16::MAX - 22, vec![3, 1]),
        (u16::MAX, vec![0, 1]),
    ] {
        let definition = definition(table_offset, &counts);
        for info in 0..=u16::MAX {
            assert_eq!(
                resource_metadata_for_definition(7, &definition, info),
                linear_metadata(&definition, info),
                "table offset {table_offset:#06x}, handle {info:#06x}",
            );
        }
    }
}

#[test]
fn resource_metadata_selects_exact_rows_across_large_and_empty_types() {
    let definition = definition(0x80, &[3_000, 0, 2]);
    // First type starts at table + 2 + 8. The third starts after 3,000
    // NAMEINFO records and two more TYPEINFO headers, including the empty type.
    for (info, type_index, index) in [
        (0x80 + 10, 0, 0),
        (0x80 + 10 + 2_999 * 12, 0, 2_999),
        (0x80 + 10 + 3_000 * 12 + 16, 2, 0),
        (0x80 + 10 + 3_000 * 12 + 16 + 12, 2, 1),
    ] {
        let metadata = resource_metadata_for_definition(7, &definition, info).unwrap();
        assert_eq!(metadata.type_index, type_index);
        assert_eq!(metadata.offset, type_index * 100_000 + index);
        assert_eq!(metadata.length, index + 1);
        assert_eq!(Some(metadata), linear_metadata(&definition, info));
        assert!(resource_metadata_for_definition(7, &definition, info + 1).is_none());
    }
    let first_type_end = 0x80 + 10 + 3_000 * 12;
    for info in first_type_end..first_type_end + 16 {
        assert!(resource_metadata_for_definition(7, &definition, info).is_none());
    }
}
