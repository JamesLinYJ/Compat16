//! Name-table and integer-id lookup shared by the KERNEL resource calls.

use std::cmp::Ordering;

use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use formats::{NeResource, NeResourceId, NeResourceType};
use win16_abi::Win16ResourceName;

use super::super::test_support::{NoHost, tiny_ne_executable};
use crate::{RuntimeError, RuntimeHost};

const RT_MENU: u16 = 4;
const RT_CUSTOM: u16 = 10;
const RT_NAME_TABLE: u16 = 15;

struct LookupHost;

impl DosHost for LookupHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for LookupHost {
    fn epoch_seconds(&self) -> i64 {
        0
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
    fn win16_ansi_compare(
        &mut self,
        left: &[u8],
        right: &[u8],
        ignore_case: bool,
    ) -> Result<i16, RuntimeError> {
        assert!(
            left.is_ascii() && right.is_ascii(),
            "this fixture compares ASCII resource names"
        );
        let order = if ignore_case {
            left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
        } else {
            left.cmp(right)
        };
        Ok(match order {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        })
    }
}

impl crate::RuntimeDdeHost for LookupHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for LookupHost {}
impl crate::RuntimeMidiHost for LookupHost {}
impl crate::RuntimeNetbiosHost for LookupHost {}

fn resource(id: NeResourceId, length: usize, offset: usize) -> NeResource {
    NeResource {
        id,
        file_offset: offset,
        byte_length: length,
        flags: 0,
        handle: 0,
        usage: 0,
    }
}

fn name_table_entry(
    type_word: u16,
    id_word: u16,
    type_name: Option<&[u8]>,
    resource_name: &[u8],
) -> Vec<u8> {
    let mut strings = Vec::new();
    match type_name {
        Some(type_name) => {
            strings.extend_from_slice(type_name);
            strings.push(0);
        }
        None => strings.push(0),
    }
    strings.extend_from_slice(resource_name);
    strings.push(0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u16::try_from(6 + strings.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&type_word.to_le_bytes());
    bytes.extend_from_slice(&id_word.to_le_bytes());
    bytes.extend_from_slice(&strings);
    bytes
}

fn install(types: Vec<NeResourceType>, image_suffix: &[u8]) -> crate::Runtime {
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], br"C:\APP.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let handle = state.modules.main;
    let record = state.modules.records.get_mut(&handle).unwrap();
    record.image.extend_from_slice(image_suffix);
    let definition = record.definition.as_mut().unwrap();
    definition.header.resource_table_offset = 0x80;
    definition.resource_types = types;
    runtime
}

#[test]
fn find_resource_resolves_name_table_strings_and_fifteen_bit_ordinals() {
    let menu_ordinal = 1_u16 | 0x8000;
    let custom_ordinal = 3_u16 | 0x8000;
    let mut table = name_table_entry(5, 2 | 0x8000, None, b"OTHER");
    table.extend(name_table_entry(
        RT_MENU,
        menu_ordinal,
        None,
        b"WORDZAPMENU",
    ));
    table.extend(name_table_entry(
        RT_CUSTOM | 0x8000,
        custom_ordinal,
        Some(b"CUSTOM"),
        b"ALIAS",
    ));
    table.extend_from_slice(&0_u16.to_le_bytes());

    let image = tiny_ne_executable();
    let table_offset = image.len();
    let types = vec![
        NeResourceType {
            id: NeResourceId::Numeric(RT_MENU),
            resources: vec![
                resource(NeResourceId::Numeric(1), 6, 0),
                resource(NeResourceId::Name(b"DIRECT".to_vec()), 2, 0),
            ],
        },
        NeResourceType {
            id: NeResourceId::Numeric(RT_CUSTOM),
            resources: vec![resource(NeResourceId::Numeric(3), 4, 0)],
        },
        NeResourceType {
            id: NeResourceId::Numeric(RT_NAME_TABLE),
            resources: vec![resource(
                NeResourceId::Numeric(1),
                table.len(),
                table_offset,
            )],
        },
    ];
    let mut runtime = install(types, &table);
    let state = runtime.win16.as_mut().unwrap();
    let mut host = LookupHost;

    let by_ordinal = state
        .find_resource(
            0,
            &Win16ResourceName::Id(1),
            &Win16ResourceName::Id(RT_MENU),
            &mut host,
        )
        .unwrap();
    let by_high_bit = state
        .find_resource(
            0,
            &Win16ResourceName::Id(menu_ordinal),
            &Win16ResourceName::Id(RT_MENU | 0x8000),
            &mut host,
        )
        .unwrap();
    let by_hash = state
        .find_resource(
            0,
            &Win16ResourceName::Name(b"#1".to_vec()),
            &Win16ResourceName::Name(b"#4".to_vec()),
            &mut host,
        )
        .unwrap();
    let by_name = state
        .find_resource(
            0,
            &Win16ResourceName::Name(b"wordzapmenu".to_vec()),
            &Win16ResourceName::Id(RT_MENU),
            &mut host,
        )
        .unwrap();
    assert_ne!(by_ordinal, 0);
    assert_eq!(by_high_bit, by_ordinal);
    assert_eq!(by_hash, by_ordinal);
    assert_eq!(by_name, by_ordinal);
    assert_eq!(state.size_of_resource(0, by_name), 6);

    let by_typed_name = state
        .find_resource(
            0,
            &Win16ResourceName::Name(b"Alias".to_vec()),
            &Win16ResourceName::Name(b"custom".to_vec()),
            &mut host,
        )
        .unwrap();
    assert_ne!(by_typed_name, 0);
    assert_ne!(by_typed_name, by_ordinal);
    assert_eq!(state.size_of_resource(0, by_typed_name), 4);

    let direct = state
        .find_resource(
            0,
            &Win16ResourceName::Name(b"direct".to_vec()),
            &Win16ResourceName::Id(RT_MENU),
            &mut host,
        )
        .unwrap();
    assert_ne!(direct, 0);
    assert_ne!(direct, by_ordinal);
    assert_eq!(state.size_of_resource(0, direct), 2);

    let missing = state
        .find_resource(
            0,
            &Win16ResourceName::Name(b"OTHER".to_vec()),
            &Win16ResourceName::Id(5),
            &mut host,
        )
        .unwrap();
    assert_eq!(missing, 0);
    let name_table = state
        .find_resource(
            0,
            &Win16ResourceName::Id(1),
            &Win16ResourceName::Id(RT_NAME_TABLE),
            &mut host,
        )
        .unwrap();
    assert_ne!(name_table, 0);
    assert_ne!(name_table, by_name);
}

#[test]
fn find_resource_keeps_directory_names_when_the_name_table_record_is_short() {
    let image = tiny_ne_executable();
    let mut table = vec![0x04, 0x00, 0x00, 0x00];
    table.extend(name_table_entry(RT_MENU, 99 | 0x8000, None, b"DIRECT"));
    let types = vec![
        NeResourceType {
            id: NeResourceId::Numeric(RT_MENU),
            resources: vec![resource(NeResourceId::Name(b"DIRECT".to_vec()), 2, 0)],
        },
        NeResourceType {
            id: NeResourceId::Numeric(RT_NAME_TABLE),
            resources: vec![resource(NeResourceId::Numeric(1), table.len(), image.len())],
        },
    ];
    let mut runtime = install(types, &table);
    let state = runtime.win16.as_mut().unwrap();
    let info = state
        .find_resource(
            0,
            &Win16ResourceName::Name(b"DIRECT".to_vec()),
            &Win16ResourceName::Id(RT_MENU),
            &mut LookupHost,
        )
        .unwrap();
    assert_ne!(info, 0);
    assert_eq!(state.size_of_resource(0, info), 2);
}

#[test]
fn null_resource_handler_restores_the_builtin_loader() {
    let types = vec![NeResourceType {
        id: NeResourceId::Numeric(RT_MENU),
        resources: vec![resource(NeResourceId::Numeric(1), 6, 0)],
    }];
    let mut runtime = install(types, &[]);
    let state = runtime.win16.as_mut().unwrap();
    let module = state.modules.main;
    let mut host = NoHost;
    let menu = Win16ResourceName::Id(RT_MENU);
    let first = state
        .set_resource_handler(module, &menu, 0xABC0, &mut host)
        .unwrap();
    assert_ne!(first, 0);
    assert_eq!(
        state.resource_handlers.get(&(module, 0)).copied(),
        Some(0xABC0)
    );

    let previous = state
        .set_resource_handler(module, &menu, 0, &mut host)
        .unwrap();
    assert_eq!(previous, 0xABC0);
    assert!(state.resource_handlers.get(&(module, 0)).is_none());

    let restored = state
        .set_resource_handler(
            module,
            &Win16ResourceName::Id(RT_MENU | 0x8000),
            0x1111,
            &mut host,
        )
        .unwrap();
    assert_eq!(restored, first);
    assert_eq!(
        state.resource_handlers.get(&(module, 0)).copied(),
        Some(0x1111)
    );

    assert_eq!(
        state
            .set_resource_handler(module, &Win16ResourceName::Id(99), 0x2222, &mut host)
            .unwrap(),
        0
    );
    assert!(state.resource_handlers.get(&(module, 1)).is_none());
    assert_eq!(
        state.resource_handlers.get(&(module, 0)).copied(),
        Some(0x1111)
    );
}

#[test]
fn load_resource_adopts_a_handler_block_that_replaces_a_discarded_one() {
    let mut runtime = install(menu_resource(), &[]);
    let mut host = NoHost;
    let info = runtime
        .win16
        .as_mut()
        .unwrap()
        .find_resource(
            0,
            &Win16ResourceName::Id(1),
            &Win16ResourceName::Id(RT_MENU),
            &mut host,
        )
        .unwrap();
    let module = runtime.win16.as_ref().unwrap().modules.main;
    let key = super::ResourceKey { module, info };
    let old = runtime
        .win16
        .as_mut()
        .unwrap()
        .global_alloc(
            win16_abi::global::GMEM_MOVEABLE,
            6,
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    let old_identity = runtime
        .win16
        .as_ref()
        .unwrap()
        .live_global_identity(old)
        .unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.resources.loaded.insert(
        key,
        super::LoadedResource {
            data: old,
            identity: old_identity,
            references: 2,
            retirement_cause: None,
        },
    );
    state.discarded_handles.insert(old);

    let replacement = state
        .global_alloc(
            win16_abi::global::GMEM_MOVEABLE,
            6,
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_ne!(replacement, 0);
    assert_ne!(replacement, old);
    assert_eq!(
        state.commit_loaded_resource(key, replacement).unwrap(),
        replacement
    );
    let entry = state.resources.loaded.get(&key).unwrap();
    assert_eq!(entry.data, replacement);
    assert_eq!(entry.references, 3);
    assert!(!state.discarded_handles.contains(&replacement));
}

#[test]
fn load_resource_keeps_a_live_handle_when_another_block_is_returned() {
    let mut runtime = install(menu_resource(), &[]);
    let mut host = NoHost;
    let info = runtime
        .win16
        .as_mut()
        .unwrap()
        .find_resource(
            0,
            &Win16ResourceName::Id(1),
            &Win16ResourceName::Id(RT_MENU),
            &mut host,
        )
        .unwrap();
    let module = runtime.win16.as_ref().unwrap().modules.main;
    let key = super::ResourceKey { module, info };
    let old = runtime
        .win16
        .as_mut()
        .unwrap()
        .global_alloc(
            win16_abi::global::GMEM_MOVEABLE,
            6,
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    let old_identity = runtime
        .win16
        .as_ref()
        .unwrap()
        .live_global_identity(old)
        .unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.resources.loaded.insert(
        key,
        super::LoadedResource {
            data: old,
            identity: old_identity,
            references: 1,
            retirement_cause: None,
        },
    );
    let replacement = state
        .global_alloc(
            win16_abi::global::GMEM_MOVEABLE,
            6,
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(state.commit_loaded_resource(key, replacement).unwrap(), 0);
    let entry = state.resources.loaded.get(&key).unwrap();
    assert_eq!(entry.data, old);
    assert_eq!(entry.identity, old_identity);
    assert_eq!(entry.references, 1);
}

fn menu_resource() -> Vec<NeResourceType> {
    vec![NeResourceType {
        id: NeResourceId::Numeric(RT_MENU),
        resources: vec![resource(NeResourceId::Numeric(1), 6, 0)],
    }]
}
