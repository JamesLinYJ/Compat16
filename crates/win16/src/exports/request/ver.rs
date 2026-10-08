//! Typed VER version and resource API arguments.

use super::Win16ResourceName;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16VerRequest {
    VerGetFileResourceSize { path: Vec<u8>, resource_type: Win16ResourceName, resource_name: Win16ResourceName, size_output: u32 },
    VerGetFileResource { path: Vec<u8>, resource_type: Win16ResourceName, resource_name: Win16ResourceName, offset: i32, count: i32, output: u32 },
    VerGetFileVersionInfoSize { path: Vec<u8>, handle_output: u32 },
    VerGetFileVersionInfo { path: Vec<u8>, handle: u32, capacity: u32, output: u32 },
    VerFindFile { flags: u16, file: Vec<u8>, windows_dir: Vec<u8>, app_dir: Vec<u8>, dir_output: u32, dir_capacity_output: u32, file_output: u32, file_capacity_output: u32 },
    VerInstallFile { flags: u16, source: Vec<u8>, destination: Vec<u8>, source_dir: Vec<u8>, destination_dir: Vec<u8>, current_dir: Vec<u8>, scratch_output: u32, scratch_capacity_output: u32 },
    VerLanguageName { language: u16, output: u32, capacity: u16 },
    VerQueryValue { block: u32, sub_block: Vec<u8>, value_output: u32, length_output: u32 },
}
