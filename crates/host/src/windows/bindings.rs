//! Focused native Windows declarations generated from Microsoft metadata.

// SDK spellings and related declarations are retained by the generator.
// Relax only their naming and usage lints; workspace safety lints still apply.
#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code
)]

include!(concat!(env!("OUT_DIR"), "/host_windows_bindings_module.rs"));
