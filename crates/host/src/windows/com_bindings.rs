//! Typed native COM bindings generated from Microsoft metadata.

// SDK spellings and dependency declarations remain generator-owned. Only
// naming and unused generated items are exempt; host safety lints still apply.
#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types, dead_code)]

include!(concat!(env!("OUT_DIR"), "/host_com_bindings_module.rs"));
