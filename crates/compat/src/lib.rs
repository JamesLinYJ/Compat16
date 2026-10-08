//! Portable compatibility-library primitives for Win16 programs.
//!
//! Checked guest data formats and environment operations are independent of
//! native services. The runtime owns export dispatch and handle lifetimes.
#![forbid(unsafe_code)]

pub mod lzexpand;
pub mod com;
pub mod automation;
pub mod win16_lzexpand;
pub mod win16_shell;
pub mod win16_ver;
pub mod win16_multimedia;
pub mod win16_network;
pub mod win16_dde;
