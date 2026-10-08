//! GUI-subsystem process entry.
#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() { std::process::exit(launcher::entry()); }
