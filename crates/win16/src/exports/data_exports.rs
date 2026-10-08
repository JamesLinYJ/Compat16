//! Typed sources for non-callable Win16 exports.
//!
//! This catalog describes literal/profile equates, runtime selector aliases,
//! and variable initial bytes. It does not turn them into callable exports.

use super::declarations::{ExportArchitecture, ExportEntryKind, ExportMetadata};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16EquateValueSource {
    Literal(i32),
    /// The same host-profile value returned by KERNEL.GetWinFlags.
    CurrentWinFlags,
    /// A selector alias resolved from the current process's checked guest
    /// memory and selector state. The declaration's real-mode value is not a
    /// protected-mode selector.
    RuntimeSelector(Win16RuntimeSelectorEquate),
}

/// KERNEL equates whose protected-mode values depend on a live selector alias.
/// The runtime resolves these through one process-owned catalog; an equate's
/// real-mode segment literal is never returned as a protected-mode selector.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Win16RuntimeSelectorEquate {
    RomBios,
    VideoA000,
    OptionRomC000,
    OptionRomD000,
    VideoB000,
    VideoB800,
    ConventionalZero,
    OptionRomE000,
    BiosData,
    BiosRomF000,
    FlatCode,
    FlatData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DataExportSource {
    Equate(Win16EquateValueSource),
    /// Initial 32-bit words from the declaration, encoded little-endian by
    /// the runtime. These words do not describe later mutable runtime state.
    VariableWords {
        words: &'static [u32],
        runtime_state: Win16VariableRuntimeState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16VariableRuntimeState {
    /// The declared words are the complete exported value, as for GUID data.
    InitialWords,
    /// The spec only provides a zero template; runtime initialization and
    /// updates are not represented by the current host contract.
    Unspecified,
}

/// Returns the typed value source for a declared Win16 equate or variable.
/// Other declaration kinds, including extern and forward records, are left to
/// the module resolver and are never represented as data by this function.
pub fn lookup_data_export_source(
    declaration: &'static ExportMetadata,
) -> Option<Win16DataExportSource> {
    if declaration.architecture != ExportArchitecture::Win16 {
        return None;
    }

    match declaration.kind {
        ExportEntryKind::Equate => {
            let source = if declaration.module.eq_ignore_ascii_case("KERNEL")
                && declaration.declared_name.eq_ignore_ascii_case("__WINFLAGS")
            {
                Win16EquateValueSource::CurrentWinFlags
            } else if let Some(selector) = runtime_selector_equate(declaration) {
                Win16EquateValueSource::RuntimeSelector(selector)
            } else {
                Win16EquateValueSource::Literal(declaration.equate_value?)
            };
            Some(Win16DataExportSource::Equate(source))
        }
        ExportEntryKind::Variable => {
            let runtime_state = if declaration.module.eq_ignore_ascii_case("KERNEL")
                && (declaration.declared_name.eq_ignore_ascii_case("THHOOK")
                    || declaration.declared_name.eq_ignore_ascii_case("__GP"))
            {
                Win16VariableRuntimeState::Unspecified
            } else {
                Win16VariableRuntimeState::InitialWords
            };
            Some(Win16DataExportSource::VariableWords {
                words: declaration.variable_values,
                runtime_state,
            })
        }
        _ => None,
    }
}

fn runtime_selector_equate(
    declaration: &'static ExportMetadata,
) -> Option<Win16RuntimeSelectorEquate> {
    if !declaration.module.eq_ignore_ascii_case("KERNEL") {
        return None;
    }

    let name = declaration.declared_name;
    match declaration.ordinal {
        173 if name.eq_ignore_ascii_case("__ROMBIOS") => Some(Win16RuntimeSelectorEquate::RomBios),
        174 if name.eq_ignore_ascii_case("__A000H") => Some(Win16RuntimeSelectorEquate::VideoA000),
        179 if name.eq_ignore_ascii_case("__D000H") => Some(Win16RuntimeSelectorEquate::OptionRomD000),
        181 if name.eq_ignore_ascii_case("__B000H") => Some(Win16RuntimeSelectorEquate::VideoB000),
        182 if name.eq_ignore_ascii_case("__B800H") => Some(Win16RuntimeSelectorEquate::VideoB800),
        183 if name.eq_ignore_ascii_case("__0000H") => Some(Win16RuntimeSelectorEquate::ConventionalZero),
        190 if name.eq_ignore_ascii_case("__E000H") => Some(Win16RuntimeSelectorEquate::OptionRomE000),
        193 if name.eq_ignore_ascii_case("__0040H") => Some(Win16RuntimeSelectorEquate::BiosData),
        194 if name.eq_ignore_ascii_case("__F000H") => Some(Win16RuntimeSelectorEquate::BiosRomF000),
        195 if name.eq_ignore_ascii_case("__C000H") => Some(Win16RuntimeSelectorEquate::OptionRomC000),
        454 if name.eq_ignore_ascii_case("__FLATCS") => Some(Win16RuntimeSelectorEquate::FlatCode),
        455 if name.eq_ignore_ascii_case("__FLATDS") => Some(Win16RuntimeSelectorEquate::FlatData),
        _ => None,
    }
}
