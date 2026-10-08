//! Guest-visible Win16 module identities and dependency reachability.

use std::collections::{BTreeMap, BTreeSet};

use formats::{NeLoadedModule, NeModule};
use crate::win16_builtin_data_exports::BuiltinDataImage;
use win16_abi::{exports::{export_descriptors, WIN16_EXPORTS}, SelectorRef};

use super::module_memory::ModuleAllocation;
use super::external_application::{ExternalApplicationRecord, is_external_guest_identity};
use crate::{DiagnosticKind, RuntimeError};

const NE_SEGMENT_MOVEABLE: u16 = 0x0010;

#[derive(Default)]
pub(super) struct ModuleRegistry {
    pub(super) records: BTreeMap<u16, ModuleRecord>,
    pub(super) main: u16,
    pub(super) first: u16,
}

pub(super) struct ModuleRecord {
    pub(super) handle: u16,
    pub(super) instance: u16,
    pub(super) path: Vec<u8>,
    pub(super) name: Vec<u8>,
    pub(super) builtin: bool,
    pub(super) pinned: bool,
    pub(super) explicit_refs: u16,
    /// Non-guest selector and continuation owners that retain module roots.
    /// These roots participate in module reachability without guest usage.
    pub(super) continuation_owner_refs: u64,
    pub(super) state: ModuleState,
    pub(super) deps: Vec<u16>,
    pub(super) definition: Option<NeModule>,
    pub(super) loaded: Option<NeLoadedModule>,
    pub(super) image: Vec<u8>,
    pub(super) allocations: Vec<ModuleAllocation>,
    pub(super) builtin_data_selector: Option<SelectorRef>,
    pub(super) builtin_data_exports: Option<BuiltinDataImage>,
    /// Virtual identities returned by SHELL APIs are queryable handles only;
    /// they do not own a loadable NE image or guest code/data segment.
    pub(super) external_application: Option<ExternalApplicationRecord>,
    pub(super) wep_called: bool,
    /// Resource globals with live external selector leases keep this retired
    /// module and its dependency roots until their cleanup can be retried.
    pub(super) resources_retirement_deferred: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ModuleState {
    Loading,
    Initializing,
    Ready,
    Unloading,
    Retired,
}

impl ModuleRegistry {
    pub(super) fn new(main: ModuleRecord) -> Self {
        let handle = main.handle;
        let mut records = BTreeMap::new();
        records.insert(handle, main);
        Self {
            records,
            main: handle,
            first: handle,
        }
    }

    /// Resolves the supported Win16 module, instance, segment, and movable
    /// segment-handle forms to their owning module handle.
    pub(super) fn by_handle(&self, input: u16) -> Option<u16> {
        if input == 0 {
            return None;
        }

        if let Some((&handle, _)) = self.records.iter()
            .find(|(_, record)| record.state != ModuleState::Retired
                && record.handle == input
                && record.external_application.as_ref()
                    .is_none_or(ExternalApplicationRecord::is_ready)) {
            return Some(handle);
        }
        if let Some((&handle, _)) = self.records.iter()
            .find(|(_, record)| record.state != ModuleState::Retired
                && record.instance == input
                && record.external_application.as_ref()
                    .is_none_or(ExternalApplicationRecord::is_ready)) {
            return Some(handle);
        }
        if let Some((&handle, _)) = self.records.iter().find(|(_, record)| {
            record.state != ModuleState::Retired
                && (record.builtin_data_selector.is_some_and(|selector| selector.raw().0 == input)
                    || record.loaded.as_ref().is_some_and(|loaded| {
                        loaded.segments.iter().any(|segment| segment.selector.0 == input)
                    }))
        }) {
            return Some(handle);
        }

        self.records.iter().find_map(|(&handle, record)| {
            if record.state == ModuleState::Retired { return None; }
            let definition = record.definition.as_ref()?;
            let loaded = record.loaded.as_ref()?;
            loaded.segments.iter().find_map(|segment| {
                let movable = definition
                    .segments
                    .iter()
                    .find(|definition| definition.number == segment.number)
                    .is_some_and(|definition| definition.flags & NE_SEGMENT_MOVEABLE != 0);
                (movable && segment.selector.0.checked_sub(1) == Some(input))
                    .then_some(handle)
            })
        })
    }

    /// Internal reachability lookup. Retired modules remain code/data owners
    /// while their original allocation identities are still present. This
    /// does not make retired module handles visible to guest lookup APIs.
    pub(super) fn retained_owner(
        &self, input: u16, selectors: &win16_abi::SelectorTable,
    ) -> Option<u16> {
        if let Some(handle) = self.by_handle(input) {
            if self.records.get(&handle).is_some_and(|record| record.external_application.is_none()) {
                return Some(handle);
            }
        }
        let current = selectors.reference(guest_core::Selector(input)).ok()
            .and_then(|reference| selectors.describe(reference).ok());
        self.records.iter().find_map(|(&handle, record)| {
            if is_external_guest_identity(record) { return None; }
            if let Some(reference) = record.builtin_data_selector {
                if let Ok(held) = selectors.describe(reference) {
                    let direct = reference.raw().0 == input;
                    let alias = current.is_some_and(|current| current.present
                        && held.present && current.base == held.base && current.limit <= held.limit);
                    if held.present && (direct || alias) { return Some(handle); }
                }
            }
            record.allocations.iter().find_map(|allocation| {
                // describe validates the retained table identity/generation,
                // so a reused raw selector cannot revive this allocation.
                let held = selectors.describe(allocation.selector).ok()?;
                if !held.present { return None; }
                let direct = allocation.selector.raw().0 == input;
                let instance = record.instance == input
                    && allocation.selector.raw().0.checked_sub(1) == Some(input);
                let alias = current.is_some_and(|current| current.present
                    && current.base == held.base && current.limit <= held.limit);
                (direct || instance || alias).then_some(handle)
            })
        })
    }

    /// Resolves resident module names and file basenames without decoding the
    /// guest's original byte strings as host paths or UTF-8.
    pub(super) fn by_name(&self, name: &[u8]) -> Option<u16> {
        let query = basename(name);
        if query.is_empty() {
            return None;
        }

        let mut data_only_provider = None;
        for (&handle, record) in &self.records {
            if record.external_application.is_some() { continue; }
            if record.state == ModuleState::Retired { continue; }
            let resident_name = record.definition.as_ref().and_then(|definition| {
                definition
                    .resident_names
                    .iter()
                    .find(|entry| entry.ordinal == 0)
                    .map(|entry| entry.name.as_slice())
            });
            let source_module_name = record.builtin && WIN16_EXPORTS.iter()
                .flat_map(|entries| entries.iter())
                .any(|entry| entry.module.as_bytes().eq_ignore_ascii_case(&record.name)
                    && module_name_matches(query, entry.source_module.as_bytes()));
            let path_name = basename(&record.path);
            let matches = module_name_matches(query, &record.name)
                || resident_name.is_some_and(|resident| module_name_matches(query, resident))
                || source_module_name
                || module_name_matches(query, path_name);
            if !matches { continue; }
            if is_data_only_builtin(record) {
                data_only_provider.get_or_insert(handle);
            } else {
                return Some(handle);
            }
        }
        data_only_provider
    }

    /// Reports explicit references plus incoming dependency edges. Pinned
    /// records retain at least one reference even without an incoming edge.
    pub(super) fn usage(&self, handle: u16) -> u16 {
        let Some(record) = self.records.get(&handle) else {
            return 0;
        };
        let incoming = self
            .records
            .values()
            .flat_map(|source| source.deps.iter())
            .filter(|&&dependency| dependency == handle)
            .count();
        let incoming = u16::try_from(incoming).unwrap_or(u16::MAX);
        let usage = record.explicit_refs.saturating_add(incoming);
        if record.pinned { usage.max(1) } else { usage }
    }

    /// Returns unmarked records; cycles without a live root are reclaimed as
    /// a group instead of keeping each other alive through reference counts.
    pub(super) fn unreachable(&self, roots: &[u16]) -> Vec<u16> {
        let mut marked = BTreeSet::new();
        let mut pending: Vec<u16> = self
            .records
            .values()
            .filter(|record| {
                record.pinned
                    || record.explicit_refs != 0
                    || record.continuation_owner_refs != 0
                    || matches!(record.state, ModuleState::Loading | ModuleState::Initializing)
            })
            .map(|record| record.handle)
            .collect();

        pending.extend_from_slice(roots);

        while let Some(handle) = pending.pop() {
            if !marked.insert(handle) {
                continue;
            }
            if let Some(record) = self.records.get(&handle) {
                pending.extend(record.deps.iter().copied());
            }
        }

        self.records
            .iter()
            .filter_map(|(&handle, record)| {
                (!marked.contains(&handle) && record.state != ModuleState::Unloading)
                    .then_some(handle)
            })
            .collect()
    }

    /// Whether a module is reachable from a frame-owned module root. Direct
    /// failed-load rollback uses this before bypassing the normal graph reaper.
    pub(super) fn continuation_owner_reaches(&self, target: u16) -> Result<bool, RuntimeError> {
        let mut pending = Vec::new();
        let mut visited = Vec::new();
        pending.try_reserve_exact(self.records.len()).map_err(|error| {
            RuntimeError::with_source(DiagnosticKind::ResourceExhausted,
                "reserve continuation module-root traversal", error)
        })?;
        visited.try_reserve_exact(self.records.len()).map_err(|error| {
            RuntimeError::with_source(DiagnosticKind::ResourceExhausted,
                "reserve visited continuation module roots", error)
        })?;
        pending.extend(self.records.values()
            .filter(|record| record.continuation_owner_refs != 0)
            .map(|record| record.handle));
        while let Some(handle) = pending.pop() {
            if visited.contains(&handle) { continue; }
            visited.push(handle);
            if handle == target { return Ok(true); }
            if let Some(record) = self.records.get(&handle) {
                for &dependency in &record.deps {
                    if !visited.contains(&dependency) && !pending.contains(&dependency) {
                        pending.push(dependency);
                    }
                }
            }
        }
        Ok(false)
    }
}

pub(super) fn is_data_only_builtin(record: &ModuleRecord) -> bool {
    record.builtin
        && record.builtin_data_selector.is_some()
        && record.builtin_data_exports.as_ref()
            .is_some_and(|image| !image.exports.is_empty())
        && !export_descriptors().iter().any(|descriptor| {
            descriptor.module().as_bytes().eq_ignore_ascii_case(&record.name)
        })
}

/// Removes only known executable suffixes for builtin module-name matching.
/// Unknown extensions and all other bytes are preserved verbatim.
pub(super) fn builtin_name(name: &[u8]) -> Vec<u8> {
    for extension in [b".DLL".as_slice(), b".EXE".as_slice(), b".DRV".as_slice()] {
        if name.len() >= extension.len()
            && name[name.len() - extension.len()..].eq_ignore_ascii_case(extension)
        {
            return name[..name.len() - extension.len()].to_vec();
        }
    }
    name.to_vec()
}

fn basename(path: &[u8]) -> &[u8] {
    let start = path
        .iter()
        .rposition(|byte| *byte == b'/' || *byte == b'\\')
        .map_or(0, |separator| separator + 1);
    &path[start..]
}

fn module_name_matches(query: &[u8], candidate: &[u8]) -> bool {
    if query.eq_ignore_ascii_case(candidate) {
        return true;
    }

    // Resident names often omit the file suffix while paths include it.
    if builtin_name(query).eq_ignore_ascii_case(&builtin_name(candidate)) {
        return true;
    }

    // A request without an extension also tries the conventional DLL name.
    if !has_extension(query)
        && candidate.len() == query.len() + b".DLL".len()
        && candidate[..query.len()].eq_ignore_ascii_case(query)
        && candidate[query.len()..].eq_ignore_ascii_case(b".DLL")
    {
        return true;
    }
    false
}

fn has_extension(name: &[u8]) -> bool {
    name.iter()
        .rposition(|byte| *byte == b'.')
        .is_some_and(|position| position != 0)
}
