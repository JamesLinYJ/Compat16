//! Host-selected availability for the x86 native generic-thunk exports.
//!
//! The Win16 ABI catalog remains architecture-neutral. A host enables these
//! bindings only after it has prepared a native x86 execution environment.

use super::*;

const KERNEL_THUNK_ORDINALS: std::ops::RangeInclusive<u16> = 513..=518;

/// Return whether a catalog descriptor is one of KERNEL.513–518.
pub(super) fn is_native_thunk_descriptor(descriptor: &Win16ExportDescriptor) -> bool {
    descriptor.module().eq_ignore_ascii_case("KERNEL")
        && KERNEL_THUNK_ORDINALS.contains(&descriptor.ordinal())
}

/// Resolve an import only when it names one of the generic-thunk exports.
/// Name imports and ordinal imports both resolve through the shared catalog.
pub(super) fn native_thunk_descriptor_for_import(
    module: &[u8],
    target: &NeImportTarget,
) -> Option<&'static Win16ExportDescriptor> {
    let lookup = match target {
        NeImportTarget::Ordinal(ordinal) => ExportLookupTarget::Ordinal(*ordinal),
        NeImportTarget::Name(name) => ExportLookupTarget::Name(name),
    };
    lookup_export(module, lookup).filter(|descriptor| is_native_thunk_descriptor(descriptor))
}

impl Win16State {
    /// Select whether this host can execute native x86 generic-thunk DLLs.
    ///
    /// Existing service-gate slots remain stable when bindings are reclassified.
    /// The setter also repairs the initial bindings if the host repeats its
    /// default `false` selection after `Win16State::load`.
    pub(crate) fn set_native_thunks_available(&mut self, available: bool) {
        for binding in &mut self.bindings {
            let replacement = match binding {
                ImportBinding::Supported(descriptor)
                    if !available && is_native_thunk_descriptor(descriptor) =>
                {
                    Some(ImportBinding::Unavailable {
                        module: descriptor.module().as_bytes().to_vec(),
                        target: NeImportTarget::Ordinal(descriptor.ordinal()),
                    })
                }
                ImportBinding::Unavailable { module, target } if available => {
                    native_thunk_descriptor_for_import(module, target)
                        .map(ImportBinding::Supported)
                }
                _ => None,
            };
            if let Some(replacement) = replacement {
                *binding = replacement;
            }
        }
        self.native_thunks_available = available;
    }
}
