use super::*;

pub(super) fn win32_symbol(
    symbol: &formats::Pe32ImportTarget,
) -> Result<Win32ImportSymbol, RuntimeError> {
    Ok(match symbol {
        formats::Pe32ImportTarget::Name { name, .. } => {
            Win32ImportSymbol::Name(copy_bytes(name, "copy PE32 typed service name")?)
        }
        formats::Pe32ImportTarget::Ordinal(value) => Win32ImportSymbol::Ordinal(*value),
    })
}

pub(super) fn copy_format_target(
    target: &formats::Pe32ImportTarget,
) -> Result<formats::Pe32ImportTarget, RuntimeError> {
    Ok(match target {
        formats::Pe32ImportTarget::Name { hint, name } => formats::Pe32ImportTarget::Name {
            hint: *hint,
            name: copy_bytes(name, "copy PE32 import lookup")?,
        },
        formats::Pe32ImportTarget::Ordinal(value) => formats::Pe32ImportTarget::Ordinal(*value),
    })
}

pub(super) fn copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))?;
    result.extend_from_slice(bytes);
    Ok(result)
}

pub(super) fn reserve<T>(
    values: &mut Vec<T>,
    count: usize,
    context: &'static str,
) -> Result<(), RuntimeError> {
    values
        .try_reserve_exact(count)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))
}

pub(super) fn resource_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, message)
}

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

pub(super) fn combine_load_failure(
    primary: RuntimeError,
    cleanup: Option<RuntimeError>,
) -> RuntimeError {
    let Some(cleanup) = cleanup else {
        return primary;
    };
    crate::win16_runtime::pe32_dispatch::aggregate_errors(
        "PE32 group map failed and image rollback remains pending",
        primary,
        cleanup,
    )
}

pub(super) fn combine(primary: RuntimeError, cleanup: Option<RuntimeError>) -> RuntimeError {
    combine_load_failure(primary, cleanup)
}

pub(super) fn provider_release_failure(
    value: Win32HostImportValue,
    last_error: Option<u32>,
) -> RuntimeError {
    let kind = if matches!(&value, Win32HostImportValue::Bool(false)) {
        Kind::HostFailure
    } else {
        Kind::InternalInvariant
    };
    RuntimeError::with_source(
        kind,
        "FreeLibrary for staged PE32 system-provider reference failed",
        ProviderReleaseOutcome { value, last_error },
    )
}

#[derive(Debug)]
struct ProviderReleaseOutcome {
    value: Win32HostImportValue,
    last_error: Option<u32>,
}

impl std::fmt::Display for ProviderReleaseOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if matches!(&self.value, Win32HostImportValue::Bool(false)) {
            formatter.write_str("Windows returned FALSE")?;
        } else {
            formatter.write_str("native cleanup returned an unexpected result shape")?;
        }
        match self.last_error {
            Some(code) => write!(formatter, " with Windows error {code}")?,
            None => formatter.write_str("; Windows last-error unavailable")?,
        }
        Ok(())
    }
}

impl std::error::Error for ProviderReleaseOutcome {}

pub(super) fn merge_error(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    let Some(primary) = slot.take() else {
        *slot = Some(error);
        return;
    };
    *slot = Some(crate::win16_runtime::pe32_dispatch::aggregate_errors(
        "PE32 load-group cleanup had multiple failures",
        primary,
        error,
    ));
}
