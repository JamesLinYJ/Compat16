//! Separate native module-query spelling from task-visible provider identity.

use crate::{DiagnosticKind as Kind, RuntimeError, Win32ImportString};

pub(super) struct SystemProviderQueryName {
    pub(super) identity: Win32ImportString,
    pub(super) native_query: Win32ImportString,
    pub(super) trailing_period_query: bool,
}

impl SystemProviderQueryName {
    pub(super) fn from_name(name: &Win32ImportString) -> Result<Self, RuntimeError> {
        match name {
            Win32ImportString::Ansi(value) => {
                let (identity, native_query) = ansi_provider_query_name(value)?;
                Ok(Self {
                    identity: Win32ImportString::Ansi(identity),
                    native_query: Win32ImportString::Ansi(native_query),
                    trailing_period_query: value.last() == Some(&b'.'),
                })
            }
            Win32ImportString::Wide(value) => {
                let (identity, native_query) = wide_provider_query_name(value)?;
                Ok(Self {
                    identity: Win32ImportString::Wide(identity),
                    native_query: Win32ImportString::Wide(native_query),
                    trailing_period_query: value.last() == Some(&(b'.' as u16)),
                })
            }
        }
    }
}

fn ansi_provider_query_name(value: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RuntimeError> {
    if value.is_empty() || value.contains(&0)
        || value.iter().any(|unit| matches!(*unit, b'/' | b'\\' | b':'))
    {
        return Err(invalid_query());
    }
    let trailing_period = value.last() == Some(&b'.');
    let append_extension = !trailing_period
        && !value
            .iter()
            .rposition(|unit| *unit == b'.')
            .is_some_and(|dot| dot != 0);
    let remove_marker = trailing_period && value.is_ascii();
    let identity_len = value.len() - if remove_marker { 1 } else { 0 };
    let extension_len = if append_extension { 4 } else { 0 };
    let identity_capacity = identity_len.checked_add(extension_len).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "system-provider identity length overflowed")
    })?;
    let mut identity = Vec::new();
    identity.try_reserve_exact(identity_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve system-provider query identity",
            error,
        )
    })?;
    identity.extend(value[..identity_len].iter().map(u8::to_ascii_lowercase));
    if append_extension {
        identity.extend_from_slice(b".dll");
    }

    let native_capacity = value.len().checked_add(extension_len).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "native provider query length overflowed")
    })?;
    let mut native_query = Vec::new();
    native_query.try_reserve_exact(native_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve native system-provider query spelling",
            error,
        )
    })?;
    native_query.extend_from_slice(value);
    if append_extension {
        native_query.extend_from_slice(b".dll");
    }
    Ok((identity, native_query))
}

fn wide_provider_query_name(value: &[u16]) -> Result<(Vec<u16>, Vec<u16>), RuntimeError> {
    if value.is_empty() || value.contains(&0)
        || value.iter().any(|unit| matches!(*unit, 0x2f | 0x5c | 0x3a))
    {
        return Err(invalid_query());
    }
    let trailing_period = value.last() == Some(&(b'.' as u16));
    let append_extension = !trailing_period
        && !value
            .iter()
            .rposition(|unit| *unit == b'.' as u16)
            .is_some_and(|dot| dot != 0);
    let remove_marker = trailing_period && value.iter().all(|unit| *unit <= 0x7f);
    let identity_len = value.len() - if remove_marker { 1 } else { 0 };
    let extension_len = if append_extension { 4 } else { 0 };
    let identity_capacity = identity_len.checked_add(extension_len).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "system-provider identity length overflowed")
    })?;
    let mut identity = Vec::new();
    identity.try_reserve_exact(identity_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve system-provider query identity",
            error,
        )
    })?;
    identity.extend(value[..identity_len].iter().map(|unit| {
        if (b'A' as u16..=b'Z' as u16).contains(unit) {
            *unit + 0x20
        } else {
            *unit
        }
    }));
    if append_extension {
        identity.extend([b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16]);
    }

    let native_capacity = value.len().checked_add(extension_len).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "native provider query length overflowed")
    })?;
    let mut native_query = Vec::new();
    native_query.try_reserve_exact(native_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve native system-provider query spelling",
            error,
        )
    })?;
    native_query.extend_from_slice(value);
    if append_extension {
        native_query.extend([b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16]);
    }
    Ok((identity, native_query))
}

fn invalid_query() -> RuntimeError {
    RuntimeError::new(
        Kind::CompatibilityGap,
        "system-provider query is not a module basename",
    )
}

pub(super) struct ResolvedSystemProviderPath {
    pub(super) identity_basename: Vec<u8>,
    pub(super) native_path: Vec<u8>,
}

impl ResolvedSystemProviderPath {
    pub(super) fn from_path(path: &[u8]) -> Result<Self, RuntimeError> {
        if path.is_empty() || path.contains(&0) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "resolved System32 provider path is empty or contains NUL",
            ));
        }
        let leaf_start = path
            .iter()
            .rposition(|unit| matches!(*unit, b'/' | b'\\' | b':'))
            .map_or(0, |separator| separator + 1);
        let leaf = &path[leaf_start..];
        if leaf.is_empty() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "resolved System32 provider path has no module basename",
            ));
        }

        let has_extension = leaf
            .iter()
            .rposition(|unit| *unit == b'.')
            .is_some_and(|dot| dot != 0 && dot + 1 < leaf.len());
        let add_suppression_marker = !has_extension
            && leaf.last() != Some(&b'.')
            && ordinary_ascii_drive_path(path);
        let mut identity_basename = copy_bytes(leaf)?;
        identity_basename.make_ascii_lowercase();
        let native_length = path
            .len()
            .checked_add(if add_suppression_marker { 1 } else { 0 })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "resolved System32 provider path length overflowed",
                )
            })?;
        let mut native_path = Vec::new();
        native_path.try_reserve_exact(native_length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native resolved System32 provider path",
                error,
            )
        })?;
        native_path.extend_from_slice(path);
        if add_suppression_marker {
            native_path.push(b'.');
        }
        Ok(Self {
            identity_basename,
            native_path,
        })
    }
}

fn ordinary_ascii_drive_path(path: &[u8]) -> bool {
    path.is_ascii()
        && path.len() >= 3
        && path[0].is_ascii_alphabetic()
        && path[1] == b':'
        && matches!(path[2], b'/' | b'\\')
}

fn copy_bytes(input: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(input.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy resolved System32 provider basename",
            error,
        )
    })?;
    output.extend_from_slice(input);
    Ok(output)
}
