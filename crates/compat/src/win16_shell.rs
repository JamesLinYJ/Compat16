//! Byte-preserving helpers for Win16 SHELL environment-string APIs.
//!
//! DOS stores each environment entry as an ANSI/OEM byte sequence followed by
//! NUL, then terminates the list with a second NUL. These helpers inspect only
//! an owned, caller-bounded copy of that guest block; they do not consult or
//! expose the host process environment.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentListError {
    MissingTerminator,
    QueryContainsNul,
    AllocationFailed,
}

impl std::fmt::Display for EnvironmentListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTerminator => f.write_str("Win16 environment list has no double-NUL terminator"),
            Self::QueryContainsNul => f.write_str("Win16 environment name contains an embedded NUL"),
            Self::AllocationFailed => f.write_str("could not allocate a Win16 environment-substitution result"),
        }
    }
}

impl std::error::Error for EnvironmentListError {}

/// Find the offset of the value for a matching environment name.
///
/// The returned offset points after the name and equals sign, matching the
/// `FindEnvironmentString` pointer into the DOS block. For an exact entry
/// without an equals sign, it points at that entry's terminating NUL. Name
/// comparison is ASCII case-insensitive while guest bytes remain unchanged.
/// DOS drive-current-directory entries such as `=C:=C:\\` retain their
/// leading equals sign as part of the name.
pub fn find_environment_string(
    block: &[u8],
    query: &[u8],
) -> Result<Option<usize>, EnvironmentListError> {
    if query.contains(&0) {
        return Err(EnvironmentListError::QueryContainsNul);
    }

    let mut cursor = 0usize;
    loop {
        let Some(relative_end) = block[cursor..].iter().position(|&byte| byte == 0) else {
            return Err(EnvironmentListError::MissingTerminator);
        };
        if relative_end == 0 {
            if block.get(cursor + 1) != Some(&0) {
                return Err(EnvironmentListError::MissingTerminator);
            }
            return Ok(None);
        }
        let end = cursor + relative_end;
        let entry = &block[cursor..end];
        if entry.len() >= query.len() && entry[..query.len()].eq_ignore_ascii_case(query) {
            match entry.get(query.len()) {
                Some(b'=') => return Ok(Some(cursor + query.len() + 1)),
                None => return Ok(Some(cursor + query.len())),
                _ => {}
            }
        }

        cursor = end + 1;
        let Some(next) = block.get(cursor).copied() else {
            return Err(EnvironmentListError::MissingTerminator);
        };
        if next == 0 {
            return Ok(None);
        }
    }
}

/// One call to Win16 `DoEnvironmentSubst` over an owned guest buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSubstitution {
    /// DWORD result: TRUE in HIWORD and the returned byte count in LOWORD on
    /// success; FALSE in HIWORD and the supplied capacity in LOWORD on failure.
    pub result: u32,
    /// New NUL-terminated prefix when expansion fits. `None` means the guest
    /// buffer must remain untouched.
    pub output: Option<Vec<u8>>,
}

/// Expand `%NAME%` references using the current guest DOS environment block.
///
/// The complete operation is staged in an owned buffer. If the source lacks a
/// NUL terminator within `capacity`, an expansion is too large, or an input
/// token is malformed, no output is returned and the caller can preserve the
/// original guest buffer. The returned successful length includes the NUL
/// terminator, matching the Win16 output-buffer contract.
pub fn do_environment_subst(
    source_buffer: &[u8],
    capacity: u16,
    environment_block: &[u8],
) -> Result<EnvironmentSubstitution, EnvironmentListError> {
    let capacity = usize::from(capacity);
    let failure = |capacity: usize| EnvironmentSubstitution {
        result: capacity as u32,
        output: None,
    };
    if capacity == 0 || source_buffer.len() < capacity {
        return Ok(failure(capacity));
    }
    let source = &source_buffer[..capacity];
    let Some(source_length) = source.iter().position(|&byte| byte == 0) else {
        return Ok(failure(capacity));
    };
    let source = &source[..source_length];

    let mut expanded = Vec::new();
    expanded.try_reserve_exact(capacity)
        .map_err(|_| EnvironmentListError::AllocationFailed)?;
    let mut cursor = 0usize;
    while cursor < source.len() {
        if source[cursor] != b'%' {
            expanded.push(source[cursor]);
            cursor += 1;
            continue;
        }
        let Some(relative_end) = source[cursor + 1..].iter().position(|&byte| byte == b'%') else {
            // A lone percent sign is literal text; preserving it also keeps
            // paths such as percentages in filenames intact.
            expanded.push(b'%');
            cursor += 1;
            continue;
        };
        let end = cursor + 1 + relative_end;
        let name = &source[cursor + 1..end];
        if name.is_empty() {
            expanded.extend_from_slice(b"%%");
            cursor = end + 1;
            continue;
        }

        let replacement = match find_environment_string(environment_block, name)? {
            Some(value_offset) => {
                let Some(value_length) = environment_block.get(value_offset..)
                    .and_then(|tail| tail.iter().position(|&byte| byte == 0)) else {
                    return Err(EnvironmentListError::MissingTerminator);
                };
                &environment_block[value_offset..value_offset + value_length]
            }
            None => &source[cursor..=end],
        };
        let next_length = expanded.len().checked_add(replacement.len())
            .and_then(|length| length.checked_add(1));
        if next_length.is_none_or(|length| length > capacity) {
            return Ok(failure(capacity));
        }
        expanded.extend_from_slice(replacement);
        cursor = end + 1;
    }

    let returned_length = expanded.len().checked_add(1).filter(|&length| length <= capacity);
    let Some(returned_length) = returned_length else {
        return Ok(failure(capacity));
    };
    expanded.push(0);
    let output_length = returned_length as u16;
    Ok(EnvironmentSubstitution {
        result: (1u32 << 16) | u32::from(output_length),
        output: Some(expanded),
    })
}
