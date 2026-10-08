use std::collections::HashMap;

use crate::error::SpecError;
use crate::model::{OrdinalSource, OrdinalToken, ParsedEntry, SpecEntry, SpecModule};
use crate::record;

pub(crate) fn parse_spec(
    module: &str,
    source_module: &str,
    spec_path: &str,
    source: &str,
) -> Result<SpecModule, SpecError> {
    for (value, label) in [
        (module, "module"),
        (source_module, "source module"),
        (spec_path, "spec path"),
    ] {
        if value.trim().is_empty() {
            return Err(SpecError::new(
                spec_path,
                0,
                format!("{label} must not be empty"),
            ));
        }
    }

    let mut header = None;
    let mut parsed_entries = Vec::new();
    let mut explicit_ordinals = HashMap::<u16, usize>::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.starts_with('#') {
            if let Some(parsed_header) = parse_header(trimmed, spec_path, line)? {
                if header.is_some() {
                    return Err(SpecError::new(spec_path, line, "duplicate module header"));
                }
                header = Some(parsed_header);
            }
            continue;
        }

        let code = strip_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }
        if line > u16::MAX as usize {
            return Err(SpecError::new(
                spec_path,
                line,
                "source line number exceeds the ExportSourceLocation limit",
            ));
        }
        if header.is_none() {
            return Err(SpecError::new(
                spec_path,
                line,
                "expected `# module=... source_module=...` before declarations",
            ));
        }

        let (ordinal_text, after_ordinal) = take_token(code)
            .ok_or_else(|| SpecError::new(spec_path, line, "expected a decimal ordinal or `@`"))?;
        let ordinal = parse_ordinal(ordinal_text, spec_path, line)?;
        if let OrdinalToken::Explicit(value) = ordinal {
            if let Some(previous_line) = explicit_ordinals.insert(value, line) {
                return Err(SpecError::new(
                    spec_path,
                    line,
                    format!("duplicate ordinal {value}; first declared on line {previous_line}"),
                ));
            }
        }

        let (directive, rest) = take_token(after_ordinal).ok_or_else(|| {
            SpecError::new(
                spec_path,
                line,
                "expected a declaration kind after the ordinal",
            )
        })?;
        if rest.is_empty() {
            return Err(SpecError::new(
                spec_path,
                line,
                format!("missing declaration after `{directive}`"),
            ));
        }
        parsed_entries.push(record::parse_record(
            directive,
            rest,
            ordinal,
            line,
            raw_line,
            spec_path,
            is_win32_path(spec_path),
        )?);
    }

    let (header_module, header_source_module) = header.ok_or_else(|| {
        SpecError::new(
            spec_path,
            0,
            "missing `# module=... source_module=...` header",
        )
    })?;
    if header_module != module {
        return Err(SpecError::new(
            spec_path,
            1,
            format!("header module `{header_module}` does not match `{module}`"),
        ));
    }
    if header_source_module != source_module {
        return Err(SpecError::new(
            spec_path,
            1,
            format!(
                "header source module `{header_source_module}` does not match `{source_module}`"
            ),
        ));
    }

    let entries = assign_ordinals(parsed_entries, explicit_ordinals, spec_path)?;
    Ok(SpecModule {
        module: module.to_owned(),
        source_module: source_module.to_owned(),
        spec_path: spec_path.to_owned(),
        entries,
    })
}

fn parse_header(
    line: &str,
    spec_path: &str,
    line_number: usize,
) -> Result<Option<(String, String)>, SpecError> {
    let content = line.strip_prefix('#').unwrap_or(line).trim();
    if !content.starts_with("module=") {
        return Ok(None);
    }

    let tokens = content.split_ascii_whitespace().collect::<Vec<_>>();
    if tokens.len() != 2 {
        return Err(SpecError::new(
            spec_path,
            line_number,
            "module header must contain exactly `module=... source_module=...`",
        ));
    }
    let module = tokens[0]
        .strip_prefix("module=")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SpecError::new(spec_path, line_number, "invalid module header field"))?;
    let source_module = tokens[1]
        .strip_prefix("source_module=")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SpecError::new(spec_path, line_number, "invalid source_module header field")
        })?;
    Ok(Some((module.to_owned(), source_module.to_owned())))
}

fn parse_ordinal(value: &str, spec_path: &str, line: usize) -> Result<OrdinalToken, SpecError> {
    if value == "@" {
        return Ok(OrdinalToken::Automatic);
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SpecError::new(
            spec_path,
            line,
            format!("invalid ordinal `{value}`; expected decimal digits or `@`"),
        ));
    }
    value
        .parse::<u16>()
        .map(OrdinalToken::Explicit)
        .map_err(|_| {
            SpecError::new(
                spec_path,
                line,
                format!("ordinal `{value}` is outside the 0..=65535 range"),
            )
        })
}

fn assign_ordinals(
    parsed_entries: Vec<ParsedEntry>,
    mut used: HashMap<u16, usize>,
    spec_path: &str,
) -> Result<Vec<SpecEntry>, SpecError> {
    let mut next_available = 1_u32;
    let mut entries = Vec::with_capacity(parsed_entries.len());
    for parsed in parsed_entries {
        let (ordinal, ordinal_source) = match parsed.ordinal {
            OrdinalToken::Explicit(value) => (value, OrdinalSource::Explicit),
            OrdinalToken::Automatic => {
                while next_available <= u16::MAX as u32
                    && used.contains_key(&(next_available as u16))
                {
                    next_available += 1;
                }
                if next_available > u16::MAX as u32 {
                    return Err(SpecError::new(
                        spec_path,
                        parsed.line,
                        "no unassigned ordinal remains for `@`",
                    ));
                }
                let value = next_available as u16;
                used.insert(value, parsed.line);
                next_available += 1;
                (value, OrdinalSource::Assigned)
            }
        };
        entries.push(SpecEntry {
            ordinal,
            ordinal_source,
            declared_name: parsed.declared_name,
            link_name: parsed.link_name,
            kind: parsed.kind,
            declaration_type: parsed.declaration_type,
            calling_convention: parsed.calling_convention,
            signature_kind: parsed.signature_kind,
            arguments: parsed.arguments,
            flags: parsed.flags,
            architecture: parsed.architecture,
            variable_values: parsed.variable_values,
            equate_value: parsed.equate_value,
            line: parsed.line,
            raw: parsed.raw,
        });
    }
    Ok(entries)
}

fn is_win32_path(spec_path: &str) -> bool {
    spec_path
        .split(|character| matches!(character, '/' | '\\'))
        .any(|segment| segment.eq_ignore_ascii_case("win32"))
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(code, _)| code)
}

fn take_token(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    Some((&input[..end], input[end..].trim_start()))
}
