use abi_schema::ExportAttributes;

use crate::error::SpecError;
use crate::model::{
    Architecture, ArgumentType, CallingConvention, DeclarationType, EntryKind, Flags, OrdinalToken,
    ParsedEntry, SignatureKind,
};

pub(crate) fn parse_record(
    directive: &str,
    rest: &str,
    ordinal: OrdinalToken,
    line: usize,
    raw: &str,
    spec_path: &str,
    win32_path: bool,
) -> Result<ParsedEntry, SpecError> {
    let mut entry = match directive {
        "pascal" => parse_function(
            rest,
            CallingConvention::Pascal,
            DeclarationType::Pascal,
            ordinal,
            line,
            raw,
            spec_path,
        )?,
        "cdecl" => parse_function(
            rest,
            CallingConvention::Cdecl,
            DeclarationType::Cdecl,
            ordinal,
            line,
            raw,
            spec_path,
        )?,
        "stdcall" => parse_function(
            rest,
            CallingConvention::Stdcall,
            DeclarationType::Stdcall,
            ordinal,
            line,
            raw,
            spec_path,
        )?,
        "varargs" => parse_function(
            rest,
            CallingConvention::Varargs,
            DeclarationType::Varargs,
            ordinal,
            line,
            raw,
            spec_path,
        )?,
        "thiscall" => parse_function(
            rest,
            CallingConvention::Thiscall,
            DeclarationType::Thiscall,
            ordinal,
            line,
            raw,
            spec_path,
        )?,
        "stub" => parse_stub(rest, ordinal, line, raw, spec_path)?,
        "variable" => parse_variable(rest, ordinal, line, raw, spec_path)?,
        "equate" => parse_equate(rest, ordinal, line, raw, spec_path)?,
        "extern" => parse_extern(rest, ordinal, line, raw, spec_path)?,
        unknown => {
            return Err(SpecError::new(
                spec_path,
                line,
                format!("unsupported declaration kind `{unknown}`"),
            ));
        }
    };

    entry.architecture = if win32_path || entry.flags.architecture_constraints.contains(&"win32") {
        Architecture::Win32Only
    } else {
        Architecture::Win16
    };
    Ok(entry)
}

fn parse_function(
    rest: &str,
    convention: CallingConvention,
    declaration_type: DeclarationType,
    ordinal: OrdinalToken,
    line: usize,
    raw: &str,
    spec_path: &str,
) -> Result<ParsedEntry, SpecError> {
    let (flags, name, arguments, link_name) = parse_call(rest, true, false, line, spec_path)?;
    reject_forward_flag(&flags, line, spec_path)?;
    let signature_kind = signature_kind(&arguments);
    Ok(ParsedEntry {
        ordinal,
        declared_name: name,
        link_name,
        kind: EntryKind::Function,
        declaration_type,
        calling_convention: Some(convention),
        signature_kind: Some(signature_kind),
        arguments,
        flags,
        architecture: Architecture::Win16,
        variable_values: Vec::new(),
        equate_value: None,
        line,
        raw: raw.to_owned(),
    })
}

fn parse_stub(
    rest: &str,
    ordinal: OrdinalToken,
    line: usize,
    raw: &str,
    spec_path: &str,
) -> Result<ParsedEntry, SpecError> {
    let (flags, name, arguments, link_name) = parse_call(rest, false, true, line, spec_path)?;
    reject_forward_flag(&flags, line, spec_path)?;
    // A bare stub has an unknown signature; explicit `()` is known empty.
    let signature_kind = if arguments.is_empty() && !rest.contains('(') {
        SignatureKind::Unknown
    } else {
        signature_kind(&arguments)
    };
    Ok(ParsedEntry {
        ordinal,
        declared_name: name,
        link_name,
        kind: EntryKind::Stub,
        declaration_type: DeclarationType::Stub,
        calling_convention: None,
        signature_kind: Some(signature_kind),
        arguments,
        flags,
        architecture: Architecture::Win16,
        variable_values: Vec::new(),
        equate_value: None,
        line,
        raw: raw.to_owned(),
    })
}

fn parse_variable(
    rest: &str,
    ordinal: OrdinalToken,
    line: usize,
    raw: &str,
    spec_path: &str,
) -> Result<ParsedEntry, SpecError> {
    let open = rest.find('(').ok_or_else(|| {
        SpecError::new(
            spec_path,
            line,
            "variable declaration requires a parenthesized value list",
        )
    })?;
    let prefix = rest[..open].trim();
    let (flags, name) = parse_flagged_name(prefix, line, spec_path, "variable")?;
    reject_forward_flag(&flags, line, spec_path)?;
    let (values_text, tail) = parenthesized_tail(&rest[open..], line, spec_path)?;
    if !tail.trim().is_empty() {
        return Err(SpecError::new(
            spec_path,
            line,
            format!("unexpected text after variable values: `{}`", tail.trim()),
        ));
    }
    let values = parse_u32_values(values_text, line, spec_path)?;
    Ok(ParsedEntry {
        ordinal,
        declared_name: name,
        link_name: None,
        kind: EntryKind::Variable,
        declaration_type: DeclarationType::Variable,
        calling_convention: None,
        signature_kind: None,
        arguments: Vec::new(),
        flags,
        architecture: Architecture::Win16,
        variable_values: values,
        equate_value: None,
        line,
        raw: raw.to_owned(),
    })
}

fn parse_equate(
    rest: &str,
    ordinal: OrdinalToken,
    line: usize,
    raw: &str,
    spec_path: &str,
) -> Result<ParsedEntry, SpecError> {
    let tokens = rest.split_ascii_whitespace().collect::<Vec<_>>();
    let (flags, body) = take_leading_flags(&tokens, line, spec_path)?;
    reject_forward_flag(&flags, line, spec_path)?;
    if body.len() != 2 {
        return Err(SpecError::new(
            spec_path,
            line,
            "equate declaration requires exactly a name and one signed integer value",
        ));
    }
    validate_name(body[0], line, spec_path, "equate name")?;
    let value = parse_i32(body[1], line, spec_path)?;
    Ok(ParsedEntry {
        ordinal,
        declared_name: body[0].to_owned(),
        link_name: None,
        kind: EntryKind::Equate,
        declaration_type: DeclarationType::Equate,
        calling_convention: None,
        signature_kind: None,
        arguments: Vec::new(),
        flags,
        architecture: Architecture::Win16,
        variable_values: Vec::new(),
        equate_value: Some(value),
        line,
        raw: raw.to_owned(),
    })
}

fn parse_extern(
    rest: &str,
    ordinal: OrdinalToken,
    line: usize,
    raw: &str,
    spec_path: &str,
) -> Result<ParsedEntry, SpecError> {
    let tokens = rest.split_ascii_whitespace().collect::<Vec<_>>();
    let (flags, body) = take_leading_flags(&tokens, line, spec_path)?;
    if body.len() != 2 {
        return Err(SpecError::new(
            spec_path,
            line,
            "extern declaration requires an exported name and one link target",
        ));
    }
    validate_name(body[0], line, spec_path, "extern name")?;
    validate_name(body[1], line, spec_path, "extern target")?;
    let kind = if flags.attributes.contains(ExportAttributes::FORWARDED) {
        EntryKind::Forward
    } else {
        EntryKind::Extern
    };
    Ok(ParsedEntry {
        ordinal,
        declared_name: body[0].to_owned(),
        link_name: Some(body[1].to_owned()),
        kind,
        declaration_type: DeclarationType::Extern,
        calling_convention: None,
        signature_kind: None,
        arguments: Vec::new(),
        flags,
        architecture: Architecture::Win16,
        variable_values: Vec::new(),
        equate_value: None,
        line,
        raw: raw.to_owned(),
    })
}

fn parse_call(
    rest: &str,
    require_signature: bool,
    allow_missing_signature: bool,
    line: usize,
    spec_path: &str,
) -> Result<(Flags, String, Vec<ArgumentType>, Option<String>), SpecError> {
    if let Some(open) = rest.find('(') {
        let prefix = rest[..open].trim();
        let (flags, name) = parse_flagged_name(prefix, line, spec_path, "export")?;
        let (arguments_text, tail) = parenthesized_tail(&rest[open..], line, spec_path)?;
        let link_name = parse_optional_alias(tail, line, spec_path)?;
        let arguments = parse_arguments(arguments_text, line, spec_path)?;
        Ok((flags, name, arguments, link_name))
    } else {
        if require_signature || !allow_missing_signature {
            return Err(SpecError::new(
                spec_path,
                line,
                "function declaration requires an argument list; use `()` for an empty signature",
            ));
        }
        let tokens = rest.split_ascii_whitespace().collect::<Vec<_>>();
        let (flags, body) = take_leading_flags(&tokens, line, spec_path)?;
        if !(1..=2).contains(&body.len()) {
            return Err(SpecError::new(
                spec_path,
                line,
                "stub requires a name and may have one trailing alias",
            ));
        }
        validate_name(body[0], line, spec_path, "stub name")?;
        let link_name = if let Some(alias) = body.get(1) {
            validate_name(alias, line, spec_path, "stub alias")?;
            Some((*alias).to_owned())
        } else {
            None
        };
        Ok((flags, body[0].to_owned(), Vec::new(), link_name))
    }
}

fn parse_flagged_name(
    prefix: &str,
    line: usize,
    spec_path: &str,
    name_kind: &str,
) -> Result<(Flags, String), SpecError> {
    let tokens = prefix.split_ascii_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(SpecError::new(
            spec_path,
            line,
            format!("{name_kind} declaration is missing its name"),
        ));
    }
    let (flags, name) = tokens.split_at(tokens.len() - 1);
    if flags.iter().any(|token| !token.starts_with('-')) {
        return Err(SpecError::new(
            spec_path,
            line,
            format!("unexpected token before {name_kind} name"),
        ));
    }
    let parsed_flags = parse_flags(flags, line, spec_path)?;
    validate_name(name[0], line, spec_path, name_kind)?;
    Ok((parsed_flags, name[0].to_owned()))
}

fn take_leading_flags<'tokens, 'text>(
    tokens: &'tokens [&'text str],
    line: usize,
    spec_path: &str,
) -> Result<(Flags, &'tokens [&'text str]), SpecError> {
    let count = tokens
        .iter()
        .take_while(|token| token.starts_with('-'))
        .count();
    let flags = parse_flags(&tokens[..count], line, spec_path)?;
    Ok((flags, &tokens[count..]))
}

fn parse_flags(tokens: &[&str], line: usize, spec_path: &str) -> Result<Flags, SpecError> {
    let mut flags = Flags::default();
    for token in tokens {
        let flag = match *token {
            "-norelay" => ExportAttributes::NO_RELAY,
            "-noname" => ExportAttributes::NONAME,
            "-ret16" => ExportAttributes::RET16,
            "-retvoid" => ExportAttributes::RETVOID,
            "-ret64" => ExportAttributes::RET64,
            "-register" => ExportAttributes::REGISTER,
            "-private" => ExportAttributes::PRIVATE,
            "-ordinal" => ExportAttributes::ORDINAL,
            "-stkprolog" => ExportAttributes::STACK_PROLOG,
            "-i386" => ExportAttributes::LEGACY_I386,
            "-forward" => ExportAttributes::FORWARDED,
            "-arch=win32" => {
                if flags.architecture_constraints.contains(&"win32") {
                    return Err(SpecError::new(
                        spec_path,
                        line,
                        "duplicate flag `-arch=win32`",
                    ));
                }
                flags.architecture_constraints.push("win32");
                continue;
            }
            unknown if unknown.starts_with("-arch=") => {
                return Err(SpecError::new(
                    spec_path,
                    line,
                    format!("unsupported architecture flag `{unknown}`"),
                ));
            }
            unknown => {
                return Err(SpecError::new(
                    spec_path,
                    line,
                    format!("unsupported export flag `{unknown}`"),
                ));
            }
        };
        if flags.attributes.contains(flag) {
            return Err(SpecError::new(
                spec_path,
                line,
                format!("duplicate export flag `{token}`"),
            ));
        }
        flags.attributes |= flag;
    }
    if flags.attributes.contains(ExportAttributes::RETVOID)
        && flags.attributes.intersects(ExportAttributes::RET16 | ExportAttributes::RET64)
    {
        return Err(SpecError::new(spec_path, line,
            "`-retvoid` cannot be combined with a return-width modifier"));
    }
    Ok(flags)
}

fn reject_forward_flag(flags: &Flags, line: usize, spec_path: &str) -> Result<(), SpecError> {
    if flags.attributes.contains(ExportAttributes::FORWARDED) {
        return Err(SpecError::new(
            spec_path,
            line,
            "`-forward` is valid only on an `extern` declaration",
        ));
    }
    Ok(())
}

fn parenthesized_tail<'a>(
    input: &'a str,
    line: usize,
    spec_path: &str,
) -> Result<(&'a str, &'a str), SpecError> {
    if !input.starts_with('(') {
        return Err(SpecError::new(spec_path, line, "expected `(`"));
    }
    let close = input[1..]
        .find(')')
        .map(|index| index + 1)
        .ok_or_else(|| SpecError::new(spec_path, line, "unterminated parenthesized declaration"))?;
    let contents = &input[1..close];
    let tail = &input[close + 1..];
    if contents.contains('(') || tail.chars().any(|character| matches!(character, '(' | ')')) {
        return Err(SpecError::new(
            spec_path,
            line,
            "nested or extra parentheses are not supported",
        ));
    }
    Ok((contents, tail))
}

fn parse_optional_alias(
    tail: &str,
    line: usize,
    spec_path: &str,
) -> Result<Option<String>, SpecError> {
    if tail.is_empty() {
        return Ok(None);
    }
    if !tail.chars().next().is_some_and(char::is_whitespace) {
        return Err(SpecError::new(
            spec_path,
            line,
            "alias must be separated from `)` by whitespace",
        ));
    }
    let aliases = tail.split_ascii_whitespace().collect::<Vec<_>>();
    if aliases.len() != 1 {
        return Err(SpecError::new(
            spec_path,
            line,
            "a declaration may have at most one trailing alias",
        ));
    }
    validate_name(aliases[0], line, spec_path, "alias")?;
    Ok(Some(aliases[0].to_owned()))
}

fn parse_arguments(
    input: &str,
    line: usize,
    spec_path: &str,
) -> Result<Vec<ArgumentType>, SpecError> {
    let tokens = split_list(input, line, spec_path, "argument list")?;
    tokens
        .into_iter()
        .map(|token| parse_argument(token, line, spec_path))
        .collect()
}

fn parse_argument(token: &str, line: usize, spec_path: &str) -> Result<ArgumentType, SpecError> {
    match token {
        "word" => Ok(ArgumentType::Word),
        "s_word" => Ok(ArgumentType::SignedWord),
        "segptr" => Ok(ArgumentType::SegmentPointer),
        "segstr" => Ok(ArgumentType::SegmentString),
        "long" => Ok(ArgumentType::Long),
        "ptr" => Ok(ArgumentType::Pointer),
        "str" => Ok(ArgumentType::String),
        "wstr" => Ok(ArgumentType::WideString),
        "int64" => Ok(ArgumentType::Int64),
        "int128" => Ok(ArgumentType::Int128),
        "float" => Ok(ArgumentType::Float),
        "double" => Ok(ArgumentType::Double),
        "unknown" => Ok(ArgumentType::Unknown),
        unknown => Err(SpecError::new(
            spec_path,
            line,
            format!("unsupported argument descriptor `{unknown}`"),
        )),
    }
}

fn parse_u32_values(input: &str, line: usize, spec_path: &str) -> Result<Vec<u32>, SpecError> {
    let tokens = split_list(input, line, spec_path, "variable initializer list")?;
    tokens
        .into_iter()
        .map(|token| parse_u32(token, line, spec_path))
        .collect()
}

fn split_list<'a>(
    input: &'a str,
    line: usize,
    spec_path: &str,
    label: &str,
) -> Result<Vec<&'a str>, SpecError> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    if input.contains(',') {
        let mut tokens = Vec::new();
        for group in input.split(',') {
            let group_tokens = group.split_ascii_whitespace().collect::<Vec<_>>();
            if group_tokens.is_empty() {
                return Err(SpecError::new(
                    spec_path,
                    line,
                    format!("empty item in {label}"),
                ));
            }
            tokens.extend(group_tokens);
        }
        return Ok(tokens);
    }
    Ok(input.split_ascii_whitespace().collect())
}

fn parse_u32(value: &str, line: usize, spec_path: &str) -> Result<u32, SpecError> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse::<u32>()
    };
    parsed.map_err(|_| {
        SpecError::new(
            spec_path,
            line,
            format!("invalid u32 variable initializer `{value}`"),
        )
    })
}

fn parse_i32(value: &str, line: usize, spec_path: &str) -> Result<i32, SpecError> {
    let out_of_range = || {
        SpecError::new(
            spec_path,
            line,
            format!("equate value `{value}` is outside the i32 range"),
        )
    };
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        let parsed = i64::from_str_radix(hex, 16).map_err(|_| {
            SpecError::new(
                spec_path,
                line,
                format!("invalid i32 equate value `{value}`"),
            )
        })?;
        return i32::try_from(parsed).map_err(|_| out_of_range());
    }
    if let Some(negative_hex) = value
        .strip_prefix("-0x")
        .or_else(|| value.strip_prefix("-0X"))
    {
        let parsed = i64::from_str_radix(negative_hex, 16).map_err(|_| {
            SpecError::new(
                spec_path,
                line,
                format!("invalid i32 equate value `{value}`"),
            )
        })?;
        return i32::try_from(-parsed).map_err(|_| out_of_range());
    }
    value.parse::<i32>().map_err(|_| {
        if value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
        {
            out_of_range()
        } else {
            SpecError::new(
                spec_path,
                line,
                format!("invalid i32 equate value `{value}`"),
            )
        }
    })
}

fn signature_kind(arguments: &[ArgumentType]) -> SignatureKind {
    if arguments.contains(&ArgumentType::Unknown) {
        SignatureKind::Unknown
    } else {
        SignatureKind::Known
    }
}

fn validate_name(name: &str, line: usize, spec_path: &str, label: &str) -> Result<(), SpecError> {
    if name.is_empty()
        || name.starts_with('-')
        || name.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b',' | b'#' | b'"' | b'\'')
        })
    {
        return Err(SpecError::new(
            spec_path,
            line,
            format!("invalid {label} `{name}`"),
        ));
    }
    Ok(())
}
