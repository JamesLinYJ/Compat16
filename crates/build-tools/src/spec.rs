use std::collections::HashMap;
use std::fmt;

use crate::{ArgumentType, CallingConvention, ExportAttributes, ExportFlags, ExportKind, Ordinal};

/// Parsed export declarations from a module specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecModule {
    /// The caller-supplied, original module name. It is never inferred or
    /// normalized from a path.
    pub original_module_name: String,
    /// Entries remain in their original source order.
    pub exports: Vec<SpecEntry>,
}

/// One supported `.spec` declaration. `values` is used by `variable` and
/// `equate`; functions, aliases, and stubs leave it empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecEntry {
    pub ordinal: Ordinal,
    pub kind: ExportKind,
    pub export_name: String,
    /// Optional C implementation alias from a function declaration.
    pub implementation_name: Option<String>,
    pub convention: Option<CallingConvention>,
    pub arguments: Vec<ArgumentType>,
    pub flags: ExportFlags,
    pub values: Vec<String>,
    /// One-based line number in the input file.
    pub source_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for SpecParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for SpecParseError {}

/// Parse module export declarations in `.spec` format.
///
/// Supported records are numbered and automatic-ordinal functions (`pascal`,
/// `cdecl`, `stdcall`, `varargs`), `stub`, `variable`, and `equate`. The parser
/// deliberately rejects unknown directives, options, argument descriptors,
/// malformed signatures, duplicate numeric ordinals, and trailing tokens.
pub fn parse_spec(
    source: &str,
    original_module_name: impl Into<String>,
) -> Result<SpecModule, SpecParseError> {
    let original_module_name = original_module_name.into();
    if original_module_name.trim().is_empty() {
        return Err(SpecParseError {
            line: 0,
            message: "original module name must not be empty".to_owned(),
        });
    }

    let mut exports = Vec::new();
    let mut ordinals = HashMap::<u16, usize>::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let code = strip_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        let (ordinal_token, after_ordinal) = take_token(code).ok_or_else(|| {
            error(line_number, "expected an ordinal or `@` automatic ordinal")
        })?;
        let ordinal = if ordinal_token == "@" {
            Ordinal::Automatic
        } else {
            if !ordinal_token.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(error(
                    line_number,
                    format!("invalid ordinal `{ordinal_token}`; expected a decimal number or `@`"),
                ));
            }
            let value = ordinal_token.parse::<u16>().map_err(|_| {
                error(
                    line_number,
                    format!("ordinal `{ordinal_token}` is outside the 0..=65535 range"),
                )
            })?;
            if let Some(previous_line) = ordinals.insert(value, line_number) {
                return Err(error(
                    line_number,
                    format!("duplicate ordinal {value}; first declared on line {previous_line}"),
                ));
            }
            Ordinal::Explicit(value)
        };

        let (directive, rest) = take_token(after_ordinal)
            .ok_or_else(|| error(line_number, "expected an export directive after the ordinal"))?;
        if rest.is_empty() {
            return Err(error(line_number, format!("missing declaration after `{directive}`")));
        }

        let entry = match directive {
            "pascal" => parse_function(
                ordinal,
                CallingConvention::Pascal,
                rest,
                line_number,
            )?,
            "cdecl" => parse_function(ordinal, CallingConvention::Cdecl, rest, line_number)?,
            "stdcall" => {
                parse_function(ordinal, CallingConvention::Stdcall, rest, line_number)?
            }
            "varargs" => {
                parse_function(ordinal, CallingConvention::Varargs, rest, line_number)?
            }
            "stub" => parse_stub(ordinal, rest, line_number)?,
            "variable" => parse_variable(ordinal, rest, line_number)?,
            "equate" => parse_equate(ordinal, rest, line_number)?,
            unknown => {
                return Err(error(
                    line_number,
                    format!("unsupported export directive `{unknown}`"),
                ));
            }
        };
        exports.push(entry);
    }

    Ok(SpecModule {
        original_module_name,
        exports,
    })
}

/// Emit stable Rust data records that reference the public types in this crate.
pub fn generate_rust(module: &SpecModule) -> String {
    let mut output = String::from(
        "// Generated export metadata. This does not\n\
         // claim that any exported service is implemented.\n\
         pub const GENERATED_MODULE: ::build_tools::GeneratedModule =\n\
         ::build_tools::GeneratedModule {\n",
    );
    output.push_str(&format!(
        "    original_module_name: {:?},\n    exports: &[\n",
        module.original_module_name
    ));

    for entry in &module.exports {
        output.push_str("        ::build_tools::GeneratedExport {\n");
        output.push_str(&format!("            ordinal: {},\n", rust_ordinal(entry.ordinal)));
        output.push_str(&format!("            kind: {},\n", rust_kind(entry.kind)));
        output.push_str(&format!("            export_name: {:?},\n", entry.export_name));
        output.push_str("            implementation_name: ");
        output.push_str(&rust_optional_string(entry.implementation_name.as_deref()));
        output.push_str(",\n            convention: ");
        output.push_str(&rust_convention(entry.convention));
        output.push_str(",\n            arguments: &[");
        for (index, argument) in entry.arguments.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(rust_argument(*argument));
        }
        output.push_str("],\n            flags: ::build_tools::ExportFlags {\n");
        output.push_str(&format!(
            "                attributes: ::build_tools::ExportAttributes::from_bits_retain({}),\n                arch_win32: {},\n",
            entry.flags.attributes.bits(),
            entry.flags.arch_win32
        ));
        output.push_str("            },\n            values: &[");
        for (index, value) in entry.values.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!("{:?}", value));
        }
        output.push_str("],\n");
        output.push_str(&format!("            source_line: {},\n", entry.source_line));
        output.push_str("        },\n");
    }

    output.push_str("    ],\n};\n");
    output
}

fn parse_function(
    ordinal: Ordinal,
    convention: CallingConvention,
    rest: &str,
    line: usize,
) -> Result<SpecEntry, SpecParseError> {
    let open = rest
        .find('(')
        .ok_or_else(|| error(line, "function declaration is missing its argument list"))?;
    let prefix = rest[..open].trim();
    let (arguments_text, tail) = parenthesized_tail(&rest[open..], line)?;
    let mut prefix_tokens = prefix.split_whitespace().collect::<Vec<_>>();
    let export_name = prefix_tokens
        .pop()
        .ok_or_else(|| error(line, "function declaration is missing its export name"))?;
    validate_name(export_name, line, "export name")?;
    let flags = parse_flags(&prefix_tokens, line)?;

    let trailing = tail.split_whitespace().collect::<Vec<_>>();
    if trailing.len() > 1 {
        return Err(error(
            line,
            format!("unexpected trailing tokens after function signature: `{}`", tail.trim()),
        ));
    }
    let implementation_name = trailing.first().copied();
    if !tail.is_empty()
        && !tail
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
    {
        return Err(error(
            line,
            "implementation alias must be separated from `)` by whitespace",
        ));
    }
    if let Some(name) = implementation_name {
        validate_name(name, line, "implementation name")?;
    }

    let arguments = parse_arguments(arguments_text, line)?;
    Ok(SpecEntry {
        ordinal,
        kind: ExportKind::Function,
        export_name: export_name.to_owned(),
        implementation_name: implementation_name.map(str::to_owned),
        convention: Some(convention),
        arguments,
        flags,
        values: Vec::new(),
        source_line: line,
    })
}

fn parse_stub(ordinal: Ordinal, rest: &str, line: usize) -> Result<SpecEntry, SpecParseError> {
    let tokens = rest.split_whitespace().collect::<Vec<_>>();
    let mut index = 0;
    while index < tokens.len() && tokens[index].starts_with('-') {
        index += 1;
    }
    let flags = parse_flags(&tokens[..index], line)?;
    let name = tokens
        .get(index)
        .copied()
        .ok_or_else(|| error(line, "stub declaration is missing its export name"))?;
    validate_name(name, line, "stub name")?;
    if index + 1 != tokens.len() {
        return Err(error(
            line,
            format!("unexpected trailing tokens after stub name: `{}`", tokens[index + 1..].join(" ")),
        ));
    }
    Ok(SpecEntry {
        ordinal,
        kind: ExportKind::Stub,
        export_name: name.to_owned(),
        implementation_name: None,
        convention: None,
        arguments: Vec::new(),
        flags,
        values: Vec::new(),
        source_line: line,
    })
}

fn parse_variable(
    ordinal: Ordinal,
    rest: &str,
    line: usize,
) -> Result<SpecEntry, SpecParseError> {
    let open = rest
        .find('(')
        .ok_or_else(|| error(line, "variable declaration is missing its initializer list"))?;
    let prefix = rest[..open].trim();
    let (values_text, tail) = parenthesized_tail(&rest[open..], line)?;
    let names = prefix.split_whitespace().collect::<Vec<_>>();
    if names.len() != 1 {
        return Err(error(line, "variable declaration must contain exactly one name before `(`"));
    }
    let name = names[0];
    validate_name(name, line, "variable name")?;
    if !tail.trim().is_empty() {
        return Err(error(
            line,
            format!("unexpected trailing tokens after variable initializer: `{}`", tail.trim()),
        ));
    }
    let values = parse_numeric_values(values_text, line)?;
    Ok(SpecEntry {
        ordinal,
        kind: ExportKind::Variable,
        export_name: name.to_owned(),
        implementation_name: None,
        convention: None,
        arguments: Vec::new(),
        flags: ExportFlags::default(),
        values,
        source_line: line,
    })
}

fn parse_equate(ordinal: Ordinal, rest: &str, line: usize) -> Result<SpecEntry, SpecParseError> {
    let (name, value) = take_token(rest)
        .ok_or_else(|| error(line, "equate declaration is missing its name and value"))?;
    validate_name(name, line, "equate name")?;
    let value_tokens = value.split_whitespace().collect::<Vec<_>>();
    if value_tokens.len() != 1 || !is_integer_literal(value_tokens[0]) {
        return Err(error(
            line,
            format!("equate `{name}` requires one decimal or hexadecimal integer value"),
        ));
    }
    Ok(SpecEntry {
        ordinal,
        kind: ExportKind::Equate,
        export_name: name.to_owned(),
        implementation_name: None,
        convention: None,
        arguments: Vec::new(),
        flags: ExportFlags::default(),
        values: vec![value_tokens[0].to_owned()],
        source_line: line,
    })
}

fn parenthesized_tail(input: &str, line: usize) -> Result<(&str, &str), SpecParseError> {
    if !input.starts_with('(') {
        return Err(error(line, "expected `(`"));
    }
    let close = input[1..]
        .find(')')
        .map(|offset| offset + 1)
        .ok_or_else(|| error(line, "unterminated parenthesized declaration"))?;
    let contents = &input[1..close];
    if contents.contains('(')
        || input[close + 1..]
            .chars()
            .any(|character| matches!(character, '(' | ')'))
    {
        return Err(error(line, "nested or extra parentheses are not supported in this declaration"));
    }
    Ok((contents, &input[close + 1..]))
}

fn parse_arguments(input: &str, line: usize) -> Result<Vec<ArgumentType>, SpecParseError> {
    let mut arguments = Vec::new();
    for raw in input.split_ascii_whitespace() {
        let argument = match raw {
            "word" => ArgumentType::Word,
            "s_word" => ArgumentType::SignedWord,
            "long" => ArgumentType::Long,
            "ptr" => ArgumentType::Pointer,
            "str" => ArgumentType::String,
            "segptr" => ArgumentType::SegmentPointer,
            "segstr" => ArgumentType::SegmentString,
            "int64" => ArgumentType::Int64,
            "float" => ArgumentType::Float,
            "wstr" => ArgumentType::WideString,
            unknown => {
                return Err(error(
                    line,
                    format!("unsupported argument descriptor `{unknown}`"),
                ));
            }
        };
        arguments.push(argument);
    }
    Ok(arguments)
}

fn parse_numeric_values(input: &str, line: usize) -> Result<Vec<String>, SpecParseError> {
    let mut values = Vec::new();
    for raw in input.split_ascii_whitespace() {
        if !is_integer_literal(raw) {
            return Err(error(
                line,
                format!("unsupported variable initializer `{raw}`; expected an integer literal"),
            ));
        }
        values.push(raw.to_owned());
    }
    if values.is_empty() {
        return Err(error(line, "variable initializer list must not be empty"));
    }
    Ok(values)
}

fn parse_flags(tokens: &[&str], line: usize) -> Result<ExportFlags, SpecParseError> {
    let mut flags = ExportFlags::default();
    for token in tokens {
        let attribute = match *token {
            "-arch=win32" => {
                if flags.arch_win32 {
                    return Err(error(line, format!("duplicate export flag `{token}`")));
                }
                flags.arch_win32 = true;
                continue;
            }
            "-ret16" => ExportAttributes::RET16,
            "-register" => ExportAttributes::REGISTER,
            "-stkprolog" => ExportAttributes::STACK_PROLOG,
            "-norelay" => ExportAttributes::NO_RELAY,
            "-private" => ExportAttributes::PRIVATE,
            unknown if unknown.starts_with('-') => {
                return Err(error(line, format!("unsupported export flag `{unknown}`")));
            }
            other => {
                return Err(error(
                    line,
                    format!("unexpected token `{other}` where an export flag was expected"),
                ));
            }
        };
        if flags.attributes.contains(attribute) {
            return Err(error(line, format!("duplicate export flag `{token}`")));
        }
        flags.attributes |= attribute;
    }
    Ok(flags)
}

fn validate_name(name: &str, line: usize, kind: &str) -> Result<(), SpecParseError> {
    if name.is_empty()
        || name.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'#' | b'"' | b'\'')
        })
        || name.starts_with('-')
    {
        return Err(error(line, format!("invalid {kind} `{name}`")));
    }
    Ok(())
}

fn is_integer_literal(input: &str) -> bool {
    let digits = if let Some(hex) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        hex
    } else if let Some(negative) = input.strip_prefix('-') {
        negative
    } else {
        input
    };
    !digits.is_empty()
        && if input.starts_with("0x") || input.starts_with("0X") {
            digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        } else {
            digits.bytes().all(|byte| byte.is_ascii_digit())
        }
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            }
            continue;
        }
        if character == '"' || character == '\'' {
            quote = Some(character);
        } else if character == '#' {
            return &line[..index];
        }
    }
    line
}

fn take_token(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let end = input
        .find(char::is_whitespace)
        .unwrap_or(input.len());
    Some((&input[..end], input[end..].trim_start()))
}

fn error(line: usize, message: impl Into<String>) -> SpecParseError {
    SpecParseError {
        line,
        message: message.into(),
    }
}

fn rust_ordinal(ordinal: Ordinal) -> String {
    match ordinal {
        Ordinal::Explicit(value) => {
            format!("::build_tools::Ordinal::Explicit({value})")
        }
        Ordinal::Automatic => "::build_tools::Ordinal::Automatic".to_owned(),
    }
}

fn rust_kind(kind: ExportKind) -> &'static str {
    match kind {
        ExportKind::Function => "::build_tools::ExportKind::Function",
        ExportKind::Stub => "::build_tools::ExportKind::Stub",
        ExportKind::Variable => "::build_tools::ExportKind::Variable",
        ExportKind::Equate => "::build_tools::ExportKind::Equate",
    }
}

fn rust_convention(convention: Option<CallingConvention>) -> String {
    match convention {
        Some(CallingConvention::Pascal) => {
            "Some(::build_tools::CallingConvention::Pascal)".to_owned()
        }
        Some(CallingConvention::Cdecl) => {
            "Some(::build_tools::CallingConvention::Cdecl)".to_owned()
        }
        Some(CallingConvention::Stdcall) => {
            "Some(::build_tools::CallingConvention::Stdcall)".to_owned()
        }
        Some(CallingConvention::Varargs) => {
            "Some(::build_tools::CallingConvention::Varargs)".to_owned()
        }
        None => "None".to_owned(),
    }
}

fn rust_argument(argument: ArgumentType) -> &'static str {
    match argument {
        ArgumentType::Word => "::build_tools::ArgumentType::Word",
        ArgumentType::SignedWord => "::build_tools::ArgumentType::SignedWord",
        ArgumentType::Long => "::build_tools::ArgumentType::Long",
        ArgumentType::Pointer => "::build_tools::ArgumentType::Pointer",
        ArgumentType::String => "::build_tools::ArgumentType::String",
        ArgumentType::SegmentPointer => "::build_tools::ArgumentType::SegmentPointer",
        ArgumentType::SegmentString => "::build_tools::ArgumentType::SegmentString",
        ArgumentType::Int64 => "::build_tools::ArgumentType::Int64",
        ArgumentType::Float => "::build_tools::ArgumentType::Float",
        ArgumentType::WideString => "::build_tools::ArgumentType::WideString",
    }
}

fn rust_optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_owned(), |value| format!("Some({value:?})"))
}

#[cfg(test)]
mod tests;
