#![forbid(unsafe_code)]

//! The registry launch protocol carries a mapped image and an unparsed tail.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use runtime::{DiagnosticKind as Kind, RuntimeError};

pub(crate) struct SystemLaunch {
    pub(crate) program: PathBuf,
    pub(crate) command: Vec<u16>,
}

pub(crate) fn parse(raw: &[u16]) -> Result<Option<SystemLaunch>, RuntimeError> {
    // The observed quoted, extensionless native invocation moves argv0's
    // closing quote past the injected control head. Recognize that complete
    // shape: an open initial quote, two separator spaces before our module
    // marker, and the displaced quote immediately after the command marker.
    // Only that boundary quote is removed; guest quotes are never rewritten.
    // Inspect this shape first, so a guest tail beginning with our marker
    // cannot be mistaken for the header after a malformed argv0 scan.
    if raw.first() == Some(&u16::from(b'"')) {
        if let Some(end) = raw[1..].iter().position(|&unit| unit == u16::from(b'"')) {
            let end = end + 1;
            let prefix = &raw[..end];
            let marker = "  --system-module ";
            if prefix.len() >= marker.len()
                && strip_ascii(&prefix[prefix.len() - marker.len()..], marker).is_some()
            {
                let start = end - "--system-module ".len();
                if start <= 3 {
                    return Err(invalid("system launch has no original module token"));
                }
                return parse_head(&raw[start..], true).map(Some);
            }
        }
    }
    // NtVdm64 selects MappedExeName independently of the command line. Its
    // first token remains the caller's original module, not our executable.
    let head = skip_space(&raw[first_token_end(raw)..]);
    if strip_ascii(head, "--system-module").is_some_and(|rest| {
        rest.first().is_none_or(|&unit| is_space(unit))
    }) {
        return parse_head(head, false).map(Some);
    }
    Ok(None)
}

fn parse_head(head: &[u16], displaced_quote: bool) -> Result<SystemLaunch, RuntimeError> {
    let module = strip_ascii(head, "--system-module \"")
        .ok_or_else(|| invalid("system launch requires a quoted mapped module"))?;
    let end = module.iter().position(|&unit| unit == u16::from(b'"'))
        .ok_or_else(|| invalid("system launch has an unterminated mapped module"))?;
    if end == 0 {
        return Err(invalid("system launch has an empty mapped module"));
    }
    let mut command = strip_ascii(&module[end + 1..], " --system-command ")
        .ok_or_else(|| invalid("system launch has an incomplete command boundary"))?;
    if displaced_quote {
        command = command.strip_prefix(&[u16::from(b'"')])
            .ok_or_else(|| invalid("system launch has an unsupported displaced quote boundary"))?;
    }
    // %c excludes the original executable. Consume only the template's one
    // separator space, then preserve every tail unit, including empty argument
    // quotes and leading/trailing whitespace. Do not append the mapped image.
    Ok(SystemLaunch {
        program: PathBuf::from(OsString::from_wide(&module[..end])),
        command: command.to_vec(),
    })
}

fn first_token_end(raw: &[u16]) -> usize {
    let mut quoted = false;
    for (index, &unit) in raw.iter().enumerate() {
        if unit == u16::from(b'"') {
            quoted = !quoted;
        } else if !quoted && is_space(unit) {
            return index;
        }
    }
    raw.len()
}

fn skip_space(raw: &[u16]) -> &[u16] {
    let end = raw.iter().position(|&unit| !is_space(unit)).unwrap_or(raw.len());
    &raw[end..]
}

fn is_space(unit: u16) -> bool {
    unit == u16::from(b' ') || unit == u16::from(b'\t')
}

fn strip_ascii<'a>(raw: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    (raw.len() >= prefix.len()
        && raw.iter().zip(prefix.bytes()).all(|(&unit, byte)| unit == u16::from(byte)))
        .then(|| &raw[prefix.len()..])
}

fn invalid(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InvalidInput, message)
}
