//! User-supplied command text is distinct from the shell's parsed argv.

use std::ffi::OsString;

use runtime::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn command_text(
    explicit: Option<String>,
    arguments: impl Iterator<Item = OsString>,
) -> Result<String, RuntimeError> {
    let arguments = arguments.collect::<Vec<_>>();
    let text = match explicit {
        Some(_) if !arguments.is_empty() => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "--command-tail cannot be combined with positional program arguments",
            ));
        }
        Some(text) => text,
        None => arguments
            .into_iter()
            .map(|argument| {
                argument.into_string().map_err(|_| {
                    RuntimeError::new(Kind::InvalidInput, "DOS arguments contain invalid Unicode")
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(" "),
    };
    if text.contains('\0') {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "program arguments contain a null character",
        ));
    }
    Ok(if text.is_empty() {
        text
    } else {
        format!(" {text}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_tail_keeps_quotes_and_internal_whitespace() {
        let text = r#"/A  "file with spaces.txt" """#;
        assert_eq!(
            command_text(Some(text.into()), std::iter::empty()).unwrap(),
            format!(" {text}")
        );
        assert_eq!(
            command_text(Some(String::new()), std::iter::empty()).unwrap(),
            ""
        );
        assert_eq!(
            command_text(Some("  /Q ".into()), std::iter::empty()).unwrap(),
            "   /Q "
        );
    }

    #[test]
    fn explicit_tail_rejects_ambiguous_extra_arguments() {
        assert!(command_text(Some("/Q".into()), [OsString::from("extra")].into_iter()).is_err());
        assert!(command_text(Some("a\0b".into()), std::iter::empty()).is_err());
    }

    #[test]
    fn ordinary_argv_retains_the_existing_cli_convention() {
        assert_eq!(
            command_text(None, ["/Q", "FILE.TXT"].into_iter().map(OsString::from)).unwrap(),
            " /Q FILE.TXT"
        );
        assert_eq!(command_text(None, std::iter::empty()).unwrap(), "");
    }
}
