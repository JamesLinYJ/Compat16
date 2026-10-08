use std::fmt;

/// A project `.spec` parse or emission error with its source location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecError {
    pub spec_path: String,
    pub line: usize,
    pub message: String,
}

impl SpecError {
    pub(crate) fn new(spec_path: &str, line: usize, message: impl Into<String>) -> Self {
        Self {
            spec_path: spec_path.to_owned(),
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for SpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(formatter, "{}: {}", self.spec_path, self.message)
        } else {
            write!(
                formatter,
                "{}:{}: {}",
                self.spec_path, self.line, self.message
            )
        }
    }
}

impl std::error::Error for SpecError {}
