//! Structured diagnostics at the machine/host/launcher boundary.
//!
//! DOS CF/AX, XMS AX/BL and other guest protocol results stay in their
//! respective services. They are not runtime failures or log severities.

mod convert;
#[cfg(test)]
mod tests;

use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticSeverity { Info, Warn, Error, Critical }

impl DiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self { Self::Info => "info", Self::Warn => "warn", Self::Error => "error", Self::Critical => "critical" }
    }
}

/// Cause category, independent of guest ABI error numbers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticKind {
    CompatibilityGap,
    GuestFault,
    InvalidInput,
    HostFailure,
    ResourceExhausted,
    ExecutionLimit,
    InternalInvariant,
}

impl DiagnosticKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompatibilityGap => "compatibility_gap",
            Self::GuestFault => "guest_fault",
            Self::InvalidInput => "invalid_input",
            Self::HostFailure => "host_failure",
            Self::ResourceExhausted => "resource_exhausted",
            Self::ExecutionLimit => "execution_limit",
            Self::InternalInvariant => "internal_invariant",
        }
    }

    /// Classify a primary failure together with an actual cleanup failure.
    /// Invariant violations remain critical; cleanup failures replace an
    /// execution limit as the operation's stopping cause.
    pub const fn with_cleanup(self, cleanup: Self) -> Self {
        match (self, cleanup) {
            (Self::InternalInvariant, _) | (_, Self::InternalInvariant) => {
                Self::InternalInvariant
            }
            (Self::ExecutionLimit, additional) => additional,
            (primary, _) => primary,
        }
    }

    const fn failure_severity(self) -> DiagnosticSeverity {
        match self {
            Self::ExecutionLimit => DiagnosticSeverity::Warn,
            Self::InternalInvariant => DiagnosticSeverity::Critical,
            _ => DiagnosticSeverity::Error,
        }
    }
}

/// A structured report. An info/warn report alone does not stop execution.
#[derive(Debug)]
pub struct Diagnostic {
    kind: DiagnosticKind,
    severity: DiagnosticSeverity,
    message: String,
    contexts: Vec<String>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl Diagnostic {
    fn new(kind: DiagnosticKind, severity: DiagnosticSeverity, message: impl Into<String>) -> Self {
        Self { kind, severity, message: message.into(), contexts: Vec::new(), source: None }
    }

    pub fn info(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self::new(kind, DiagnosticSeverity::Info, message)
    }

    /// Call only after the caller has an explicit recoverable outcome.
    pub fn warning(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self::new(kind, DiagnosticSeverity::Warn, message)
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.contexts.push(context.into());
        self
    }

    pub fn with_cause(mut self, cause: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(cause));
        self
    }

    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as &(dyn Error + 'static))
    }

    pub const fn kind(&self) -> DiagnosticKind { self.kind }
    pub const fn severity(&self) -> DiagnosticSeverity { self.severity }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}/{}] ", self.severity().as_str(), self.kind.as_str())?;
        for context in self.contexts.iter().rev() { write!(f, "{context}: ")?; }
        f.write_str(&self.message)?;
        if let Some(source) = &self.source {
            if !self.message.is_empty() { f.write_str(": ")?; }
            write!(f, "{source}")?;
        }
        Ok(())
    }
}

/// A stopped operation. Reporting severity and execution outcome are separate:
/// an explicit instruction limit is a warning but still stops this run.
#[derive(Debug)]
pub struct RuntimeError(Diagnostic);

impl RuntimeError {
    pub fn new(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self(Diagnostic::new(kind, kind.failure_severity(), message))
    }

    pub fn with_source(
        kind: DiagnosticKind,
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self(Diagnostic::new(kind, kind.failure_severity(), message).with_cause(source))
    }

    pub(crate) fn from_source(kind: DiagnosticKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self::with_source(kind, "", source)
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.0 = self.0.with_context(context);
        self
    }

    /// Preserve both stopped operations without inventing damaged state from
    /// the number of failures. Actual invariant violations remain critical.
    pub fn with_cleanup(self, context: &'static str, cleanup: Self) -> Self {
        let kind = self.kind().with_cleanup(cleanup.kind());
        Self::with_source(kind, context, RuntimeCleanupFailure { primary: self, cleanup })
    }

    pub const fn diagnostic(&self) -> &Diagnostic { &self.0 }
    pub const fn kind(&self) -> DiagnosticKind { self.0.kind() }
    pub const fn severity(&self) -> DiagnosticSeverity { self.0.severity() }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.cause()
    }
}

// Error::source has one edge. A typed pair retains both runtime errors and
// their classifications; generic string context would erase the second cause.
#[derive(Debug)]
struct RuntimeCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl fmt::Display for RuntimeCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl Error for RuntimeCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
