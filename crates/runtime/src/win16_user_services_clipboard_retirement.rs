//! Failure-safe owner transfer and retry for clipboard GlobalHeap blocks.

use std::sync::Arc;

use win16_abi::GlobalHandle;

use super::{GuestClipboardEntry, Win16State};
use crate::win16_runtime::global_memory::GlobalTeardownResult;
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn clipboard_retained_error(
    operation: &'static str,
    selector_aliases: u16,
    page_locks: u16,
    internal_pins: u16,
) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!(
        "Win16 clipboard {operation} is deferred by {selector_aliases} selector aliases, {page_locks} page locks and {internal_pins} internal pins",
    ))
}

#[derive(Debug)]
pub(super) struct RetiredClipboardOwner {
    pub(super) entry: GuestClipboardEntry,
    pub(super) cause: ClipboardRetirementCause,
}

#[derive(Debug)]
pub(super) enum ClipboardRetirementCause {
    Pending,
    Retained {
        selector_aliases: u16,
        page_locks: u16,
        internal_pins: u16,
        original: Option<Arc<RuntimeError>>,
    },
    Error(Arc<RuntimeError>),
}

impl ClipboardRetirementCause {
    pub(super) fn retained(result: GlobalTeardownResult) -> Self {
        match result {
            GlobalTeardownResult::Retained {
                selector_aliases, page_locks, internal_pins,
            } => Self::Retained {
                selector_aliases, page_locks, internal_pins, original: None,
            },
            GlobalTeardownResult::Freed => Self::Pending,
        }
    }

    pub(super) fn from_error(error: RuntimeError) -> (Self, RuntimeError) {
        let error = Arc::new(error);
        let report = RuntimeError::with_source(
            error.kind(), "Win16 clipboard owner teardown retained its typed failure",
            Arc::clone(&error),
        );
        (Self::Error(error), report)
    }

    fn remember_retained(&mut self, result: GlobalTeardownResult) -> Option<RuntimeError> {
        let GlobalTeardownResult::Retained {
            selector_aliases, page_locks, internal_pins,
        } = result else { return None; };
        let original = match self {
            Self::Error(error) => Some(Arc::clone(error)),
            Self::Retained { original, .. } => original.clone(),
            Self::Pending => None,
        };
        let retry = clipboard_retained_error(
            "owner cleanup", selector_aliases, page_locks, internal_pins,
        );
        *self = Self::Retained {
            selector_aliases, page_locks, internal_pins,
            original: original.clone(),
        };
        original.map(|cause| RuntimeError::with_source(
            cause.kind(), "Win16 clipboard owner retains its first typed cleanup cause", cause,
        ).with_cleanup("retrying retained clipboard owner", retry))
    }

    fn remember_error(&mut self, error: RuntimeError) -> RuntimeError {
        let original = match self {
            Self::Error(cause) => Some(Arc::clone(cause)),
            Self::Retained { original, .. } => original.clone(),
            Self::Pending => None,
        };
        if let Some(cause) = original {
            *self = Self::Error(Arc::clone(&cause));
            RuntimeError::with_source(
                cause.kind(), "Win16 clipboard owner retains its first typed cleanup cause", cause,
            ).with_cleanup("retrying clipboard owner cleanup", error)
        } else {
            let cause = Arc::new(error);
            let report = RuntimeError::with_source(
                cause.kind(), "Win16 clipboard owner retained its first typed cleanup cause",
                Arc::clone(&cause),
            );
            *self = Self::Error(cause);
            report
        }
    }

    fn retry_cause(&self) -> Option<RuntimeError> {
        match self {
            Self::Pending => None,
            Self::Error(error) => Some(RuntimeError::with_source(
                error.kind(), "Win16 clipboard owner has a retained earlier cleanup failure",
                Arc::clone(error),
            )),
            Self::Retained { selector_aliases, page_locks, internal_pins, original } => {
                let latest = clipboard_retained_error(
                    "previous owner cleanup", *selector_aliases, *page_locks, *internal_pins,
                );
                Some(match original {
                    Some(cause) => RuntimeError::with_source(cause.kind(),
                        "Win16 clipboard owner retains its first typed cleanup cause",
                        Arc::clone(cause)).with_cleanup("previous owner cleanup remains deferred", latest),
                    None => latest,
                })
            }
        }
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn retire_all_clipboard_data(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.retire_all_clipboard_data_with_reservation(None)
    }

    pub(super) fn retire_all_clipboard_data_with_reservation(
        &mut self,
        mut reservation: Option<&mut usize>,
    ) -> Result<(), RuntimeError> {
        let displaced = self.clipboard_state.entries.len();
        if let Some(reserved) = reservation.as_mut() {
            if **reserved < displaced || self.clipboard_state.reserved_retired < displaced {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "EmptyClipboard retirement exceeded its pre-host owner reservation"));
            }
            for _ in 0..displaced {
                if !self.clipboard_state.consume_retired_reservation(*reserved) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "clipboard owner reservation accounting changed during transfer"));
                }
            }
        } else {
            self.clipboard_state.ensure_retired_capacity(displaced)?;
        }
        for (_, entry) in std::mem::take(&mut self.clipboard_state.entries) {
            self.clipboard_state.retired.push(RetiredClipboardOwner {
                entry, cause: ClipboardRetirementCause::Pending,
            });
        }

        let mut failure = None;
        let mut index = 0;
        while index < self.clipboard_state.retired.len() {
            let (handle, identity, ownership) = {
                let owner = &self.clipboard_state.retired[index];
                (owner.entry.handle, owner.entry.identity, owner.entry.ownership)
            };
            match (handle, identity) {
                (None, None) => { self.clipboard_state.retired.remove(index); }
                (Some(handle), Some(identity)) => {
                    match self.free_global_on_teardown(handle, identity) {
                        Ok(GlobalTeardownResult::Freed) => {
                            self.clipboard_state.retired.remove(index);
                        }
                        Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                            let owner = &mut self.clipboard_state.retired[index];
                            if let Some(error) = owner.cause.remember_retained(retained) {
                                remember_clipboard_failure(&mut failure, error);
                            } else if reservation.is_none() {
                                if let Some(error) = owner.cause.retry_cause() {
                                    remember_clipboard_failure(&mut failure, error);
                                }
                            }
                            index += 1;
                        }
                        Err(error) => {
                            let owner = &mut self.clipboard_state.retired[index];
                            let report = owner.cause.remember_error(
                                error.with_context(ownership.cleanup_context()));
                            remember_clipboard_failure(&mut failure, report);
                            index += 1;
                        }
                    }
                }
                _ => {
                    remember_clipboard_failure(&mut failure, RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired Win16 clipboard owner lost its exact creation identity",
                    ));
                    index += 1;
                }
            }
        }
        match failure { Some(error) => Err(error), None => Ok(()) }
    }

    pub(super) fn retire_clipboard_format(
        &mut self,
        format: u16,
        except: Option<(u16, GlobalHandle)>,
        reservation: Option<&mut usize>,
    ) -> Result<GlobalTeardownResult, RuntimeError> {
        let Some(entry) = self.clipboard_state.get(format).cloned() else {
            return Ok(GlobalTeardownResult::Freed);
        };
        if except.is_some_and(|(handle, identity)|
            entry.handle == Some(handle) && entry.identity == Some(identity))
        {
            self.clipboard_state.remove(format);
            return Ok(GlobalTeardownResult::Freed);
        }
        match (entry.handle, entry.identity) {
            (None, None) => {
                self.clipboard_state.remove(format);
                Ok(GlobalTeardownResult::Freed)
            }
            (Some(handle), Some(identity)) => {
                match self.free_global_on_teardown(handle, identity) {
                    Ok(GlobalTeardownResult::Freed) => {
                        self.clipboard_state.remove(format);
                        Ok(GlobalTeardownResult::Freed)
                    }
                    Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                        self.transfer_clipboard_owner(format, entry, reservation, retained)?;
                        Ok(retained)
                    }
                    Err(error) => {
                        let cleanup_context = entry.ownership.cleanup_context();
                        self.transfer_clipboard_owner(format, entry, reservation,
                            GlobalTeardownResult::Freed)?;
                        let owner = self.clipboard_state.retired.last_mut().ok_or_else(||
                            RuntimeError::new(Kind::InternalInvariant,
                                "failed clipboard owner transfer lost its retry record"))?;
                        return Err(owner.cause.remember_error(
                            error.with_context(cleanup_context)));
                    }
                }
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 clipboard owner has a raw handle without its creation identity")),
        }
    }

    fn transfer_clipboard_owner(
        &mut self,
        format: u16,
        expected: GuestClipboardEntry,
        reservation: Option<&mut usize>,
        cause: GlobalTeardownResult,
    ) -> Result<(), RuntimeError> {
        if !self.clipboard_state.get(format).is_some_and(|current|
            current.handle == expected.handle && current.identity == expected.identity)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "clipboard owner generation changed before exact retirement transfer"));
        }
        let reserved = reservation.is_some_and(|token|
            self.clipboard_state.consume_retired_reservation(token));
        if !reserved { self.clipboard_state.ensure_retired_capacity(1)?; }
        let entry = self.clipboard_state.remove(format).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "clipboard owner disappeared during retirement transfer"))?;
        self.clipboard_state.retired.push(RetiredClipboardOwner {
            entry,
            cause: match cause {
                GlobalTeardownResult::Freed => ClipboardRetirementCause::Pending,
                retained => ClipboardRetirementCause::retained(retained),
            },
        });
        Ok(())
    }

    pub(super) fn retire_displaced_clipboard_entry(
        &mut self,
        entry: GuestClipboardEntry,
        reservation: &mut usize,
    ) -> Result<GlobalTeardownResult, RuntimeError> {
        let cleanup_context = entry.ownership.cleanup_context();
        let (handle, identity) = match (entry.handle, entry.identity) {
            (None, None) => return Ok(GlobalTeardownResult::Freed),
            (Some(handle), Some(identity)) => (handle, identity),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "displaced Win16 clipboard owner lost its exact creation identity")),
        };
        match self.free_global_on_teardown(handle, identity) {
            Ok(GlobalTeardownResult::Freed) => Ok(GlobalTeardownResult::Freed),
            Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                if !self.clipboard_state.consume_retired_reservation(reservation) {
                    self.clipboard_state.ensure_retired_capacity(1)?;
                }
                self.clipboard_state.retired.push(RetiredClipboardOwner {
                    entry, cause: ClipboardRetirementCause::retained(retained),
                });
                Ok(retained)
            }
            Err(error) => {
                if !self.clipboard_state.consume_retired_reservation(reservation) {
                    self.clipboard_state.ensure_retired_capacity(1)?;
                }
                let (cause, report) = ClipboardRetirementCause::from_error(
                    error.with_context(cleanup_context));
                self.clipboard_state.retired.push(RetiredClipboardOwner { entry, cause });
                Err(report)
            }
        }
    }
}

fn remember_clipboard_failure(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        Some(primary) => primary.with_cleanup("completing clipboard owner retirement", error),
        None => error,
    });
}
