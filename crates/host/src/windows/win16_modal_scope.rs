//! Per-operation modal scopes and owner-thread cancellation evidence.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::{HWND, WPARAM};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::WindowsAndMessaging::{EndDialog, GetWindowThreadProcessId};

use super::{MODAL_CANCEL_SENTINEL, ModalWorkerControl, current_control, merge_failure};

use super::MODAL_WAKE_MESSAGE;

thread_local! {
    pub(super) static MODAL_FRAMES: RefCell<Vec<ModalFrame>> = const {
        RefCell::new(Vec::new())
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ModalToken(pub(super) usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum ModalDisposition {
    Returned,
    Cancelled { signal: ModalCancellationSignal, scope_id: u64 },
}

pub(in crate::windows) struct ModalScopeRetirement {
    pub(in crate::windows) disposition: ModalDisposition,
    pub(in crate::windows) retired_guest_work:
        Vec<runtime::Win16NativeModalGuestWorkRetirement>,
}

#[derive(Debug)]
pub(in crate::windows) struct ModalScopeFinishError {
    pub(in crate::windows) cause: RuntimeError,
    pub(in crate::windows) retired_guest_work:
        Vec<runtime::Win16NativeModalGuestWorkRetirement>,
}

impl std::fmt::Display for ModalScopeFinishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.cause)
    }
}

impl std::error::Error for ModalScopeFinishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum ModalCancellationSignal {
    /// The worker-thread hook executed PostQuitMessage while this scope was entered.
    OwnerThreadPostQuit,
    /// This scope's DLGPROC matched its token and EndDialog succeeded.
    DialogEndDialog,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ModalKind {
    DialogProcedure,
    MessageBoxOk,
    NativeSystemModal,
}

pub(super) struct ModalFrame {
    pub(super) token: ModalToken,
    pub(super) operation_id: u64,
    pub(super) parent: Option<ModalToken>,
    pub(super) kind: ModalKind,
    pub(super) hwnd: Option<HWND>,
    pub(super) entered: bool,
    pub(super) closing: bool,
    pub(super) cancel_posted: bool,
    pub(super) cancel_signal: Option<ModalCancellationSignal>,
    pub(super) failure: Option<RuntimeError>,
}

pub(in crate::windows) fn modal_stack_is_empty() -> bool {
    MODAL_FRAMES.with(|frames| frames.try_borrow().is_ok_and(|frames| frames.is_empty()))
}

pub(super) fn mark_system_modal_cancelled(
    control: &ModalWorkerControl,
) -> Result<(), RuntimeError> {
    if !control.owner_thread() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 system-modal cancellation was recorded outside its owner thread",
        ));
    }
    MODAL_FRAMES.with(|frames| {
        let mut frames = frames.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal scope stack is borrowed while recording owner-thread quit",
            )
        })?;
        for frame in &mut *frames {
            if frame.entered
                && matches!(
                    frame.kind,
                    ModalKind::MessageBoxOk | ModalKind::NativeSystemModal
                )
            {
                frame.cancel_signal = Some(ModalCancellationSignal::OwnerThreadPostQuit);
            }
        }
        Ok(())
    })
}

/// This !Send scope ties one operation and HWND generation to its owner thread.
pub(in crate::windows) struct ModalScope {
    token: ModalToken,
    operation_id: u64,
    control: Arc<ModalWorkerControl>,
    entered: bool,
    active: bool,
    _owner_thread: PhantomData<Rc<()>>,
}

impl ModalScope {
    pub(in crate::windows) fn begin_dialog(
        operation_id: u64,
    ) -> Result<Option<Self>, RuntimeError> {
        Self::begin_with_kind(operation_id, ModalKind::DialogProcedure)
    }

    pub(super) fn begin_with_kind(
        operation_id: u64,
        kind: ModalKind,
    ) -> Result<Option<Self>, RuntimeError> {
        if super::super::win16_windows::current_operation_id() != Some(operation_id) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal scope does not match the active USER worker operation",
            ));
        }
        let control = current_control().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal scope was created outside its USER worker thread",
            )
        })?;
        let _gate = control.publication.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal scope entry state",
            )
        })?;
        if !control.owner_thread() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal call is not running on the USER owner thread",
            ));
        }
        if control.terminal_requested() {
            return Ok(None);
        }
        let token = control.next_scope_token()?;
        MODAL_FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed",
                )
            })?;
            frames.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "track nested Win16 modal scope",
                    error,
                )
            })?;
            let parent = frames.last().map(|frame| frame.token);
            frames.push(ModalFrame {
                token,
                operation_id,
                parent,
                kind,
                hwnd: None,
                entered: false,
                closing: false,
                cancel_posted: false,
                cancel_signal: None,
                failure: None,
            });
            Ok::<(), RuntimeError>(())
        })?;
        drop(_gate);
        Ok(Some(Self {
            token,
            operation_id,
            control,
            entered: false,
            active: true,
            _owner_thread: PhantomData,
        }))
    }

    pub(in crate::windows) fn native_call_started(&mut self) -> Result<bool, RuntimeError> {
        let _gate = self.control.publication.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal native-call entry state",
            )
        })?;
        if !self.control.owner_thread()
            || super::super::win16_windows::current_operation_id() != Some(self.operation_id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal call left its owner thread or active USER operation before native entry",
            ));
        }
        if self.control.terminal_requested() {
            return Ok(false);
        }
        if self.entered {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal scope entered its native call more than once",
            ));
        }
        let marked = MODAL_FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed at native entry",
                )
            })?;
            let frame = frames
                .iter_mut()
                .find(|frame| frame.token == self.token)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 modal scope disappeared before native entry",
                    )
                })?;
            if frame.entered {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal frame was entered more than once",
                ));
            }
            frame.entered = true;
            Ok(())
        });
        marked?;
        let (wake_generation, pending_wake) = super::super::win16_windows::worker_context()
            .map(|state| state.borrow().multimedia_wake_state())
            .unwrap_or((0, false));
        if let Err((work, error)) = self.control.activate_modal_scope(
            self.operation_id,
            self.token.0 as u64,
            pending_wake,
            wake_generation,
        ) {
            MODAL_FRAMES.with(|frames| {
                if let Ok(mut frames) = frames.try_borrow_mut()
                    && let Some(frame) = frames.iter_mut().find(|frame| frame.token == self.token)
                {
                    frame.entered = false;
                }
            });
            drop(_gate);
            return Err(self.control.abort_after_ingress_failure(work, error));
        }
        self.entered = true;
        Ok(true)
    }

    pub(in crate::windows) fn bind_dialog(&mut self, dialog: HWND) -> Result<(), RuntimeError> {
        if !self.entered || dialog.is_null() || !self.control.owner_thread() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DLGPROC attempted to bind a null, unentered, or foreign-thread HWND",
            ));
        }
        if super::super::win16_windows::current_operation_id() != Some(self.operation_id) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DLGPROC HWND does not match the active worker operation",
            ));
        }
        let mut owner_process = 0u32;
        let owner_thread = unsafe { GetWindowThreadProcessId(dialog, &mut owner_process) };
        if owner_thread == 0 {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "query the Win16 DLGPROC HWND owner",
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
        if owner_thread != self.control.thread_id.load(Ordering::Acquire)
            || owner_process != unsafe { GetCurrentProcessId() }
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DLGPROC HWND belongs to a different USER worker",
            ));
        }
        MODAL_FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed",
                )
            })?;
            let frame = frames
                .iter_mut()
                .find(|frame| frame.token == self.token)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DLGPROC modal scope is no longer registered",
                    )
                })?;
            if frame.kind != ModalKind::DialogProcedure || frame.hwnd.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 DLGPROC modal scope was bound to an unexpected HWND",
                ));
            }
            frame.hwnd = Some(dialog);
            Ok(())
        })
    }

    /// Called only by this scope's DLGPROC; EndDialog is legal at this boundary.
    pub(in crate::windows) fn handle_cancel(
        &self,
        dialog: HWND,
        message: u32,
        w_param: WPARAM,
    ) -> Result<bool, RuntimeError> {
        if message != MODAL_WAKE_MESSAGE
            || w_param != self.token.0
            || !self.control.terminal_requested()
            || !self.control.owner_thread()
        {
            return Ok(false);
        }
        let matched = MODAL_FRAMES.with(|frames| -> Result<bool, RuntimeError> {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed",
                )
            })?;
            let Some(frame) = frames.iter_mut().find(|frame| frame.token == self.token) else {
                return Ok(false);
            };
            if frame.kind != ModalKind::DialogProcedure || frame.hwnd != Some(dialog) {
                return Ok(false);
            }
            Ok(true)
        })?;
        if !matched {
            return Ok(false);
        }
        // No TLS borrow is held while calling reentrant USER code.
        if unsafe { EndDialog(dialog, MODAL_CANCEL_SENTINEL) } == 0 {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            let failure = RuntimeError::with_source(
                Kind::HostFailure,
                "end the Win16 modal dialog from its DLGPROC during worker cancellation",
                std::io::Error::from_raw_os_error(error as i32),
            );
            self.record_scope_failure(failure)?;
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 modal dialog cancellation failed in its DLGPROC",
            ));
        }
        self.mark_cancel_signal(ModalCancellationSignal::DialogEndDialog)?;
        Ok(true)
    }

    pub(in crate::windows) fn disposition(&self) -> ModalDisposition {
        self.scope_disposition()
            .unwrap_or(ModalDisposition::Returned)
    }

    fn scope_disposition(&self) -> Option<ModalDisposition> {
        MODAL_FRAMES.with(|frames| {
            let frames = frames.try_borrow().ok()?;
            let frame = frames.iter().find(|frame| frame.token == self.token)?;
            frame
                .cancel_signal
                .map(|signal| ModalDisposition::Cancelled {
                    signal,
                    scope_id: self.token.0 as u64,
                })
        })
    }

    pub(in crate::windows) fn finish(
        mut self,
    ) -> Result<ModalScopeRetirement, ModalScopeFinishError> {
        let mut failure = None;
        if !self.entered {
            failure = Some(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal scope was finished without entering its native call",
            ));
        }
        let popped = MODAL_FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed during native return",
                )
            })?;
            let Some(frame) = frames.last() else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is empty during native return",
                ));
            };
            let actual_parent = frames.iter().rev().nth(1).map(|parent| parent.token);
            if frame.token != self.token || frame.parent != actual_parent {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal call returned outside its exact nesting frame",
                ));
            }
            let frame = frames.pop().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal frame disappeared during native return",
                )
            })?;
            let _destroy_was_observed = frame.closing;
            Ok((frame.cancel_signal, frame.failure))
        });
        self.active = false;
        let mut retired_guest_work = Vec::new();
        match popped {
            Ok((cancel_signal, frame_failure)) => {
                let disposition = cancel_signal.map_or(ModalDisposition::Returned, |signal| {
                    ModalDisposition::Cancelled {
                        signal,
                        scope_id: self.token.0 as u64,
                    }
                });
                match self.control.retire_modal_scope(
                    self.operation_id,
                    self.token.0 as u64,
                ) {
                    Ok(retired) => retired_guest_work = retired,
                    Err(error) => merge_failure(&mut failure, error,
                        "Win16 modal return and guest-work scope retirement both failed"),
                }
                if let Some(error) = frame_failure {
                    merge_failure(&mut failure, error, "Win16 modal DLGPROC failures combined");
                }
                if let Some(error) = self.control.take_callback_failure() {
                    merge_failure(&mut failure, error, "Win16 modal hook callback failed");
                }
                if let Err(error) = super::super::win16_windows::requeue_deferred_guest_notifications() {
                    merge_failure(&mut failure, error,
                        "Win16 modal return and deferred notification requeue both failed");
                }
                return match failure {
                    Some(cause) => Err(ModalScopeFinishError { cause, retired_guest_work }),
                    None => Ok(ModalScopeRetirement { disposition, retired_guest_work }),
                };
            }
            Err(error) => merge_failure(&mut failure, error, "Win16 modal scope cleanup failed"),
        }
        let cause = failure.unwrap_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 modal scope returned without retiring its native frame",
        ));
        Err(ModalScopeFinishError { cause, retired_guest_work })
    }

    fn mark_cancel_signal(&self, signal: ModalCancellationSignal) -> Result<(), RuntimeError> {
        MODAL_FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed while recording cancellation",
                )
            })?;
            let frame = frames
                .iter_mut()
                .find(|frame| frame.token == self.token)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 modal frame disappeared while recording cancellation",
                    )
                })?;
            frame.cancel_signal = Some(signal);
            Ok(())
        })
    }

    fn record_scope_failure(&self, error: RuntimeError) -> Result<(), RuntimeError> {
        MODAL_FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is already borrowed while recording failure",
                )
            })?;
            let frame = frames
                .iter_mut()
                .find(|frame| frame.token == self.token)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 modal scope disappeared while recording failure",
                    )
                })?;
            merge_failure(
                &mut frame.failure,
                error,
                "Win16 modal dialog failures combined",
            );
            Ok(())
        })
    }
}

impl Drop for ModalScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let dropped = MODAL_FRAMES.with(|frames| {
            let Ok(mut frames) = frames.try_borrow_mut() else {
                return false;
            };
            let Some(frame) = frames.last() else {
                return false;
            };
            let actual_parent = frames.iter().rev().nth(1).map(|parent| parent.token);
            if frame.token != self.token || frame.parent != actual_parent {
                return false;
            }
            frames.pop();
            true
        });
        if self.entered || !dropped {
            self.control.record_callback_failure(RuntimeError::new(
                Kind::InternalInvariant,
                if self.entered {
                    "Win16 modal scope left without recording the native return"
                } else {
                    "prepared Win16 modal scope could not retire in stack order"
                },
            ));
        } else if super::modal_stack_is_empty()
            && let Err(error) = super::super::win16_windows::requeue_deferred_guest_notifications()
        {
            self.control.record_callback_failure(error);
        }
    }
}
