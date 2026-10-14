//! USER worker timer bookkeeping and guest WM_TIMER queue provenance.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::os::windows::io::OwnedHandle;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::DataExchange::{ChangeClipboardChain, CloseClipboard};
use windows_sys::Win32::UI::WindowsAndMessaging::{IsWindow, KillTimer, PeekMessageW};

use super::super::super::win16_gdi::Win16Dcs;
use super::super::super::win16_images::Win16Images;
use super::super::super::win16_modal::{ModalWorkerControl, ModalWorkerHooks};
use super::com_sta::{Win16ComStaState, Win16ComWorkerClient};
use super::terminal_responses::{send_terminal_results, terminal_evidence};
use super::{
    ActiveOperation, PendingCreation, WORKER_CONTEXT, WorkerCommand, WorkerState, process_command,
    receive_command, shutdown_all,
};

pub(super) fn worker_main(
    receiver: Receiver<WorkerCommand>,
    wake_event: Arc<OwnedHandle>,
    multimedia_generation: Arc<AtomicU64>,
    worker_alive: Arc<AtomicBool>,
    dcs: Win16Dcs,
    images: Win16Images,
    oem_text_codec: crate::windows::guest_text::GuestTextCodec,
    shutdown_storage: Arc<
        Mutex<Vec<super::super::win16_common_dialog_worker::ShutdownStorageGuard>>,
    >,
    worker_retirement_id: u64,
    toolbar_bitmap_retention: Arc<
        Mutex<super::super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention>,
    >,
    identity_source: Arc<AtomicU64>,
    modal_control: Arc<ModalWorkerControl>,
    native_drop_retirements: super::NativeDropRetirementQueueHandle,
    ready: SyncSender<Result<Win16ComWorkerClient, RuntimeError>>,
) {
    struct MarkWorkerExited(Arc<AtomicBool>);
    impl Drop for MarkWorkerExited {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    // The sender keeps the event alive, while this guard rejects late
    // signals after the actual worker thread exits.
    let worker_liveness = Arc::clone(&worker_alive);
    let _worker_exit = MarkWorkerExited(worker_alive);
    let _cursor_clip_exit = super::super::win16_cursor_clip::WorkerExitGuard;

    // Each thread needs its own USER queue. This call intentionally does not
    // dispatch queued messages; callbacks are delivered only by explicit
    // synchronous operations with a runtime continuation available.
    let mut message = unsafe { std::mem::zeroed() };
    unsafe {
        PeekMessageW(
            &mut message,
            std::ptr::null_mut(),
            0,
            0,
            windows_sys::Win32::UI::WindowsAndMessaging::PM_NOREMOVE,
        );
    }
    if let Err(error) = super::super::win16_guest_notifications::initialize_queue() {
        let _ = ready.send(Err(error));
        return;
    }
    let mut terminal_failures = Vec::new();
    if let Err(error) = terminal_failures.try_reserve_exact(4) {
        let _ = ready.send(Err(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 terminal failure tracking",
            error,
        )));
        return;
    }
    let (com, com_client) = match Win16ComStaState::initialize(Arc::clone(&wake_event)) {
        Ok(com) => com,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let state = Rc::new(RefCell::new(WorkerState {
        text_codec: dcs.text_codec(),
        oem_text_codec,
        window_text_contexts:
            super::super::win16_window_text_context::WindowTextContextStack::default(),
        shutdown_storage,
        worker_retirement_id,
        toolbar_bitmap_retention,
        window_properties: super::super::win16_window_properties::WindowPropertyStore::default(),
        native_procedures: super::super::win16_native_procedures::NativeProcedures::default(),
        window_identity_cookies: HashMap::new(),
        commands: Arc::new(Mutex::new(receiver)),
        com: Rc::clone(&com),
        deferred_native_messages:
            super::super::win16_deferred_native_messages::DeferredNativeMessageQueue::default(),
        identity_source,
        classic_dde_endpoints: BTreeMap::new(),
        classic_dde_endpoints_by_native: HashMap::new(),
        classic_dde_quiescing_owners: HashMap::new(),
        active_classic_dde_operations: Vec::new(),
        pending_classic_dde_ingress: std::collections::VecDeque::new(),
        classic_dde_native_peers: HashMap::new(),
        active_user_waits: Vec::new(),
        wake_event,
        multimedia_generation_seen: multimedia_generation.load(Ordering::Acquire),
        multimedia_generation,
        modal_control: Arc::clone(&modal_control),
        dcs,
        images,
        shell_processes: Vec::new(),
        accelerator_tables:
            super::super::win16_user_cursor_accelerator::Win16AcceleratorTables::new(),
        live_find_replace: BTreeMap::new(),
        classes: BTreeMap::new(),
        windows: HashMap::new(),
        windows_by_native: HashMap::new(),
        drop_accepting_windows: HashSet::new(),
        retired_window_tokens: HashSet::new(),
        menus: BTreeMap::new(),
        menus_by_native: HashMap::new(),
        system_menus: BTreeMap::new(),
        window_menus: BTreeMap::new(),
        pending_window_menu_retirements: Vec::new(),
        active_menu_call_owners: Vec::new(),
        deferred_menu_retirements: Vec::new(),
        retiring_menu_native_handles: Vec::new(),
        menu_children: BTreeMap::new(),
        owned_menus: BTreeSet::new(),
        owned_menu_roots: BTreeSet::new(),
        retained_unmapped_menu_owners: Vec::new(),
        pending_creations: Vec::<PendingCreation>::new(),
        pending_mdi_creations: Vec::new(),
        active_operations: Vec::<ActiveOperation>::new(),
        live_callbacks: Vec::new(),
        pending_dialog_routes: Vec::new(),
        dialog_icon_sidecars: super::super::win16_dialog_icon_controls::IconSidecars::new(),
        dialog_routes_by_native: HashMap::new(),
        dialog_creation_data: HashMap::new(),
        dialog_children_by_native: HashMap::new(),
        window_creation_instances: HashMap::new(),
        clipboard_open: false,
        clipboard_viewers: BTreeMap::new(),
        native_timers: BTreeSet::new(),
        timer_records: BTreeMap::new(),
        timer_by_native: BTreeMap::new(),
        next_host_timer_id: 1,
        next_native_callback_timer_id: usize::MAX / 2,
        guest_timer_posts: BTreeMap::new(),
        native_drop_files: super::state::NativeDropFilesQueue::default(),
        native_drop_retirements,
        drag_lists: Vec::new(),
        drag_list_origins: Vec::new(),
        drag_list_message: None,
        toolbar_bitmap_sidecars: Vec::new(),
        pending_toolbar_dc_releases: Vec::new(),
        pending_toolbar_dc_release_reservations: 0,
        next_guest_timer_post_token: usize::MAX,
        callbacks_enabled: true,
        aborted: false,
        shutdown_requested: false,
        abort_waiters: Vec::new(),
        shutdown_waiters: Vec::new(),
        terminal_wake_requests: BTreeSet::new(),
        terminal_failures,
        cancelled_modals: Vec::new(),
        terminal_proof: None,
        terminal_proof_error: None,
    }));
    WORKER_CONTEXT.with(|slot| *slot.borrow_mut() = Some(Rc::clone(&state)));

    let mut modal_hooks = match ModalWorkerHooks::install(modal_control) {
        Ok(hooks) => Some(hooks),
        Err(error) => {
            WORKER_CONTEXT.with(|slot| *slot.borrow_mut() = None);
            let result = match com.shutdown_resources() {
                Ok(()) => error,
                Err(cleanup) => super::combine_worker_failures(
                    error,
                    cleanup,
                    "install USER worker hooks and retire its COM STA both failed",
                ),
            };
            let _ = ready.send(Err(result));
            return;
        }
    };
    if ready.send(Ok(com_client)).is_err() {
        if let Err(error) = com
            .close_callback_ingress("Win16 USER worker creator stopped during startup")
            .and_then(|()| com.shutdown_resources())
        {
            eprintln!("runtime: cannot retire COM after USER startup disconnect: {error}");
            retain_com_sta_without_terminal_ack();
        }
        WORKER_CONTEXT.with(|slot| *slot.borrow_mut() = None);
        return;
    }

    loop {
        let Some(command) = receive_command(&state) else {
            worker_liveness.store(false, Ordering::Release);
            let com = { Rc::clone(&state.borrow().com) };
            if let Err(error) = com.close_callback_ingress("Win16 USER command owner disappeared") {
                eprintln!("runtime: cannot close COM callbacks after USER disconnect: {error}");
                retain_com_sta_without_terminal_ack();
            }
            if !com.is_quiescent() {
                // The client channel is gone, so no exact terminal ack can
                // arrive. Keep this STA and its owned native references alive
                // rather than dropping an unacknowledged result or releasing
                // apartment-bound objects on another thread.
                retain_com_sta_without_terminal_ack();
            }
            if let Err(error) = com.shutdown_resources() {
                eprintln!(
                    "runtime: cannot safely retire COM after USER command disconnect: {error}"
                );
                retain_com_sta_without_terminal_ack();
            }
            break;
        };
        process_command(&state, command);
        if finish_abort_or_shutdown(&state, &mut modal_hooks) {
            break;
        }
    }

    if let Some(hooks) = modal_hooks.take() {
        let hook_error = hooks.finish().err();
        let (
            abort_waiters,
            shutdown_waiters,
            cancelled_modals,
            mut errors,
            callback_error,
            worker_generation,
            proof,
            proof_error,
            quiescence,
        ) = {
            let mut state = state.borrow_mut();
            let (worker_generation, proof, proof_error, quiescence) = terminal_evidence(&state);
            (
                std::mem::take(&mut state.abort_waiters),
                std::mem::take(&mut state.shutdown_waiters),
                std::mem::take(&mut state.cancelled_modals),
                std::mem::take(&mut state.terminal_failures),
                state.modal_control.take_callback_failure(),
                worker_generation,
                proof,
                proof_error,
                quiescence,
            )
        };
        errors.push(Arc::new(RuntimeError::new(
            Kind::HostFailure,
            "Win16 USER worker exited before completing its terminal request",
        )));
        if let Some(error) = hook_error {
            errors.push(Arc::new(error));
        }
        if let Some(error) = callback_error {
            errors.push(Arc::new(error));
        }
        send_terminal_results(
            abort_waiters.into_iter().chain(shutdown_waiters).collect(),
            errors,
            cancelled_modals,
            worker_generation,
            proof,
            proof_error,
            quiescence,
        );
    }
    WORKER_CONTEXT.with(|slot| *slot.borrow_mut() = None);
}

fn retain_com_sta_without_terminal_ack() -> ! {
    if let Err(error) = super::super::win16_cursor_clip::cleanup_for_exit() {
        eprintln!("runtime: cursor clipping cleanup before retained USER exit failed: {error}");
    }
    // There is no live command sender left to acknowledge the exact retained
    // result. Parking retains WorkerState, its bounded terminal journal, the
    // native object/media tables, and the initialized USER/OLE STA together.
    // The failed-shutdown reaper already owns this worker's JoinHandle.
    loop {
        std::thread::park();
    }
}

fn finish_abort_or_shutdown(
    state: &Rc<RefCell<WorkerState>>,
    modal_hooks: &mut Option<ModalWorkerHooks>,
) -> bool {
    // ReleaseDC retries can fail while the worker remains live. Do them only
    // after terminal readiness is known, but before taking timers or marking
    // their records inactive, so a retry failure preserves the native timer set.
    if terminal_cleanup_ready_for_retry(state) {
        if let Err(error) = super::super::win16_common_controls_dc_retention::retry(state) {
            return fail_terminal_dc_retry(state, error);
        }
    }
    let (
        ready,
        shutdown,
        abort_waiters,
        shutdown_waiters,
        timers,
        errors,
        cancelled_modals,
        worker_generation,
        proof,
        proof_error,
        quiescence,
    ) = {
        let mut state = state.borrow_mut();
        if !state.aborted && !state.shutdown_requested {
            return false;
        }
        if !state.active_operations.is_empty() {
            return false;
        }
        let ready_requests = state.terminal_wake_requests.clone();
        let abort_ready = state
            .abort_waiters
            .iter()
            .any(|(request_id, _)| ready_requests.contains(request_id));
        let shutdown_ready = state
            .shutdown_waiters
            .iter()
            .any(|(request_id, _)| ready_requests.contains(request_id));
        if !abort_ready && !shutdown_ready {
            return false;
        }
        let shutdown = state.shutdown_requested && shutdown_ready;
        let callback_stack_empty = state.live_callbacks.is_empty();
        let modal_scope_stack_empty = super::super::super::win16_modal::modal_stack_is_empty();
        if !callback_stack_empty || !modal_scope_stack_empty {
            let abort_waiters = take_ready_waiters(&mut state.abort_waiters, &ready_requests);
            let shutdown_waiters = if shutdown {
                take_ready_waiters(&mut state.shutdown_waiters, &ready_requests)
            } else {
                Vec::new()
            };
            for (request_id, _) in abort_waiters.iter().chain(shutdown_waiters.iter()) {
                state.terminal_wake_requests.remove(request_id);
            }
            let mut errors = std::mem::take(&mut state.terminal_failures);
            errors.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 terminal request reached an empty operation stack with an active modal registration",
            )));
            if let Some(error) = state.modal_control.take_callback_failure() {
                errors.push(Arc::new(error));
            }
            let cancelled_modals = std::mem::take(&mut state.cancelled_modals);
            let (worker_generation, proof, proof_error, quiescence) = terminal_evidence(&state);
            send_terminal_results(
                abort_waiters.into_iter().chain(shutdown_waiters).collect(),
                errors,
                cancelled_modals,
                worker_generation,
                proof,
                proof_error,
                quiescence,
            );
            // A negative receipt does not prove that the modal API or USER
            // thread has retired. Keep the worker alive and its owner intact.
            return false;
        }
        let abort_waiters = take_ready_waiters(&mut state.abort_waiters, &ready_requests);
        let shutdown_waiters = if shutdown {
            take_ready_waiters(&mut state.shutdown_waiters, &ready_requests)
        } else {
            Vec::new()
        };
        for (request_id, _) in abort_waiters.iter().chain(shutdown_waiters.iter()) {
            state.terminal_wake_requests.remove(request_id);
        }
        let timers = if shutdown {
            BTreeSet::new()
        } else {
            let timers = std::mem::take(&mut state.native_timers);
            for timer in state.timer_records.values_mut() {
                timer.active = false;
            }
            timers
        };
        let errors = std::mem::take(&mut state.terminal_failures);
        let cancelled_modals = std::mem::take(&mut state.cancelled_modals);
        let (worker_generation, proof, proof_error, quiescence) = terminal_evidence(&state);
        (
            true,
            shutdown,
            abort_waiters,
            shutdown_waiters,
            timers,
            errors,
            cancelled_modals,
            worker_generation,
            proof,
            proof_error,
            quiescence,
        )
    };
    if !ready {
        return false;
    }
    if shutdown {
        let com = { Rc::clone(&state.borrow().com) };
        if !com.is_quiescent() {
            let mut errors = errors;
            errors.push(Arc::new(RuntimeError::new(
                Kind::HostFailure,
                format!(
                    "Win16 COM shutdown is waiting for {} active and {} unacknowledged terminal operations",
                    com.active_count(),
                    com.unsettled_count(),
                ),
            )));
            send_terminal_results(
                abort_waiters.into_iter().chain(shutdown_waiters).collect(),
                errors,
                cancelled_modals,
                worker_generation,
                proof,
                proof_error,
                quiescence,
            );
            // The caller can now poll and acknowledge the exact retained COM
            // terminals, then retry shutdown. Do not tear down USER state or
            // release the apartment while those results still own IDs.
            return false;
        }
    }
    for (hwnd, id) in timers {
        // SAFETY: These native timer identities were returned by USER and are
        // killed on the same worker thread after all callbacks have unwound.
        unsafe { KillTimer(hwnd as HWND, id) };
    }
    cleanup_clipboard_state(state);
    if shutdown {
        let mut errors = errors;
        if let Err(error) = shutdown_all(state) {
            errors.push(Arc::new(error));
            errors.extend(std::mem::take(&mut state.borrow_mut().terminal_failures));
            if let Some(error) = state.borrow().modal_control.take_callback_failure() {
                errors.push(Arc::new(error));
            }
            send_terminal_results(
                abort_waiters.into_iter().chain(shutdown_waiters).collect(),
                errors,
                cancelled_modals,
                worker_generation,
                proof,
                proof_error,
                quiescence,
            );
            // Preserve the worker and all still-live native owners. A later
            // shutdown request retries only the resources still mapped.
            return false;
        }
        let com = { Rc::clone(&state.borrow().com) };
        if let Err(error) = com.shutdown_resources() {
            errors.push(Arc::new(error));
            send_terminal_results(
                abort_waiters.into_iter().chain(shutdown_waiters).collect(),
                errors,
                cancelled_modals,
                worker_generation,
                proof,
                proof_error,
                quiescence,
            );
            return false;
        }
        {
            let mut state = state.borrow_mut();
            // Borrowed HWNDs survive worker shutdown, but their queued
            // HDROP owners do not: the exact MSG leases are canceled here.
            state.native_drop_files.retire_all();
            state.drop_accepting_windows.clear();
        }
        let (timers, late_failures) = {
            let mut state = state.borrow_mut();
            state.guest_timer_posts.clear();
            let timers = std::mem::take(&mut state.native_timers);
            for timer in state.timer_records.values_mut() {
                timer.active = false;
            }
            state.timer_records.clear();
            state.timer_by_native.clear();
            state.pending_dialog_routes.clear();
            let late_failures = std::mem::take(&mut state.terminal_failures);
            (timers, late_failures)
        };
        errors.extend(late_failures);
        for (hwnd, id) in timers {
            unsafe { KillTimer(hwnd as HWND, id) };
        }
        if let Some(hooks) = modal_hooks.take() {
            if let Err(error) = hooks.finish() {
                errors.push(Arc::new(error));
            }
        }
        if let Some(error) = state.borrow().modal_control.take_callback_failure() {
            errors.push(Arc::new(error));
        }
        send_terminal_results(
            abort_waiters,
            errors.clone(),
            cancelled_modals.clone(),
            worker_generation,
            proof.clone(),
            proof_error.as_ref().map(Arc::clone),
            quiescence,
        );
        let mut borrowed = state.borrow_mut();
        borrowed.dialog_routes_by_native.clear();
        borrowed.dialog_children_by_native.clear();
        borrowed.window_creation_instances.clear();
        borrowed.clipboard_viewers.clear();
        drop(borrowed);
        send_terminal_results(
            shutdown_waiters,
            errors,
            cancelled_modals,
            worker_generation,
            proof,
            proof_error,
            quiescence,
        );
        true
    } else {
        let mut errors = errors;
        if let Err(error) = super::super::win16_native_procedures::restore_subclasses(state) {
            errors.push(Arc::new(error));
        }
        if let Some(error) = state.borrow().modal_control.take_callback_failure() {
            errors.push(Arc::new(error));
        }
        send_terminal_results(
            abort_waiters,
            errors,
            cancelled_modals,
            worker_generation,
            proof,
            proof_error,
            quiescence,
        );
        false
    }
}

fn terminal_cleanup_ready_for_retry(state: &Rc<RefCell<WorkerState>>) -> bool {
    let state = state.borrow();
    if (!state.aborted && !state.shutdown_requested)
        || !state.active_operations.is_empty()
        || !super::super::super::win16_modal::modal_stack_is_empty()
    {
        return false;
    }
    let abort_ready = state
        .abort_waiters
        .iter()
        .any(|(request_id, _)| state.terminal_wake_requests.contains(request_id));
    let shutdown_ready = state
        .shutdown_waiters
        .iter()
        .any(|(request_id, _)| state.terminal_wake_requests.contains(request_id));
    abort_ready || shutdown_ready
}

fn fail_terminal_dc_retry(state: &Rc<RefCell<WorkerState>>, error: RuntimeError) -> bool {
    let (
        abort_waiters,
        shutdown_waiters,
        errors,
        cancelled_modals,
        worker_generation,
        proof,
        proof_error,
        quiescence,
    ) = {
        let mut state = state.borrow_mut();
        let ready_requests = state.terminal_wake_requests.clone();
        let abort_waiters = take_ready_waiters(&mut state.abort_waiters, &ready_requests);
        let shutdown = state.shutdown_requested
            && state
                .shutdown_waiters
                .iter()
                .any(|(request_id, _)| ready_requests.contains(request_id));
        let shutdown_waiters = if shutdown {
            take_ready_waiters(&mut state.shutdown_waiters, &ready_requests)
        } else {
            Vec::new()
        };
        for (request_id, _) in abort_waiters.iter().chain(shutdown_waiters.iter()) {
            state.terminal_wake_requests.remove(request_id);
        }
        if abort_waiters.is_empty() && shutdown_waiters.is_empty() {
            // Readiness is checked on the same worker thread immediately
            // before ReleaseDC; preserve an unexpected result for a later retry.
            state.terminal_failures.push(Arc::new(error));
            return false;
        }
        let mut errors = std::mem::take(&mut state.terminal_failures);
        errors.push(Arc::new(error));
        if let Some(error) = state.modal_control.take_callback_failure() {
            errors.push(Arc::new(error));
        }
        let cancelled_modals = std::mem::take(&mut state.cancelled_modals);
        let (worker_generation, proof, proof_error, quiescence) = terminal_evidence(&state);
        (
            abort_waiters,
            shutdown_waiters,
            errors,
            cancelled_modals,
            worker_generation,
            proof,
            proof_error,
            quiescence,
        )
    };
    send_terminal_results(
        abort_waiters.into_iter().chain(shutdown_waiters).collect(),
        errors,
        cancelled_modals,
        worker_generation,
        proof,
        proof_error,
        quiescence,
    );
    // The worker stays live; native_timers and timer_records were not changed.
    false
}

fn take_ready_waiters(
    waiters: &mut Vec<(u64, std::sync::mpsc::Sender<super::ShutdownResult>)>,
    ready: &BTreeSet<u64>,
) -> Vec<(u64, std::sync::mpsc::Sender<super::ShutdownResult>)> {
    let mut selected = Vec::new();
    let mut pending = Vec::new();
    for waiter in waiters.drain(..) {
        if ready.contains(&waiter.0) {
            selected.push(waiter);
        } else {
            pending.push(waiter);
        }
    }
    *waiters = pending;
    selected
}

fn cleanup_clipboard_state(state: &Rc<RefCell<WorkerState>>) {
    let clipboard_open = state.borrow().clipboard_open;
    if clipboard_open && unsafe { CloseClipboard() } != 0 {
        state.borrow_mut().clipboard_open = false;
    }

    let viewers = {
        let state = state.borrow();
        state
            .clipboard_viewers
            .iter()
            .map(|(token, viewer)| (*token, *viewer))
            .collect::<Vec<_>>()
    };
    for (token, viewer) in viewers {
        let hwnd = viewer.window as HWND;
        let remove = unsafe { IsWindow(hwnd) } == 0
            || unsafe { ChangeClipboardChain(hwnd, viewer.next_viewer as HWND) != 0 };
        if remove {
            let mut state = state.borrow_mut();
            if state.clipboard_viewers.get(&token).is_some_and(|current| {
                current.window == viewer.window && current.next_viewer == viewer.next_viewer
            }) {
                state.clipboard_viewers.remove(&token);
            }
        }
    }
}

pub(in crate::windows::win16_windows) fn remove_window_maps(
    state: &Rc<RefCell<WorkerState>>,
    token: runtime::Win16HostWindow,
    hwnd: HWND,
) {
    super::super::win16_guest_notifications::mark_window_retired(token);
    let previous = { state.borrow().windows.get(&token).copied() };
    let removed_hwnd = previous.unwrap_or(hwnd);
    let exact_native_owner = state
        .borrow()
        .windows_by_native
        .get(&(removed_hwnd as usize))
        .is_some_and(|identity| identity.window == token)
        && previous == Some(removed_hwnd);
    let drop_file_ledger_retired = if exact_native_owner {
        match super::super::win16_message_loop::retire_drop_files_for_window(
            state,
            token,
            removed_hwnd,
        ) {
            Ok(()) => true,
            Err(error) => {
                // A receipt reservation failure leaves its exact ledger owner
                // intact for retry/terminal cleanup. Do not erase it while
                // retiring the HWND maps.
                super::super::win16_menu_attachment::latch_retirement_failure(state, error);
                false
            }
        }
    } else {
        true
    };
    if let Err(error) = super::super::win16_menu_attachment::capture_window_menu_retirement(
        state,
        token,
        removed_hwnd,
    ) {
        super::super::win16_menu_attachment::latch_retirement_failure(state, error);
    }
    // USER may destroy a private/window DC with its HWND. Retire only this
    // owner's borrowed identities so future guest calls cannot reuse its HDC
    // bits; the shared table performs no native deletion for these aliases.
    let dcs = { state.borrow().dcs.clone() };
    dcs.retire_window(token);
    super::super::win16_window_properties::retire_window(state, token, removed_hwnd);
    super::super::win16_native_procedures::retire_base(state, token);
    super::super::win16_window_identity::retire(state, token, removed_hwnd);
    super::super::win16_common_dialog_worker::retire_window(state, token);
    let mut retired_children = Vec::new();
    let shared = state;
    let mut state = state.borrow_mut();
    // Every real token reserves this tombstone capacity before publication,
    // so recording retirement cannot allocate after the native HWND is gone.
    state.retired_window_tokens.insert(token);
    state.deferred_native_messages.retire_window(token);
    state.windows.remove(&token);
    state.window_creation_instances.remove(&token);
    state.drop_accepting_windows.remove(&token);
    if drop_file_ledger_retired {
        state.native_drop_files.retire_window(token);
    }
    // A deferred destroy completion can refer to an HWND already reused by
    // USER. Only retire native sidecars still attached to this exact token.
    let owns_mapping = state
        .windows_by_native
        .get(&(removed_hwnd as usize))
        .is_some_and(|identity| identity.window == token);
    if owns_mapping {
        let native = removed_hwnd as usize;
        state.windows_by_native.remove(&native);
        retire_native_window_state(&mut state, native);
        state.dialog_routes_by_native.remove(&native);
        state.dialog_creation_data.remove(&native);
        let dialog_children = state
            .dialog_children_by_native
            .remove(&native)
            .unwrap_or_default();
        for (child, child_token) in dialog_children {
            let borrowed_alias = state
                .windows_by_native
                .get(&child)
                .copied()
                .filter(|identity| {
                    identity.window == child_token && !identity.owned && identity.class.is_none()
                });
            if let Some(identity) = borrowed_alias {
                retired_children.push((identity.window, child));
            }
        }
    }
    // A dialog child may have been associated with a different live dialog
    // root. Remove only this retiring token; another generation can already
    // be using the same recycled HWND bits.
    for children in state.dialog_children_by_native.values_mut() {
        children.retain(|_, child_token| *child_token != token);
    }
    state
        .dialog_children_by_native
        .retain(|_, children| !children.is_empty());
    state.window_menus.remove(&token);
    state.system_menus.remove(&token);
    drop(state);
    // Retire borrowed descendants while their token mappings still exist,
    // so property owners can verify HWND identity before native cleanup.
    // All native property operations run outside the mutable worker borrow.
    for (token, native) in retired_children {
        remove_window_maps(shared, token, native as HWND);
    }
}

fn retire_native_window_state(state: &mut WorkerState, native: usize) {
    state.native_timers.retain(|(owner, _)| *owner != native);
    for timer in state.timer_records.values_mut() {
        if timer.hwnd == native {
            timer.active = false;
        }
    }
    state
        .guest_timer_posts
        .retain(|(owner, _), _| *owner != native);
}
