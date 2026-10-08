//! WNet printer watches, asynchronous USER posts, and lifecycle cleanup.

use std::sync::Arc;

use guest_core::OwnerId;

use super::Win16State;
use super::network_print_api::{
    print_invariant, remember_error, WN_BAD_VALUE, WN_NET_ERROR,
    WN_NOT_SUPPORTED, WN_SUCCESS,
};
use super::window_post::{
    consume_window_post_attempt, resolve_window_post_step, started_failure_error,
    window_post_attempt_consumed, window_post_attempt_result, WindowPostAttempt,
    WindowPostOutcome,
};
use super::network_print_cleanup;
use super::network_print_completion as completion;
use super::network_print_jobs::Win16NetworkPrintJobs;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16GuestNotification, Win16GuestNotificationSource, Win16GuestNotificationTarget,
    Win16HostNetworkQueueOperation, Win16HostNetworkQueueResult,
    Win16HostSpoolOperation, Win16WindowOperation,
};

impl Win16State {
    /// Queue-change delivery is called from the runtime's existing guest
    /// safe-point. Every USER post is asynchronous and source ACK follows the
    /// exact PostGuestNotification proof readback and consumption.
    pub(in crate::win16_runtime) fn dispatch_pending_network_print_notification(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        self.sweep_retired_network_print_windows(host)?;
        self.poll_network_print_queue_changes(host)?;
        let Some(owner) = self.tasks.current() else { return Ok(true); };
        let event = self.network_print_jobs.get(&owner)
            .and_then(Win16NetworkPrintJobs::peek_queue_event);
        let Some(event) = event else { return Ok(true); };
        if let Some(failure) = &event.started_failure {
            return Err(started_failure_error(failure, "WNet queue notification POST remains owned by USER"));
        }
        let watch_target = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.watch_window(event.watch));
        if watch_target != Some((event.guest_window, event.window)) {
            return Err(print_invariant("WNet queue event lost its exact watch/window identity"));
        }
        if event.post_attempt.is_some() {
            return self.resume_network_print_post(owner, event.watch, event.sequence, host);
        }
        if self.window_handles.get(&event.guest_window) != Some(&event.window) {
            self.cleanup_network_print_window(owner, event.guest_window, event.window, host)?;
            return Ok(true);
        }
        if event.notification_source_id == 0 || event.notification_source_id == u64::MAX
            || event.watch.token() == 0 || event.sequence == 0
        {
            return Err(print_invariant("WNet queue event has an invalid shared source identity"));
        }
        if self.ensure_user_queue(host)?.is_none() {
            return Ok(false);
        }
        let notification = Win16GuestNotification {
            target: Win16GuestNotificationTarget::Window {
                window: event.window,
                guest_hwnd: event.guest_window,
            },
            source: Win16GuestNotificationSource {
                id: event.notification_source_id,
                generation: event.watch.token(),
                sequence: event.sequence,
            },
            message: event.message,
            w_param: event.index,
            l_param: 0,
        };
        let step = match host.win16_window_begin(
            Win16WindowOperation::PostGuestNotification(notification),
        ) {
            Ok(step) => step,
            // The boundary defines a plain Err as pre-enqueue. Keep the same
            // event identity; the next safe-point may submit it once again.
            Err(error) => return Err(error.with_context(format!(
                "WNet queue POST {}:{}:{} failed before enqueue",
                notification.source.id, notification.source.generation,
                notification.source.sequence,
            ))),
        };
        match resolve_window_post_step(step)? {
            WindowPostOutcome::StartedFailure(failure) => {
                let retained = self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet queue watch owner disappeared"))?
                    .retain_queue_post_failure(event.watch, event.sequence, Arc::clone(&failure));
                if !retained { return Err(print_invariant("WNet queue POST failure changed its exact event owner")); }
                Err(started_failure_error(&failure, "WNet queue POST failed after enqueue"))
            }
            WindowPostOutcome::SourceRetired(receipt) => {
                let retained = self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet queue watch owner disappeared"))?
                    .retain_queue_post_attempt(
                        event.watch, event.sequence, WindowPostAttempt::SourceRetired(receipt),
                    );
                if !retained { return Err(print_invariant("WNet queue POST changed its exact event owner")); }
                self.resume_network_print_post(owner, event.watch, event.sequence, host)
            }
            WindowPostOutcome::Retained(attempt) => {
                let retained = self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet queue watch owner disappeared"))?
                    .retain_queue_post_attempt(event.watch, event.sequence, attempt);
                if !retained { return Err(print_invariant("WNet queue POST changed its exact event owner")); }
                Err(RuntimeError::new(Kind::CompatibilityGap,
                    "WNet queue POST returned without a consumable normal source proof; event remains retained"))
            }
            WindowPostOutcome::Completed(_) => Err(print_invariant(
                "WNet queue POST returned a local completion instead of a USER proof")),
        }
    }

    pub(super) fn cleanup_network_print_window(
        &mut self,
        owner: OwnerId,
        guest_hwnd: u16,
        window: crate::Win16HostWindow,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let watches = self.network_print_jobs.get(&owner)
            .map(|jobs| network_print_cleanup::watches_for_destroyed_window(jobs, guest_hwnd, window))
            .transpose()?.unwrap_or_default();
        for watch in watches {
            self.consume_pending_network_print_post(owner, watch, host)?;
            let status = self.unwatch_one(owner, watch, host)?;
            if status != WN_SUCCESS {
                return Err(RuntimeError::new(Kind::HostFailure, format!(
                    "WNet window cleanup could not retire watch {} (WN 0x{status:04X})", watch.token(),
                )));
            }
        }
        if let Some(jobs) = self.network_print_jobs.get_mut(&owner) {
            jobs.retire_window_cleanup_marker(guest_hwnd, window);
        }
        self.drop_empty_network_print_owner(owner);
        Ok(())
    }

    pub(super) fn sweep_retired_network_print_windows(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut owners = Vec::new();
        owners.try_reserve_exact(self.network_print_jobs.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate WNet retired-window owner sweep", error,
        ))?;
        owners.extend(self.network_print_jobs.keys().copied());
        for owner in owners {
            let pending = self.network_print_jobs.get(&owner)
                .map(Win16NetworkPrintJobs::retired_windows_for_cleanup)
                .transpose()?.unwrap_or_default();
            for (guest_hwnd, window) in pending {
                self.cleanup_network_print_window_tree(owner, guest_hwnd, window, host)?;
            }
        }
        Ok(())
    }

    /// Retire watches attached to an exact HWND subtree during the safe-point
    /// sweep. Traverse children only while the root still names that exact
    /// native incarnation; a reused guest alias cleans only the old watch.
    pub(super) fn cleanup_network_print_window_tree(
        &mut self,
        owner: OwnerId,
        root_guest_hwnd: u16,
        root_window: crate::Win16HostWindow,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut pending = Vec::new();
        pending.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate WNet destroyed-window cleanup stack", error,
        ))?;
        pending.push((root_guest_hwnd, root_window));
        let mut visited = std::collections::BTreeSet::new();
        while let Some((guest_hwnd, window)) = pending.pop() {
            if !visited.insert(guest_hwnd) { continue; }
            if guest_hwnd == root_guest_hwnd
                && self.window_handles.get(&root_guest_hwnd) != Some(&root_window)
            {
                // A retired alias may already have been reused. Clean the old
                // exact watch without traversing the new HWND's child tree.
                self.cleanup_network_print_window(owner, guest_hwnd, window, host)?;
                return Ok(());
            }
            self.cleanup_network_print_window(owner, guest_hwnd, window, host)?;
            let mut children = Vec::new();
            for (child, parent) in &self.window_parents {
                if *parent == guest_hwnd {
                    children.try_reserve(1).map_err(|error| RuntimeError::with_source(
                        Kind::ResourceExhausted, "allocate WNet destroyed-window child list", error,
                    ))?;
                    children.push(*child);
                }
            }
            pending.try_reserve(children.len()).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "grow WNet destroyed-window cleanup stack", error,
            ))?;
            for child in children {
                if let Some(window) = self.window_handles.get(&child).copied() {
                    pending.push((child, window));
                }
            }
        }
        Ok(())
    }

    /// Task cleanup owns all host tokens, printer watches, and queue-data
    /// selector leases until each exact native release succeeds.
    pub(super) fn cleanup_network_print_task(
        &mut self,
        owner: OwnerId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let plan = match self.network_print_jobs.get(&owner) {
            Some(jobs) => network_print_cleanup::plan(jobs)?,
            // Snapshot leases may have been registered by the host before a
            // runtime allocation failed. Even with no remaining guest map,
            // ReleaseNetworkOwner must enumerate and retire those host tokens.
            None => network_print_cleanup::Win16NetworkPrintCleanupPlan {
                watches: Vec::new(),
                queue_data: Vec::new(),
            },
        };
        let mut first_error = None;
        for watch in plan.watches {
            let result = self.consume_pending_network_print_post(owner, watch, host)
                .and_then(|()| self.unwatch_one(owner, watch, host));
            match result {
                Ok(WN_SUCCESS) => {}
                Ok(status) => remember_error(&mut first_error, RuntimeError::new(Kind::HostFailure,
                    format!("task cleanup could not retire WNet watch {} (WN 0x{status:04X})", watch.token()))),
                Err(error) => remember_error(&mut first_error, error),
            }
        }
        match host.win16_spool(Win16HostSpoolOperation::ReleaseNetworkOwner { owner }) {
            Ok(result) => match completion::spool_status(result) {
                Ok(WN_SUCCESS) => {
                    if let Some(jobs) = self.network_print_jobs.get_mut(&owner) {
                        jobs.retire_all_owned_jobs();
                    }
                }
                Ok(status) => remember_error(&mut first_error, RuntimeError::new(
                    Kind::HostFailure,
                    format!("task cleanup ReleaseNetworkOwner returned WN status 0x{status:04X}"),
                )),
                Err(error) => remember_error(&mut first_error, error),
            },
            Err(error) => remember_error(&mut first_error,
                error.with_context("release task-owned Win16 spool leases")),
        }
        for lease in plan.queue_data {
            if let Err(error) = self.release_queue_data_lease(owner, &lease) {
                remember_error(&mut first_error, error);
            }
        }
        if let Some(jobs) = self.network_print_jobs.get_mut(&owner) {
            jobs.retire_task_reservations();
        }
        self.drop_empty_network_print_owner(owner);
        first_error.map_or(Ok(()), Err)
    }

    /// Stop every native printer-change producer while retaining accepted
    /// USER POST failure rows for the exact terminal source-stack ACK.
    pub(in crate::win16_runtime) fn quiesce_network_print_producers(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(owner) = self.tasks.current() else { return Ok(()); };
        let watches = self.network_print_jobs.get(&owner)
            .map(Win16NetworkPrintJobs::watches_for_producer_quiescence)
            .transpose()?.unwrap_or_default();
        let mut first_error = None;
        for watch in watches {
            let event = self.network_print_jobs.get(&owner)
                .and_then(|jobs| jobs.queue_event_for_watch(watch));
            if !event.as_ref().is_some_and(|event| event.started_failure.is_some()) {
                if let Err(error) = self.consume_pending_network_print_post(owner, watch, host) {
                    remember_error(&mut first_error, error);
                    continue;
                }
                if let Some(jobs) = self.network_print_jobs.get_mut(&owner) {
                    jobs.discard_unposted_queue_event(watch);
                }
            }
            let result = match host.win16_network_print_queues(
                Win16HostNetworkQueueOperation::Unwatch { watch },
            ) {
                Ok(result) => result,
                Err(error) => {
                    remember_error(&mut first_error, error.with_context(format!(
                        "stop WNet printer-change producer {}", watch.token(),
                    )));
                    continue;
                }
            };
            match completion::queue_status(result) {
                Ok(WN_SUCCESS) => {
                    let marked = self.network_print_jobs.get_mut(&owner)
                        .is_some_and(|jobs| jobs.mark_watch_native_unwatched(watch));
                    if !marked {
                        remember_error(&mut first_error, print_invariant(
                            "WNet producer quiescence lost its exact watch record"));
                    }
                }
                Ok(status) => remember_error(&mut first_error, RuntimeError::new(
                    Kind::HostFailure,
                    format!("stop WNet printer-change producer {} returned WN 0x{status:04X}", watch.token()),
                )),
                Err(error) => remember_error(&mut first_error, error),
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(in crate::win16_runtime) fn owns_terminal_network_print_post_source(
        &self,
        top: &crate::Win16WindowTerminalSourceTop,
    ) -> Result<bool, RuntimeError> {
        let crate::Win16WindowTerminalSourceTop::User {
            operation, kind, state, worker_generation,
        } = top else { return Ok(false); };
        if *kind != crate::Win16NativeWindowOperationKind::PostGuestNotification {
            return Ok(false);
        }
        let mut found = false;
        for jobs in self.network_print_jobs.values() {
            if jobs.started_failure_for_terminal_source(
                *operation, *kind, *state, *worker_generation,
            )?.is_some() {
                if found {
                    return Err(print_invariant(
                        "one USER POST failure is retained by multiple WNet task owners"));
                }
                found = true;
            }
        }
        Ok(found)
    }

    pub(in crate::win16_runtime) fn retire_network_print_terminal_post_source(
        &mut self,
        receipt: &crate::Win16WindowAbortReceipt,
        top: &crate::Win16WindowTerminalSourceTop,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.network_print_jobs.values().any(Win16NetworkPrintJobs::has_watches) {
            return Err(print_invariant(
                "WNet terminal POST retirement started before printer producers were quiesced"));
        }
        if !self.owns_terminal_network_print_post_source(top)? { return Ok(false); }
        let crate::Win16WindowTerminalSourceTop::User {
            operation, kind, state, worker_generation,
        } = top else { return Ok(false); };
        let mut owner = None;
        let mut exact = None;
        for (candidate_owner, jobs) in &self.network_print_jobs {
            if let Some(candidate) = jobs.started_failure_for_terminal_source(
                *operation, *kind, *state, *worker_generation,
            )? {
                if exact.is_some() {
                    return Err(print_invariant("WNet terminal source identity is not unique"));
                }
                owner = Some(*candidate_owner);
                exact = Some(candidate);
            }
        }
        let owner = owner.ok_or_else(|| print_invariant("WNet terminal source owner disappeared"))?;
        let (watch, sequence, failure) = exact.ok_or_else(||
            print_invariant("WNet terminal POST event disappeared"))?;
        let cached = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WNet terminal POST lost the cached USER abort receipt"))?;
        if cached.request_id != receipt.request_id
            || cached.worker_generation != receipt.worker_generation
            || receipt.worker_generation != failure.worker_generation
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WNet terminal POST source does not match the exact cached abort receipt"));
        }
        let ack = self.terminal_ack_for_post_failure(&failure, receipt, top)?;
        self.acknowledge_started_post_failure(&failure, host)?;
        if !host.win16_window_terminal_acknowledged(receipt, &ack)? {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WNet terminal POST ACK has no exact native tombstone readback"));
        }
        let removed = self.network_print_jobs.get_mut(&owner)
            .ok_or_else(|| print_invariant("WNet terminal owner disappeared after ACK"))?
            .acknowledge_started_failure(watch, sequence, &failure)?;
        if !removed { return Err(print_invariant("WNet terminal ACK lost its exact POST event")); }
        self.drop_empty_network_print_owner(owner);
        Ok(true)
    }

    pub(super) fn watch_network_print_queue(
        &mut self,
        owner: OwnerId,
        operation: Win16HostNetworkQueueOperation,
        guest_window: u16,
        local_device: Vec<u8>,
        n_queue: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(window) = self.window_handles.get(&guest_window).copied() else {
            return Ok(WN_BAD_VALUE);
        };
        self.network_print_jobs.entry(owner).or_default().reserve_watch_slot()?;
        let result = match host.win16_network_print_queues(operation) {
            Ok(result) => result,
            Err(error) => {
                self.network_print_jobs.get_mut(&owner)
                    .ok_or_else(|| print_invariant("WNet watch task table disappeared"))?
                    .cancel_watch_slot_reservation();
                return Err(error);
            }
        };
        let Win16HostNetworkQueueResult::Watch { watch, notification_source_id, native_error } = result else {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet watch task table disappeared"))?
                .cancel_watch_slot_reservation();
            return Err(print_invariant("WNetWatchQueue received a different host queue result"));
        };
        let Some(watch) = watch else {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet watch task table disappeared"))?
                .cancel_watch_slot_reservation();
            return Ok(native_error.map_or(WN_NET_ERROR, completion::map_native_error));
        };
        let source_id = notification_source_id.unwrap_or(0);
        self.network_print_jobs.get_mut(&owner)
            .ok_or_else(|| print_invariant("WNet watch task table disappeared"))?
            .insert_watch(watch, source_id, guest_window, window, local_device, n_queue)?;
        if source_id == 0 || source_id == u64::MAX {
            host.report_diagnostic(&Diagnostic::warning(Kind::InternalInvariant,
                "native WNet watch succeeded without its globally allocated notification source identity; watch retained for cleanup"));
            return Ok(WN_NOT_SUPPORTED);
        }
        Ok(WN_SUCCESS)
    }

    pub(super) fn unwatch_network_print_queues(
        &mut self,
        owner: OwnerId,
        watches: Vec<crate::Win16HostNetworkQueueWatch>,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let mut first_status = WN_SUCCESS;
        for watch in watches {
            let status = self.unwatch_one(owner, watch, host)?;
            if status != WN_SUCCESS && first_status == WN_SUCCESS { first_status = status; }
        }
        Ok(first_status)
    }

    fn unwatch_one(
        &mut self,
        owner: OwnerId,
        watch: crate::Win16HostNetworkQueueWatch,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if self.network_print_jobs.get(&owner)
            .is_some_and(|jobs| jobs.watch_native_unwatched(watch))
        {
            let retired = self.network_print_jobs.get_mut(&owner)
                .is_some_and(|jobs| network_print_cleanup::retire_watch_after_host_unwatch(jobs, watch));
            if !retired { return Err(print_invariant("quiesced WNet watch disappeared before retirement")); }
            self.drop_empty_network_print_owner(owner);
            return Ok(WN_SUCCESS);
        }
        self.consume_pending_network_print_post(owner, watch, host)?;
        let result = host.win16_network_print_queues(Win16HostNetworkQueueOperation::Unwatch { watch })?;
        let status = completion::queue_status(result)?;
        if status == WN_SUCCESS {
            let jobs = self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet unwatch owner disappeared"))?;
            network_print_cleanup::retire_watch_after_host_unwatch(jobs, watch);
        }
        Ok(status)
    }

    fn poll_network_print_queue_changes(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if !self.network_print_jobs.values().any(Win16NetworkPrintJobs::has_watches) {
            return Ok(());
        }
        for jobs in self.network_print_jobs.values_mut() { jobs.reserve_queue_event_capacity()?; }
        let result = host.win16_network_print_queues(Win16HostNetworkQueueOperation::PeekChanges)?;
        let Win16HostNetworkQueueResult::Changes { changed, failed_watch, native_error } = result else {
            return Err(print_invariant("WNet queue poll returned a different host result"));
        };
        if let (Some(watch), Some(code)) = (failed_watch, native_error) {
            host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure, format!(
                "nonblocking WNet printer-watch poll failed for token {} with native error {code}; ownership retained",
                watch.token(),
            )));
        } else if failed_watch.is_some() || native_error.is_some() {
            host.report_diagnostic(&Diagnostic::warning(Kind::InternalInvariant,
                "WNet printer-watch poll returned an incomplete typed failure; watch ownership retained"));
        }
        for watch in changed {
            let mut found = false;
            for jobs in self.network_print_jobs.values_mut() {
                if jobs.watch_exists(watch) {
                    jobs.publish_queue_changes(std::iter::once(watch))?;
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(RuntimeError::new(Kind::InternalInvariant, format!(
                    "native WNet change poll referenced unowned watch token {}", watch.token(),
                )));
            }
        }
        Ok(())
    }

    fn resume_network_print_post(
        &mut self,
        owner: OwnerId,
        watch: crate::Win16HostNetworkQueueWatch,
        sequence: u64,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let event = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.queue_event(watch, sequence))
            .ok_or_else(|| print_invariant("WNet USER POST retry lost its queue event"))?;
        if event.started_failure.is_some() {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WNet queue POST remains retained after USER accepted its failed operation"));
        }
        let posted = {
            let jobs = self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet USER POST owner disappeared"))?;
            let event = jobs.queue_events_for_update(watch, sequence)
                .ok_or_else(|| print_invariant("WNet USER POST attempt disappeared"))?;
            let attempt = event.post_attempt.as_mut()
                .ok_or_else(|| print_invariant("WNet USER POST retry has no exact proof"))?;
            consume_window_post_attempt(host, attempt)?
        };
        if posted {
            let event = self.network_print_jobs.get(&owner)
                .and_then(|jobs| jobs.queue_event(watch, sequence))
                .ok_or_else(|| print_invariant("WNet posted queue event disappeared before ACK"))?;
            if event.post_attempt.as_ref().is_none_or(|attempt|
                !window_post_attempt_consumed(attempt)
                    || window_post_attempt_result(attempt) != Some(true))
            {
                return Err(print_invariant("WNet queue ACK lacks its exact consumed successful POST proof"));
            }
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet queue event owner disappeared before ACK"))?
                .acknowledge_queue_event(watch, sequence)?;
        } else {
            self.network_print_jobs.get_mut(&owner)
                .ok_or_else(|| print_invariant("WNet rejected queue event owner disappeared"))?
                .retry_queue_event_after_rejection(watch, sequence)?;
        }
        Ok(true)
    }

    fn consume_pending_network_print_post(
        &mut self,
        owner: OwnerId,
        watch: crate::Win16HostNetworkQueueWatch,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let event = self.network_print_jobs.get(&owner)
            .and_then(|jobs| jobs.queue_event_for_watch(watch));
        let Some(event) = event else { return Ok(()); };
        if let Some(failure) = event.started_failure {
            // The native watch can be released now. Keep the precise USER
            // failure row detached until task teardown reaches its exact
            // terminal source-stack top and acknowledges it.
            let _ = failure;
            return Ok(());
        }
        if event.post_attempt.is_some() {
            let _ = self.resume_network_print_post(owner, watch, event.sequence, host)?;
        }
        Ok(())
    }

}
