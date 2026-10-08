use super::*;
use runtime::{DiagnosticKind as Kind, Win16HostMciNotificationRouteOwner};

pub(super) fn combine_failure_kind(primary: Kind, cleanup: Kind) -> Kind {
    // Preserve invariants; otherwise cleanup replaces only an ExecutionLimit primary category.
    if primary == Kind::InternalInvariant || cleanup == Kind::InternalInvariant {
        Kind::InternalInvariant
    } else if primary == Kind::ExecutionLimit {
        cleanup
    } else {
        primary
    }
}

impl MciNotificationLedger {
    pub(super) fn can_retire_sink(&self) -> bool {
        self.source_admission_closed
            && self.pending_count == 0
            && self.by_device.is_empty()
            && self.any_device.is_empty()
            && self.events.is_empty()
            && self.failed_callbacks.is_empty()
            && self.wake_failures.is_empty()
            && self.worker_wait_failure.is_none()
            && self.worker_wait_wake_failure.is_none()
            && self.entered_yield_failure.is_none()
            && self.entered_yield_wake_failure.is_none()
            && self.entered_yield_client_failure.is_none()
    }

    pub(super) fn quiescence_snapshot(&self) -> (usize, usize, usize, usize, bool) {
        (
            self.pending_count,
            self.events.len(),
            self.failed_callbacks.len(),
            self.wake_failures
                .len()
                .saturating_add(usize::from(self.worker_wait_failure.is_some()))
                .saturating_add(usize::from(self.worker_wait_wake_failure.is_some()))
                .saturating_add(usize::from(self.entered_yield_failure.is_some()))
                .saturating_add(usize::from(self.entered_yield_wake_failure.is_some()))
                .saturating_add(usize::from(self.entered_yield_client_failure.is_some())),
            self.can_retire_sink(),
        )
    }

    pub(super) fn reserve(
        &mut self,
        native_device: Option<u32>,
        device: Option<Win16HostMciDevice>,
        target: Win16HostWindow,
        allow_new_device: bool,
        source_id: Option<u64>,
    ) -> Result<Win16HostMciNotificationId, RuntimeError> {
        if self.source_admission_closed {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "MCI notification source admission is closed during task teardown",
            ));
        }
        if source_id.is_some_and(|id| id == 0 || id == u64::MAX) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI notification route has a zero or reserved shared source ID",
            ));
        }
        let exact_open = allow_new_device
            && native_device.is_none()
            && device.is_none()
            && source_id.is_some();
        let exact_existing = !allow_new_device
            && native_device.is_some()
            && device.is_some()
            && source_id.is_some();
        if !exact_open && !exact_existing {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "MCI_NOTIFY has no exact pre-submit device-generation and shared source owner",
            ));
        }
        let id = self.next_id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "MCI notification identity space is exhausted",
            )
        })?;
        let pending_count = self.pending_count.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "pending MCI notification count is exhausted",
            )
        })?;
        self.events
            .try_reserve(self.pending_count.saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve host MCI notification delivery",
                    error,
                )
            })?;
        self.failed_callbacks
            .try_reserve(self.pending_count.saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI callback failure receipt before native dispatch",
                    error,
                )
            })?;
        // Several callback and wake failures can accumulate before the guest
        // drains this route; reserve ownership space before native dispatch.
        self.wake_failures
            .try_reserve(self.pending_count.saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve typed MCI wake-failure receipts before native dispatch",
                    error,
                )
            })?;
        let route = NotificationRoute {
            id: Win16HostMciNotificationId(id),
            native_device,
            device,
            target,
            allow_new_device,
            source_id,
            tombstone: false,
        };
        match native_device {
            Some(native) => {
                if let Some(routes) = self.by_device.get_mut(&native) {
                    routes.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve MCI notification route",
                            error,
                        )
                    })?;
                    routes.push_back(route);
                } else {
                    // Build the route queue before publishing a device key. An
                    // Entry default would leave an unretirable empty route if
                    // allocating this first notification failed.
                    self.by_device.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve MCI notification device route",
                            error,
                        )
                    })?;
                    let mut routes = VecDeque::new();
                    routes.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve MCI notification route",
                            error,
                        )
                    })?;
                    routes.push_back(route);
                    self.by_device.insert(native, routes);
                }
            }
            None => {
                self.any_device.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve wildcard MCI notification route",
                        error,
                    )
                })?;
                self.any_device.push_back(route);
            }
        }
        self.next_id = id;
        self.pending_count = pending_count;
        Ok(Win16HostMciNotificationId(id))
    }

    pub(super) fn close_source_admission(&mut self) {
        self.source_admission_closed = true;
    }

    pub(super) fn source_snapshot(
        &self,
    ) -> Result<(
        Vec<Win16HostMciNotificationRouteOwner>,
        Vec<Win16HostMciNotification>,
        Vec<Arc<RuntimeError>>,
    ), RuntimeError> {
        let mut routes = Vec::new();
        routes.try_reserve_exact(self.pending_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot exact MCI notification route owners before producer barrier",
                error,
            )
        })?;
        let mut append_route = |route: &NotificationRoute| {
            routes.push(Win16HostMciNotificationRouteOwner {
                notification: route.id,
                device: route.device,
                source_id: route.source_id,
                target: route.target,
                allow_new_device: route.allow_new_device,
                tombstone: route.tombstone,
            });
        };
        for queue in self.by_device.values() {
            for route in queue {
                append_route(route);
            }
        }
        for route in &self.any_device {
            append_route(route);
        }
        routes.sort_unstable_by_key(|route| route.notification);

        let mut events = Vec::new();
        events.try_reserve_exact(self.events.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot exact queued MCI notifications before producer barrier",
                error,
            )
        })?;
        events.extend(self.events.iter().copied());

        let retained_optional = usize::from(self.worker_wait_failure.is_some())
            .saturating_add(usize::from(self.worker_wait_wake_failure.is_some()))
            .saturating_add(usize::from(self.entered_yield_failure.is_some()))
            .saturating_add(usize::from(self.entered_yield_wake_failure.is_some()))
            .saturating_add(usize::from(self.entered_yield_client_failure.is_some()));
        let cause_count = self
            .failed_callbacks
            .len()
            .saturating_add(self.wake_failures.len())
            .saturating_add(retained_optional);
        let mut causes = Vec::new();
        causes.try_reserve_exact(cause_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot retained MCI notification causes before producer barrier",
                error,
            )
        })?;
        causes.extend(self.failed_callbacks.iter().map(|failure| Arc::clone(&failure.cause)));
        causes.extend(self.wake_failures.iter().cloned());
        causes.extend(self.worker_wait_failure.iter().cloned());
        causes.extend(self.worker_wait_wake_failure.iter().cloned());
        causes.extend(self.entered_yield_failure.iter().cloned());
        causes.extend(self.entered_yield_wake_failure.iter().cloned());
        causes.extend(self.entered_yield_client_failure.iter().cloned());
        Ok((routes, events, causes))
    }

    pub(super) fn cancel(&mut self, id: Win16HostMciNotificationId) {
        let mut removed = false;
        self.by_device.retain(|_, routes| {
            if !removed {
                if let Some(index) = routes.iter().position(|route| route.id == id) {
                    routes.remove(index);
                    removed = true;
                }
            }
            !routes.is_empty()
        });
        if !removed {
            if let Some(index) = self.any_device.iter().position(|route| route.id == id) {
                self.any_device.remove(index);
                removed = true;
            }
        }
        if removed {
            self.pending_count = self.pending_count.saturating_sub(1);
        }
        if let Some(index) = self.events.iter().position(|event| event.id == id) {
            self.events.remove(index);
        }
    }

    pub(super) fn quarantine_open(
        &mut self,
        id: Win16HostMciNotificationId,
        native_device: u32,
        device: Option<Win16HostMciDevice>,
    ) {
        // If the callback already arrived, discard that exact event. Otherwise
        // keep a tombstone at its reserved FIFO position so a late callback
        // cannot be mistaken for a later native device that reuses this ID.
        if let Some(index) = self.events.iter().position(|event| event.id == id) {
            self.events.remove(index);
            return;
        }
        if self
            .failed_callbacks
            .iter()
            .any(|failure| failure.id == Some(id))
        {
            self.cancel(id);
            return;
        }
        let route = if let Some(route) = self
            .by_device
            .values_mut()
            .find_map(|routes| routes.iter_mut().find(|route| route.id == id))
        {
            Some(route)
        } else {
            self.any_device.iter_mut().find(|route| route.id == id)
        };
        if let Some(route) = route {
            route.native_device = Some(native_device);
            route.device = device;
            route.allow_new_device = false;
            route.tombstone = true;
        }
    }

    pub(super) fn next_dispatch(
        &self,
        native_device: u32,
    ) -> Result<Option<NotificationDispatch>, RuntimeError> {
        // MM_MCINOTIFY has no command ID, so overlapping routes are not FIFO-identifiable.
        let specific = self.by_device.get(&native_device).into_iter().flatten();
        let wildcard = self
            .any_device
            .iter()
            .filter(|route| route.native_device.is_none_or(|id| id == native_device));
        let mut selected = None;
        for route in specific.chain(wildcard) {
            if selected.is_some() {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "MM_MCINOTIFY lacks a command identity for multiple retained MCI routes; exact owners remain queued",
                ));
            }
            selected = Some(route);
        }
        Ok(selected.map(|route| NotificationDispatch {
            id: route.id,
            device: route.device,
            allow_new_device: route.allow_new_device,
            source_id: route.source_id,
            tombstone: route.tombstone,
        }))
    }

    pub(super) fn consume_tombstone(
        &mut self,
        native_device: u32,
        id: Win16HostMciNotificationId,
    ) -> bool {
        if !self
            .next_dispatch(native_device)
            .ok()
            .flatten()
            .is_some_and(|dispatch| dispatch.id == id && dispatch.tombstone)
        {
            return false;
        }
        let removed = if self
            .by_device
            .get(&native_device)
            .and_then(VecDeque::front)
            .is_some_and(|route| route.id == id)
        {
            self.by_device
                .get_mut(&native_device)
                .and_then(VecDeque::pop_front)
                .is_some()
        } else if let Some(index) = self.any_device.iter().position(|route| route.id == id) {
            self.any_device.remove(index).is_some()
        } else {
            false
        };
        if removed {
            self.pending_count = self.pending_count.saturating_sub(1);
            self.by_device
                .retain(|_, routes| !routes.is_empty());
        }
        removed
    }

    pub(super) fn bind_open_notification(
        &mut self,
        id: Win16HostMciNotificationId,
        native_device: u32,
        device: Win16HostMciDevice,
        source_id: u64,
    ) -> Result<(), RuntimeError> {
        if source_id == 0 || source_id == u64::MAX {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI OPEN notification binding has a zero or reserved shared source ID",
            ));
        }
        let failed_status = self
            .failed_callbacks
            .iter()
            .find(|failure| failure.id == Some(id) && failure.native_device == native_device)
            .map(|failure| failure.status);
        if let Some(route) = self.any_device.iter_mut().find(|route| route.id == id) {
            if route.source_id != Some(source_id) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI OPEN notification source changed after its pre-submit reservation",
                ));
            }
            route.native_device = Some(native_device);
            route.device = Some(device);
            route.allow_new_device = false;
        } else if let Some(event) = self
            .events
            .iter()
            .find(|event| event.id == id && event.device == device)
        {
            if event.source.id == source_id
                && event.source.generation == device.generation
                && event.source.sequence == id.0
            {
                return Ok(());
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "delivered MCI OPEN event does not preserve its exact pre-reserved source tuple",
            ));
        } else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI OPEN notification lost its pre-reserved route and delivered event",
            ));
        }

        if let Some(status) = failed_status {
            let status = u16::try_from(status).map_err(|_| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "native MCI notification status does not fit the Win16 callback ABI",
                )
            })?;
            if !self.deliver(native_device, id, Some(device), source_id, status) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI OPEN callback receipt no longer matches its pre-reserved route",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn retain_callback_failure(
        &mut self,
        native_device: u32,
        id: Option<Win16HostMciNotificationId>,
        status: usize,
        cause: RuntimeError,
    ) {
        if self
            .failed_callbacks
            .iter()
            .any(|failure| failure.native_device == native_device && failure.id == id)
        {
            // Keep the first queue owner and retain the duplicate's raw fields
            // and typed cause as a separate protocol failure.
            self.retain_wake_failure(RuntimeError::with_source(
                cause.kind(),
                format!(
                    "native MCI duplicated notification route {:?} for device {} with raw status {}",
                    id.map(|value| value.0), native_device, status
                ),
                cause,
            ));
            return;
        }
        self.failed_callbacks.push_back(MciCallbackFailure {
            native_device,
            id,
            status,
            cause: Arc::new(cause),
        });
    }

    pub(super) fn retire_failed_open_callback(
        &mut self,
        id: Win16HostMciNotificationId,
    ) {
        if self
            .failed_callbacks
            .iter()
            .any(|failure| failure.id == Some(id))
        {
            // Native rollback has completed, and this exact callback already
            // arrived. It no longer needs a route tombstone to catch a late
            // completion, so retire both owners together.
            self.cancel(id);
        }
        self.failed_callbacks
            .retain(|failure| failure.id != Some(id));
    }

    pub(super) fn quarantine_unbound_open(
        &mut self,
        id: Win16HostMciNotificationId,
    ) {
        if self
            .events
            .iter()
            .any(|event| event.id == id)
            || self
                .failed_callbacks
                .iter()
                .any(|failure| failure.id == Some(id))
        {
            self.cancel(id);
            return;
        }
        if let Some(route) = self.any_device.iter_mut().find(|route| route.id == id) {
            route.device = None;
            route.allow_new_device = false;
            route.tombstone = true;
        }
    }

    pub(super) fn deliver(
        &mut self,
        native_device: u32,
        expected: Win16HostMciNotificationId,
        resolved_device: Option<Win16HostMciDevice>,
        source_id: u64,
        status: u16,
    ) -> bool {
        let dispatch = self.next_dispatch(native_device).ok().flatten();
        let can_route_device = dispatch.is_some_and(|dispatch| {
            dispatch.id == expected
                && !dispatch.tombstone
                && source_id != 0
                && source_id != u64::MAX
                && dispatch.source_id == Some(source_id)
                && (dispatch.device.is_some() || resolved_device.is_some())
                && dispatch
                    .device
                    .is_none_or(|expected_device| resolved_device == Some(expected_device))
        });
        if !can_route_device {
            return false;
        }
        let route = self
            .by_device
            .get_mut(&native_device)
            .and_then(|routes| {
                routes
                    .front()
                    .is_some_and(|route| route.id == expected)
                    .then(|| routes.pop_front())
                    .flatten()
            })
            .or_else(|| {
                self.any_device
                    .iter()
                    .position(|route| {
                        route.id == expected
                            && route.native_device.is_none_or(|id| id == native_device)
                    })
                    .and_then(|index| self.any_device.remove(index))
            });
        let Some(route) = route else {
            return false;
        };
        let device = route.device.or(resolved_device);
        let Some(device) = device else { return false };
        self.pending_count = self.pending_count.saturating_sub(1);
        self.events.push_back(Win16HostMciNotification {
            id: route.id,
            device: route.device.unwrap_or(device),
            source: Win16GuestNotificationSource {
                id: source_id,
                generation: device.generation,
                sequence: route.id.0,
            },
            status,
            target: route.target,
        });
        self.by_device.retain(|_, routes| !routes.is_empty());
        true
    }

    pub(super) fn peek(&mut self) -> Result<Option<Win16HostMciNotification>, RuntimeError> {
        if let Some(event) = self.events.front().copied() {
            return Ok(Some(event));
        }
        if !self.failed_callbacks.is_empty() {
            return Err(self.failure_error(
                "native MCI callback resolution and/or notification wake failed; exact callback receipts remain retained",
            )?);
        }
        if !self.wake_failures.is_empty()
            || self.worker_wait_failure.is_some()
            || self.worker_wait_wake_failure.is_some()
            || self.entered_yield_failure.is_some()
            || self.entered_yield_wake_failure.is_some()
            || self.entered_yield_client_failure.is_some()
        {
            return Err(self.failure_error(
                "native MCI wait, entered YIELD, or notification delivery failed; its exact owner remains retained",
            )?);
        }
        Ok(None)
    }

    pub(super) fn retain_wake_failure(&mut self, error: RuntimeError) {
        // Never replace an earlier typed cause with the latest wake failure.
        self.wake_failures.push_back(Arc::new(error));
    }

    pub(super) fn retain_worker_wait_failure(&mut self, error: Arc<RuntimeError>) -> bool {
        if self.worker_wait_failure.is_none() {
            self.worker_wait_failure = Some(error);
            self.worker_wait_wake_pending = true;
            return true;
        }
        false
    }

    pub(super) fn worker_wait_wake_pending(&self) -> bool {
        self.worker_wait_wake_pending
    }

    pub(super) fn retain_worker_wait_wake_failure(&mut self, error: RuntimeError) {
        if self.worker_wait_wake_failure.is_none() {
            self.worker_wait_wake_failure = Some(Arc::new(error));
        }
    }

    pub(super) fn retain_entered_yield_failure(&mut self, error: Arc<RuntimeError>) {
        if self.entered_yield_failure.is_none() {
            self.entered_yield_failure = Some(error);
            self.entered_yield_wake_pending = true;
        }
    }

    pub(super) fn entered_yield_wake_pending(&self) -> bool {
        self.entered_yield_wake_pending
    }

    pub(super) fn retain_entered_yield_wake_failure(&mut self, error: RuntimeError) {
        if self.entered_yield_wake_failure.is_none() {
            self.entered_yield_wake_failure = Some(Arc::new(error));
        }
    }

    pub(super) fn retain_entered_yield_client_failure(&mut self, error: RuntimeError) {
        if self.entered_yield_client_failure.is_none() {
            self.entered_yield_client_failure = Some(Arc::new(error));
        }
    }
}
