//! Exact native identities and retirement evidence for reentrant transfers.

use std::sync::Arc;

use super::*;

impl NativeState {
    pub(super) fn retire_shutdown_transfer_guards(
        &mut self,
        instances: &[runtime::Win16DdeNativeInstanceReceipt],
    ) -> Result<(Vec<runtime::Win16DdeNativeTransferGuardReceipt>, bool), RuntimeError> {
        let mut receipts = Vec::new();
        receipts
            .try_reserve(self.data_transfer_guards.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact DDE transfer-guard shutdown receipts",
                    error,
                )
            })?;
        let mut guards = Vec::new();
        guards
            .try_reserve(self.data_transfer_guards.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "snapshot exact DDE transfer-guard identities for shutdown",
                    error,
                )
            })?;
        guards.extend(
            self.data_transfer_guards
                .iter()
                .map(|(key, guard)| (*key, *guard)),
        );
        for ((operation, data), guard) in guards {
            if guard.instance_retired {
                self.data_transfer_guards.remove(&(operation, data));
                receipts.push(runtime::Win16DdeNativeTransferGuardReceipt {
                    operation,
                    data,
                    instance: guard.instance,
                    source: runtime::Win16DdeNativeTransferGuardSource::InstanceUninitialized,
                    failure: instances
                        .iter()
                        .find(|entry| entry.instance == guard.instance)
                        .and_then(|entry| entry.failure.clone()),
                });
            } else {
                receipts.push(runtime::Win16DdeNativeTransferGuardReceipt {
                    operation,
                    data,
                    instance: guard.instance,
                    source: runtime::Win16DdeNativeTransferGuardSource::Retained,
                    failure: Some(Arc::new(RuntimeError::new(
                        Kind::HostFailure,
                        "DDE transfer guard has no successful exact-instance uninitialize receipt",
                    ))),
                });
            }
        }
        Ok((receipts, self.data_transfer_guards.is_empty()))
    }

    pub(super) fn register_data_transfer_guard(
        &mut self,
        operation: Win16HostDdeOperation,
        token: Win16HostDdeData,
        instance: Win16HostDdeInstance,
        native: HDDEDATA,
        origin: DataOrigin,
        format: u16,
    ) -> Result<(), RuntimeError> {
        if !self.data.get(&token).is_some_and(|record| {
            record.available
                && record.instance == instance
                && record.native == native
                && record.origin == origin
                && record.format == format
        }) {
            return Err(protocol_error(
                "DDE transfer guard source identity changed before call",
            ));
        }
        if self.data_transfer_guards.contains_key(&(operation, token)) {
            return Err(protocol_error(
                "DDE transfer guard identity was registered twice",
            ));
        }
        self.data_transfer_guards.insert(
            (operation, token),
            PendingDataTransferGuard {
                token,
                instance,
                native: native as usize,
                format,
                origin,
                guest_free_seen: false,
                instance_retired: false,
                begun: false,
            },
        );
        Ok(())
    }

    pub(super) fn begin_data_transfer(
        &mut self,
        operation: Win16HostDdeOperation,
        token: Win16HostDdeData,
        instance: Win16HostDdeInstance,
        native: HDDEDATA,
        origin: DataOrigin,
        format: u16,
        adapter_owns_source: bool,
    ) -> Result<(), RuntimeError> {
        let guard = self
            .data_transfer_guards
            .get(&(operation, token))
            .ok_or_else(|| protocol_error("DDE transaction lost its pre-call transfer guard"))?;
        if guard.token != token
            || guard.instance != instance
            || guard.native != native as usize
            || guard.format != format
            || guard.origin != origin
            || guard.begun
        {
            return Err(protocol_error(
                "DDE transaction transfer guard identity changed before native entry",
            ));
        }
        let record = self.data.get_mut(&token).ok_or_else(|| {
            protocol_error("DDE transaction source disappeared before native entry")
        })?;
        if !record.available
            || record.instance != instance
            || record.native != native
            || record.format != format
            || record.origin != origin
        {
            return Err(protocol_error(
                "DDE transaction source changed before native entry",
            ));
        }
        if adapter_owns_source
            && !matches!(
                origin,
                DataOrigin::Created {
                    retain_after_transfer: false
                }
            )
        {
            return Err(protocol_error(
                "DDE adapter ownership is only valid for consumed guest-created data",
            ));
        }
        if let DataOrigin::Created {
            retain_after_transfer,
        } = origin
        {
            record.transferred = true;
            if !retain_after_transfer {
                // The execute command is translated to an owned UTF-16 buffer,
                // so DDEML never receives this original guest-ANSI handle.
                // Take responsibility for its lifetime before making the
                // guest token unavailable, matching ClientTransaction's
                // consumed-input contract without letting DDEML free it.
                record.native_owned = adapter_owns_source;
                record.available = false;
                if self.data_by_native.get(&(native as usize)) == Some(&token) {
                    self.data_by_native.remove(&(native as usize));
                }
            }
        }
        self.data_transfer_guards
            .get_mut(&(operation, token))
            .ok_or_else(|| protocol_error("DDE transaction transfer guard disappeared"))?
            .begun = true;
        Ok(())
    }

    pub(super) fn cancel_unbegun_data_transfer_guard(
        &mut self,
        operation: Win16HostDdeOperation,
        token: Win16HostDdeData,
        instance: Win16HostDdeInstance,
        native: HDDEDATA,
        origin: DataOrigin,
        format: u16,
    ) -> Result<(), RuntimeError> {
        let guard = self
            .data_transfer_guards
            .get(&(operation, token))
            .copied()
            .ok_or_else(|| protocol_error("DDE transaction lost its registered transfer guard"))?;
        if guard.token != token
            || guard.instance != instance
            || guard.native != native as usize
            || guard.origin != origin
            || guard.format != format
            || guard.begun
        {
            return Err(protocol_error(
                "DDE transaction cannot cancel a mismatched or entered transfer guard",
            ));
        }
        self.data_transfer_guards.remove(&(operation, token));
        Ok(())
    }

    pub(super) fn finish_data_transfer_guard(
        &mut self,
        operation: Win16HostDdeOperation,
        token: Win16HostDdeData,
        instance: Win16HostDdeInstance,
        native: HDDEDATA,
        origin: DataOrigin,
        format: u16,
    ) -> Result<(bool, bool), RuntimeError> {
        let guard = self
            .data_transfer_guards
            .get(&(operation, token))
            .copied()
            .ok_or_else(|| protocol_error("DDE transaction lost its pending transfer guard"))?;
        if guard.token != token
            || guard.instance != instance
            || guard.native != native as usize
            || guard.origin != origin
            || guard.format != format
            || !guard.begun
        {
            return Err(protocol_error(
                "DDE transaction transfer guard source identity changed",
            ));
        }
        let record_matches = self.data.get(&token).is_some_and(|record| {
            record.instance == instance
                && record.native == native
                && record.origin == origin
                && record.format == format
        });
        if !record_matches && !guard.guest_free_seen && !guard.instance_retired {
            return Err(protocol_error(
                "DDE transaction source disappeared without a retirement receipt",
            ));
        }
        self.data_transfer_guards.remove(&(operation, token));
        Ok((guard.guest_free_seen, guard.instance_retired))
    }

    pub(super) fn note_guest_free_retirement(
        &mut self,
        token: Win16HostDdeData,
    ) -> Result<(), RuntimeError> {
        let captured = self
            .data
            .get(&token)
            .copied()
            .ok_or_else(|| protocol_error("successful DDE FreeData lost its host identity"))?;
        for guard in self.data_transfer_guards.values_mut().filter(|guard| {
            guard.token == token
                && guard.instance == captured.instance
                && guard.native == captured.native as usize
                && guard.origin == captured.origin
                && guard.format == captured.format
        }) {
            guard.guest_free_seen = true;
        }
        let record = self
            .data
            .get_mut(&token)
            .ok_or_else(|| protocol_error("successful DDE FreeData lost its host identity"))?;
        record.available = false;
        record.guest_freed = true;
        if self.data_by_native.get(&(record.native as usize)) == Some(&token) {
            self.data_by_native.remove(&(record.native as usize));
        }
        self.collect_consumed_data(token)?;
        Ok(())
    }
}
