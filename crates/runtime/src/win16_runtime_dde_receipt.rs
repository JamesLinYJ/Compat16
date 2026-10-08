//! Exact ClientTransaction result and transfer receipt handling.

use super::*;
use crate::Win16HostDdeDataTransferOutcome;
use crate::win16_dde::Win16DdeDataOrigin;
use crate::win16_runtime::guest_ranges::commit_guest_writes_with_selectors;
use compat_services::win16_dde::error as dde_error;

// Windows 3.1 DDEML.H: XTYP_REQUEST = 0x00b0 | XCLASS_DATA; the low type
// bits are compared through the ABI transaction_type::TYPE_MASK.
const DDE_XTYP_REQUEST: u32 = 0x20b0;
const DDE_TIMEOUT_ASYNC: u32 = u32::MAX;

impl Win16State {
    pub(super) fn validate_dde_transaction_shape(
        continuation: &Win16DdeContinuation,
        result: &Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        use Win16DdeRequest as R;
        use Win16HostDdeValue as V;

        let R::ClientTransaction {
            data: input,
            result_output,
            timeout,
            transaction_type,
            ..
        } = &continuation.request
        else {
            if result.transaction_result.is_some() || result.data_transfer.is_some() {
                return Err(invariant(
                    "non-transaction DDE operation carried transaction-only payload",
                ));
            }
            return Ok(());
        };
        let V::ClientTransaction {
            data,
            succeeded,
            entered_native,
        } = &result.value
        else {
            return Err(invariant(
                "DDE ClientTransaction returned the wrong result value type",
            ));
        };
        if (*succeeded && result.dde_error != dde_error::NO_ERROR)
            || (!*succeeded && data.is_some())
        {
            return Err(invariant(
                "DDE transaction value contradicts its DMLERR or result-data state",
            ));
        }
        if *succeeded {
            let should_return_data = *timeout != DDE_TIMEOUT_ASYNC
                && compat_services::win16_dde::transaction_type::base(u32::from(*transaction_type))
                    == compat_services::win16_dde::transaction_type::base(DDE_XTYP_REQUEST);
            if data.is_some() != should_return_data {
                return Err(invariant(
                    "DDE transaction data result does not match synchronous XTYP_REQUEST semantics",
                ));
            }
        }
        if !*entered_native && (*succeeded || result.dde_error == dde_error::NO_ERROR) {
            return Err(invariant(
                "DDE transaction reported success or no error without native entry",
            ));
        }
        if *entered_native {
            match (
                *result_output != 0,
                result.transaction_result,
                continuation.outputs.transaction_result.as_ref(),
            ) {
                (true, Some(_), Some(_)) | (false, None, None) => {}
                (true, _, _) => {
                    return Err(invariant(
                        "entered DDE transaction omitted its requested pdwResult value",
                    ));
                }
                (false, Some(_), _) => {
                    return Err(invariant(
                        "entered DDE transaction returned an unrequested pdwResult value",
                    ));
                }
                (_, _, _) => {
                    return Err(invariant(
                        "DDE transaction result capture does not match its request",
                    ));
                }
            }
        } else if result.transaction_result.is_some() {
            return Err(invariant(
                "preflight DDE transaction returned an uninitialized pdwResult",
            ));
        }

        match (input, result.data_transfer.as_ref()) {
            (win16_abi::Win16DdeTransactionData::DataHandle(_), Some(receipt)) => {
                let not_passed =
                    matches!(receipt.outcome, Win16HostDdeDataTransferOutcome::NotPassed);
                if not_passed == *entered_native {
                    return Err(invariant(
                        "DDE transaction entered-native flag contradicts its transfer receipt",
                    ));
                }
            }
            (win16_abi::Win16DdeTransactionData::DataHandle(_), None) => {
                return Err(invariant(
                    "existing DDE data input omitted its transfer receipt",
                ));
            }
            (_, Some(_)) => {
                return Err(invariant(
                    "non-handle DDE transaction carried a data transfer receipt",
                ));
            }
            (_, None) => {}
        }
        Ok(())
    }
}

impl super::DdeCompletionAccess<'_> {

    pub(super) fn commit_failed_transaction_result(
        &self,
        continuation: &Win16DdeContinuation,
        result: &Win16HostDdeResult,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        use Win16DdeRequest as R;
        use Win16HostDdeValue as V;
        match (&continuation.request, &result.value) {
            (
                R::ClientTransaction { result_output, .. },
                V::ClientTransaction {
                    entered_native: true,
                    ..
                },
            ) => {
                match (
                    *result_output != 0,
                    result.transaction_result,
                    continuation.outputs.transaction_result.as_ref(),
                ) {
                    (true, Some(value), Some(output)) => commit_guest_writes_with_selectors(
                        self.selectors(),
                        memory,
                        vec![(output.clone(), value.to_le_bytes().to_vec())],
                    ),
                    (false, None, None) => Ok(()),
                    (true, _, _) => Err(invariant(
                        "native failed DDE transaction omitted its requested pdwResult",
                    )),
                    (false, Some(_), _) => Err(invariant(
                        "native failed DDE transaction returned an unrequested pdwResult",
                    )),
                    (_, _, _) => Err(invariant(
                        "failed DDE transaction result capture does not match its request",
                    )),
                }
            }
            (
                R::ClientTransaction { .. },
                V::ClientTransaction {
                    entered_native: false,
                    ..
                },
            ) => {
                if result.transaction_result.is_some() {
                    return Err(invariant(
                        "preflight DDE transaction returned an uninitialized pdwResult",
                    ));
                }
                Ok(())
            }
            (R::ClientTransaction { .. }, _) => Err(invariant(
                "failed DDE transaction completion has the wrong result type",
            )),
            (_, _) if result.transaction_result.is_some() => Err(invariant(
                "failed non-transaction DDE operation carried a transaction result",
            )),
            _ => Ok(()),
        }
    }

    pub(super) fn finish_data_transfer_receipt(
        &mut self,
        continuation: &Win16DdeContinuation,
        result: &Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        use Win16DdeRequest as R;
        let guard = continuation.data_transfer_guard;
        if let Some(guard) = guard {
            if self.dde.data_transfer_guard_matches(
                guard.guard_id,
                guard.guest_data,
                guard.host_data,
                guard.owner,
                guard.origin,
            ) != Some(true)
            {
                return Err(invariant(
                    "DDE input transfer guard or its identity disappeared",
                ));
            }
        }
        if let (Some(guard), Some(receipt)) = (guard, result.data_transfer.as_ref()) {
            if receipt.token != guard.host_data || continuation.instance != Some(guard.owner) {
                return Err(invariant(
                    "DDE transaction transfer receipt identifies the wrong input data",
                ));
            }
            validate_transaction_transfer_result(continuation, result)?;
            if matches!(receipt.outcome, Win16HostDdeDataTransferOutcome::NotPassed) {
                self.dde
                    .restore_data_transfer(
                        guard.guard_id,
                        guard.guest_data,
                        guard.host_data,
                        guard.owner,
                        guard.origin,
                    )
                    .ok_or_else(|| {
                        invariant(
                            "DDE input data disappeared before restoring a NotPassed transfer",
                        )
                    })?;
            }
        }
        let evidence = match guard {
            Some(guard) => Some(
                self.dde
                    .take_guest_free_evidence(
                        guard.guard_id,
                        guard.guest_data,
                        guard.host_data,
                        guard.owner,
                        guard.origin,
                    )
                    .ok_or_else(|| {
                        invariant("DDE input transfer guard or its identity disappeared")
                    })?,
            ),
            None => None,
        };
        match (&continuation.request, guard, result.data_transfer.as_ref()) {
            (
                R::ClientTransaction {
                    data: win16_abi::Win16DdeTransactionData::DataHandle(guest),
                    ..
                },
                Some(guard),
                Some(receipt),
            ) if *guest == guard.guest_data => {
                if receipt.token != guard.host_data || continuation.instance != Some(guard.owner) {
                    return Err(invariant(
                        "DDE transaction transfer receipt identifies the wrong input data",
                    ));
                }
                let (captured_previously_transferred, source_freed, instance_uninitialized) =
                    evidence.ok_or_else(|| {
                        invariant("DDE transfer receipt lost its registered source evidence")
                    })?;
                if captured_previously_transferred != guard.previously_transferred {
                    return Err(invariant(
                        "DDE transfer guard changed its captured prior state",
                    ));
                }
                validate_transaction_transfer_result(continuation, result)?;
                let live_origin = self.dde.data_origin(guard.guest_data);
                let live_owner = self.dde.instance_for_data(guard.guest_data);
                let live_host = self.dde.host_data(guard.guest_data);
                let live_matches = live_host == Some(guard.host_data)
                    && live_owner == Some(guard.owner)
                    && live_origin == Some(guard.origin);
                match receipt.outcome {
                    Win16HostDdeDataTransferOutcome::NotPassed => {
                        if result.dde_error == dde_error::NO_ERROR {
                            return Err(invariant(
                                "DDE NotPassed receipt accompanied a success-shaped transaction result",
                            ));
                        }
                        if !source_freed && !instance_uninitialized && !live_matches {
                            return Err(invariant(
                                "DDE input identity changed before a NotPassed receipt",
                            ));
                        }
                    }
                    Win16HostDdeDataTransferOutcome::Consumed => {
                        if source_freed {
                            return Err(invariant(
                                "DDE consumed receipt conflicts with a guest FreeData retirement",
                            ));
                        }
                        if !matches!(
                            guard.origin,
                            Win16DdeDataOrigin::Created {
                                retain_after_transfer: false
                            }
                        ) || !guard.transfer_marked
                        {
                            return Err(invariant(
                                "DDE host consumed a non-transferable or mismatched data handle",
                            ));
                        }
                        if instance_uninitialized {
                            if live_matches {
                                return Err(invariant(
                                    "successful DdeUninitialize left its consumed input mapping live",
                                ));
                            }
                        } else {
                            if !live_matches
                                || self.dde.data_transfer_state(guard.guest_data) != Some(true)
                            {
                                return Err(invariant(
                                    "DDE host consumed a non-transferable or mismatched data handle",
                                ));
                            }
                            let removed = self
                                .dde
                                .consume_data_transfer(guard.guest_data)
                                .map_err(|_| {
                                    invariant(
                                        "DDE consumed receipt contradicted runtime data state",
                                    )
                                })?;
                            if let Some(removed) = removed {
                                if let Some(block) = removed.access_block {
                                    self.free_runtime_dde_block(block.identity)?;
                                }
                            }
                        }
                    }
                    Win16HostDdeDataTransferOutcome::RetainedReadOnly => {
                        if !matches!(
                            guard.origin,
                            Win16DdeDataOrigin::Created {
                                retain_after_transfer: true
                            }
                        ) || !guard.transfer_marked
                        {
                            return Err(invariant(
                                "retained DDE input data was not kept read-only",
                            ));
                        }
                        if source_freed || instance_uninitialized {
                            if live_matches {
                                return Err(invariant(
                                    "DDE source retirement evidence conflicts with a live APPOWNED source",
                                ));
                            }
                        } else if !live_matches
                            || self.dde.data_transfer_state(guard.guest_data) != Some(true)
                            || self.dde.data_is_writable(guard.guest_data) != Some(false)
                        {
                            return Err(invariant(
                                "retained DDE input data was not kept read-only",
                            ));
                        }
                    }
                    Win16HostDdeDataTransferOutcome::CopiedInputRetained => {
                        if !matches!(
                            guard.origin,
                            Win16DdeDataOrigin::CallbackBorrowed | Win16DdeDataOrigin::ClientResult
                        ) || guard.transfer_marked
                        {
                            return Err(invariant(
                                "DDE host copied a source with unsupported provenance",
                            ));
                        }
                        if source_freed || instance_uninitialized {
                            if live_matches {
                                return Err(invariant(
                                    "DDE source retirement evidence conflicts with a live copied source",
                                ));
                            }
                        } else if !live_matches
                            || self.dde.data_transfer_state(guard.guest_data)
                                != Some(guard.previously_transferred)
                        {
                            return Err(invariant(
                                "copied DDE input source changed identity while still live",
                            ));
                        }
                    }
                }
            }
            (
                R::ClientTransaction {
                    data: win16_abi::Win16DdeTransactionData::DataHandle(_),
                    ..
                },
                None,
                _,
            ) => return Err(invariant("DDE transaction lost its input transfer guard")),
            (_, Some(_), _) => {
                return Err(invariant("DDE transfer guard does not match its request"));
            }
            (_, None, Some(_)) => return Err(invariant("unexpected DDE data transfer receipt")),
            (_, None, None) => {}
        }
        Ok(())
    }
}

fn validate_transaction_transfer_result(
    continuation: &Win16DdeContinuation,
    result: &Win16HostDdeResult,
) -> Result<(), RuntimeError> {
    use Win16DdeRequest as R;
    use Win16HostDdeValue as V;

    let R::ClientTransaction {
        data: win16_abi::Win16DdeTransactionData::DataHandle(_),
        result_output,
        ..
    } = &continuation.request
    else {
        return Err(invariant(
            "DDE transfer receipt is not attached to an existing data input",
        ));
    };
    let V::ClientTransaction {
        data,
        succeeded,
        entered_native,
    } = &result.value
    else {
        return Err(invariant(
            "DDE transfer receipt has the wrong transaction result value",
        ));
    };
    if (*succeeded && result.dde_error != dde_error::NO_ERROR) || (!*succeeded && data.is_some()) {
        return Err(invariant(
            "DDE transaction status fields contradict the DMLERR result",
        ));
    }
    if let Some(receipt) = result.data_transfer.as_ref() {
        let not_passed = matches!(receipt.outcome, Win16HostDdeDataTransferOutcome::NotPassed);
        if not_passed == *entered_native {
            return Err(invariant(
                "DDE transaction entered-native flag contradicts its transfer receipt",
            ));
        }
    } else {
        return Err(invariant(
            "existing DDE data input omitted its transfer receipt",
        ));
    }
    if !*entered_native {
        if *succeeded || result.transaction_result.is_some() {
            return Err(invariant(
                "preflight DDE transaction returned native-only outputs",
            ));
        }
        return Ok(());
    }
    match (
        *result_output != 0,
        result.transaction_result,
        continuation.outputs.transaction_result.as_ref(),
    ) {
        (true, Some(_), Some(_)) | (false, None, None) => Ok(()),
        (true, _, _) => Err(invariant(
            "entered DDE transaction omitted its requested pdwResult value",
        )),
        (false, Some(_), _) => Err(invariant(
            "entered DDE transaction returned an unrequested pdwResult value",
        )),
        (_, _, _) => Err(invariant(
            "DDE transaction result capture does not match its request",
        )),
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    super::invariant(message)
}
