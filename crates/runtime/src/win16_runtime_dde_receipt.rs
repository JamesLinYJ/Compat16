//! Exact ClientTransaction result and transfer receipt handling.

use super::*;
use crate::Win16HostDdeDataTransferOutcome;
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
        continuation: &mut Win16DdeContinuation,
        result: &Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        validate_normal_transfer_receipt(continuation, result)?;
        continuation.validate_transfer_settlement_record(result)?;
        if continuation.transfer_guard_retired {
            continuation.require_transfer_settlement(result)?;
            return self.retry_dde_guest_block_retirements();
        }
        if let Some(guard) = continuation.data_transfer_guard {
            let receipt = result.data_transfer.as_ref().expect("validated transfer receipt");
            super::super::transfer::settle_transfer_guard(
                self.dde, guard,
                crate::Win16DdeNativeTransferGuardSource::NativeCompletion(receipt.outcome),
                self.dde_retired_guest_blocks,
            )?;
        }
        continuation.mark_transfer_settled(result);
        self.retry_dde_guest_block_retirements()
    }

}

pub(in crate::win16_runtime) fn validate_normal_transfer_receipt(
    continuation: &Win16DdeContinuation,
    result: &Win16HostDdeResult,
) -> Result<(), RuntimeError> {
    validate_transfer_receipt(&continuation.request, continuation.instance,
        continuation.data_transfer_guard, continuation.outputs.transaction_result.is_some(), result)
}

pub(in crate::win16_runtime) fn validate_transfer_receipt(
    request: &Win16DdeRequest,
    instance: Option<u32>,
    guard: Option<super::super::DdeDataTransferGuard>,
    transaction_output: bool,
    result: &Win16HostDdeResult,
) -> Result<(), RuntimeError> {
    match (request, guard, result.data_transfer) {
        (Win16DdeRequest::ClientTransaction {
            data: win16_abi::Win16DdeTransactionData::DataHandle(guest), ..
        }, Some(guard), Some(receipt))
            if *guest == guard.guest_data && receipt.token == guard.host_data
                && instance == Some(guard.owner) =>
        {
            validate_transaction_transfer_result(request, transaction_output, result)
        }
        (Win16DdeRequest::ClientTransaction {
            data: win16_abi::Win16DdeTransactionData::DataHandle(_), ..
        }, _, _) | (_, Some(_), _) | (_, _, Some(_)) => Err(invariant(
            "DDE transfer receipt does not match its exact request and input owner")),
        (_, None, None) => Ok(()),
    }
}

fn validate_transaction_transfer_result(
    request: &Win16DdeRequest,
    transaction_output: bool,
    result: &Win16HostDdeResult,
) -> Result<(), RuntimeError> {
    use Win16DdeRequest as R;
    use Win16HostDdeValue as V;

    let R::ClientTransaction {
        data: win16_abi::Win16DdeTransactionData::DataHandle(_),
        result_output,
        ..
    } = request
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
        if *succeeded || result.transaction_result.is_some() || result.dde_error == dde_error::NO_ERROR {
            return Err(invariant(
                "preflight DDE transaction returned native-only outputs",
            ));
        }
        return Ok(());
    }
    match (
        *result_output != 0,
        result.transaction_result,
        transaction_output,
    ) {
        (true, Some(_), true) | (false, None, false) => Ok(()),
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
