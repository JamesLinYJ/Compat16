//! Exact transfer receipts close their guard only after source validation.

use super::*;
use crate::win16_dde::{Win16DdeAccessBlock, Win16DdeGuestBlockRetirementPhase};
use crate::{Win16HostDdeData, Win16HostDdeInstance};
use guest_core::{OwnerId, PhysAddr, memory::Memory};
use win16_abi::{AllocationFlags, GlobalHandle, GlobalHeap, SelectorTable};

const HOST_INSTANCE: Win16HostDdeInstance = Win16HostDdeInstance(91);
const HOST_DATA: Win16HostDdeData = Win16HostDdeData(92);
const CREATED: Origin = Origin::Created {
    retain_after_transfer: false,
};
const APPOWNED: Origin = Origin::Created {
    retain_after_transfer: true,
};

struct TransferFixture {
    dde: Win16DdeState,
    guard: DdeDataTransferGuard,
    retired: Vec<Win16DdeRetiredGuestBlock>,
}

impl TransferFixture {
    fn staged(origin: Origin, previously_transferred: bool) -> Self {
        let mut dde = Win16DdeState::new();
        let (owner, route) = dde.stage_initialization(0x1234_0000, 7).unwrap();
        dde.commit_initialization(owner, HOST_INSTANCE, route)
            .unwrap();
        let guest_data = dde.add_data(owner, HOST_DATA, origin).unwrap();
        if previously_transferred {
            assert_eq!(origin, APPOWNED);
            dde.mark_data_transferred(guest_data).unwrap();
        }
        let guard_id = dde.allocate_data_transfer_guard().unwrap();
        dde.register_data_transfer_guard(
            guest_data,
            guard_id,
            HOST_DATA,
            owner,
            origin,
            previously_transferred,
        )
        .unwrap();
        Self {
            dde,
            guard: DdeDataTransferGuard {
                guard_id,
                guest_data,
                host_data: HOST_DATA,
                owner,
                origin,
                previously_transferred,
                transfer_marked: matches!(origin, Origin::Created { .. }),
            },
            retired: Vec::new(),
        }
    }

    fn begun(origin: Origin, previously_transferred: bool) -> Self {
        let mut fixture = Self::staged(origin, previously_transferred);
        let guard = fixture.guard;
        fixture
            .dde
            .begin_data_transfer(
                guard.guest_data,
                guard.guard_id,
                guard.host_data,
                guard.owner,
                guard.origin,
            )
            .unwrap();
        fixture
    }

    fn settle(&mut self, source: Source) -> Result<(), RuntimeError> {
        settle_transfer_guard(&mut self.dde, self.guard, source, &mut self.retired)
    }

    fn assert_closed(&self) {
        assert_eq!(self.dde.pending_data_transfer_guard_count(), 0);
        assert_eq!(self.snapshot().guard, None);
    }

    fn snapshot(&self) -> SourceSnapshot {
        let guard = self.guard;
        SourceSnapshot {
            host: self.dde.host_data(guard.guest_data),
            owner: self.dde.instance_for_data(guard.guest_data),
            origin: self.dde.data_origin(guard.guest_data),
            transferred: self.dde.data_transfer_state(guard.guest_data),
            writable: self.dde.data_is_writable(guard.guest_data),
            block: self.dde.access_block(guard.guest_data),
            guard: self.dde.data_transfer_guard_retirement_state(
                guard.guard_id,
                guard.guest_data,
                guard.host_data,
                guard.owner,
                guard.origin,
            ),
            guards: self.dde.pending_data_transfer_guard_count(),
        }
    }

    fn assert_rejected_unchanged(&mut self, guard: DdeDataTransferGuard, source: Source) {
        let before = self.snapshot();
        let retired_before = retired_snapshot(&self.retired);
        let error =
            settle_transfer_guard(&mut self.dde, guard, source, &mut self.retired).unwrap_err();
        assert_eq!(error.kind(), Kind::InternalInvariant);
        assert_eq!(self.snapshot(), before);
        assert_eq!(retired_snapshot(&self.retired), retired_before);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SourceSnapshot {
    host: Option<Win16HostDdeData>,
    owner: Option<u32>,
    origin: Option<Origin>,
    transferred: Option<bool>,
    writable: Option<bool>,
    block: Option<Win16DdeAccessBlock>,
    guard: Option<(bool, bool, bool, bool)>,
    guards: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct RetiredSnapshot {
    identity: GlobalHandle,
    locked: bool,
    phase: Win16DdeGuestBlockRetirementPhase,
    selector_aliases: u16,
    page_locks: u16,
    internal_pins: u16,
    failure: Option<String>,
}

fn retired_snapshot(blocks: &[Win16DdeRetiredGuestBlock]) -> Vec<RetiredSnapshot> {
    blocks
        .iter()
        .map(|block| RetiredSnapshot {
            identity: block.identity,
            locked: block.locked,
            phase: block.phase,
            selector_aliases: block.selector_aliases,
            page_locks: block.page_locks,
            internal_pins: block.internal_pins,
            failure: block.failure.as_ref().map(ToString::to_string),
        })
        .collect()
}

struct BlockFixture {
    memory: Memory,
    heap: GlobalHeap,
    selectors: SelectorTable,
}

impl BlockFixture {
    fn new() -> Self {
        Self {
            memory: Memory::with_size(0x10_0000).unwrap(),
            heap: GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap(),
            selectors: SelectorTable::new().unwrap(),
        }
    }

    fn allocate(&mut self) -> (GlobalHandle, u32) {
        let identity = self
            .heap
            .alloc(&mut self.memory, OwnerId(1), 16, AllocationFlags::movable())
            .unwrap();
        let pointer = self
            .heap
            .lock(identity, &mut self.selectors, &self.memory)
            .unwrap();
        (identity, pointer.far_value())
    }
}

#[test]
fn consumed_receipt_removes_unleased_source_and_closes_exact_guard() {
    let mut fixture = TransferFixture::begun(CREATED, false);
    assert_eq!(fixture.dde.host_data(fixture.guard.guest_data), None);
    assert_eq!(
        fixture.dde.data_transfer_state(fixture.guard.guest_data),
        Some(true)
    );

    fixture
        .settle(Source::NativeCompletion(Outcome::Consumed))
        .unwrap();

    fixture.assert_closed();
    assert_eq!(
        fixture.dde.instance_for_data(fixture.guard.guest_data),
        None
    );
    assert_eq!(fixture.dde.data_origin(fixture.guard.guest_data), None);
    assert_eq!(
        fixture.dde.data_transfer_state(fixture.guard.guest_data),
        None
    );
    assert!(fixture.retired.is_empty());
}

#[test]
fn retained_read_only_receipt_keeps_appowned_source_and_closes_exact_guard() {
    for prior in [false, true] {
        let mut fixture = TransferFixture::begun(APPOWNED, prior);

        fixture
            .settle(Source::NativeCompletion(Outcome::RetainedReadOnly))
            .unwrap();

        fixture.assert_closed();
        assert_eq!(
            fixture.dde.host_data(fixture.guard.guest_data),
            Some(HOST_DATA)
        );
        assert_eq!(
            fixture.dde.data_transfer_state(fixture.guard.guest_data),
            Some(true)
        );
        assert_eq!(
            fixture.dde.data_is_writable(fixture.guard.guest_data),
            Some(false)
        );
        assert_eq!(
            fixture.dde.can_free_data(fixture.guard.guest_data),
            Some(true)
        );
        assert!(fixture.retired.is_empty());
    }
}

#[test]
fn copied_input_receipt_keeps_callback_and_client_result_sources_unchanged() {
    for origin in [Origin::CallbackBorrowed, Origin::ClientResult] {
        let mut fixture = TransferFixture::begun(origin, false);
        let before = fixture.snapshot();

        fixture
            .settle(Source::NativeCompletion(Outcome::CopiedInputRetained))
            .unwrap();

        fixture.assert_closed();
        let after = fixture.snapshot();
        assert_eq!(after.host, before.host);
        assert_eq!(after.owner, before.owner);
        assert_eq!(after.origin, before.origin);
        assert_eq!(after.transferred, Some(false));
        assert_eq!(after.writable, before.writable);
        assert!(fixture.retired.is_empty());
    }
}

#[test]
fn not_passed_sources_restore_the_captured_view_for_every_origin() {
    for source in [
        Source::NotEntered,
        Source::PreflightRejected,
        Source::NativeCompletion(Outcome::NotPassed),
    ] {
        for (origin, prior) in [
            (CREATED, false),
            (APPOWNED, false),
            (APPOWNED, true),
            (Origin::CallbackBorrowed, false),
            (Origin::ClientResult, false),
        ] {
            let mut fixture = TransferFixture::begun(origin, prior);

            fixture.settle(source).unwrap();

            fixture.assert_closed();
            assert_eq!(
                fixture.dde.host_data(fixture.guard.guest_data),
                Some(HOST_DATA)
            );
            assert_eq!(
                fixture.dde.data_transfer_state(fixture.guard.guest_data),
                Some(prior)
            );
            assert_eq!(
                fixture.dde.data_is_writable(fixture.guard.guest_data),
                Some(matches!(origin, Origin::Created { .. }) && !prior)
            );
            assert!(fixture.retired.is_empty());
        }
    }
}

#[test]
fn not_passed_after_nested_guest_free_never_resurrects_source() {
    let mut fixture = TransferFixture::begun(APPOWNED, false);
    fixture
        .dde
        .remove_data_after_guest_free(fixture.guard.guest_data)
        .unwrap()
        .unwrap();
    assert_eq!(fixture.snapshot().guard, Some((false, true, false, true)));

    fixture
        .settle(Source::NativeCompletion(Outcome::NotPassed))
        .unwrap();

    fixture.assert_closed();
    assert_eq!(fixture.dde.host_data(fixture.guard.guest_data), None);
    assert_eq!(
        fixture.dde.instance_for_data(fixture.guard.guest_data),
        None
    );
    assert!(fixture.retired.is_empty());
}

#[test]
fn wrong_guard_identity_prior_or_transfer_mark_preserves_exact_guard() {
    let fixture = TransferFixture::begun(CREATED, false);
    let guard = fixture.guard;
    let mut wrong_id = guard;
    wrong_id.guard_id += 1;
    let mut wrong_token = guard;
    wrong_token.guest_data += 1;
    let mut wrong_host = guard;
    wrong_host.host_data = Win16HostDdeData(HOST_DATA.0 + 1);
    let mut wrong_owner = guard;
    wrong_owner.owner += 1;
    let mut wrong_origin = guard;
    wrong_origin.origin = APPOWNED;
    let mut wrong_prior = guard;
    wrong_prior.previously_transferred = true;
    let mut wrong_mark = guard;
    wrong_mark.transfer_marked = false;
    let mut fixture = fixture;

    for wrong in [
        wrong_id,
        wrong_token,
        wrong_host,
        wrong_owner,
        wrong_origin,
        wrong_prior,
        wrong_mark,
    ] {
        fixture.assert_rejected_unchanged(wrong, Source::NativeCompletion(Outcome::Consumed));
        assert_eq!(fixture.dde.pending_data_transfer_guard_count(), 1);
    }

    fixture
        .settle(Source::NativeCompletion(Outcome::Consumed))
        .unwrap();
    fixture.assert_closed();
}

#[test]
fn changed_live_provenance_preserves_captured_guard_evidence() {
    let mut fixture = TransferFixture::begun(Origin::CallbackBorrowed, false);
    assert_eq!(
        fixture
            .dde
            .add_client_result_data(fixture.guard.owner, HOST_DATA),
        Some(fixture.guard.guest_data)
    );
    assert_eq!(
        fixture.dde.data_origin(fixture.guard.guest_data),
        Some(Origin::ClientResult)
    );

    fixture.assert_rejected_unchanged(
        fixture.guard,
        Source::NativeCompletion(Outcome::CopiedInputRetained),
    );
    assert_eq!(fixture.dde.pending_data_transfer_guard_count(), 1);
}

#[test]
fn receipts_for_the_wrong_source_origin_do_not_consume_guard() {
    for (origin, outcome) in [
        (CREATED, Outcome::RetainedReadOnly),
        (CREATED, Outcome::CopiedInputRetained),
        (APPOWNED, Outcome::Consumed),
        (APPOWNED, Outcome::CopiedInputRetained),
        (Origin::CallbackBorrowed, Outcome::Consumed),
        (Origin::CallbackBorrowed, Outcome::RetainedReadOnly),
        (Origin::ClientResult, Outcome::Consumed),
        (Origin::ClientResult, Outcome::RetainedReadOnly),
    ] {
        let mut fixture = TransferFixture::begun(origin, false);
        fixture.assert_rejected_unchanged(fixture.guard, Source::NativeCompletion(outcome));
        assert_eq!(fixture.dde.pending_data_transfer_guard_count(), 1);
    }
}

#[test]
fn unbegun_native_receipts_and_retained_source_preserve_guard() {
    for (origin, source) in [
        (CREATED, Source::NativeCompletion(Outcome::Consumed)),
        (
            APPOWNED,
            Source::NativeCompletion(Outcome::RetainedReadOnly),
        ),
        (
            Origin::CallbackBorrowed,
            Source::NativeCompletion(Outcome::CopiedInputRetained),
        ),
        (
            Origin::ClientResult,
            Source::NativeCompletion(Outcome::CopiedInputRetained),
        ),
        (CREATED, Source::InstanceUninitialized),
    ] {
        let mut fixture = TransferFixture::staged(origin, false);
        fixture.assert_rejected_unchanged(fixture.guard, source);
        assert_eq!(fixture.snapshot().guard, Some((false, false, false, false)));
        fixture.settle(Source::NotEntered).unwrap();
        fixture.assert_closed();
    }
    let mut fixture = TransferFixture::begun(CREATED, false);
    fixture.assert_rejected_unchanged(fixture.guard, Source::Retained);
}

#[test]
fn missing_guard_is_never_inferred_to_be_a_successful_settlement() {
    for source in [
        Source::NotEntered,
        Source::PreflightRejected,
        Source::NativeCompletion(Outcome::Consumed),
        Source::NativeCompletion(Outcome::RetainedReadOnly),
        Source::NativeCompletion(Outcome::CopiedInputRetained),
        Source::NativeCompletion(Outcome::NotPassed),
        Source::InstanceUninitialized,
    ] {
        let mut fixture = TransferFixture::begun(APPOWNED, false);
        fixture
            .dde
            .cancel_data_transfer_guard(fixture.guard.guard_id)
            .unwrap();
        fixture.assert_rejected_unchanged(fixture.guard, source);
    }
    let mut fixture = TransferFixture::begun(CREATED, false);
    fixture
        .settle(Source::NativeCompletion(Outcome::Consumed))
        .unwrap();
    fixture.assert_rejected_unchanged(fixture.guard, Source::NativeCompletion(Outcome::Consumed));
}

#[test]
fn instance_uninitialized_receipt_closes_new_retirement_evidence() {
    for origin in [
        CREATED,
        APPOWNED,
        Origin::CallbackBorrowed,
        Origin::ClientResult,
    ] {
        let mut fixture = TransferFixture::begun(origin, false);
        let before = fixture.snapshot();
        assert_eq!(before.guard, Some((false, false, false, true)));

        // The receipt changes the captured uninitialized bit from false to
        // true before closing it. The helper's close assertion checks that
        // new evidence rather than comparing with the old false bit.
        fixture.settle(Source::InstanceUninitialized).unwrap();

        fixture.assert_closed();
        let after = fixture.snapshot();
        assert_eq!(after.host, before.host);
        assert_eq!(after.owner, before.owner);
        assert_eq!(after.origin, before.origin);
        assert_eq!(after.transferred, before.transferred);
        assert_eq!(
            fixture.dde.host_instance(fixture.guard.owner),
            Some(HOST_INSTANCE)
        );
        assert!(fixture.retired.is_empty());
    }
}

#[test]
fn already_uninitialized_instance_closes_without_recreating_data() {
    for source in [
        Source::InstanceUninitialized,
        Source::NativeCompletion(Outcome::NotPassed),
        Source::NativeCompletion(Outcome::Consumed),
    ] {
        let mut fixture = TransferFixture::begun(CREATED, false);
        fixture.dde.remove_instance(fixture.guard.owner).unwrap();
        assert_eq!(fixture.snapshot().guard, Some((false, false, true, true)));

        fixture.settle(source).unwrap();

        fixture.assert_closed();
        assert_eq!(fixture.dde.host_data(fixture.guard.guest_data), None);
        assert_eq!(
            fixture.dde.instance_for_data(fixture.guard.guest_data),
            None
        );
        assert!(fixture.retired.is_empty());
    }
}

#[test]
fn retirement_evidence_with_visible_alias_is_rejected_without_losing_guard() {
    let mut fixture = TransferFixture::begun(APPOWNED, false);
    let guard = fixture.guard;
    fixture
        .dde
        .mark_transfer_guard_instance_uninitialized(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .unwrap();
    assert_eq!(
        fixture.dde.host_data(guard.guest_data),
        Some(guard.host_data)
    );

    for source in [
        Source::InstanceUninitialized,
        Source::NativeCompletion(Outcome::NotPassed),
        Source::NativeCompletion(Outcome::RetainedReadOnly),
    ] {
        fixture.assert_rejected_unchanged(guard, source);
        assert_eq!(fixture.snapshot().guard, Some((false, false, true, true)));
    }
}

#[test]
fn consumed_receipt_keeps_access_lease_until_its_matching_unaccess() {
    let mut fixture = TransferFixture::staged(CREATED, false);
    let mut blocks = BlockFixture::new();
    let (identity, pointer) = blocks.allocate();
    let guard = fixture.guard;
    fixture
        .dde
        .retain_access_block(
            guard.guest_data,
            identity.raw().0,
            identity,
            pointer,
            16,
            true,
        )
        .unwrap();
    fixture
        .dde
        .begin_data_transfer(
            guard.guest_data,
            guard.guard_id,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .unwrap();

    fixture
        .settle(Source::NativeCompletion(Outcome::Consumed))
        .unwrap();

    fixture.assert_closed();
    assert_eq!(fixture.dde.host_data(guard.guest_data), None);
    assert_eq!(
        fixture.dde.host_data_for_unaccess(guard.guest_data),
        Some(HOST_DATA)
    );
    assert_eq!(
        fixture.dde.access_block(guard.guest_data).unwrap().identity,
        identity
    );
    assert!(fixture.retired.is_empty());
    assert_eq!(
        fixture
            .dde
            .take_access_block(guard.guest_data)
            .unwrap()
            .identity,
        identity
    );
    assert_eq!(
        fixture
            .dde
            .release_unowned_data(guard.guest_data)
            .unwrap()
            .host,
        HOST_DATA
    );
    assert_eq!(fixture.dde.instance_for_data(guard.guest_data), None);
    assert_eq!(blocks.heap.allocation_count(), 1);
}

#[test]
fn existing_retained_block_owner_survives_successful_transfer_settlement() {
    let mut fixture = TransferFixture::begun(CREATED, false);
    let mut blocks = BlockFixture::new();
    let (identity, _) = blocks.allocate();
    let mut retained = Win16DdeRetiredGuestBlock::pending(identity, true);
    retained.phase = Win16DdeGuestBlockRetirementPhase::Retained;
    retained.selector_aliases = 1;
    retained.internal_pins = 1;
    retained.failure = Some(std::sync::Arc::new(RuntimeError::new(
        Kind::HostFailure,
        "test keeps an outstanding guest-block retirement",
    )));
    fixture.retired.push(retained);
    let before = retired_snapshot(&fixture.retired);

    fixture
        .settle(Source::NativeCompletion(Outcome::Consumed))
        .unwrap();

    fixture.assert_closed();
    assert_eq!(retired_snapshot(&fixture.retired), before);
    assert_eq!(blocks.heap.allocation_count(), 1);
}

#[test]
fn duplicate_access_block_retirement_owner_preserves_transfer_and_queue() {
    let mut fixture = TransferFixture::staged(CREATED, false);
    let mut blocks = BlockFixture::new();
    let (identity, pointer) = blocks.allocate();
    fixture
        .dde
        .retain_access_block(
            fixture.guard.guest_data,
            identity.raw().0,
            identity,
            pointer,
            16,
            true,
        )
        .unwrap();
    let guard = fixture.guard;
    fixture
        .dde
        .begin_data_transfer(
            guard.guest_data,
            guard.guard_id,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .unwrap();
    fixture
        .retired
        .push(Win16DdeRetiredGuestBlock::pending(identity, true));

    fixture.assert_rejected_unchanged(fixture.guard, Source::NativeCompletion(Outcome::Consumed));

    assert_eq!(fixture.dde.pending_data_transfer_guard_count(), 1);
    assert_eq!(fixture.retired.len(), 1);
    assert_eq!(fixture.retired[0].identity, identity);
    assert_eq!(
        fixture
            .dde
            .access_block(fixture.guard.guest_data)
            .unwrap()
            .identity,
        identity
    );
}
