//! Cycle-aware callbacks and edge retirement for published load groups.

use super::*;
use crate::pe32::{Pe32CallLease, Pe32LoadGroupId, Pe32LoadRecovery};

impl Pe32ThunkDispatcher {
    pub(super) fn next_group_process_detach(
        &mut self,
    ) -> Result<Option<Pe32CallLease>, RuntimeError> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(self.modules.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve PE32 grouped detach candidates",
                    error,
                )
            })?;
        for module in &self.modules {
            let identity = module.transaction.module();
            if self.registry.stage(identity.token()) != Some(crate::pe32::Pe32ModuleStage::Retiring)
                || !self.registry.entrypoint_needs_detach(identity)?
            {
                continue;
            }
            let Some(group) = self.registry.load_group(identity)? else {
                continue;
            };
            let member = module.group_member.as_ref().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "retiring PE32 group module lost its detach-order owner",
                )
            })?;
            if member.group != group {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "retiring PE32 module changed load-group identity",
                ));
            }
            let sequence = member.attach_sequence.ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "retiring attached PE32 module lost its attach sequence",
                )
            })?;
            candidates.push((sequence, group, identity));
        }
        candidates.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| left.2.cmp(&right.2))
        });
        for (_, group, module) in candidates {
            if let Some(lease) = self.registry.prepare_group_process_detach(group, module)? {
                return Ok(Some(lease));
            }
        }
        Ok(None)
    }

    pub(super) fn clear_retired_load_group_edges(&mut self) -> Result<bool, RuntimeError> {
        let count = self
            .modules
            .len()
            .checked_add(self.recoveries.len())
            .and_then(|count| {
                count.checked_add(if self.active_load_group.is_some() {
                    1
                } else {
                    0
                })
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "PE32 load-group identity count overflowed",
                )
            })?;
        let mut groups = Vec::<Pe32LoadGroupId>::new();
        groups.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 retiring load-group identities",
                error,
            )
        })?;
        for module in &self.modules {
            if let Some(group) = module.transaction.load_group()
                && !groups.contains(&group)
            {
                groups.push(group);
            }
        }
        for recovery in &self.recoveries {
            if let Pe32LoadRecovery::Module(transaction) = recovery
                && let Some(group) = transaction.load_group()
                && !groups.contains(&group)
            {
                groups.push(group);
            }
        }
        if let Some(group) = self.active_load_group.as_ref().map(|active| active.id)
            && !groups.contains(&group)
        {
            groups.push(group);
        }

        let mut cleared = false;
        let mut first_error = None;
        for group in groups {
            let members = match self.registry.retiring_group_members(group) {
                Ok(members) => members,
                Err(error) => {
                    keep_first(&mut first_error, error);
                    continue;
                }
            };
            if members.is_empty() {
                continue;
            }
            match self.registry.clear_retired_group_edges(group, &members) {
                Ok(Some(changed)) => cleared |= changed,
                Ok(None) => {}
                Err(error) => keep_first(&mut first_error, error),
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(cleared),
        }
    }
}
