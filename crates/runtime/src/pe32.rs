//! Private ownership and call identities for legacy PE32 guest modules.
//!
//! This is runtime-side bookkeeping only. It does not load native x86 DLLs or
//! make a PE export callable until the guest executor accepts a prepared lease.

mod identity;
mod image_arena;
mod load;
mod loader;
mod registry;
mod types;

pub(crate) use identity::{
    Pe32CallLease, Pe32CallLeaseState, Pe32ModuleIdentity, Pe32ProcedureToken,
    Pe32TypedHostServiceId,
};
pub(crate) use image_arena::{Pe32ImageArena, Pe32ImageLease};
pub(crate) use loader::{
    Pe32LoadRecovery, Pe32LoadTransaction, apply_group_iat_writes,
    preflight_unlinked_group_image, prepare_unlinked_group_module,
};
pub(crate) use registry::{Pe32CallCompletion, Pe32ModuleRegistry};
pub(crate) use types::{
    Pe32CallReason, Pe32CallableTarget, Pe32ExportKey, Pe32GuestAddress, Pe32GuestImage,
    Pe32IatWrite, Pe32ImportBinding, Pe32ImportTarget, Pe32LinkPlan, Pe32LoadGroupId,
    Pe32ModuleStage, Pe32RetirementInfo, Pe32SymbolResult,
};
