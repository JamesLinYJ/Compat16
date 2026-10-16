//! Integrity boundary for serialized JIT compilation artifacts.

use cranelift_codegen::incremental_cache::CacheKvStore;
use std::{borrow::Cow, sync::Arc};

pub const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;

/// Compiled code serialized by the pinned compiler for this exact cache key.
/// Safe providers can retain or encrypt this value, but cannot change its key
/// or bytes. Restoring bytes requires an explicit host integrity guarantee.
#[derive(Clone)]
pub struct Artifact {
    key: [u8; 32],
    bytes: Vec<u8>,
}
impl Artifact {
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Restore a host-authenticated artifact.
    ///
    /// # Safety
    /// The bytes must originate from Artifact::bytes() for this same key and
    /// remain protected against modification/rebinding by untrusted writers.
    /// A checksum alone is insufficient. The native host account is trusted;
    /// this API must never accept guest-provided plaintext or authentication.
    pub unsafe fn from_authenticated(key: &[u8], bytes: Vec<u8>) -> Option<Self> {
        Self::compiled(key, bytes)
    }
    fn compiled(key: &[u8], bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return None;
        }
        Some(Self {
            key: key.try_into().ok()?,
            bytes,
        })
    }
}

/// Optional host storage. I/O failures are cache misses, not guest failures.
/// This crate has no filesystem, DPAPI, DOS, Win16 or runtime dependency.
pub trait ArtifactStore: Send + Sync {
    fn load(&self, key: &[u8; 32]) -> Option<Artifact>;
    fn store(&self, artifact: &Artifact) -> bool;
}

pub(crate) struct Adapter<'a> {
    pub store: Option<&'a Arc<dyn ArtifactStore>>,
    pub writes: u64,
}
impl CacheKvStore for Adapter<'_> {
    fn get(&self, key: &[u8]) -> Option<Cow<'_, [u8]>> {
        let key = <&[u8; 32]>::try_from(key).ok()?;
        let artifact = self.store?.load(key)?;
        if artifact.key() != key {
            return None;
        }
        Some(Cow::Owned(artifact.bytes))
    }
    fn insert(&mut self, key: &[u8], bytes: Vec<u8>) {
        if let (Some(store), Some(artifact)) = (self.store, Artifact::compiled(key, bytes))
            && store.store(&artifact)
        {
            self.writes = self.writes.saturating_add(1);
        }
    }
}
