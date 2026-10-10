//! Token publication and live image-owner recovery, independent of USER calls.

use super::*;

pub(super) struct RetainedNativeImage {
    pub(super) image: NativeImage,
    #[cfg(test)]
    test_destruction: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    test_unlocked_table: Option<Weak<Mutex<ImageTable>>>,
}

impl RetainedNativeImage {
    fn new(image: NativeImage) -> Self {
        Self {
            image,
            #[cfg(test)] test_destruction: None,
            #[cfg(test)] test_unlocked_table: None,
        }
    }
}

impl Drop for RetainedNativeImage {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(counter) = &self.test_destruction {
            if self.image.owned {
                if let Some(table) = self.test_unlocked_table.as_ref().and_then(Weak::upgrade) {
                    assert!(table.try_lock().is_ok(), "owned image destroyed under its table mutex");
                }
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            return;
        }
        destroy(self.image);
    }
}

/// Pins an image incarnation without holding the identity-table mutex.
pub(in crate::windows) struct Win16IconLease(pub(super) Arc<RetainedNativeImage>);

impl Win16IconLease {
    pub(in crate::windows) fn native(&self) -> HICON { self.0.image.handle() }
}

/// Consumed by registration on success and failure. A collision is disarmed:
/// the already indexed owner remains the sole destruction authority.
pub(super) struct NativeIconGuard(Option<RetainedNativeImage>);

impl NativeIconGuard {
    pub(super) fn new(handle: HICON) -> Self { Self::new_kind(handle, ImageKind::Icon) }

    pub(super) fn new_kind(handle: HICON, kind: ImageKind) -> Self {
        Self(Some(RetainedNativeImage::new(NativeImage::new(handle, kind, true))))
    }
}

pub(super) struct ImageTable {
    pub(super) images: BTreeMap<u64, Arc<RetainedNativeImage>>,
    // Raw bits are lookup keys, never evidence of ownership on their own.
    owners: BTreeMap<usize, Weak<RetainedNativeImage>>,
    next_id: u64,
    maintenance_left: usize,
    #[cfg(test)]
    sweep_visits: usize,
}

impl ImageTable {
    pub(super) fn new() -> Self {
        Self {
            images: BTreeMap::new(), owners: BTreeMap::new(), next_id: 1, maintenance_left: 64,
            #[cfg(test)] sweep_visits: 0,
        }
    }

    pub(super) fn sweep(&mut self) {
        #[cfg(test)]
        let sweep_visits = &mut self.sweep_visits;
        self.owners.retain(|_, owner| {
            #[cfg(test)] { *sweep_visits += 1; }
            owner.strong_count() != 0
        });
        self.maintenance_left = self.owners.len().max(64);
    }

    pub(super) fn maintain(&mut self) {
        // Bulk extraction must not traverse every live owner for every icon.
        self.maintenance_left = self.maintenance_left.saturating_sub(1);
        if self.maintenance_left == 0 { self.sweep(); }
    }

    fn next_token(&self) -> Result<(u64, u64), RuntimeError> {
        self.next_id.checked_add(1).map(|next| (self.next_id, next)).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "Win16 host image identity exhausted")
        })
    }

    pub(super) fn register_owned(
        &mut self,
        guard: &mut NativeIconGuard,
        collision: &mut Option<Arc<RetainedNativeImage>>,
    ) -> Result<u64, RuntimeError> {
        self.maintain();
        let incoming = guard.0.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "native image registration consumed its owner twice",
        ))?;
        let raw = incoming.image.handle;
        *collision = self.owners.get(&raw).and_then(Weak::upgrade);
        if collision.is_some() {
            incoming.image.owned = false;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native image registration contradicts an existing live owner"));
        }
        let (token, next) = self.next_token()?;
        let owner = Arc::new(guard.0.take().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "native image registration lost its owner",
        ))?);
        self.owners.insert(raw, Arc::downgrade(&owner));
        self.images.insert(token, owner);
        self.next_id = next;
        Ok(token)
    }

    pub(super) fn register_borrowed(&mut self, handle: HICON, kind: ImageKind)
        -> Result<u64, RuntimeError> {
        self.maintain();
        let (token, next) = self.next_token()?;
        self.images.insert(token, Arc::new(RetainedNativeImage::new(
            NativeImage::new(handle, kind, false),
        )));
        self.next_id = next;
        Ok(token)
    }

    pub(super) fn adopt(
        &mut self,
        handle: HICON,
        kind: ImageKind,
        recovered: &mut Option<Arc<RetainedNativeImage>>,
    ) -> Result<u64, RuntimeError> {
        self.maintain();
        *recovered = self.owners.get(&(handle as usize)).and_then(Weak::upgrade);
        if let Some(owner) = recovered.as_ref() {
            if owner.image.kind != kind || !owner.image.owned {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native image result disagrees with its live owner kind"));
            }
            if let Some((&token, _)) = self.images.iter().find(|(_, image)| Arc::ptr_eq(image, owner)) {
                return Ok(token);
            }
            let (token, next) = self.next_token()?;
            self.images.insert(token, Arc::clone(owner));
            self.next_id = next;
            return Ok(token);
        }
        // Without a live owner, the native result's caller is responsible for
        // its external lifetime. Expired weak metadata cannot revive an owner.
        if let Some((&token, _)) = self.images.iter().find(|(_, image)| {
            image.image.kind == kind && image.image.handle == handle as usize
        }) {
            return Ok(token);
        }
        self.register_borrowed(handle, kind)
    }
}

#[cfg(test)]
#[path = "win16_image_ownership_tests.rs"]
mod image_ownership_tests;
