use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;

mod sealed {
    pub trait Sealed {}
}

/// A 16-bit guest handle with a Rust type that identifies its object class.
///
/// Raw zero is reserved as the null handle. Implementations must not turn an
/// invalid raw value into a valid handle.
pub trait TypedHandle: sealed::Sealed + Copy + Eq + Ord + fmt::Debug {
    fn from_raw(raw: u16) -> Option<Self>;
    fn raw(self) -> u16;
}

macro_rules! define_handle {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroU16);

        impl $name {
            pub const fn from_raw(raw: u16) -> Option<Self> {
                match NonZeroU16::new(raw) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            pub const fn raw(self) -> u16 {
                self.0.get()
            }
        }

        impl TypedHandle for $name {
            fn from_raw(raw: u16) -> Option<Self> {
                NonZeroU16::new(raw).map(Self)
            }

            fn raw(self) -> u16 {
                self.0.get()
            }
        }

        impl sealed::Sealed for $name {}
    };
}

define_handle!(WindowHandle);
define_handle!(DeviceContextHandle);
define_handle!(BitmapHandle);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleError {
    Exhausted,
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => f.write_str(
                "No unused 16-bit object handles remain; valid handles range from 1 through 65,535.",
            ),
        }
    }
}

impl std::error::Error for HandleError {}

/// A typed handle table that never reissues a handle after removal.
///
/// The finite 16-bit namespace is intentionally consumed monotonically. This
/// gives guest handles the stale-handle safety of generations without encoding
/// a wrapping generation into the guest-visible 16-bit value.
#[derive(Debug)]
pub struct HandleTable<H: TypedHandle, T> {
    next_raw: u32,
    entries: BTreeMap<H, T>,
}

impl<H: TypedHandle, T> Default for HandleTable<H, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: TypedHandle, T> HandleTable<H, T> {
    pub fn new() -> Self {
        Self {
            next_raw: 1,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, value: T) -> Result<H, HandleError> {
        if self.next_raw > u32::from(u16::MAX) {
            return Err(HandleError::Exhausted);
        }

        let raw = self.next_raw as u16;
        self.next_raw += 1;
        let handle = H::from_raw(raw).ok_or(HandleError::Exhausted)?;
        if handle.raw() != raw || self.entries.contains_key(&handle) {
            return Err(HandleError::Exhausted);
        }
        self.entries.insert(handle, value);
        Ok(handle)
    }

    pub fn get(&self, handle: H) -> Option<&T> {
        self.entries.get(&handle)
    }

    pub fn get_mut(&mut self, handle: H) -> Option<&mut T> {
        self.entries.get_mut(&handle)
    }

    pub fn contains(&self, handle: H) -> bool {
        self.entries.contains_key(&handle)
    }

    pub fn remove(&mut self, handle: H) -> Option<T> {
        self.entries.remove(&handle)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (H, &T)> + '_ {
        self.entries.iter().map(|(handle, value)| (*handle, value))
    }
}

#[cfg(test)]
mod tests;
