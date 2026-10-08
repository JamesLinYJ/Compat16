//! Owned Win16 window-property values crossing the runtime/host boundary.

/// A property key supplied by the guest. Atom values remain opaque bits; the
/// host may use its global atom table only for an ANSI string key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostPropertyName {
    Atom(u16),
    String(Vec<u8>),
}

/// The name form that the original successful SetProp call supplied. Win16
/// EnumProps exposes atoms as selector-zero pointers and strings as guest FAR
/// pointers, so the host must retain this distinction in its property sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostPropertyCallbackName {
    Atom(u16),
    String(Vec<u8>),
}
