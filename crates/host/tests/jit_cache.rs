//! Focused, noninteractive native-cache validation using the product module.
#![cfg(windows)]

#[path = "../src/windows/jit_cache.rs"]
mod jit_cache;

#[test]
fn default_cache_provider_is_optional() {
    // Merely obtaining the optional provider must not create UI or require
    // persistence to be available. All writes use isolated temporary caches.
    drop(jit_cache::open_default());
}
