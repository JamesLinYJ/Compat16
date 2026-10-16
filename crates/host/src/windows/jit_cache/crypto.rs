//! Windows account authentication plus bounded, key-bound JIT cache data.

use runtime::JitArtifact;
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

const MAGIC: &[u8; 8] = b"C16JITA1";
const MAX_PAYLOAD: usize = 1024 * 1024;
const HEADER: usize = 8 + 32 + 32;

// This fixed envelope binds an opaque Cranelift artifact to its compiler key.
// DPAPI supplies account authentication; SHA-256 additionally rejects corrupt
// outputs even when a native decrypt call reports success. No custom cipher
// or executable-code deserializer is implemented here.
pub(super) fn protect(artifact: &JitArtifact) -> Option<Vec<u8>> {
    if artifact.bytes().len() > MAX_PAYLOAD {
        return None;
    }
    let mut plaintext = Vec::new();
    plaintext
        .try_reserve_exact(HEADER + artifact.bytes().len())
        .ok()?;
    plaintext.extend_from_slice(MAGIC);
    plaintext.extend_from_slice(artifact.key());
    plaintext.extend_from_slice(&Sha256::digest(artifact.bytes()));
    plaintext.extend_from_slice(artifact.bytes());
    crypt(true, artifact.key(), &plaintext)
}
pub(super) fn restore(key: &[u8; 32], ciphertext: &[u8]) -> Option<JitArtifact> {
    let plaintext = crypt(false, key, ciphertext)?;
    if plaintext.len() <= HEADER
        || plaintext.len() > HEADER + MAX_PAYLOAD
        || &plaintext[..8] != MAGIC
        || &plaintext[8..40] != key
    {
        return None;
    }
    let bytes = &plaintext[HEADER..];
    if &Sha256::digest(bytes)[..] != &plaintext[40..HEADER] {
        return None;
    }
    let mut body = Vec::new();
    body.try_reserve_exact(bytes.len()).ok()?;
    body.extend_from_slice(bytes);
    // SAFETY: Store accepts only immutable artifacts emitted by compat16-jit.
    // DPAPI's account MAC, key-specific entropy, versioned envelope and digest
    // all validated before any native-code deserialization. Native code under
    // this logon account is trusted; guest file writes cannot forge this path.
    unsafe { JitArtifact::from_authenticated(key, body) }
}

struct NativeBlob(CRYPT_INTEGER_BLOB);
impl Drop for NativeBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            unsafe {
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}
fn crypt(protect: bool, key: &[u8; 32], input: &[u8]) -> Option<Vec<u8>> {
    if input.len() > MAX_PAYLOAD + 16 * 1024 {
        return None;
    }
    let mut entropy_bytes = Vec::from(&b"Compat16/jit/artifact/v1/"[..]);
    entropy_bytes.extend_from_slice(key);
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(input.len()).ok()?,
        pbData: input.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output = NativeBlob(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    });
    // SAFETY: Both input buffers remain live and read-only for the synchronous
    // OS call. Output is an owned LocalAlloc buffer, freed on every exit path.
    // Prompt pointers are NULL and UI is forbidden for both operations.
    let success = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    let length = output.0.cbData as usize;
    if success == 0 || output.0.pbData.is_null() || length == 0 || length > MAX_PAYLOAD + 16 * 1024
    {
        return None;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).ok()?;
    bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(output.0.pbData, length) });
    Some(bytes)
}
