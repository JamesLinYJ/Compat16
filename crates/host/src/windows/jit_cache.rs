//! Native-account compilation cache. Guest plaintext never becomes native code.

#[path = "jit_cache/crypto.rs"]
mod crypto;
#[cfg(test)]
#[path = "jit_cache/tests.rs"]
mod tests;

use cap_std::fs::{Dir, OpenOptions};
use runtime::{JitArtifact, JitArtifactStore};
use std::{
    ffi::OsString,
    io::{Read, Write},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use windows_sys::Win32::{
    System::Com::{CoCreateGuid, CoTaskMemFree},
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

const MAX_FILES: usize = 4096;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 1024 * 1024 + 16 * 1024;

pub(super) struct DiskCache {
    dir: Dir,
}
impl DiskCache {
    fn open(path: &Path) -> Option<Self> {
        std::fs::create_dir_all(path).ok()?;
        Some(Self {
            dir: Dir::open_ambient_dir(path, cap_std::ambient_authority()).ok()?,
        })
    }
    fn file_name(key: &[u8; 32]) -> String {
        use std::fmt::Write;
        let mut name = String::with_capacity(71);
        for byte in key {
            write!(&mut name, "{byte:02x}").expect("write string");
        }
        name.push_str(".c16jit");
        name
    }
    fn admit(&self, target: &str, incoming: u64) -> Option<()> {
        let mut files = Vec::new();
        let mut total = 0_u64;
        let mut target_size = 0_u64;
        let mut target_exists = false;
        // Bound enumeration even if external writers fill this dedicated
        // directory. Only regular files in this cache's namespace are pruned.
        for (index, entry) in self.dir.entries().ok()?.enumerate() {
            if index > MAX_FILES * 2 + 16 {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            if !managed_name(&name) || !entry.file_type().ok()?.is_file() {
                continue;
            }
            let metadata = entry.metadata().ok()?;
            total = total.checked_add(metadata.len())?;
            if name == target {
                target_size = metadata.len();
                target_exists = true;
            }
            files.push((metadata.modified().ok()?, name, metadata.len()));
        }
        files.sort_by_key(|file| file.0);
        let mut count = files.len() + usize::from(!target_exists);
        let mut planned = total.checked_sub(target_size)?.checked_add(incoming)?;
        for (_, name, bytes) in files {
            if count <= MAX_FILES && planned <= MAX_TOTAL_BYTES {
                return Some(());
            }
            if name == target {
                continue;
            }
            self.dir.remove_file(&name).ok()?;
            count -= 1;
            planned = planned.checked_sub(bytes)?;
        }
        (count <= MAX_FILES && planned <= MAX_TOTAL_BYTES).then_some(())
    }
}
impl JitArtifactStore for DiskCache {
    fn load(&self, key: &[u8; 32]) -> Option<JitArtifact> {
        let mut file = self.dir.open(Self::file_name(key)).ok()?;
        let size = usize::try_from(file.metadata().ok()?.len()).ok()?;
        if size == 0 || size > MAX_FILE_BYTES {
            return None;
        }
        let mut data = Vec::new();
        data.try_reserve_exact(size).ok()?;
        Read::by_ref(&mut file)
            .take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .ok()?;
        if data.len() != size {
            return None;
        }
        crypto::restore(key, &data)
    }
    fn store(&self, artifact: &JitArtifact) -> bool {
        self.publish(artifact).is_some()
    }
}
impl DiskCache {
    fn publish(&self, artifact: &JitArtifact) -> Option<()> {
        let data = crypto::protect(artifact)?;
        if data.len() > MAX_FILE_BYTES {
            return None;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        // std's Windows file lock coordinates admission and publication across
        // processes. Contention is a missed cache write, never a guest stall.
        let lock = self.dir.open_with("write.lock", &options).ok()?.into_std();
        lock.try_lock().ok()?;
        let name = Self::file_name(artifact.key());
        self.admit(&name, data.len() as u64)?;
        let pending = PendingFile {
            dir: &self.dir,
            name: format!("pending-{}.tmp", unique_name()?),
            published: false,
        };
        self.write_pending(pending, &name, &data)
    }
    fn write_pending(
        &self,
        mut pending: PendingFile<'_>,
        target: &str,
        bytes: &[u8],
    ) -> Option<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = self.dir.open_with(&pending.name, &options).ok()?;
        file.write_all(bytes).ok()?;
        file.sync_all().ok()?;
        drop(file);
        self.dir.rename(&pending.name, &self.dir, target).ok()?;
        pending.published = true;
        Some(())
    }
}
struct PendingFile<'a> {
    dir: &'a Dir,
    name: String,
    published: bool,
}
impl Drop for PendingFile<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.dir.remove_file(&self.name);
        }
    }
}
fn managed_name(name: &str) -> bool {
    name.len() == 71
        && name.ends_with(".c16jit")
        && name.as_bytes()[..64].iter().all(u8::is_ascii_hexdigit)
}
fn unique_name() -> Option<String> {
    let mut guid = windows_sys::core::GUID::from_u128(0);
    // SAFETY: This is an owned initialized GUID output; no COM apartment or UI.
    if unsafe { CoCreateGuid(&mut guid) } < 0 {
        return None;
    }
    Some(format!(
        "{:08x}{:04x}{:04x}{:016x}",
        guid.data1,
        guid.data2,
        guid.data3,
        u64::from_be_bytes(guid.data4)
    ))
}
fn local_app_data() -> Option<PathBuf> {
    struct Folder(*mut u16);
    impl Drop for Folder {
        fn drop(&mut self) {
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
    let mut folder = Folder(std::ptr::null_mut());
    // SAFETY: The native service allocates a terminated wide path for this
    // logon account; Folder owns the allocation through conversion.
    if unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            0,
            std::ptr::null_mut(),
            &mut folder.0,
        )
    } < 0
        || folder.0.is_null()
    {
        return None;
    }
    for length in 0..32768 {
        if unsafe { *folder.0.add(length) } == 0 {
            let wide = unsafe { std::slice::from_raw_parts(folder.0, length) };
            return Some(PathBuf::from(OsString::from_wide(wide)));
        }
    }
    None
}
/// Optional per-account cache outside the program's guest filesystem root.
/// The host native account is trusted; DPAPI is not a same-account sandbox.
pub(super) fn open_default() -> Option<Arc<dyn JitArtifactStore>> {
    let path = local_app_data()?.join("Compat16").join("Jit").join("v1");
    Some(Arc::new(DiskCache::open(&path)?))
}
