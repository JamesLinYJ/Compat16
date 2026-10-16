use super::*;
use compat16_jit::{CodeCache, Instruction, IntegerState, Operand, Operation, Register, Statistics};
use std::process::Command;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("compat16-jit-{}", unique_name().unwrap()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn cache(&self) -> Arc<DiskCache> {
        Arc::new(DiskCache::open(&self.0).unwrap())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn run(store: Arc<DiskCache>) -> Statistics {
    let mut cache = CodeCache::default();
    cache.set_artifact_store(Some(store));
    let register = Register::new(0, 4, false).unwrap();
    let program = [
        Instruction::new(Operation::Move, register, Operand::Immediate(41)).unwrap(),
        Instruction::new(Operation::Increment, register, Operand::Immediate(0)).unwrap(),
    ];
    for _ in 0..4 {
        let mut state = IntegerState::default();
        if cache.execute_block(&program, &mut state, &mut [IntegerState::default(); 2]) {
            assert_eq!(state.registers[0], 42);
        }
    }
    let statistics = cache.statistics();
    assert_eq!(statistics.failures, 0);
    assert!(statistics.blocks_executed > 0);
    statistics
}
fn artifact_file(scratch: &Scratch) -> PathBuf {
    std::fs::read_dir(&scratch.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.file_name().unwrap().to_str().is_some_and(managed_name))
        .unwrap()
}

#[test]
fn corrupt_truncated_oversized_and_rebound_files_are_cache_misses() {
    let scratch = Scratch::new();
    assert!(run(scratch.cache()).persistent_writes > 0);
    let path = artifact_file(&scratch);
    let encrypted = std::fs::read(&path).unwrap();
    assert!(run(scratch.cache()).persistent_hits > 0);
    let name = path.file_stem().unwrap().to_str().unwrap();
    let key: [u8; 32] = std::array::from_fn(|index| {
        u8::from_str_radix(&name[index * 2..index * 2 + 2], 16).unwrap()
    });
    let mut changed = encrypted.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 0x80;
    for bytes in [
        changed,
        encrypted[..encrypted.len() / 2].to_vec(),
        vec![0; MAX_FILE_BYTES + 1],
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(scratch.cache().load(&key).is_none());
        let statistics = run(scratch.cache());
        assert_eq!(statistics.persistent_hits, 0);
        assert!(statistics.persistent_writes > 0);
    }
    let mut other_key = key;
    other_key[0] ^= 1;
    std::fs::write(scratch.0.join(DiskCache::file_name(&other_key)), encrypted).unwrap();
    assert!(scratch.cache().load(&other_key).is_none());
}

#[test]
fn lock_contention_only_skips_persistence() {
    let scratch = Scratch::new();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(scratch.0.join("write.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let statistics = run(scratch.cache());
    assert_eq!(statistics.persistent_writes, 0);
    drop(lock);
    assert!(run(scratch.cache()).persistent_writes > 0);
}

#[test]
fn persistent_child() {
    let Some(path) = std::env::var_os("COMPAT16_JIT_CACHE_PROBE_DIR") else {
        return;
    };
    let cache = Arc::new(DiskCache::open(Path::new(&path)).unwrap());
    let statistics = run(cache);
    let phase = std::env::var("COMPAT16_JIT_CACHE_PROBE_PHASE").unwrap();
    match phase.as_str() {
        "write" => {
            assert_eq!(statistics.persistent_hits, 0);
            assert!(statistics.persistent_writes > 0);
        }
        "read" => assert!(statistics.persistent_hits > 0),
        _ => panic!("unknown persistence probe phase"),
    }
    std::fs::write(
        Path::new(&path).join(format!("{phase}.receipt")),
        format!(
            "hits={} writes={} failures={}\n",
            statistics.persistent_hits, statistics.persistent_writes, statistics.failures
        ),
    )
    .unwrap();
}

#[test]
fn encrypted_jit_artifact_survives_two_fresh_processes() {
    let scratch = Scratch::new();
    for phase in ["write", "read"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "jit_cache::tests::persistent_child",
                "--exact",
                "--nocapture",
            ])
            .env("COMPAT16_JIT_CACHE_PROBE_DIR", &scratch.0)
            .env("COMPAT16_JIT_CACHE_PROBE_PHASE", phase)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let receipt = std::fs::read_to_string(scratch.0.join(format!("{phase}.receipt"))).unwrap();
        assert!(receipt.contains("failures=0"));
        eprintln!("persistent-cache phase={phase} {receipt}");
    }
}
