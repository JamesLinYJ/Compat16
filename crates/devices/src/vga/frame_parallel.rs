//! A runtime-owned Rayon pool whose native threads finish before teardown.

use std::thread::{self, JoinHandle};

const MAX_SCANOUT_WORKERS: usize = 4;

pub(super) struct ScanoutPool {
    pool: Option<rayon::ThreadPool>,
    workers: Vec<JoinHandle<()>>,
}

impl ScanoutPool {
    pub(super) fn new() -> Option<Self> {
        let worker_count = thread::available_parallelism()
            .map(|count| count.get().min(MAX_SCANOUT_WORKERS))
            .unwrap_or(1);
        if worker_count <= 1 {
            return None;
        }

        // Own handles before starting the pool so partial initialization and
        // unwinding use the same join path as normal runtime destruction.
        let mut owned = Self {
            pool: None,
            workers: Vec::new(),
        };
        owned.workers.try_reserve_exact(worker_count).ok()?;
        let result = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .thread_name(|index| format!("graphics-scanout-{index}"))
            .spawn_handler(|worker| {
                let mut builder = thread::Builder::new();
                if let Some(name) = worker.name() {
                    builder = builder.name(name.to_owned());
                }
                if let Some(stack_size) = worker.stack_size() {
                    builder = builder.stack_size(stack_size);
                }
                owned.workers.push(builder.spawn(move || worker.run())?);
                Ok(())
            })
            .build();
        // Rayon signals any already started workers when build fails. The
        // owned wrapper then joins them before returning the serial fallback.
        owned.pool = Some(result.ok()?);
        Some(owned)
    }

    pub(super) fn thread_pool(&self) -> &rayon::ThreadPool {
        self.pool
            .as_ref()
            .expect("a scanout pool is published only after initialization")
    }
}

impl Drop for ScanoutPool {
    fn drop(&mut self) {
        // Dropping Rayon signals shutdown but does not wait for it. Join every
        // OS thread so none can execute module code after runtime/DLL teardown.
        drop(self.pool.take());
        for worker in self.workers.drain(..) {
            // A panicked worker is already finished; still join the others.
            let _ = worker.join();
        }
    }
}
