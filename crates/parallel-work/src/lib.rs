//! A shared, owned executor for bounded batches of pure buffer calculations.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread::{self, JoinHandle};

const MAX_WORKERS: usize = 4;
const JOBS_PER_WORKER: usize = 2;

pub type SharedExecutor = Arc<BoundedExecutor>;

/// One engine shares this owner across scanout, PCM mixing and buffer format
/// conversion. It admits one synchronous batch of at most eight scoped jobs
/// on at most four native threads. There is no persistent job queue.
///
/// Jobs borrow only pure data. Native USER, GDI, WinMM and COM calls, guest CPU
/// execution and completion callbacks remain on their owning threads.
#[derive(Default)]
pub struct BoundedExecutor {
    state: Mutex<PoolState>,
    stopping: AtomicBool,
}

#[derive(Default)]
struct PoolState {
    pool: Option<OwnedPool>,
    initialization_attempted: bool,
}

impl BoundedExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    /// The offset is relative to the full output buffer. Every job completes
    /// before this returns, retaining input and output lifetimes and ordering.
    pub fn for_each_chunk<T: Send>(
        &self,
        output: &mut [T],
        minimum_parallel_items: usize,
        operation: impl Fn(usize, &mut [T]) + Sync,
    ) {
        self.for_each_chunk_aligned(output, minimum_parallel_items, 1, operation);
    }

    /// Keeps chunk boundaries on complete rows, sample blocks or other groups
    /// of `alignment` items. A short final group is allowed. Reentrant and
    /// concurrent callers use serial work immediately instead of waiting for
    /// admission or extending the worker queue.
    pub fn for_each_chunk_aligned<T: Send>(
        &self,
        output: &mut [T],
        minimum_parallel_items: usize,
        alignment: usize,
        operation: impl Fn(usize, &mut [T]) + Sync,
    ) {
        if output.is_empty() {
            return;
        }
        if self.stopping.load(Ordering::Acquire) || output.len() < minimum_parallel_items.max(1) {
            operation(0, output);
            return;
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                operation(0, output);
                return;
            }
        };
        if self.stopping.load(Ordering::Acquire) {
            drop(state);
            operation(0, output);
            return;
        }
        if !state.initialization_attempted {
            state.initialization_attempted = true;
            state.pool = OwnedPool::new();
        }
        let Some(pool) = state.pool.as_ref() else {
            drop(state);
            operation(0, output);
            return;
        };
        let job_limit = pool.worker_count * JOBS_PER_WORKER;
        let alignment = alignment.max(1);
        let chunk_size = output
            .len()
            .div_ceil(job_limit)
            .div_ceil(alignment)
            .saturating_mul(alignment);
        pool.thread_pool().scope(|scope| {
            for (index, chunk) in output.chunks_mut(chunk_size).enumerate() {
                let operation = &operation;
                scope.spawn(move |_| operation(index * chunk_size, chunk));
            }
        });
        // A job may request shutdown reentrantly. Join only after its entire
        // scope has returned, from this caller rather than a pool worker.
        let retired = self
            .stopping
            .load(Ordering::Acquire)
            .then(|| state.pool.take())
            .flatten();
        // Keep admission locked through joining so another shutdown caller
        // cannot observe an empty pool before these threads have finished.
        drop(retired);
        drop(state);
    }

    /// Stops admission and joins the workers after the current batch. Returns
    /// false for a request from a Rayon job: an active batch's caller joins
    /// when its scope returns, or top-level teardown completes the request.
    /// Top-level teardown receives true only after
    /// every worker has finished. Further calculations use the caller thread.
    pub fn shutdown(&self) -> bool {
        self.stopping.store(true, Ordering::Release);
        if rayon::current_thread_index().is_some() {
            return false;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retired = state.pool.take();
        drop(retired);
        drop(state);
        true
    }
}

struct OwnedPool {
    pool: Option<rayon::ThreadPool>,
    workers: Vec<JoinHandle<()>>,
    worker_count: usize,
}

impl OwnedPool {
    fn new() -> Option<Self> {
        let worker_count = thread::available_parallelism()
            .map(|count| count.get().min(MAX_WORKERS))
            .unwrap_or(1);
        if worker_count <= 1 {
            return None;
        }
        let mut owned = Self {
            pool: None,
            workers: Vec::new(),
            worker_count,
        };
        owned.workers.try_reserve_exact(worker_count).ok()?;
        let result = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .thread_name(|index| format!("host-buffer-{index}"))
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
        // Rayon signals workers created before failed initialization. The
        // local owner joins those handles before choosing serial calculation.
        owned.pool = Some(result.ok()?);
        Some(owned)
    }

    fn thread_pool(&self) -> &rayon::ThreadPool {
        self.pool
            .as_ref()
            .expect("a work pool is published only after initialization")
    }
}

impl Drop for OwnedPool {
    fn drop(&mut self) {
        // Rayon signals shutdown without waiting. Join the native handles so
        // no worker can execute module code after the last engine owner drops.
        drop(self.pool.take());
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
