//! Exact extended-precision normal multiplication. Exceptional classes and
//! range results decline before publishing output to the caller.
use crate::{
    ArtifactStore, Statistics,
    compiler::{Compiler, FloatFunction},
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Float80 {
    pub significand: u64,
    pub sign_exponent: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FloatResult {
    pub value: Float80,
    pub exceptions: u16,
    pub c1: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct FloatPlan {
    pub precision: u8,
    pub rounding: u8,
}
#[repr(C)]
pub(crate) struct FloatState {
    pub words: [u64; 6],
}
#[derive(Clone, Copy)]
enum Entry {
    Cold(u8),
    Compiled(FloatFunction),
    Rejected,
}
pub struct FloatCache {
    compiler: Compiler,
    entries: [Entry; 12],
    statistics: Statistics,
}
impl Default for FloatCache {
    fn default() -> Self {
        Self {
            compiler: Compiler::default(),
            entries: [Entry::Cold(0); 12],
            statistics: Statistics::default(),
        }
    }
}
impl FloatCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    /// Produces the same 80-bit normal product, precision flag and C1 as an
    /// extended-precision multiply with x87 PC/RC. No host FP mode is used.
    /// None means the owner must use its full software arithmetic semantics.
    pub fn multiply(&mut self, left: Float80, right: Float80, control: u16) -> Option<FloatResult> {
        let normal = |v: Float80| {
            v.sign_exponent & 0x7fff != 0
                && v.sign_exponent & 0x7fff != 0x7fff
                && v.significand >> 63 != 0
        };
        if !normal(left) || !normal(right) {
            return None;
        }
        let (precision, index) = match (control >> 8) & 3 {
            0 => (24, 0),
            2 => (53, 1),
            _ => (64, 2),
        };
        let rounding = ((control >> 10) & 3) as u8;
        let index = index * 4 + usize::from(rounding);
        let function = match self.entries[index] {
            Entry::Compiled(function) => function,
            Entry::Rejected => return None,
            Entry::Cold(count) => {
                self.entries[index] = Entry::Cold(count + 1);
                if count < 31 {
                    return None;
                }
                match self.compiler.compile_float(FloatPlan {
                    precision,
                    rounding,
                }) {
                    Ok(code) => {
                        self.entries[index] = Entry::Compiled(code.function);
                        self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                        self.statistics.float_compiled =
                            self.statistics.float_compiled.saturating_add(1);
                        self.statistics.persistent_hits = self
                            .statistics
                            .persistent_hits
                            .saturating_add(u64::from(code.cache_hit));
                        self.statistics.persistent_writes = self
                            .statistics
                            .persistent_writes
                            .saturating_add(code.cache_writes);
                        code.function
                    }
                    Err(_) => {
                        self.entries[index] = Entry::Rejected;
                        self.statistics.failures = self.statistics.failures.saturating_add(1);
                        return None;
                    }
                }
            }
        };
        let mut state = FloatState {
            words: [
                left.significand,
                right.significand,
                u64::from(left.sign_exponent) | u64::from(right.sign_exponent) << 16,
                0,
                0,
                0,
            ],
        };
        // SAFETY: Generated arithmetic has this exact C signature and can only
        // access the six exclusive owned words. It is nontrapping and bounded.
        // Private pointers remain live and cannot escape or race destruction.
        if unsafe { function(&mut state) } == 0 {
            self.statistics.float_fallbacks = self.statistics.float_fallbacks.saturating_add(1);
            return None;
        }
        self.statistics.executed = self.statistics.executed.saturating_add(1);
        self.statistics.float_executed = self.statistics.float_executed.saturating_add(1);
        Some(FloatResult {
            value: Float80 {
                significand: state.words[3],
                sign_exponent: state.words[4] as u16,
            },
            exceptions: state.words[5] as u16,
            c1: state.words[5] & (1 << 16) != 0,
        })
    }
}
impl Drop for FloatCache {
    fn drop(&mut self) {
        self.entries.fill(Entry::Rejected);
        // SAFETY: No generated pointer escapes and no call can overlap &mut drop.
        unsafe {
            self.compiler.clear();
        }
    }
}
