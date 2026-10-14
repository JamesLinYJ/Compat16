//! Native integer translation with a bounded, process-local code cache.
//!
//! This crate contains the generated-code call boundary. The x86 CPU crate
//! remains entirely safe Rust. Code can only touch IntegerState; guest memory,
//! guest pointers, native callbacks and guest exception delivery never enter
//! generated code. Cranelift owns W^X publication and instruction-cache flushes.

mod ir;
mod lowering;
use cranelift_codegen::ir::AbiParam;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};
pub use ir::{Condition, Instruction, IntegerState, Operand, Operation, Register};
use std::collections::HashMap;

const HOT_THRESHOLD: u8 = 32;
const MAX_ENTRIES: usize = 1024;

#[derive(Default, Clone, Copy, Debug)]
pub struct Statistics {
    pub compiled: u64,
    pub executed: u64,
    pub failures: u64,
    pub cache_resets: u64,
}
enum Entry {
    Cold(u8),
    Compiled(unsafe extern "C" fn(*mut IntegerState)),
    Rejected,
}

/// No function pointer escapes this owner. Exclusive execution prevents an
/// eviction/free from racing an executing function, including destruction.
pub struct CodeCache {
    module: Option<JITModule>,
    entries: HashMap<Instruction, Entry>,
    next_function: u64,
    statistics: Statistics,
    enabled: bool,
}
impl Default for CodeCache {
    fn default() -> Self {
        Self {
            module: None,
            entries: HashMap::new(),
            next_function: 0,
            statistics: Statistics::default(),
            enabled: true,
        }
    }
}
impl CodeCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns false without changing the state for cold, unsupported or
    /// failed compilation. The caller executes its interpreter in that case.
    pub fn execute(&mut self, instruction: Instruction, state: &mut IntegerState) -> bool {
        let Some(function) = self.ready(instruction) else {
            return false;
        };
        self.invoke(function, state);
        true
    }

    /// Resolve hotness and compilation before invoking the input provider.
    /// Cold/failing paths never read operands, so interpreter fallback cannot
    /// duplicate a device read. Provider errors precede native execution.
    pub fn execute_with<E>(
        &mut self,
        instruction: Instruction,
        input: impl FnOnce() -> Result<IntegerState, E>,
    ) -> Result<Option<IntegerState>, E> {
        let Some(function) = self.ready(instruction) else {
            return Ok(None);
        };
        let mut state = input()?;
        self.invoke(function, &mut state);
        Ok(Some(state))
    }

    fn ready(
        &mut self,
        instruction: Instruction,
    ) -> Option<unsafe extern "C" fn(*mut IntegerState)> {
        if !self.enabled {
            return None;
        }
        if !self.entries.contains_key(&instruction) && self.entries.len() == MAX_ENTRIES {
            self.clear();
            self.statistics.cache_resets = self.statistics.cache_resets.saturating_add(1);
        }
        if !self.entries.contains_key(&instruction) && self.entries.try_reserve(1).is_err() {
            return None;
        }
        let entry = self.entries.entry(instruction).or_insert(Entry::Cold(0));
        let function = match entry {
            Entry::Compiled(function) => *function,
            Entry::Rejected => return None,
            Entry::Cold(count) => {
                *count = count.saturating_add(1);
                if *count < HOT_THRESHOLD {
                    return None;
                }
                match self.compile(instruction) {
                    Ok(function) => {
                        self.entries.insert(instruction, Entry::Compiled(function));
                        self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                        function
                    }
                    Err(_) => {
                        self.entries.insert(instruction, Entry::Rejected);
                        self.statistics.failures = self.statistics.failures.saturating_add(1);
                        // OS dynamic-code restrictions and compiler failures
                        // leave the interpreter available; do not retry forever.
                        self.enabled = false;
                        return None;
                    }
                }
            }
        };
        Some(function)
    }

    fn invoke(
        &mut self,
        function: unsafe extern "C" fn(*mut IntegerState),
        state: &mut IntegerState,
    ) {
        // SAFETY: This function was emitted from checked pointer-free IR, uses
        // the native C ABI and accesses only this live exclusive IntegerState.
        // Its module remains owned until after the call has returned.
        unsafe {
            function(state);
        }
        self.statistics.executed = self.statistics.executed.saturating_add(1);
    }

    fn compile(
        &mut self,
        instruction: Instruction,
    ) -> Result<unsafe extern "C" fn(*mut IntegerState), String> {
        if self.module.is_none() {
            self.module = Some(JITModule::new(
                JITBuilder::with_flags(
                    &[("opt_level", "speed"), ("enable_verifier", "true")],
                    cranelift_module::default_libcall_names(),
                )
                .map_err(|error| error.to_string())?,
            ));
        }
        let module = self.module.as_mut().expect("initialized module");
        let name = format!("integer_{}", self.next_function);
        self.next_function = self
            .next_function
            .checked_add(1)
            .ok_or("function identity exhausted")?;
        let mut context = module.make_context();
        context.func.signature = module.make_signature();
        context
            .func
            .signature
            .params
            .push(AbiParam::new(module.target_config().pointer_type()));
        let id = module
            .declare_function(&name, Linkage::Local, &context.func.signature)
            .map_err(|error| error.to_string())?;
        let mut frontend = FunctionBuilderContext::new();
        {
            let mut builder = FunctionBuilder::new(&mut context.func, &mut frontend);
            let block = builder.create_block();
            builder.append_block_params_for_function_params(block);
            builder.switch_to_block(block);
            builder.seal_block(block);
            let pointer = builder.block_params(block)[0];
            lowering::emit(&mut builder, pointer, instruction);
            use cranelift_codegen::ir::InstBuilder;
            builder.ins().return_(&[]);
            builder.finalize(module.target_config());
        }
        module
            .define_function(id, &mut context)
            .map_err(|error| error.to_string())?;
        module
            .finalize_definitions()
            .map_err(|error| error.to_string())?;
        let pointer = module.get_finalized_function(id);
        // SAFETY: The generated signature is exactly native C (*mut
        // IntegerState)->void. Entry storage is private to the module owner.
        Ok(unsafe {
            std::mem::transmute::<*const u8, unsafe extern "C" fn(*mut IntegerState)>(pointer)
        })
    }

    fn clear(&mut self) {
        self.entries.clear();
        if let Some(module) = self.module.take() {
            // SAFETY: &mut self excludes execute(), pointers never escape,
            // and all cached function pointers have just been discarded.
            unsafe {
                module.free_memory();
            }
        }
    }
}
impl Drop for CodeCache {
    fn drop(&mut self) {
        self.clear();
    }
}
