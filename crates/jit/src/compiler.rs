//! Compilation, relocation and executable-memory ownership.

use crate::{
    Condition, Instruction, IntegerState,
    artifact::{Adapter, ArtifactStore},
    lowering,
};
use cranelift_codegen::ir::{AbiParam, InstBuilder, MemFlagsData, condcodes::IntCC, types};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module, ModuleReloc};
use std::sync::Arc;

pub(crate) type Function = unsafe extern "C" fn(*mut IntegerState, *mut IntegerState);
pub(crate) type MemoryFunction =
    unsafe extern "C" fn(*mut IntegerState, *mut u8, u32, u32, u32) -> u64;
pub(crate) type FloatBlockFunction =
    unsafe extern "C" fn(*mut crate::FloatRegisters, *mut u8, u32) -> u32;
pub(crate) type FloatLoopFunction =
    unsafe extern "C" fn(*mut crate::FloatRegisters, *mut IntegerState, *mut u8, u32) -> u64;
pub(crate) enum FloatCompilation<'a> {
    Scalar(crate::floating::FloatPlan),
    Loop(&'a crate::FloatLoop, crate::floating::FloatPlan),
    Block(&'a crate::FloatBlock, crate::floating::FloatPlan),
}
pub(crate) type FloatFunction = unsafe extern "C" fn(*mut crate::floating::FloatState) -> u32;
pub(crate) type LoopFunction = unsafe extern "C" fn(*mut IntegerState, u32) -> u64;
pub(crate) type RegionFunction = unsafe extern "C" fn(*mut IntegerState, u32, u32, *mut u32) -> u64;
#[derive(Default)]
pub(crate) struct Compiler {
    module: Option<JITModule>,
    next_function: u64,
    pub store: Option<Arc<dyn ArtifactStore>>,
}
pub(crate) struct Compiled<F> {
    pub function: F,
    pub cache_hit: bool,
    pub cache_writes: u64,
}
impl Compiler {
    pub fn compile(&mut self, instructions: &[Instruction]) -> Result<Compiled<Function>, String> {
        let code = self.compile_body(instructions, None, None, None, None)?;
        // SAFETY: Checkpoint emission has the exact two-pointer C signature.
        Ok(Compiled {
            function: unsafe { std::mem::transmute::<*const u8, Function>(code.function) },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    pub fn compile_loop(
        &mut self,
        instructions: &[Instruction],
        condition: Option<Condition>,
    ) -> Result<Compiled<LoopFunction>, String> {
        let code = self.compile_body(instructions, Some(condition), None, None, None)?;
        // SAFETY: Loop emission has the exact pointer/u32 -> u64 C signature.
        Ok(Compiled {
            function: unsafe { std::mem::transmute::<*const u8, LoopFunction>(code.function) },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    pub fn compile_memory_loop(
        &mut self,
        plan: &crate::MemoryLoop,
    ) -> Result<Compiled<MemoryFunction>, String> {
        let code = self.compile_body(&[], None, Some(plan), None, None)?;
        // SAFETY: Memory emission has exactly the private five-argument C signature.
        Ok(Compiled {
            function: unsafe { std::mem::transmute::<*const u8, MemoryFunction>(code.function) },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    pub fn compile_region(
        &mut self,
        plan: &crate::Region,
    ) -> Result<Compiled<RegionFunction>, String> {
        let code = self.compile_body(&[], None, None, Some(plan), None)?;
        // SAFETY: Region emission has this exact four-argument C signature.
        Ok(Compiled {
            function: unsafe { std::mem::transmute::<*const u8, RegionFunction>(code.function) },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    pub fn compile_float(
        &mut self,
        plan: crate::floating::FloatPlan,
    ) -> Result<Compiled<FloatFunction>, String> {
        let code =
            self.compile_body(&[], None, None, None, Some(FloatCompilation::Scalar(plan)))?;
        // SAFETY: Float emission has exactly the private one-pointer C signature.
        Ok(Compiled {
            function: unsafe { std::mem::transmute::<*const u8, FloatFunction>(code.function) },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    pub fn compile_float_block(
        &mut self,
        block: &crate::FloatBlock,
        plan: crate::floating::FloatPlan,
    ) -> Result<Compiled<FloatBlockFunction>, String> {
        let code = self.compile_body(
            &[],
            None,
            None,
            None,
            Some(FloatCompilation::Block(block, plan)),
        )?;
        // SAFETY: Block emission has the exact owned-state/buffer/budget C signature.
        Ok(Compiled {
            function: unsafe {
                std::mem::transmute::<*const u8, FloatBlockFunction>(code.function)
            },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    pub fn compile_float_loop(
        &mut self,
        loop_: &crate::FloatLoop,
        plan: crate::floating::FloatPlan,
    ) -> Result<Compiled<FloatLoopFunction>, String> {
        let code = self.compile_body(
            &[],
            None,
            None,
            None,
            Some(FloatCompilation::Loop(loop_, plan)),
        )?;
        // SAFETY: Loop emission uses this exact three-pointer/budget C signature.
        Ok(Compiled {
            function: unsafe { std::mem::transmute::<*const u8, FloatLoopFunction>(code.function) },
            cache_hit: code.cache_hit,
            cache_writes: code.cache_writes,
        })
    }
    fn compile_body(
        &mut self,
        instructions: &[Instruction],
        loop_condition: Option<Option<Condition>>,
        memory: Option<&crate::MemoryLoop>,
        region: Option<&crate::Region>,
        floating: Option<FloatCompilation<'_>>,
    ) -> Result<Compiled<*const u8>, String> {
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
        let pointer_type = module.target_config().pointer_type();
        context
            .func
            .signature
            .params
            .push(AbiParam::new(pointer_type));
        if floating.is_none() {
            context.func.signature.params.push(AbiParam::new(
                if loop_condition.is_some() || region.is_some() {
                    types::I32
                } else {
                    pointer_type
                },
            ));
        }
        if memory.is_some() {
            context
                .func
                .signature
                .params
                .extend([AbiParam::new(types::I32); 3]);
        }
        if region.is_some() {
            context
                .func
                .signature
                .params
                .extend([AbiParam::new(types::I32), AbiParam::new(pointer_type)]);
        }
        if matches!(&floating, Some(FloatCompilation::Block(..))) {
            context
                .func
                .signature
                .params
                .extend([AbiParam::new(pointer_type), AbiParam::new(types::I32)]);
        }
        if matches!(&floating, Some(FloatCompilation::Loop(..))) {
            context.func.signature.params.extend([
                AbiParam::new(pointer_type),
                AbiParam::new(pointer_type),
                AbiParam::new(types::I32),
            ]);
        }
        if matches!(&floating, Some(FloatCompilation::Loop(..))) {
            context
                .func
                .signature
                .returns
                .push(AbiParam::new(types::I64));
        } else if floating.is_some() {
            context
                .func
                .signature
                .returns
                .push(AbiParam::new(types::I32));
        } else if loop_condition.is_some() || memory.is_some() || region.is_some() {
            context
                .func
                .signature
                .returns
                .push(AbiParam::new(types::I64));
        }
        let id = module
            .declare_function(&name, Linkage::Local, &context.func.signature)
            .map_err(|error| error.to_string())?;
        let mut frontend = FunctionBuilderContext::new();
        {
            let mut builder = FunctionBuilder::new(&mut context.func, &mut frontend);
            let entry = builder.create_block();
            builder.append_block_params_for_function_params(entry);
            builder.switch_to_block(entry);
            builder.seal_block(entry);
            let state_pointer = builder.block_params(entry)[0];
            if let Some(plan) = floating {
                match plan {
                    FloatCompilation::Scalar(plan) => {
                        crate::float_lowering::emit(&mut builder, plan)
                    }
                    FloatCompilation::Loop(loop_, plan) => {
                        crate::float_block_lowering::emit_loop(&mut builder, loop_, plan)
                    }
                    FloatCompilation::Block(block, plan) => {
                        crate::float_block_lowering::emit(&mut builder, block, plan)
                    }
                }
            } else if let Some(region) = region {
                crate::region_lowering::emit(&mut builder, region);
            } else if let Some(memory) = memory {
                crate::memory_lowering::emit(&mut builder, memory);
            } else if let Some(condition) = loop_condition {
                emit_loop(&mut builder, state_pointer, instructions, condition);
            } else {
                let checkpoints = builder.block_params(entry)[1];
                let mut state = lowering::State::load(&mut builder, state_pointer);
                for (index, &instruction) in instructions.iter().enumerate() {
                    lowering::emit(&mut builder, &mut state, instruction);
                    // Each snapshot is private owned state. It is not a guest
                    // write, a retirement or permission to skip a CPU boundary.
                    for word in 0..9_i32 {
                        let value = state.words[word as usize];
                        builder.ins().store(
                            MemFlagsData::trusted(),
                            value,
                            checkpoints,
                            (index as i32) * 36 + word * 4,
                        );
                    }
                }
                state.write_back(&mut builder, state_pointer);
                builder.ins().return_(&[]);
            }
            builder.finalize(module.target_config());
        }
        let mut adapter = Adapter {
            store: self.store.as_ref(),
            writes: 0,
        };
        let mut control = cranelift_control::ControlPlane::default();
        let cache_hit = if adapter.store.is_some() {
            context
                .compile_with_cache(module.isa(), &mut adapter, &mut control)
                .map_err(|error| error.inner.to_string())?
                .1
        } else {
            context
                .compile(module.isa(), &mut control)
                .map_err(|error| error.inner.to_string())?;
            false
        };
        let code = context.compiled_code().expect("compiled function");
        let relocations: Vec<_> = code
            .buffer
            .relocs()
            .iter()
            .map(|relocation| ModuleReloc::from_mach_reloc(relocation, &context.func, id))
            .collect();
        module
            .define_function_bytes(
                id,
                u64::from(code.buffer.alignment),
                code.code_buffer(),
                &relocations,
            )
            .map_err(|error| error.to_string())?;
        module
            .finalize_definitions()
            .map_err(|error| error.to_string())?;
        let pointer = module.get_finalized_function(id);
        Ok(Compiled {
            function: pointer,
            cache_hit,
            cache_writes: adapter.writes,
        })
    }

    /// All cached entry pointers must be discarded before this call.
    pub unsafe fn clear(&mut self) {
        if let Some(module) = self.module.take() {
            // SAFETY: The sole owner cleared entries and excludes generated-code calls.
            unsafe {
                module.free_memory();
            }
        }
    }
}

// SSA block parameters keep all guest values in host registers across the
// backedge. No checkpoint stores, guest fetches, callbacks or memory effects
// occur in the body. The owner must validate code and event budgets first.
fn emit_loop(
    b: &mut FunctionBuilder<'_>,
    pointer: cranelift_codegen::ir::Value,
    instructions: &[Instruction],
    condition: Option<Condition>,
) {
    let entry = b.current_block().expect("entry block");
    let budget = b.block_params(entry)[1];
    let initial = lowering::State::load(b, pointer);
    let body = b.create_block();
    let exit = b.create_block();
    b.set_cold_block(exit);
    for _ in 0..10 {
        b.append_block_param(body, types::I32);
    }
    let mut incoming: Vec<_> = initial.words.into_iter().map(Into::into).collect();
    incoming.push(budget.into());
    b.ins().jump(body, &incoming);
    b.switch_to_block(body);
    let mut state = lowering::State {
        words: std::array::from_fn(|i| b.block_params(body)[i]),
    };
    let remaining = b.block_params(body)[9];
    let live = lowering::live_flags(instructions);
    for (&instruction, live) in instructions.iter().zip(live) {
        lowering::emit_live(b, &mut state, instruction, live);
    }
    let again = match condition {
        Some(condition) => lowering::condition_value(b, state.words[8], condition),
        None => b.ins().iconst(types::I8, 1),
    };
    let left = b.ins().iadd_imm_s(remaining, -1);
    let more = b.ins().icmp_imm_s(IntCC::NotEqual, left, 0);
    let repeat = b.ins().band(again, more);
    let mut outgoing: Vec<_> = state.words.into_iter().map(Into::into).collect();
    outgoing.push(left.into());
    b.ins().brif(repeat, body, &outgoing, exit, &[]);
    b.seal_block(body);
    b.switch_to_block(exit);
    b.seal_block(exit);
    state.write_back(b, pointer);
    let done = b.ins().isub(budget, left);
    let done = b.ins().uextend(types::I64, done);
    let done = b.ins().ishl_imm_u(done, 1);
    let again = b.ins().uextend(types::I64, again);
    let result = b.ins().bor(done, again);
    b.ins().return_(&[result]);
}
