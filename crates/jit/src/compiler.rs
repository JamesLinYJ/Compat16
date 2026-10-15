//! Compilation, relocation and executable-memory ownership.

use crate::{
    Instruction, IntegerState,
    artifact::{Adapter, ArtifactStore},
    lowering,
};
use cranelift_codegen::ir::{AbiParam, InstBuilder, MemFlagsData};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module, ModuleReloc};
use std::sync::Arc;

pub(crate) type Function = unsafe extern "C" fn(*mut IntegerState, *mut IntegerState);
#[derive(Default)]
pub(crate) struct Compiler {
    module: Option<JITModule>,
    next_function: u64,
    pub store: Option<Arc<dyn ArtifactStore>>,
}
pub(crate) struct Compiled {
    pub function: Function,
    pub cache_hit: bool,
    pub cache_writes: u64,
}
impl Compiler {
    pub fn compile(&mut self, instructions: &[Instruction]) -> Result<Compiled, String> {
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
            .extend([AbiParam::new(pointer_type); 2]);
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
        // SAFETY: This exact C signature was emitted above. Pointers remain
        // private to the code owner, and Cranelift owns relocation, W^X and
        // instruction-cache publication for both fresh and restored code.
        let function = unsafe { std::mem::transmute::<*const u8, Function>(pointer) };
        Ok(Compiled {
            function,
            cache_hit,
            cache_writes: adapter.writes,
        })
    }

    /// All cached entry pointers must be discarded before this call.
    pub unsafe fn clear(&mut self) {
        if let Some(module) = self.module.take() {
            // SAFETY: The sole owner cleared entries and excludes native calls.
            unsafe {
                module.free_memory();
            }
        }
    }
}
