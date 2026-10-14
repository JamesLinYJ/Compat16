use x86_cpu::Cpu;

use crate::RuntimeError;

pub(super) fn restored_copy(source: &Cpu) -> Result<Cpu, RuntimeError> {
    let model = source.model();
    let registers = source.regs.clone();
    let context = source.capture_context();
    let mut restored = Cpu::new_with_model(registers, model);
    restored.set_execution_engine(source.execution_engine());
    restored
        .restore_context(&context)
        .map_err(RuntimeError::from)?;
    Ok(restored)
}
