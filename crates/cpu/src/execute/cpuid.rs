//! CPUID results are derived only from the selected guest compatibility profile.

use guest_core::Registers;

use crate::CpuModel;

pub(super) fn execute(registers: &mut Registers, model: CpuModel) {
    let [eax, ebx, ecx, edx] = model.cpuid_result(registers.eax);
    registers.eax = eax;
    registers.ebx = ebx;
    registers.ecx = ecx;
    registers.edx = edx;
}
