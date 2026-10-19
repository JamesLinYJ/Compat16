use super::test_support::NoHost;
use crate::Runtime;
use guest_core::{GuestMemory, PhysAddr, Registers};
use x86_cpu::{CpuArchitecturalContext, CpuSegmentCacheState};

#[test]
fn message_address_getters_reload_equal_es_but_setters_preserve_unreal_caches() {
    for dl in 0..10 {
        let mut runtime = Runtime::load(&[0xf4], &[], b"C:\\SEGMENTS.COM").unwrap();
        let mut provider = Registers {
            eax: 0x122e,
            edx: dl | 1,
            es: 0x4000,
            ..Default::default()
        };
        assert!(runtime.dos.message_address_service(&mut provider));
        runtime.cpu.regs = Registers {
            eax: 0x122e,
            edx: dl,
            cs: 0x1000,
            ss: 0x2000,
            ds: 0x3000,
            es: 0x4000,
            fs: 0x5000,
            gs: 0x6000,
            esp: 0x100,
            eflags: 2,
            ..Default::default()
        };
        let mut segments =
            [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000].map(|selector| CpuSegmentCacheState {
                selector,
                base: u32::from(selector) << 4,
                limit: 0xffff,
                access: 0x93,
                flags: 0,
                usable: true,
            });
        segments[0].access = 0x9b;
        segments[2].base = 0x80000;
        segments[2].limit = 0x1ffff;
        segments[3].base = 0x70000;
        segments[3].limit = 0x1ffff;
        runtime
            .cpu
            .import_architectural_context(CpuArchitecturalContext {
                cr0: 0x10,
                cr2: 0,
                cr3: 0,
                cpl: 0,
                segments,
                tables: Default::default(),
                ldt: Default::default(),
                task: Default::default(),
            })
            .unwrap();
        runtime
            .memory
            .write(
                PhysAddr(0x10000),
                &[
                    0x26, 0xa1, 0, 0, // MOV AX,ES:[0]
                    0x89, 0xc3, // MOV BX,AX
                    0xa1, 0, 0, // MOV AX,DS:[0]
                ],
            )
            .unwrap();
        for (address, marker) in [(0x40000, 0x1111), (0x70000, 0x2222), (0x80000, 0x3333)] {
            runtime.memory.write_u16(PhysAddr(address), marker).unwrap();
        }
        runtime.call_interrupt_service(0x2f, &mut NoHost).unwrap();
        assert_eq!(runtime.cpu.regs.es, 0x4000);
        for _ in 0..3 {
            runtime.cpu.step(&mut runtime.memory.bus()).unwrap();
        }
        assert_eq!(
            runtime.cpu.regs.bx(),
            if dl & 1 == 0 { 0x1111 } else { 0x2222 },
            "DL={dl}"
        );
        assert_eq!(
            runtime.cpu.regs.ax(),
            0x3333,
            "unrelated DS cache changed for DL={dl}"
        );
    }
}
