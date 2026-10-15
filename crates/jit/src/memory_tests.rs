use super::*;
fn register(index: u8) -> Register {
    Register::new(index, 2, false).unwrap()
}
fn plan() -> MemoryLoop {
    let memory = ValueOperand::Memory {
        address: Address::new(Some(register(6)), None, 1, 0, 16).unwrap(),
        bytes: 2,
    };
    MemoryLoop::new(
        vec![
            BlockInstruction::Memory(
                MemoryInstruction::new(
                    Operation::Move,
                    ValueOperand::Register(register(0)),
                    memory,
                )
                .unwrap(),
            ),
            BlockInstruction::Memory(
                MemoryInstruction::new(Operation::Add, memory, ValueOperand::Register(register(0)))
                    .unwrap(),
            ),
            BlockInstruction::Integer(
                Instruction::new(Operation::Add, register(6), Operand::Immediate(2)).unwrap(),
            ),
            BlockInstruction::Integer(
                Instruction::new(Operation::Decrement, register(1), Operand::Immediate(0)).unwrap(),
            ),
        ],
        Some(Condition::NotEqual),
    )
    .unwrap()
}
fn warm(cache: &mut MemoryLoopCache, plan: &MemoryLoop) {
    // Compile directly once to keep any verifier failure diagnostic concrete.
    crate::compiler::Compiler::default()
        .compile_memory_loop(plan)
        .unwrap();
    for _ in 0..8 {
        let mut data = [1u8; 8];
        let mut state = input();
        cache.execute(
            plan,
            &mut state,
            MemoryWindow {
                start: 0x300,
                bytes: &mut data,
            },
            1,
        );
    }
    assert_eq!(cache.statistics().failures, 0);
}
fn input() -> IntegerState {
    IntegerState {
        registers: [0xabcd_0000, 3, 0, 0, 0, 0, 0x300, 0],
        flags: 0x203,
    }
}
#[test]
fn guarded_memory_loop_commits_values_flags_and_precise_budget_positions() {
    let plan = plan();
    let mut cache = MemoryLoopCache::default();
    warm(&mut cache, &plan);
    for budget in 1..=20 {
        let mut state = input();
        let mut data = [1u8, 0, 0x80, 0x7f, 0xff, 0xff, 0x55, 0xaa];
        let result = cache
            .execute(
                &plan,
                &mut state,
                MemoryWindow {
                    start: 0x300,
                    bytes: &mut data,
                },
                budget,
            )
            .unwrap();
        assert_eq!(result.retired, budget.min(15));
        if budget >= 15 {
            assert_eq!(result.next_instruction, 5);
            assert_eq!(state.registers[0], 0xabcd_ffff);
            assert_eq!(state.registers[1], 0);
            assert_eq!(state.registers[6], 0x306);
            assert_eq!(state.flags, 0x246);
            assert_eq!(data, [2, 0, 0, 0xff, 0xfe, 0xff, 0x55, 0xaa]);
        } else {
            assert_eq!(result.next_instruction, budget % 5);
        }
    }
}
#[test]
fn window_miss_preserves_the_completed_prefix_and_never_crosses_a_slice() {
    let plan = plan();
    let mut cache = MemoryLoopCache::default();
    warm(&mut cache, &plan);
    let mut state = input();
    let mut data = [1u8, 0, 0x77];
    let result = cache
        .execute(
            &plan,
            &mut state,
            MemoryWindow {
                start: 0x300,
                bytes: &mut data,
            },
            100,
        )
        .unwrap();
    assert_eq!(
        result,
        MemoryOutcome {
            retired: 5,
            next_instruction: 0
        }
    );
    assert_eq!(data, [2, 0, 0x77]);
    assert_eq!(state.registers[6], 0x302);
    assert_eq!(state.registers[1], 2);
    let original = state;
    let bytes = data;
    let result = cache
        .execute(
            &plan,
            &mut state,
            MemoryWindow {
                start: 0x300,
                bytes: &mut data,
            },
            100,
        )
        .unwrap();
    assert_eq!(
        result,
        MemoryOutcome {
            retired: 0,
            next_instruction: 0
        }
    );
    assert_eq!(state, original);
    assert_eq!(data, bytes);
    assert_eq!(
        cache.execute(
            &plan,
            &mut state,
            MemoryWindow {
                start: u32::MAX,
                bytes: &mut data
            },
            100
        ),
        None
    );
    assert_eq!(state, original);
    assert_eq!(data, bytes);
}
#[test]
fn false_conditional_memory_moves_still_require_the_complete_read_range() {
    let address = Address::new(Some(register(6)), None, 1, 0, 16).unwrap();
    let operation = MemoryInstruction::new(
        Operation::ConditionalMove(Condition::Equal),
        ValueOperand::Register(register(0)),
        ValueOperand::Memory { address, bytes: 2 },
    )
    .unwrap();
    let plan = MemoryLoop::new(vec![BlockInstruction::Memory(operation)], None).unwrap();
    let mut cache = MemoryLoopCache::default();
    warm(&mut cache, &plan);
    let mut state = input();
    let original = state;
    let mut data = [0x55];
    assert_eq!(
        cache.execute(
            &plan,
            &mut state,
            MemoryWindow {
                start: 0x300,
                bytes: &mut data
            },
            10
        ),
        Some(MemoryOutcome {
            retired: 0,
            next_instruction: 0
        })
    );
    assert_eq!(state, original);
}
#[test]
fn memory_loop_artifacts_restore_without_capturing_buffer_addresses() {
    let store = std::sync::Arc::new(crate::tests::Store::default());
    let plan = plan();
    for restored in [false, true] {
        let mut cache = MemoryLoopCache::default();
        cache.set_artifact_store(Some(store.clone()));
        warm(&mut cache, &plan);
        let mut state = input();
        let mut data = vec![3u8; 8];
        let result = cache
            .execute(
                &plan,
                &mut state,
                MemoryWindow {
                    start: 0x300,
                    bytes: &mut data,
                },
                100,
            )
            .unwrap();
        assert_eq!(result.retired, 15);
        assert_eq!(cache.statistics().persistent_hits > 0, restored);
        assert_eq!(cache.statistics().persistent_writes > 0, !restored);
    }
}
