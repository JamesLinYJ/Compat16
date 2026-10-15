use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct Store(Mutex<HashMap<[u8; 32], Artifact>>);
impl ArtifactStore for Store {
    fn load(&self, key: &[u8; 32]) -> Option<Artifact> {
        self.0.lock().ok()?.get(key).cloned()
    }
    fn store(&self, artifact: &Artifact) -> bool {
        self.0
            .lock()
            .unwrap()
            .insert(*artifact.key(), artifact.clone());
        true
    }
}
fn instructions() -> [Instruction; 4] {
    let ax = Register::new(0, 2, false).unwrap();
    let ah = Register::new(0, 1, true).unwrap();
    let ebx = Register::new(3, 4, false).unwrap();
    [
        Instruction::new(Operation::Move, ax, Operand::Immediate(0x7fff)).unwrap(),
        Instruction::new(Operation::AddCarry, ax, Operand::Immediate(0)).unwrap(),
        Instruction::new(Operation::SignExtend, ebx, Operand::Register(ah)).unwrap(),
        Instruction::new(
            Operation::SetCondition(Condition::Overflow),
            ah,
            Operand::Immediate(0),
        )
        .unwrap(),
    ]
}

#[test]
fn fused_checkpoints_match_individually_generated_instructions() {
    let program = instructions();
    let mut block = CodeCache::default();
    let mut singles = CodeCache::default();
    for round in 0..64 {
        let original = IntegerState {
            registers: [0xdead_beef; 8],
            flags: 2 | (round & 1),
        };
        let mut combined = original;
        let mut checkpoints = [IntegerState::default(); MAX_BLOCK_INSTRUCTIONS];
        let fused = block.execute_block(&program, &mut combined, &mut checkpoints);
        let mut individual = original;
        for (index, &instruction) in program.iter().enumerate() {
            let before = individual;
            let generated = singles.execute(instruction, &mut individual);
            if !generated {
                // Warm without duplicating the operation in its input state.
                for _ in 0..32 {
                    individual = before;
                    singles.execute(instruction, &mut individual);
                }
            }
            if fused {
                assert_eq!(checkpoints[index], individual);
            }
        }
        if fused {
            assert_eq!(combined, individual);
        }
    }
    assert!(block.statistics().blocks_executed > 0);
    assert_eq!(block.statistics().failures, 0);
}

#[test]
fn serialized_artifact_avoids_recompilation_in_a_fresh_code_owner() {
    let store = Arc::new(Store::default());
    let run = || {
        let mut cache = CodeCache::default();
        cache.set_artifact_store(Some(store.clone()));
        let mut output = [IntegerState::default(); MAX_BLOCK_INSTRUCTIONS];
        for _ in 0..4 {
            let mut state = IntegerState {
                registers: [u32::MAX; 8],
                flags: 3,
            };
            if cache.execute_block(&instructions(), &mut state, &mut output) {
                assert_eq!(state.registers[3], 0xffff_ff80);
                assert_eq!(state.registers[0] & 0xffff, 0x0100);
            }
        }
        cache.statistics()
    };
    let first = run();
    assert_eq!(first.persistent_hits, 0);
    assert!(first.persistent_writes > 0);
    let second = run();
    assert!(second.persistent_hits > 0);
    assert_eq!(second.failures, 0);
}

#[test]
fn invalid_block_shapes_leave_both_owned_buffers_unchanged() {
    let mut cache = CodeCache::default();
    let mut state = IntegerState {
        registers: [0x1234_5678; 8],
        flags: 0x8d7,
    };
    let original = state;
    let mut output = [original; MAX_BLOCK_INSTRUCTIONS];
    assert!(!cache.execute_block(&[], &mut state, &mut output));
    assert!(!cache.execute_block(
        &vec![instructions()[0]; MAX_BLOCK_INSTRUCTIONS + 1],
        &mut state,
        &mut output
    ));
    assert!(!cache.execute_block(&instructions(), &mut state, &mut []));
    assert_eq!(state, original);
    assert_eq!(output, [original; MAX_BLOCK_INSTRUCTIONS]);
    assert_eq!(cache.statistics().compiled, 0);
}

#[test]
fn authenticated_artifacts_cannot_be_rebound_to_another_compiler_key() {
    let store = Arc::new(Store::default());
    let mut producer = CodeCache::default();
    producer.set_artifact_store(Some(store.clone()));
    for _ in 0..3 {
        producer.execute_block(
            &instructions(),
            &mut IntegerState::default(),
            &mut [IntegerState::default(); MAX_BLOCK_INSTRUCTIONS],
        );
    }
    struct WrongKey(Artifact);
    impl ArtifactStore for WrongKey {
        fn load(&self, _: &[u8; 32]) -> Option<Artifact> {
            Some(self.0.clone())
        }
        fn store(&self, _: &Artifact) -> bool {
            false
        }
    }
    let artifact = store.0.lock().unwrap().values().next().unwrap().clone();
    let mut consumer = CodeCache::default();
    consumer.set_artifact_store(Some(Arc::new(WrongKey(artifact))));
    let different = Instruction::new(
        Operation::Move,
        Register::new(0, 4, false).unwrap(),
        Operand::Immediate(42),
    )
    .unwrap();
    let mut state = IntegerState::default();
    for _ in 0..40 {
        consumer.execute(different, &mut state);
    }
    assert_eq!(state.registers[0], 42);
    assert_eq!(consumer.statistics().persistent_hits, 0);
    assert_eq!(consumer.statistics().failures, 0);
}

#[test]
fn arithmetic_overflow_matches_wide_math_for_every_byte_and_carry() {
    let mut cache = CodeCache::default();
    for (operation, subtract) in [
        (Operation::AddCarry, false),
        (Operation::SubtractBorrow, true),
    ] {
        let instruction = Instruction::new(
            operation,
            Register::new(0, 1, false).unwrap(),
            Operand::Register(Register::new(1, 1, false).unwrap()),
        )
        .unwrap();
        for _ in 0..32 {
            cache.execute(instruction, &mut IntegerState::default());
        }
        for left in 0_u32..256 {
            for right in 0_u32..256 {
                for carry in 0..2 {
                    let mut state = IntegerState {
                        registers: [left, right, 0, 0, 0, 0, 0, 0],
                        flags: 2 | carry,
                    };
                    assert!(cache.execute(instruction, &mut state));
                    let a = i32::from(left as u8 as i8);
                    let b = i32::from(right as u8 as i8) + carry as i32;
                    let signed = if subtract { a - b } else { a + b };
                    let unsigned = if subtract {
                        left.wrapping_sub(right).wrapping_sub(carry)
                    } else {
                        left + right + carry
                    };
                    assert_eq!(state.registers[0], unsigned & 255);
                    assert_eq!(
                        state.flags & (1 << 11) != 0,
                        !(-128..=127).contains(&signed)
                    );
                    assert_eq!(
                        state.flags & 1 != 0,
                        if subtract {
                            left < right + carry
                        } else {
                            left + right + carry > 255
                        }
                    );
                }
            }
        }
    }
    assert_eq!(cache.statistics().failures, 0);
}
