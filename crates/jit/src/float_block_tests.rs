use super::*;
fn value(significand: u64, sign_exponent: u16) -> Float80 {
    Float80 {
        significand,
        sign_exponent,
    }
}
fn input() -> FloatRegisters {
    FloatRegisters {
        values: [value(1 << 63, 0x3fff); 8],
        status: 0x4100,
        tags: 0xfff0,
        control: 0x37f,
    }
}
fn warm(cache: &mut FloatBlockCache, block: &FloatBlock) {
    compiler::Compiler::default()
        .compile_float_block(
            block,
            crate::floating::FloatPlan {
                operation: FloatOperation::Add,
                precision: 64,
                rounding: 0,
            },
        )
        .unwrap();
    for _ in 0..8 {
        cache.execute(block, &mut input(), &mut [0; 256], 32);
    }
    assert_eq!(cache.statistics().failures, 0);
}
#[test]
fn repeating_float_bodies_keep_budgets_integer_backedges_and_exact_prefixes() {
    let cx = Register::new(1, 2, false).unwrap();
    let tail = IntegerLoop::new(
        vec![Instruction::new(Operation::Decrement, cx, Operand::Immediate(1)).unwrap()],
        Some(Condition::NotEqual),
    )
    .unwrap();
    assert!(
        FloatLoop::new(
            FloatBlock::new(vec![FloatInstruction::One]).unwrap(),
            tail.clone()
        )
        .is_none()
    );
    let plan = FloatLoop::new(
        FloatBlock::new(vec![FloatInstruction::Negate, FloatInstruction::Absolute]).unwrap(),
        tail,
    )
    .unwrap();
    let mut cache = FloatBlockCache::default();
    let mut tails = LoopCache::default();
    let registers = || {
        let mut s = IntegerState::default();
        s.registers[1] = 3;
        s.flags = 0x203;
        s
    };
    for _ in 0..32 {
        cache.execute_loop(&plan, &mut input(), &mut registers(), &mut tails, None, 32);
    }
    for budget in 0..=16 {
        let mut state = input();
        let mut integer = registers();
        let Some(out) =
            cache.execute_loop(&plan, &mut state, &mut integer, &mut tails, None, budget)
        else {
            assert_eq!(budget, 0);
            assert_eq!(state, input());
            assert_eq!(integer, registers());
            continue;
        };
        assert!(out.retired <= budget && out.retired <= 12);
        assert_eq!(integer.registers[1], 3 - out.retired / 4);
        assert_eq!(
            state.values[0].sign_exponent,
            if out.retired % 4 == 1 { 0xbfff } else { 0x3fff }
        );
        assert_eq!(&state.values[1..], &input().values[1..]);
        assert_eq!(state.control, input().control);
        assert_eq!(out.last_memory, None);
        assert_eq!(out.last_float, if out.retired % 4 == 1 { 0 } else { 1 });
        assert_eq!(
            out.position,
            if out.retired == 12 {
                FloatLoopPosition::Finished
            } else {
                match out.retired % 4 {
                    0 => FloatLoopPosition::Floating(0),
                    1 => FloatLoopPosition::Floating(1),
                    2 => FloatLoopPosition::IntegerTail,
                    _ => panic!("split integer tail"),
                }
            }
        );
    }
    assert!(tails.statistics().loop_iterations > 0);
}
#[test]
fn register_entry_rejects_memory_ir_and_matches_window_execution_prefixes() {
    let mut cache = FloatBlockCache::default();
    for memory in [
        FloatInstruction::Load80 { offset: 0 },
        FloatInstruction::Store80 {
            offset: 0,
            pop: false,
        },
        FloatInstruction::LoadMemory {
            format: FloatMemoryFormat::Binary32,
            offset: 0,
        },
        FloatInstruction::BinaryMemory {
            operation: FloatOperation::Add,
            format: FloatMemoryFormat::Binary64,
            offset: 0,
            reverse: false,
        },
    ] {
        let block = FloatBlock::new(vec![memory, FloatInstruction::Negate]).unwrap();
        let mut state = input();
        let original = state;
        assert_eq!(cache.execute_registers(&block, &mut state, 2), None);
        assert_eq!(state, original);
    }
    let block =
        FloatBlock::new(vec![FloatInstruction::Negate, FloatInstruction::Absolute]).unwrap();
    warm(&mut cache, &block);
    for budget in 0..=3 {
        let mut state = input();
        let mut reference = state;
        let actual = cache.execute_registers(&block, &mut state, budget);
        let expected = cache.execute(&block, &mut reference, &mut [0xa5; 256], budget);
        assert_eq!(actual, expected);
        assert_eq!(state, reference);
    }
}
#[test]
fn sparse_and_tag_only_blocks_preserve_unwritten_extended_payloads() {
    let stores = FloatBlock::new(vec![
        FloatInstruction::Store80 {
            offset: 1,
            pop: true,
        },
        FloatInstruction::Store80 {
            offset: 21,
            pop: true,
        },
    ])
    .unwrap();
    let pushes = FloatBlock::new(vec![FloatInstruction::One, FloatInstruction::Zero]).unwrap();
    let mut cache = FloatBlockCache::default();
    warm(&mut cache, &stores);
    warm(&mut cache, &pushes);
    for top in 0..8 {
        for budget in 1..=2 {
            let values = std::array::from_fn(|i| value((1 << 63) + i as u64, 0x3fff + i as u16));
            let mut state = FloatRegisters {
                values,
                status: top << 11,
                tags: 0xfff0,
                control: 0x37f,
            };
            // An unused malformed payload must be preserved verbatim, even
            // when its tag is empty and both live operands are popped.
            state.values[4] = value(0x1234, 0xffff);
            let before = state.values;
            let mut bytes = [0xa5; 256];
            assert_eq!(
                cache.execute(&stores, &mut state, &mut bytes, budget),
                Some(budget)
            );
            assert_eq!(state.values, before);
            assert_eq!((state.status >> 11) & 7, (top + budget as u16) & 7);
            assert_eq!(state.tags, if budget == 1 { 0xfff3 } else { 0xffff });
            for i in 0..budget as usize {
                let offset = 1 + i * 20;
                assert_eq!(
                    &bytes[offset..offset + 8],
                    &values[i].significand.to_le_bytes()
                );
                assert_eq!(
                    &bytes[offset + 8..offset + 10],
                    &values[i].sign_exponent.to_le_bytes()
                );
                bytes[offset..offset + 10].fill(0xa5);
            }
            assert_eq!(bytes, [0xa5; 256]);
            state.values = before;
            state.status = top << 11;
            state.tags = 0xffff;
            assert_eq!(
                cache.execute(&pushes, &mut state, &mut bytes, budget),
                Some(budget)
            );
            assert_eq!(state.values[7], value(1 << 63, 0x3fff));
            assert_eq!(
                state.values[6],
                if budget == 1 { before[6] } else { value(0, 0) }
            );
            assert_eq!(&state.values[..6], &before[..6]);
            assert_eq!((state.status >> 11) & 7, (top + 8 - budget as u16) & 7);
        }
    }
}
#[test]
fn float_blocks_keep_exact_prefixes_stack_tags_and_owned_ram() {
    let block = FloatBlock::new(vec![
        FloatInstruction::Load80 { offset: 7 },
        FloatInstruction::Binary {
            operation: FloatOperation::Multiply,
            destination: 0,
            source: 1,
            reverse: false,
            pop: false,
        },
        FloatInstruction::Binary {
            operation: FloatOperation::Add,
            destination: 0,
            source: 1,
            reverse: false,
            pop: false,
        },
        FloatInstruction::Store80 {
            offset: 33,
            pop: true,
        },
    ])
    .unwrap();
    let mut cache = FloatBlockCache::default();
    warm(&mut cache, &block);
    for budget in 1..=6 {
        let mut state = input();
        state.status |= 0x8080; // Raw restored summary with no pending flags.
        let mut bytes = [0xa5u8; 256];
        bytes[7..15].copy_from_slice(&((1u64 << 63) + 1).to_le_bytes());
        bytes[15..17].copy_from_slice(&0x3fffu16.to_le_bytes());
        let original = bytes;
        let n = cache
            .execute(&block, &mut state, &mut bytes, budget)
            .unwrap();
        assert_eq!(n, budget.min(4));
        assert_eq!(state.status & 0x8080, 0);
        assert_eq!(state.status & 0x3800, if budget < 4 { 7 << 11 } else { 0 });
        if budget < 4 {
            assert_eq!(bytes, original);
            assert_eq!(state.tags & (3 << 14), 0);
        } else {
            assert_eq!(state.tags, 0xfff0);
            assert_eq!(&bytes[33..41], &(1u64 << 63).to_le_bytes());
            assert_eq!(&bytes[41..43], &0x4000u16.to_le_bytes());
            bytes[33..43].copy_from_slice(&original[33..43]);
            assert_eq!(bytes, original);
        }
    }
}
#[test]
fn float_blocks_stop_before_special_or_empty_operands_and_after_unmasked_precision() {
    let instruction = FloatInstruction::Binary {
        operation: FloatOperation::Multiply,
        destination: 0,
        source: 1,
        reverse: false,
        pop: false,
    };
    let block = FloatBlock::new(vec![instruction; 3]).unwrap();
    let mut cache = FloatBlockCache::default();
    warm(&mut cache, &block);
    let mut state = input();
    state.tags |= 3;
    let before = state;
    assert_eq!(cache.execute(&block, &mut state, &mut [0; 256], 3), Some(0));
    assert_eq!(state, before);
    let mut state = input();
    state.values[0] = value(1, 0);
    let before = state;
    assert_eq!(cache.execute(&block, &mut state, &mut [0; 256], 3), Some(0));
    assert_eq!(state, before);
    let mut state = input();
    state.control &= !32;
    state.values[0] = value((1 << 63) + 1, 0x3fff);
    state.values[1] = state.values[0];
    assert_eq!(cache.execute(&block, &mut state, &mut [0; 256], 3), Some(1));
    assert_eq!(state.values[0], value((1 << 63) + 2, 0x3fff));
    assert_eq!(state.status & 0x80a0, 0x80a0);
    let before = state;
    assert_eq!(cache.execute(&block, &mut state, &mut [0; 256], 3), None);
    assert_eq!(state, before);
}
#[test]
fn float_blocks_validate_offsets_indices_lengths_and_restore_persistent_artifacts() {
    assert!(FloatBlock::new(vec![FloatInstruction::Exchange(8); 2]).is_none());
    assert!(FloatBlock::new(vec![FloatInstruction::Load80 { offset: 247 }; 2]).is_none());
    for (format, last) in [
        (FloatMemoryFormat::Binary32, 252),
        (FloatMemoryFormat::Binary64, 248),
    ] {
        assert!(
            FloatBlock::new(vec![
                FloatInstruction::LoadMemory {
                    format,
                    offset: last
                };
                2
            ])
            .is_some()
        );
        assert!(
            FloatBlock::new(vec![
                FloatInstruction::LoadMemory {
                    format,
                    offset: last + 1
                };
                2
            ])
            .is_none()
        );
        assert!(
            FloatBlock::new(vec![
                FloatInstruction::BinaryMemory {
                    operation: FloatOperation::Add,
                    format,
                    offset: last + 1,
                    reverse: false
                };
                2
            ])
            .is_none()
        );
    }
    assert!(FloatBlock::new(vec![FloatInstruction::One; 33]).is_none());
    assert!(FloatBlock::new(Vec::new()).is_none());
    assert!(FloatBlock::new(vec![FloatInstruction::One]).is_some());
    let block = FloatBlock::new(vec![
        FloatInstruction::LoadRegister(0),
        FloatInstruction::StoreRegister {
            destination: 1,
            pop: true,
        },
    ])
    .unwrap();
    let store = Arc::new(crate::tests::Store::default());
    let run = || {
        let mut cache = FloatBlockCache::default();
        cache.set_artifact_store(Some(store.clone()));
        warm(&mut cache, &block);
        cache.statistics()
    };
    assert!(run().persistent_writes > 0);
    assert!(run().persistent_hits > 0);
}

#[test]
fn floating_direct_dispatch_rechecks_modes_and_is_revoked_before_eviction() {
    let block = FloatBlock::new(vec![
        FloatInstruction::Binary {
            operation: FloatOperation::Multiply,
            destination: 0,
            source: 1,
            reverse: false,
            pop: false,
        };
        2
    ])
    .unwrap();
    let mut cache = FloatBlockCache::default();
    warm(&mut cache, &block);
    for control in [0x37f, 0x7f, 0x37f, 0x35f] {
        for _ in 0..8 {
            let mut state = input();
            state.control = control;
            state.values[0] = value((1 << 63) + 1, 0x3fff);
            if cache
                .execute(&block, &mut state, &mut [0; 256], 2)
                .is_some()
            {
                assert_eq!(
                    state.values[0].significand,
                    (1 << 63) + u64::from(control & 0x300 != 0)
                );
                assert_eq!(state.status & 32, if control & 0x300 == 0 { 32 } else { 0 });
            }
        }
    }
    assert_eq!(cache.statistics().float_blocks_compiled, 2);
    let equivalent = FloatBlock::new(block.instructions().to_vec()).unwrap();
    assert_eq!(
        cache.execute(&equivalent, &mut input(), &mut [0; 256], 2),
        Some(2)
    );
    assert_eq!(cache.statistics().float_blocks_compiled, 2);
    // Distinct, valid cold blocks fill the cache without compiling hundreds
    // of functions. The oldest block's direct entry must also be revoked.
    for index in 0..256 {
        let offset = (index % 247) as u8;
        let other = FloatBlock::new(vec![
            FloatInstruction::Store80 {
                offset,
                pop: index >= 247,
            };
            2
        ])
        .unwrap();
        assert_eq!(cache.execute(&other, &mut input(), &mut [0; 256], 2), None);
    }
    assert_eq!(cache.statistics().cache_resets, 1);
    assert_eq!(cache.execute(&block, &mut input(), &mut [0; 256], 2), None);
    warm(&mut cache, &block);
    assert_eq!(cache.statistics().float_blocks_compiled, 3);
    assert_eq!(cache.statistics().failures, 0);
}
