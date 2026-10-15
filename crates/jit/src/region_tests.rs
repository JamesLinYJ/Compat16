use super::*;

fn op(operation: Operation, index: u8, immediate: u32) -> Instruction {
    Instruction::new(
        operation,
        Register::new(index, 2, false).unwrap(),
        Operand::Immediate(immediate),
    )
    .unwrap()
}
fn graph() -> Region {
    Region::new(
        vec![
            RegionBlock {
                instructions: vec![op(Operation::Add, 0, 3), op(Operation::Test, 0, 1)],
                branch: RegionBranch::Conditional {
                    condition: Condition::Equal,
                    taken: RegionTarget::Block(2),
                    fallthrough: RegionTarget::Block(1),
                    prefer_taken: false,
                },
            },
            RegionBlock {
                instructions: vec![op(Operation::AddCarry, 3, 7)],
                branch: RegionBranch::Jump(RegionTarget::Block(2)),
            },
            RegionBlock {
                instructions: vec![op(Operation::Decrement, 1, 0)],
                branch: RegionBranch::Conditional {
                    condition: Condition::NotEqual,
                    taken: RegionTarget::Block(0),
                    fallthrough: RegionTarget::Exit(0),
                    prefer_taken: true,
                },
            },
        ],
        1,
    )
    .unwrap()
}
fn start() -> RegionPosition {
    RegionPosition::Block {
        block: 0,
        instruction: 0,
    }
}
fn ready(cache: &mut RegionCache, plan: &Region) {
    for _ in 0..8 {
        cache.execute(
            plan,
            &mut IntegerState {
                registers: [30; 8],
                flags: 0x203,
            },
            start(),
            256,
        );
    }
    assert!(cache.statistics().regions_compiled > 0);
    assert_eq!(cache.statistics().failures, 0);
}
fn reference(
    plan: &Region,
    singles: &mut CodeCache,
    mut state: IntegerState,
    mut position: RegionPosition,
    budget: u32,
) -> (IntegerState, RegionOutcome) {
    let mut retired = 0;
    while let RegionPosition::Block { block, instruction } = position {
        let body = &plan.blocks[usize::from(block)];
        if retired == budget
            && (usize::from(instruction) < body.instructions.len() || body.branch.retires() != 0)
        {
            break;
        }
        if usize::from(instruction) < body.instructions.len() {
            let ir = body.instructions[usize::from(instruction)];
            if !singles.execute(ir, &mut state) {
                let original = state;
                for _ in 0..32 {
                    state = original;
                    singles.execute(ir, &mut state);
                }
            }
            retired += 1;
            position = RegionPosition::Block {
                block,
                instruction: instruction + 1,
            };
        } else {
            retired += body.branch.retires();
            let target = match body.branch {
                RegionBranch::Continue(t) | RegionBranch::Jump(t) => t,
                RegionBranch::Conditional {
                    condition,
                    taken,
                    fallthrough,
                    ..
                } => {
                    let f = state.flags;
                    let test = match condition {
                        Condition::Equal => f & 0x40 != 0,
                        Condition::NotEqual => f & 0x40 == 0,
                        _ => unreachable!(),
                    };
                    if test { taken } else { fallthrough }
                }
            };
            position = match target {
                RegionTarget::Block(block) => RegionPosition::Block {
                    block,
                    instruction: 0,
                },
                RegionTarget::Exit(i) => RegionPosition::Exit(i),
            };
        }
    }
    (
        state,
        RegionOutcome {
            retired,
            next: position,
        },
    )
}

#[test]
fn linked_diamonds_cycles_and_every_budget_prefix_match_single_instructions() {
    let plan = graph();
    let mut cache = RegionCache::default();
    ready(&mut cache, &plan);
    let mut singles = CodeCache::default();
    for count in [1, 2, 7, 30, 0xffff] {
        for budget in 1..=256 {
            for initial in [0, 0x7fff, 0xffff, 0x1234_ffff] {
                let input = IntegerState {
                    registers: [initial, count, 9, 0xffff, 0, 0, 0, 0],
                    flags: 0xad7,
                };
                let (expected, outcome) = reference(&plan, &mut singles, input, start(), budget);
                let mut actual = input;
                let got = cache.execute(&plan, &mut actual, start(), budget).unwrap();
                assert_eq!(got, outcome, "budget={budget} count={count}");
                assert_eq!(actual, expected, "budget={budget} count={count}");
                if matches!(got.next, RegionPosition::Block { .. }) {
                    let (expected, outcome) = reference(&plan, &mut singles, actual, got.next, 17);
                    assert_eq!(
                        cache.execute(&plan, &mut actual, got.next, 17),
                        Some(outcome)
                    );
                    assert_eq!(actual, expected);
                }
            }
        }
    }
    assert!(cache.statistics().direct_links > cache.statistics().regions_executed);
    assert!(cache.statistics().branches_taken > 0 && cache.statistics().branches_fallthrough > 0);
}

#[test]
fn zero_cost_cycles_bad_targets_and_invalid_entries_never_execute() {
    assert!(
        Region::new(
            vec![RegionBlock {
                instructions: vec![],
                branch: RegionBranch::Continue(RegionTarget::Block(0))
            }],
            0
        )
        .is_none()
    );
    assert!(
        Region::new(
            vec![RegionBlock {
                instructions: vec![],
                branch: RegionBranch::Jump(RegionTarget::Block(1))
            }],
            0
        )
        .is_none()
    );
    assert!(
        Region::new(
            vec![RegionBlock {
                instructions: vec![],
                branch: RegionBranch::Jump(RegionTarget::Exit(0))
            }],
            0
        )
        .is_none()
    );
    let plan = graph();
    let mut cache = RegionCache::default();
    let initial = IntegerState {
        registers: [0xfeed_beef; 8],
        flags: 0xad7,
    };
    let mut state = initial;
    for position in [
        RegionPosition::Block {
            block: 16,
            instruction: 0,
        },
        RegionPosition::Block {
            block: 0,
            instruction: 3,
        },
        RegionPosition::Exit(0),
    ] {
        assert_eq!(cache.execute(&plan, &mut state, position, 256), None);
        assert_eq!(state, initial);
    }
    assert_eq!(cache.execute(&plan, &mut state, start(), 0), None);
    assert_eq!(state, initial);
    assert_eq!(cache.statistics().compiled, 0);
    // Branch-only cycles also terminate, and the default public budget is capped.
    let branches = Region::new(
        vec![RegionBlock {
            instructions: vec![],
            branch: RegionBranch::Jump(RegionTarget::Block(0)),
        }],
        0,
    )
    .unwrap();
    ready(&mut cache, &branches);
    let before = cache.statistics();
    let result = cache
        .execute(&branches, &mut state, start(), u32::MAX)
        .unwrap();
    assert_eq!(result.retired, 256);
    assert_eq!(state, initial);
    assert_eq!(cache.statistics().direct_links - before.direct_links, 256);
    assert_eq!(
        cache.statistics().branches_taken - before.branches_taken,
        256
    );
}

#[test]
fn linked_artifacts_relocate_in_new_owners_and_layout_is_in_the_key() {
    let store = Arc::new(crate::tests::Store::default());
    let run = |plan: &Region| {
        let mut cache = RegionCache::default();
        cache.set_artifact_store(Some(store.clone()));
        ready(&mut cache, plan);
        cache.statistics()
    };
    let plan = graph();
    assert!(run(&plan).persistent_writes > 0);
    assert!(run(&plan).persistent_hits > 0);
    let mut changed = plan.blocks.clone();
    if let RegionBranch::Conditional { prefer_taken, .. } = &mut changed[0].branch {
        *prefer_taken = true;
    }
    assert_eq!(run(&Region::new(changed, 1).unwrap()).persistent_hits, 0);
}

#[test]
fn sequential_edges_do_not_invent_retirement_and_eviction_drops_all_links() {
    let plan = Region::new(
        vec![
            RegionBlock {
                instructions: vec![op(Operation::Increment, 0, 0)],
                branch: RegionBranch::Continue(RegionTarget::Block(1)),
            },
            RegionBlock {
                instructions: vec![op(Operation::AddCarry, 3, 1)],
                branch: RegionBranch::Jump(RegionTarget::Block(0)),
            },
        ],
        0,
    )
    .unwrap();
    let mut cache = RegionCache::default();
    ready(&mut cache, &plan);
    let mut singles = CodeCache::default();
    for budget in 1..=256 {
        let input = IntegerState {
            registers: [0xffff; 8],
            flags: 0x203,
        };
        let (expected, outcome) = reference(&plan, &mut singles, input, start(), budget);
        let mut state = input;
        assert_eq!(
            cache.execute(&plan, &mut state, start(), budget),
            Some(outcome)
        );
        assert_eq!(state, expected);
    }
    for i in 0..256 {
        let other = Region::new(
            vec![RegionBlock {
                instructions: vec![op(Operation::Move, 0, i)],
                branch: RegionBranch::Jump(RegionTarget::Block(0)),
            }],
            0,
        )
        .unwrap();
        assert_eq!(
            cache.execute(&other, &mut IntegerState::default(), start(), 2),
            None
        );
    }
    let mut state = IntegerState::default();
    assert_eq!(cache.execute(&plan, &mut state, start(), 256), None);
    assert_eq!(state, IntegerState::default());
    assert!(cache.statistics().cache_resets > 0);
    ready(&mut cache, &plan);
}
