use super::*;
fn value(significand: u64, sign_exponent: u16) -> Float80 {
    Float80 {
        significand,
        sign_exponent,
    }
}
fn warm(cache: &mut FloatCache, control: u16) {
    for _ in 0..32 {
        cache.multiply(value(1 << 63, 0x3fff), value(1 << 63, 0x3fff), control);
    }
    assert_eq!(cache.statistics().failures, 0);
}
#[test]
fn extended_products_preserve_bits_beyond_double_and_round_all_controls() {
    let mut cache = FloatCache::default();
    for pc in [0, 2, 3] {
        let precision = match pc {
            0 => 24,
            2 => 53,
            _ => 64,
        };
        for rc in 0..4 {
            let control = 0x7f | pc << 8 | rc << 10;
            warm(&mut cache, control);
            for negative in [false, true] {
                let sign = if negative { 0x8000 } else { 0 };
                let lhs = value((1 << 63) + 1, 0x403e | sign); // ±(2^63 + 1)
                let result = cache
                    .multiply(lhs, value(1 << 63, 0x3fff), control)
                    .unwrap();
                let up = precision < 64 && ((negative && rc == 1) || (!negative && rc == 2));
                assert_eq!(
                    result.value,
                    value(
                        if precision == 64 {
                            lhs.significand
                        } else {
                            (1 << 63) + if up { 1 << (64 - precision) } else { 0 }
                        },
                        lhs.sign_exponent
                    )
                );
                assert_eq!(result.exceptions, if precision == 64 { 0 } else { 32 });
                assert_eq!(result.c1, up);
            }
            if precision < 64 {
                for odd in [false, true] {
                    let halfway = (1 << 63) + (if odd { 3 } else { 1 }) * (1 << (63 - precision));
                    let result = cache
                        .multiply(value(halfway, 0x3fff), value(1 << 63, 0x3fff), control)
                        .unwrap();
                    let up = rc == 2 || rc == 0 && odd;
                    let rounded =
                        (1 << 63) + (u64::from(odd) + u64::from(up)) * (1 << (64 - precision));
                    assert_eq!(result.value, value(rounded, 0x3fff));
                    assert_eq!(result.exceptions, 32);
                    assert_eq!(result.c1, up);
                }
            }
        }
    }
    assert_eq!(cache.statistics().float_compiled, 12);
    assert_eq!(cache.statistics().failures, 0);
}
#[test]
fn multiply_uses_complete_product_and_declines_classes_and_range_results() {
    let mut cache = FloatCache::default();
    warm(&mut cache, 0x37f);
    let near_one = value((1 << 63) + 1, 0x3fff);
    let result = cache.multiply(near_one, near_one, 0x37f).unwrap();
    assert_eq!(result.value, value((1 << 63) + 2, 0x3fff));
    assert_eq!(result.exceptions, 32);
    assert!(!result.c1);
    warm(&mut cache, 0xb7f);
    let result = cache.multiply(near_one, near_one, 0xb7f).unwrap();
    assert_eq!(result.value, value((1 << 63) + 3, 0x3fff));
    assert!(result.c1);
    for left in [
        value(1, 0),
        value(1 << 63, 0),
        value(1 << 63, 0x7fff),
        value(0xc000_0000_0000_0001, 0x7fff),
        value(1, 0x3fff),
        value(u64::MAX, 0x7ffe),
        value(1 << 63, 1),
    ] {
        assert!(
            cache
                .multiply(
                    left,
                    value(1 << 63, if left.sign_exponent == 1 { 1 } else { 0x4000 }),
                    0x37f
                )
                .is_none()
        );
    }
    assert!(cache.statistics().float_fallbacks > 0);
}
#[test]
fn extended_multiply_artifacts_restore_without_operand_or_state_pointers() {
    let store = Arc::new(crate::tests::Store::default());
    let run = || {
        let mut cache = FloatCache::default();
        cache.set_artifact_store(Some(store.clone()));
        warm(&mut cache, 0x37f);
        cache.statistics()
    };
    assert!(run().persistent_writes > 0);
    assert!(run().persistent_hits > 0);
}
