use rustc_apfloat::{ieee::Quad, Float, Round};

use crate::x87_state::{Ext80, X87State};

use super::kernel;
use super::status;
use super::value::{self, Decoded, Number, IE, ZE};
use crate::x87_math::X87_DE;

pub(super) fn fyl2x(state: &mut X87State, plus_one: bool) -> bool {
    let Some(x_raw) = crate::x87::read_st(state, 0) else { return true; };
    let Some(y_raw) = crate::x87::read_st(state, 1) else { return true; };
    // Decode without committing DE first: FYL2X/FYL2XP1 can discover a
    // higher-priority domain IE (or divide-by-zero ZE) from the pair itself.
    let x = value::decode(x_raw);
    let y = value::decode(y_raw);

    if let Some(nan) = value::propagated_nan(&[x, y]) {
        if !crate::x87::raise_flags(state, status::prioritized_input_flags(&[x, y])) {
            return true;
        }
        finish_pop(state, plain_result(nan, 0));
        return true;
    }
    if matches!(x.number, Number::Unsupported) || matches!(y.number, Number::Unsupported) {
        if !crate::x87::raise_flags(state, status::prioritized_input_flags(&[x, y])) {
            return true;
        }
        finish_pop(state, plain_result(crate::x87::indefinite(), 0));
        return true;
    }

    let (logarithm, mut flags) = logarithm_operand(x, plus_one);
    let result = product_with_log(y, logarithm);
    flags |= result.flags;
    let mut math_result = match result.number {
        Product::Invalid => plain_result(crate::x87::indefinite(), IE),
        Product::Infinity { negative } => plain_result(value::raw_infinity(negative), 0),
        Product::Finite {
            value,
            exponent_adjust,
            known_inexact,
        } => status::round_quad_scaled(state, value, exponent_adjust, known_inexact),
    };
    math_result.exceptions |= flags;
    let input_denormal = (x.flags | y.flags) & X87_DE;
    // A selected domain IE/ZE wins over source #D even when that higher
    // exception is masked; masked #D may only accompany lower O/U/P results.
    if math_result.exceptions & (IE | ZE) == 0 {
        math_result.exceptions |= input_denormal;
    }
    finish_pop(state, math_result);
    true
}

#[derive(Clone, Copy)]
enum Logarithm {
    Finite {
        value: Quad,
        exponent_adjust: i32,
        exact: bool,
    },
    Infinity { negative: bool },
    Invalid,
}

fn logarithm_operand(input: Decoded, plus_one: bool) -> (Logarithm, u16) {
    match input.number {
        Number::Finite(x) => {
            if plus_one && x.bitwise_eq(-kernel::one().scalbn(-1)) {
                return (
                    Logarithm::Finite {
                        value: Quad::from_bits(0xbfff_0000_0000_0000_0000_0000_0000_0000),
                        exponent_adjust: 0,
                        exact: true,
                    },
                    0,
                );
            }
            let (argument, exact_argument) = if plus_one {
                if x.abs() <= kernel::one().scalbn(-1) {
                    let (value, exponent_adjust, exact) = kernel::log2_one_plus(x);
                    return (
                        Logarithm::Finite {
                            value,
                            exponent_adjust,
                            exact,
                        },
                        0,
                    );
                }
                if x.is_negative() {
                    ((x + kernel::one()).value, true)
                } else if x.ilogb() <= 112 {
                    ((x + kernel::one()).value, true)
                } else {
                    // Above Quad's relative-precision window, +1 is smaller
                    // than 2^-113 of x. It cannot affect an extended result
                    // outside a hard-to-round boundary; keep the leading
                    // logarithm instead of letting a rounded x+1 corrupt a
                    // moderate or tiny x case.
                    (x, false)
                }
            } else {
                (x, true)
            };
            if argument.is_zero() {
                if plus_one && x.is_negative() {
                    return (Logarithm::Infinity { negative: true }, ZE);
                }
                if !plus_one {
                    return (Logarithm::Infinity { negative: true }, ZE);
                }
                return (Logarithm::Invalid, IE);
            }
            if argument.is_negative() {
                return (Logarithm::Invalid, IE);
            }
            let (value, exact) = kernel::log2_positive(argument);
            (
                Logarithm::Finite {
                    value,
                    exponent_adjust: 0,
                    exact: exact && exact_argument,
                },
                0,
            )
        }
        Number::Infinity { negative: false } => (Logarithm::Infinity { negative: false }, 0),
        Number::Infinity { negative: true } => (Logarithm::Invalid, IE),
        Number::NaN { .. } | Number::Unsupported => (Logarithm::Invalid, IE),
    }
}

#[derive(Clone, Copy)]
enum Product {
    Finite {
        value: Quad,
        exponent_adjust: i32,
        known_inexact: bool,
    },
    Infinity { negative: bool },
    Invalid,
}

#[derive(Clone, Copy)]
struct ProductResult {
    number: Product,
    flags: u16,
}

fn product_with_log(y: Decoded, logarithm: Logarithm) -> ProductResult {
    match logarithm {
        Logarithm::Invalid => ProductResult::invalid(IE),
        Logarithm::Infinity { negative: log_negative } => match y.number {
            Number::Finite(value) if value.is_zero() => ProductResult::invalid(IE),
            Number::Finite(value) => {
                ProductResult::infinite(value.is_negative() ^ log_negative, 0)
            }
            Number::Infinity { negative } => ProductResult::infinite(negative ^ log_negative, 0),
            Number::NaN { .. } | Number::Unsupported => ProductResult::invalid(IE),
        },
        Logarithm::Finite {
            value: log_value,
            exponent_adjust: log_scale,
            exact,
        } => match y.number {
            Number::Finite(y_value) => {
                if y_value.is_zero() || log_value.is_zero() {
                    let product = (y_value * log_value).value;
                    return ProductResult::finite(product, 0, false, 0);
                }
                // Normalize both finite operands before multiplication. The
                // Quad exponent range is the same order as Ext80's; multiplying
                // unscaled inputs can therefore erase valid x87 overflow and
                // deep-underflow results before the register-bias phase sees
                // them. `rustc_apfloat` supplies the 113-bit product, while
                // this small exponent ledger preserves its exact power-of-two
                // scale across the missing extended-exponent API.
                let y_exponent = y_value.ilogb();
                let log_exponent = log_value.ilogb();
                let normalized_y = y_value.scalbn(-y_exponent);
                let normalized_log = log_value.scalbn(-log_exponent);
                let multiplied = normalized_y.mul_r(normalized_log, Round::NearestTiesToEven);
                let product_exponent = multiplied.value.ilogb();
                let normalized_product = multiplied.value.scalbn(-product_exponent);
                let product_inexact = multiplied
                    .status
                    .contains(rustc_apfloat::Status::INEXACT);
                ProductResult::finite(
                    normalized_product,
                    y_exponent
                        .saturating_add(log_exponent)
                        .saturating_add(log_scale)
                        .saturating_add(product_exponent),
                    !exact || product_inexact,
                    0,
                )
                .with_flags(
                    crate::x87_math::map_status(multiplied.status),
                )
            }
            Number::Infinity { negative } => {
                if log_value.is_zero() {
                    ProductResult::invalid(IE)
                } else {
                    ProductResult::infinite(negative ^ log_value.is_negative(), 0)
                }
            }
            Number::NaN { .. } | Number::Unsupported => ProductResult::invalid(IE),
        },
    }
}

impl ProductResult {
    fn finite(value: Quad, exponent_adjust: i32, known_inexact: bool, flags: u16) -> Self {
        Self {
            number: Product::Finite {
                value,
                exponent_adjust,
                known_inexact: known_inexact && !value.is_zero(),
            },
            flags,
        }
    }

    fn infinite(negative: bool, flags: u16) -> Self {
        Self {
            number: Product::Infinity { negative },
            flags,
        }
    }

    fn invalid(flags: u16) -> Self {
        Self {
            number: Product::Invalid,
            flags,
        }
    }

    fn with_flags(mut self, flags: u16) -> Self {
        self.flags |= flags;
        self
    }
}

fn finish_pop(state: &mut X87State, result: crate::x87_math::MathResult) {
    if let Some((value, c1)) = status::commit_result(state, result) {
        status::set_result_conditions(state, c1);
        crate::x87::write_st(state, 1, value);
        crate::x87::pop(state);
    }
}

fn plain_result(value: Ext80, exceptions: u16) -> crate::x87_math::MathResult {
    crate::x87_math::MathResult {
        value,
        exceptions,
        c1: false,
        range: None,
    }
}
