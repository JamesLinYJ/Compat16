use std::{env, fmt::Write as _, fs, path::PathBuf};

fn main() {
    const INPUT: &str = "src/x87_transcendental/coefficients.hex";
    const GROUPS: [(&str, usize); 8] = [
        ("SIN", 14),
        ("COS", 15),
        ("EXP", 20),
        ("ATAN", 9),
        ("ATANH", 9),
        ("ATAN_CENTERS", 33),
        ("LOG_CENTERS", 33),
        ("INV_LN2", 1),
    ];
    println!("cargo::rerun-if-changed={INPUT}");
    let source = fs::read_to_string(INPUT).expect("Read x87 coefficient data");
    let mut lines = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let mut output = String::new();
    for (name, count) in GROUPS {
        assert_eq!(
            lines.next(),
            Some(format!("[{name}]").as_str()),
            "Unexpected x87 coefficient section"
        );
        writeln!(output, "pub(super) const {name}: [u128; {count}] = [").unwrap();
        for _ in 0..count {
            let line = lines.next().expect("Missing x87 coefficient");
            let hex = line
                .strip_prefix("0x")
                .expect("Expected hexadecimal x87 coefficient");
            let value = u128::from_str_radix(&hex.replace('_', ""), 16)
                .expect("Invalid binary128 coefficient");
            writeln!(output, "    0x{value:032x},").unwrap();
        }
        output.push_str("];\n");
    }
    assert!(
        lines.next().is_none(),
        "Unexpected extra x87 coefficient data"
    );
    let directory = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    fs::write(directory.join("x87_coefficients.rs"), output)
        .expect("Write x87 coefficient constants");
}
