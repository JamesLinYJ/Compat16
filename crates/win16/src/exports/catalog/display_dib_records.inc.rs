// Splice this record inside the existing `export_catalog!` body after declaring
// `#[path = "exports/catalog/display_dib_parameters.rs"] mod display_dib_parameters;`
// in `exports.rs`.

DisplayDib => DISPLAY_DIB: ("DISPDIB", 1u16, Stack, display_dib_parameters::DISPLAY_DIB, Word);
