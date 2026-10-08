//! Guest-only Pen Windows algorithms that do not need a native tablet service.

use crate::penwin_wire::{Point16Wire, Rect16Wire};

pub(crate) const SYVHI_SPECIAL: u16 = 0;
pub(crate) const SYVHI_ANSI: u16 = 1;
pub(crate) const SYVHI_GESTURE: u16 = 2;
pub(crate) const SYVHI_KANJI: u16 = 3;
pub(crate) const SYVHI_SHAPE: u16 = 4;
pub(crate) const SYVHI_UNICODE: u16 = 5;
pub(crate) const SYVHI_VKEY: u16 = 6;
pub(crate) const SYV_NULL: u32 = 0x0000_0000;
pub(crate) const SYV_UNKNOWN: u32 = 0x0000_0001;
pub(crate) const SYV_EMPTY: u32 = 0x0000_0003;
pub(crate) const SYV_BEGINOR: u32 = 0x0000_0010;
pub(crate) const SYV_ENDOR: u32 = 0x0000_0011;
pub(crate) const SYV_OR: u32 = 0x0000_0012;
pub(crate) const SYV_SOFTNEWLINE: u32 = 0x0000_0020;
pub(crate) const SYV_SPACENULL: u32 = 0x0001_0000;
pub(crate) const SYV_CLEAR: u32 = 0x0002_ffd5;
pub(crate) const SYV_EXTENDSELECT: u32 = 0x0002_ffd8;
pub(crate) const SYV_UNDO: u32 = 0x0002_ffd9;
pub(crate) const SYV_COPY: u32 = 0x0002_ffda;
pub(crate) const SYV_CUT: u32 = 0x0002_ffdb;
pub(crate) const SYV_PASTE: u32 = 0x0002_ffdc;
pub(crate) const SYV_CLEARWORD: u32 = 0x0002_ffdd;
pub(crate) const SYV_KKCONVERT: u32 = 0x0002_ffd4;
pub(crate) const SYV_USER: u32 = 0x0002_ffde;
pub(crate) const SYV_CORRECT: u32 = 0x0002_ffdf;
pub(crate) const SYV_BACKSPACE: u32 = 0x0002_0008;
pub(crate) const SYV_TAB: u32 = 0x0002_0009;
pub(crate) const SYV_RETURN: u32 = 0x0002_000d;
pub(crate) const SYV_SPACE: u32 = 0x0002_0020;
pub(crate) const SYV_CIRCLE_UPPER_A: u32 = 0x0002_24b6;
pub(crate) const SYV_CIRCLE_UPPER_Z: u32 = 0x0002_24cf;
pub(crate) const SYV_CIRCLE_LOWER_A: u32 = 0x0002_24d0;
pub(crate) const SYV_CIRCLE_LOWER_Z: u32 = 0x0002_24e9;
pub(crate) const SYV_SHAPE_LINE: u32 = 0x0004_0001;
pub(crate) const SYV_SHAPE_ELLIPSE: u32 = 0x0004_0002;
pub(crate) const SYV_SHAPE_RECT: u32 = 0x0004_0003;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PenPoint {
    pub(crate) x: i16,
    pub(crate) y: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PenRect {
    pub(crate) left: i16,
    pub(crate) top: i16,
    pub(crate) right: i16,
    pub(crate) bottom: i16,
}

impl From<Point16Wire> for PenPoint {
    fn from(point: Point16Wire) -> Self {
        Self { x: point.x.get(), y: point.y.get() }
    }
}

impl From<PenRect> for Rect16Wire {
    fn from(rectangle: PenRect) -> Self {
        Self {
            left: rectangle.left.into(),
            top: rectangle.top.into(),
            right: rectangle.right.into(),
            bottom: rectangle.bottom.into(),
        }
    }
}

/// Compute the Windows 3.1 Pen API rectangle; no points yields the empty
/// rectangle at the origin, and a single point yields an empty rect at it.
pub(crate) fn bounding_rect_from_points(points: &[PenPoint]) -> PenRect {
    let Some(first) = points.first().copied() else {
        return PenRect { left: 0, top: 0, right: 0, bottom: 0 };
    };
    let mut bounds = PenRect { left: first.x, top: first.y, right: first.x, bottom: first.y };
    for point in points.iter().copied().skip(1) {
        bounds.left = bounds.left.min(point.x);
        bounds.top = bounds.top.min(point.y);
        bounds.right = bounds.right.max(point.x);
        bounds.bottom = bounds.bottom.max(point.y);
    }
    bounds
}

/// Convert a bounded null-terminated ANSI byte span, including its terminator,
/// to `SYV` values. Conversion stops when the destination limit is reached.
pub(crate) fn character_to_symbol(bytes: &[u8], max_symbols: usize) -> Vec<u32> {
    let mut symbols = Vec::with_capacity(bytes.len().min(max_symbols));
    for byte in bytes.iter().copied().take(max_symbols) {
        if byte == 0 {
            symbols.push(SYV_NULL);
            break;
        }
        symbols.push(0x0001_0000 | u32::from(byte));
    }
    symbols
}

/// Convert ANSI-class symbols only; gestures, Unicode, Kanji, and private
/// recognizer symbols need recognizer-specific mapping and are reported absent.
pub(crate) fn symbol_to_character(symbols: &[u32], max_symbols: usize) -> (Vec<u8>, usize, bool) {
    let mut characters = Vec::with_capacity(symbols.len().min(max_symbols));
    for symbol in symbols.iter().copied().take(max_symbols) {
        if symbol == SYV_NULL {
            characters.push(0);
            let converted = characters.len();
            return (characters, converted, true);
        }
        if (symbol >> 16) as u16 != SYVHI_ANSI {
            let converted = characters.len();
            return (characters, converted, false);
        }
        characters.push(symbol as u8);
    }
    let converted = characters.len();
    (characters, converted, true)
}

pub(crate) fn is_special_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_SPECIAL
}

pub(crate) fn is_ansi_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_ANSI
}

pub(crate) fn is_gesture_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_GESTURE
}

pub(crate) fn is_kanji_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_KANJI
}

pub(crate) fn is_shape_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_SHAPE
}

pub(crate) fn is_unicode_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_UNICODE
}

pub(crate) fn is_virtual_key_symbol(symbol: u32) -> bool {
    (symbol >> 16) as u16 == SYVHI_VKEY
}

pub(crate) fn is_standard_gesture(symbol: u32) -> bool {
    matches!(symbol, SYV_KKCONVERT | SYV_CLEAR | SYV_EXTENDSELECT | SYV_UNDO
        | SYV_COPY | SYV_CUT | SYV_PASTE | SYV_CLEARWORD | SYV_USER | SYV_CORRECT)
}

pub(crate) fn is_ansi_gesture(symbol: u32) -> bool {
    matches!(symbol, SYV_BACKSPACE | SYV_TAB | SYV_RETURN | SYV_SPACE)
}

pub(crate) fn is_app_gesture(symbol: u32) -> bool {
    (SYV_CIRCLE_UPPER_A..=SYV_CIRCLE_LOWER_Z).contains(&symbol)
}

pub(crate) fn is_lower_app_gesture(symbol: u32) -> bool {
    (SYV_CIRCLE_LOWER_A..=SYV_CIRCLE_LOWER_Z).contains(&symbol)
}

pub(crate) fn is_upper_app_gesture(symbol: u32) -> bool {
    (SYV_CIRCLE_UPPER_A..=SYV_CIRCLE_UPPER_Z).contains(&symbol)
}

/// `ChSyvToAnsi`: the low byte of the low word is the ANSI character value.
pub(crate) fn ansi_from_symbol(symbol: u32) -> u8 {
    symbol as u8
}

/// `SyvCharacterToSymbol`: this macro maps even NUL to an ANSI-class value;
/// the CharacterToSymbol API itself maps a string terminator to SYV_NULL.
pub(crate) fn symbol_from_ansi(character: u8) -> u32 {
    u32::from(character) | 0x0001_0000
}

/// `SyvKanjiToSymbol` preserves a 16-bit shift-code value.
pub(crate) fn symbol_from_kanji(character: u16) -> u32 {
    u32::from(character) | 0x0003_0000
}

pub(crate) fn symbol_from_upper_app_gesture(character: u8) -> u32 {
    u32::from(character)
        .wrapping_sub(u32::from(b'A'))
        .wrapping_add(SYV_CIRCLE_UPPER_A)
}

pub(crate) fn symbol_from_lower_app_gesture(character: u8) -> u32 {
    u32::from(character)
        .wrapping_sub(u32::from(b'a'))
        .wrapping_add(SYV_CIRCLE_LOWER_A)
}

pub(crate) fn ansi_from_app_gesture(symbol: u32) -> Option<u8> {
    match symbol {
        SYV_CIRCLE_UPPER_A..=SYV_CIRCLE_UPPER_Z => {
            Some(b'A' + (symbol - SYV_CIRCLE_UPPER_A) as u8)
        }
        SYV_CIRCLE_LOWER_A..=SYV_CIRCLE_LOWER_Z => {
            Some(b'a' + (symbol - SYV_CIRCLE_LOWER_A) as u8)
        }
        _ => None,
    }
}
