//! Generic selection policy for an ANSI code page from resource metadata and
//! already-extracted text samples.
//!
//! This is the legacy Win16 ANSI profile: declarations, language and font
//! charset metadata take precedence over statistical detection. Statistical
//! detection never selects UTF-8 or UTF-16. UTF-8 may still be selected when
//! supplied as a unique declaration or explicit override; UTF-16 declarations
//! are ignored because resource translation code page 1200/1201 can describe
//! Unicode resource storage rather than a Win16 ANSI code page. An explicit
//! override is returned unchanged, including Unicode code pages.

use chardetng::{EncodingDetector, Iso2022JpDetection, Utf8Detection};

/// The source that determined the selected code page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextEncodingEvidence {
    /// A unique code page declared for the resource text.
    DeclaredCodePage,
    /// A unique code page derived from resource language metadata.
    Language,
    /// A unique code page derived from a font charset.
    FontCharset,
    /// A best-effort guess from extracted text bytes.
    Statistical,
    /// The caller-provided locale fallback.
    LocaleFallback,
    /// The caller-provided explicit override.
    Explicit,
}

/// A code-page conflict in one metadata source tier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextEncodingConflict {
    /// Metadata tier that supplied multiple distinct code pages.
    pub evidence: TextEncodingEvidence,
    /// Distinct candidates, sorted by numeric code-page identifier.
    pub code_pages: Vec<u32>,
}

/// Selected Windows code page and any unresolved metadata conflicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextEncodingSelection {
    /// The Windows numeric code-page identifier selected by the policy.
    pub code_page: u32,
    /// The highest-priority unambiguous source used for the selection.
    pub evidence: TextEncodingEvidence,
    /// Conflicts retained from metadata tiers; a conflict never selects its
    /// first candidate merely because it appeared first in the input.
    pub conflicts: Vec<TextEncodingConflict>,
}

/// Choose an ANSI code page using explicit override, resource metadata,
/// extracted-text statistics, then the locale fallback.
///
/// Metadata priority is `declared` > `language_code_pages` >
/// `charset_code_pages`. A tier with multiple distinct candidates is recorded
/// in [`TextEncodingSelection::conflicts`] and skipped; selection continues at
/// the next tier. Conflicts from all metadata tiers are retained, including
/// tiers lower in priority than the selected one. Duplicate candidates do not
/// create a conflict. Code page 0 (the Windows ACP alias) and UTF-16 code pages
/// 1200/1201 are omitted from automatic metadata selection; callers should
/// provide a resolved locale code page and should not treat UTF-16 resource
/// storage as the Win16 ANSI code page.
///
/// `samples` must contain only text bytes already extracted by the caller.
/// This function does not inspect executables or scan arbitrary binary data.
/// ASCII-only and empty samples provide no statistical evidence and use the
/// fallback. UTF-8 is explicitly denied as a statistical guess. Any sample
/// beginning with a Unicode BOM disables statistics for the entire batch:
/// mixed Unicode/legacy resources need a separate storage-aware analysis.
/// Handle BOM-marked Unicode text separately or pass a deliberate
/// explicit code page. Statistical results are heuristics, not proof that an
/// undeclared byte stream has one uniquely identifiable encoding.
pub fn detect_ansi_code_page(
    declared: &[u32],
    language_code_pages: &[u32],
    charset_code_pages: &[u32],
    samples: &[Vec<u8>],
    fallback: u32,
    explicit: Option<u32>,
) -> TextEncodingSelection {
    let declared = metadata_candidates(declared);
    let languages = metadata_candidates(language_code_pages);
    let charsets = metadata_candidates(charset_code_pages);

    let mut conflicts = Vec::new();
    record_conflict(
        &mut conflicts,
        TextEncodingEvidence::DeclaredCodePage,
        &declared,
    );
    record_conflict(&mut conflicts, TextEncodingEvidence::Language, &languages);
    record_conflict(&mut conflicts, TextEncodingEvidence::FontCharset, &charsets);

    if let Some(code_page) = explicit {
        return TextEncodingSelection {
            code_page,
            evidence: TextEncodingEvidence::Explicit,
            conflicts,
        };
    }

    for (candidates, evidence) in [
        (&declared, TextEncodingEvidence::DeclaredCodePage),
        (&languages, TextEncodingEvidence::Language),
        (&charsets, TextEncodingEvidence::FontCharset),
    ] {
        if let [code_page] = candidates.as_slice() {
            return TextEncodingSelection {
                code_page: *code_page,
                evidence,
                conflicts,
            };
        }
    }

    if let Some(code_page) = statistical_code_page(samples) {
        return TextEncodingSelection {
            code_page,
            evidence: TextEncodingEvidence::Statistical,
            conflicts,
        };
    }

    TextEncodingSelection {
        code_page: fallback,
        evidence: TextEncodingEvidence::LocaleFallback,
        conflicts,
    }
}

fn metadata_candidates(code_pages: &[u32]) -> Vec<u32> {
    let mut candidates: Vec<_> = code_pages
        .iter()
        .copied()
        .filter(|code_page| !matches!(*code_page, 0 | 1200 | 1201))
        .collect();
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn record_conflict(
    conflicts: &mut Vec<TextEncodingConflict>,
    evidence: TextEncodingEvidence,
    candidates: &[u32],
) {
    if candidates.len() > 1 {
        conflicts.push(TextEncodingConflict {
            evidence,
            code_pages: candidates.to_vec(),
        });
    }
}

fn statistical_code_page(samples: &[Vec<u8>]) -> Option<u32> {
    if samples.is_empty() || samples.iter().any(|sample| begins_with_unicode_bom(sample)) {
        return None;
    }

    // These samples are independent legacy Windows resource strings, not
    // an email stream carrying persistent ISO-2022 escape state.
    let mut detector = EncodingDetector::new(Iso2022JpDetection::Deny);
    let mut has_non_ascii = false;
    for (index, sample) in samples.iter().enumerate() {
        if index > 0 {
            // Separate independent SBCS/DBCS samples. feed() still sees one
            // stream; the separator does not reset a stateful decoder.
            detector.feed(b"\n", false);
        }
        has_non_ascii |= detector.feed(sample, index + 1 == samples.len());
    }
    if !has_non_ascii {
        return None;
    }

    let encoding = detector.guess(None, Utf8Detection::Deny);
    windows_code_page_for_encoding_name(encoding.name())
}

fn begins_with_unicode_bom(sample: &[u8]) -> bool {
    sample.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
        || sample.starts_with(&[0xEF, 0xBB, 0xBF])
        || sample.starts_with(&[0xFF, 0xFE])
        || sample.starts_with(&[0xFE, 0xFF])
}

fn windows_code_page_for_encoding_name(name: &str) -> Option<u32> {
    // These canonical labels follow the WHATWG Encoding Standard's names and
    // labels. Their numeric identifiers are Windows code-page IDs. This map is
    // intentionally limited to encodings chardetng 1.0 can return; it is not a
    // general-purpose encoding-label database.
    // Sources: https://encoding.spec.whatwg.org/#names-and-labels and
    // https://learn.microsoft.com/windows/win32/intl/code-page-identifiers
    match name {
        "windows-1250" => Some(1250),
        "windows-1251" => Some(1251),
        "windows-1252" => Some(1252),
        "windows-1253" => Some(1253),
        "windows-1254" => Some(1254),
        "windows-1255" => Some(1255),
        "windows-1256" => Some(1256),
        "windows-1257" => Some(1257),
        "windows-1258" => Some(1258),
        "windows-874" => Some(874),
        "GBK" => Some(936),
        "Big5" => Some(950),
        "Shift_JIS" => Some(932),
        // encoding_rs uses the Windows Korean superset, not CP51949.
        // https://docs.rs/encoding_rs/latest/encoding_rs/static.EUC_KR.html
        "EUC-KR" => Some(949),
        // CP20932 is an approximation: Windows lacks the three-byte JIS
        // X 0212 sequences and differs on some two-byte/error mappings.
        // https://docs.rs/encoding_rs/latest/encoding_rs/static.EUC_JP.html
        "EUC-JP" => Some(20932),
        "ISO-8859-2" => Some(28592),
        "ISO-8859-4" => Some(28594),
        "ISO-8859-5" => Some(28595),
        "ISO-8859-6" => Some(28596),
        "ISO-8859-7" => Some(28597),
        "ISO-8859-8" => Some(28598),
        "ISO-8859-13" => Some(28603),
        "KOI8-U" => Some(21866),
        "IBM866" => Some(866),
        // UTF-8 and ISO-2022-JP are denied above; UTF-16 is not a guess result.
        _ => None,
    }
}
