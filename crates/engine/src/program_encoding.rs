//! Select one legacy ANSI profile before starting a Win16 program instance.

use compat_services::win16_ver::query_win16_ansi;
use host_services::windows::text_encoding_metadata::{
    ansi_code_page_for_charset, ansi_code_page_for_language, is_supported_ansi_code_page,
    legacy_locale_ansi_code_page,
};
use runtime::{Diagnostic, DiagnosticKind as Kind, RuntimeHost};
use text_codec::{TextEncodingEvidence, TextEncodingSelection, detect_ansi_code_page};
use zerocopy::{
    FromBytes, Immutable, KnownLayout, Unaligned,
    byteorder::{LittleEndian, U16},
};

#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct Translation {
    language: U16<LittleEndian>,
    code_page: U16<LittleEndian>,
}

pub(super) struct ProgramEncoding {
    pub selection: TextEncodingSelection,
    unavailable_statistical_page: Option<u32>,
}

pub(super) fn resolve(bytes: &[u8], explicit: Option<u32>) -> Option<ProgramEncoding> {
    let image = formats::parse_ne(bytes).ok()?;
    let profile = formats::collect_ne_text_profile(bytes, &image);
    let mut declared = Vec::new();
    let mut languages = Vec::new();
    for range in profile.version_resource_ranges {
        let Some(block) = bytes.get(range) else {
            continue;
        };
        let Ok(Some(value)) = query_win16_ansi(block, b"\\VarFileInfo\\Translation") else {
            continue;
        };
        let Some(end) = value.offset.checked_add(value.length as usize) else {
            continue;
        };
        let Some(pairs) = block.get(value.offset..end) else {
            continue;
        };
        if pairs.len() % core::mem::size_of::<Translation>() != 0 {
            continue;
        }
        // The shared version codec owns the tree contract; zerocopy reads only
        // its checked fixed DWORD language/code-page entries.
        for pair in pairs.chunks_exact(core::mem::size_of::<Translation>()) {
            let Ok(pair) = Translation::ref_from_bytes(pair) else {
                continue;
            };
            let page = u32::from(pair.code_page.get());
            if is_supported_ansi_code_page(page) {
                declared.push(page);
            }
            if let Some(page) = ansi_code_page_for_language(pair.language.get()) {
                languages.push(page);
            }
        }
    }
    let fonts: Vec<_> = profile
        .font_charsets
        .into_iter()
        .filter_map(ansi_code_page_for_charset)
        .collect();
    // 1252 is the conventional Western Win16 fallback when the native locale
    // does not provide a legacy ANSI page; it is not a detected encoding.
    let fallback = legacy_locale_ansi_code_page().unwrap_or(1252);
    let mut selection = detect_ansi_code_page(
        &declared,
        &languages,
        &fonts,
        &profile.strings,
        fallback,
        explicit,
    );
    let mut unavailable_statistical_page = None;
    if selection.evidence == TextEncodingEvidence::Statistical
        && !is_supported_ansi_code_page(selection.code_page)
    {
        unavailable_statistical_page = Some(selection.code_page);
        selection.code_page = fallback;
        selection.evidence = TextEncodingEvidence::LocaleFallback;
    }
    Some(ProgramEncoding {
        selection,
        unavailable_statistical_page,
    })
}

pub(super) fn report(host: &mut host_services::windows::WindowsHost, profile: &ProgramEncoding) {
    let selection = &profile.selection;
    host.report_diagnostic(&Diagnostic::info(
        Kind::CompatibilityGap,
        format!(
            "Win16 ANSI code page {} selected from {}",
            selection.code_page,
            evidence_name(selection.evidence)
        ),
    ));
    if let Some(page) = profile.unavailable_statistical_page {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            format!(
                "detected code page {page} is unavailable on this host; using locale fallback {}",
                selection.code_page
            ),
        ));
    }
    if selection.evidence == TextEncodingEvidence::Statistical && selection.code_page == 20932 {
        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
            "EUC-JP detection uses Windows code page 20932; three-byte JIS X 0212 and some character mappings are unsupported"));
    }
    for conflict in &selection.conflicts {
        let candidates = conflict
            .code_pages
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            format!(
                "conflicting {} code pages ({candidates}); using selected code page {}",
                evidence_name(conflict.evidence),
                selection.code_page
            ),
        ));
    }
}

pub(super) fn evidence_name(value: TextEncodingEvidence) -> &'static str {
    match value {
        TextEncodingEvidence::DeclaredCodePage => "resource code-page declaration",
        TextEncodingEvidence::Language => "resource language",
        TextEncodingEvidence::FontCharset => "font character set",
        TextEncodingEvidence::Statistical => "resource text statistics",
        TextEncodingEvidence::LocaleFallback => "legacy locale fallback",
        TextEncodingEvidence::Explicit => "explicit override",
    }
}
