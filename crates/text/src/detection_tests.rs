use super::*;

fn chinese() -> Vec<Vec<u8>> {
    vec![CodePage::Cp936.encode("打开文件，保存文档。无法找到指定文件，请检查文件名称和目录是否正确。帮助主题包括打印设置、编辑文本、查找内容以及复制粘贴操作。").unwrap()]
}

#[test]
fn program_ansi_ui_text_has_its_own_scope_from_version_translations() {
    let selected = detect_program_ansi_code_page(&[1252], &[1252], &[], &[], &chinese(), 1252, None);
    assert_eq!((selected.code_page, selected.evidence), (936, TextEncodingEvidence::Statistical));
}

#[test]
fn program_ansi_western_ui_is_not_forced_to_a_dbcs_version_hint() {
    let (bytes, _, errors) = encoding_rs::WINDOWS_1252.encode(
        "Édition du document : veuillez vérifier le répertoire et sélectionner le fichier désiré. Les caractères accentués sont affichés correctement, ainsi que les opérations de copie et d'impression.");
    assert!(!errors);
    let selected = detect_program_ansi_code_page(&[936], &[936], &[], &[], &[bytes.into_owned()], 936, None);
    assert_eq!((selected.code_page, selected.evidence), (1252, TextEncodingEvidence::Statistical));
}

#[test]
fn program_ansi_cyrillic_ui_is_not_forced_to_a_western_version_hint() {
    let (bytes, _, errors) = encoding_rs::WINDOWS_1251.encode(
        "Открытие документа. Не удаётся найти указанный файл. Проверьте правильность имени файла и каталога. Справка содержит сведения о печати документов, редактировании текста и поиске нужной информации.");
    assert!(!errors);
    let selected = detect_program_ansi_code_page(&[1252], &[1252], &[], &[], &[bytes.into_owned()], 1252, None);
    assert_eq!((selected.code_page, selected.evidence), (1251, TextEncodingEvidence::Statistical));
}

#[test]
fn program_ansi_other_dbcs_ui_resources_are_not_forced_to_a_western_hint() {
    for (encoding, page, text) in [
        (encoding_rs::SHIFT_JIS, 932, "ファイルを開くことができません。ファイル名とディレクトリが正しいかどうか確認してください。ヘルプには文書の印刷、テキストの編集、必要な情報の検索についての説明が含まれています。"),
        (encoding_rs::BIG5, 950, "無法開啟指定的檔案，請檢查檔案名稱和目錄是否正確。說明主題包括列印設定、編輯文字、尋找內容以及複製貼上操作。您可以選擇其他檔案，或者取消目前的操作。"),
        (encoding_rs::EUC_KR, 949, "지정한 파일을 열 수 없습니다. 파일 이름과 디렉터리가 올바른지 확인하십시오. 도움말에는 문서 인쇄, 텍스트 편집 및 필요한 정보 검색에 대한 설명이 포함되어 있습니다."),
    ] {
        let (bytes, _, errors) = encoding.encode(text);
        assert!(!errors);
        let selected = detect_program_ansi_code_page(&[1252], &[1252], &[], &[], &[bytes.into_owned()], 1252, None);
        assert_eq!((selected.code_page, selected.evidence), (page, TextEncodingEvidence::Statistical));
    }
}

#[test]
fn program_ansi_ui_font_metadata_keeps_precedence_over_text_statistics() {
    let selected = detect_program_ansi_code_page(&[1252], &[1252], &[932], &[], &chinese(), 1252, None);
    assert_eq!((selected.code_page, selected.evidence), (932, TextEncodingEvidence::FontCharset));
}

#[test]
fn program_ansi_ascii_and_missing_ui_use_version_hints_before_locale() {
    for samples in [vec![], vec![b"Open file".to_vec()]] {
        let selected = detect_program_ansi_code_page(&[1251], &[1252], &[], &[], &samples, 936, None);
        assert_eq!((selected.code_page, selected.evidence), (1251, TextEncodingEvidence::DeclaredCodePage));
        let selected = detect_program_ansi_code_page(&[], &[932], &[], &[], &samples, 936, None);
        assert_eq!((selected.code_page, selected.evidence), (932, TextEncodingEvidence::Language));
        let selected = detect_program_ansi_code_page(&[], &[], &[], &[], &samples, 936, None);
        assert_eq!((selected.code_page, selected.evidence), (936, TextEncodingEvidence::LocaleFallback));
    }
}

#[test]
fn program_ansi_conflicts_preserve_both_resource_scopes_without_first_candidate_bias() {
    let selected = detect_program_ansi_code_page(
        &[1252, 936, 1252], &[932, 1251], &[949, 950], &[], &chinese(), 1252, None,
    );
    assert_eq!((selected.code_page, selected.evidence), (936, TextEncodingEvidence::Statistical));
    assert_eq!(selected.conflicts, [
        TextEncodingConflict { evidence: TextEncodingEvidence::DeclaredCodePage, code_pages: vec![936, 1252] },
        TextEncodingConflict { evidence: TextEncodingEvidence::Language, code_pages: vec![932, 1251] },
        TextEncodingConflict { evidence: TextEncodingEvidence::FontCharset, code_pages: vec![949, 950] },
    ]);
}

#[test]
fn program_ansi_explicit_override_still_wins_over_all_resource_scopes() {
    for page in [936, 1252, 65001, 1200] {
        let selected = detect_program_ansi_code_page(&[1251], &[932], &[949], &[], &chinese(), 1252, Some(page));
        assert_eq!((selected.code_page, selected.evidence), (page, TextEncodingEvidence::Explicit));
    }
}

#[test]
fn program_ansi_bom_and_unicode_storage_tags_do_not_become_legacy_text_guesses() {
    for samples in [vec![vec![0xff, 0xfe, 0x41, 0x00]], vec![vec![0xef, 0xbb, 0xbf, 0xc3, 0xa9]]] {
        let selected = detect_program_ansi_code_page(&[1200, 1201], &[], &[], &[], &samples, 936, None);
        assert_eq!((selected.code_page, selected.evidence), (936, TextEncodingEvidence::LocaleFallback));
    }
}

#[test]
fn actual_text_declarations_keep_the_original_detector_contract() {
    // Unlike version translations, these are declarations for these samples.
    let selected = detect_ansi_code_page(&[1252], &[936], &[932], &chinese(), 936, None);
    assert_eq!((selected.code_page, selected.evidence), (1252, TextEncodingEvidence::DeclaredCodePage));
}

#[test]
fn program_ansi_visible_labels_are_not_outweighed_by_string_table_lookup_data() {
    let lookup = vec![(0x80..=0xff).collect::<Vec<u8>>()];
    // Verify this fixture actually biases the weaker statistical source.
    let weak = detect_ansi_code_page(&[], &[], &[], &lookup, 1252, None);
    assert_ne!(weak.code_page, 936);
    let selected = detect_program_ansi_code_page(&[1252], &[1252], &[], &chinese(), &lookup, 1252, None);
    assert_eq!((selected.code_page, selected.evidence), (936, TextEncodingEvidence::Statistical));
    let selected = detect_program_ansi_code_page(&[1252], &[1252], &[], &[b"File".to_vec()], &chinese(), 1252, None);
    assert_eq!((selected.code_page, selected.evidence), (936, TextEncodingEvidence::Statistical));
}
