use super::*;

// Independent, hand-encoded fixtures: one literal group and one group
// whose third token copies the overlapping `AB` ring sequence.
const LITERAL_FIXTURE: &[u8] = &[
    b'S', b'Z', b'D', b'D', 0x88, 0xf0, 0x27, 0x33, b'A', b'x', 4, 0, 0, 0,
    0x0f, b'D', b'A', b'T', b'A',
];
const OVERLAP_FIXTURE: &[u8] = &[
    b'S', b'Z', b'D', b'D', 0x88, 0xf0, 0x27, 0x33, b'A', b'x', 5, 0, 0, 0,
    0x03, b'A', b'B', 0xf0, 0xf0,
];

#[test]
fn decodes_literal_fixture_and_preserves_header_fields() {
    let (header, output) = decode_szdd(LITERAL_FIXTURE, 4).unwrap().unwrap();
    assert_eq!(header.compression_type, b'A');
    assert_eq!(header.last_character, b'x');
    assert_eq!(header.uncompressed_size, 4);
    assert_eq!(output.as_slice(), &b"DATA"[..]);
}

#[test]
fn expands_overlapping_back_reference() {
    let (_, output) = decode_szdd(OVERLAP_FIXTURE, 5).unwrap().unwrap();
    assert_eq!(output.as_slice(), &b"ABABA"[..]);
}

#[test]
fn stream_reads_partially_and_seeks_with_bounds() {
    let mut stream = SzddStream::open(LITERAL_FIXTURE, 4).unwrap().unwrap();
    let mut first = [0; 2];
    assert_eq!(stream.read(&mut first), 2);
    assert_eq!(&first[..], &b"DA"[..]);
    assert_eq!(stream.position(), 2);
    assert_eq!(stream.seek(SeekFrom::End(-2)).unwrap(), 2);
    let mut rest = [0; 8];
    assert_eq!(stream.read(&mut rest), 2);
    assert_eq!(&rest[..2], &b"TA"[..]);
    assert_eq!(stream.read(&mut rest), 0);
    assert_eq!(stream.seek(SeekFrom::Current(-5)), Err(LzError::InvalidSeek));
    assert_eq!(stream.seek(SeekFrom::Start(5)), Err(LzError::InvalidSeek));
}

#[test]
fn legacy_end_seek_counts_back_from_eof() {
    let mut stream = SzddStream::open(LITERAL_FIXTURE, 4).unwrap().unwrap();
    assert_eq!(stream.seek_lz(2, LzSeekOrigin::Start).unwrap(), 2);
    assert_eq!(stream.seek_lz(1, LzSeekOrigin::Current).unwrap(), 3);
    assert_eq!(stream.seek_lz(1, LzSeekOrigin::End).unwrap(), 3);
    assert_eq!(stream.seek_lz(5, LzSeekOrigin::End), Err(LzError::InvalidSeek));
}

#[test]
fn rejects_size_limits_and_truncated_tokens() {
    assert_eq!(
        decode_szdd(LITERAL_FIXTURE, 3),
        Err(LzError::OutputTooLarge {
            declared: 4,
            limit: 3
        })
    );
    let truncated_literal = &[
        b'S', b'Z', b'D', b'D', 0x88, 0xf0, 0x27, 0x33, b'A', b'x', 2, 0, 0, 0,
        0x01, b'A',
    ];
    assert_eq!(
        decode_szdd(truncated_literal, 2),
        Err(LzError::TruncatedStream { output_offset: 1 })
    );
}

#[test]
fn distinguishes_non_szdd_truncated_header_and_unknown_method() {
    assert_eq!(inspect_szdd(b"plain"), Ok(None));
    assert_eq!(inspect_szdd(&SZDD_MAGIC), Err(LzError::TruncatedHeader));
    let mut unknown = LITERAL_FIXTURE.to_vec();
    unknown[8] = b'B';
    assert_eq!(
        inspect_szdd(&unknown),
        Err(LzError::UnknownCompressionType(b'B'))
    );
    assert_eq!(SzddStream::open(b"plain", 100).unwrap(), None);
}
