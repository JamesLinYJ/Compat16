//! FindFirst exhaustion is DOS error 18; distinct failures retain their errors.

use super::*;

const DTA: u32 = 0x10080;
const DTA_SENTINEL: [u8; 43] = [0xa5; 43];

fn fixture(path: &[u8]) -> (DosKernel, TestHost, TestMemory) {
    let dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    host.directory_create(b"C:\\LIST").unwrap();
    let mut memory = TestMemory(vec![0; 0x10_0000]);
    memory.put(DTA, &DTA_SENTINEL);
    memory.put(0x10100, path);
    memory.put(0x10100 + path.len() as u32, &[0]);
    (dos, host, memory)
}

fn registers(service: u8, attributes: u16) -> Registers {
    Registers {
        eax: 0xaaaa_0000 | (u32::from(service) << 8), ebx: 0xbbbb_4567,
        ecx: 0xcccc_0000 | u32::from(attributes), edx: 0xdddd_0100,
        esp: 0x1111_2222, ebp: 0x3333_4444, esi: 0xeeee_9abc,
        edi: 0xffff_def0, eip: 0x5555_6666, eflags: 0xad6,
        cs: 0x7777, ds: 0x1000, es: 0xfffe, ss: 0x8888,
        fs: 0x9999, gs: 0xabcd,
    }
}

fn assert_error(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    service: u8,
    attributes: u16,
    code: DosErrorCode,
) {
    let mut regs = registers(service, attributes);
    let mut expected = regs.clone();
    expected.set_ax(code as u16);
    expected.set_carry(true);
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
}

fn read_dta(memory: &TestMemory) -> [u8; 43] {
    let mut bytes = [0; 43];
    memory.read(PhysAddr(DTA), &mut bytes).unwrap();
    bytes
}

#[test]
fn find_first_exhaustion_returns_18_and_preserves_dta_after_filtering() {
    for (path, candidate_attributes, requested_attributes) in [
        (b"C:\\LIST\\*.BIN".as_slice(), Some(0x20), 0),
        (b"C:\\LIST\\MISSING.TXT".as_slice(), Some(0x20), 0),
        (b"C:\\LIST\\A.TXT".as_slice(), Some(0x02), 0),
        (b"C:\\LIST\\A.TXT".as_slice(), Some(0x04), 0),
        (b"C:\\LIST\\A.TXT".as_slice(), Some(0x08), 0),
        (b"C:\\LIST\\A.TXT".as_slice(), Some(0x10), 0),
        (b"C:\\LIST\\*.*".as_slice(), Some(0x20), 0x08),
        (b"C:\\LIST\\*.*".as_slice(), None, 0),
    ] {
        let (mut dos, mut host, mut memory) = fixture(path);
        if let Some(attributes) = candidate_attributes {
            add_test_file(&mut host, b"C:\\LIST\\A.TXT", attributes, b"unchanged");
        }
        assert_error(&mut dos, &mut host, &mut memory, 0x4e, requested_attributes, DosErrorCode::NoMoreFiles);
        assert_eq!(read_dta(&memory), DTA_SENTINEL);
        assert_eq!(host.search_open_calls, [b"C:\\LIST\\".to_vec()]);
        let token = DosHostSearch(1);
        assert_eq!(host.search_next_calls, vec![token; if candidate_attributes.is_some() { 2 } else { 1 }]);
        assert_eq!(host.search_close_calls, [token]);
        assert!(host.searches.is_empty());
        assert!(dos.searches.is_empty());

        let next_calls = host.search_next_calls.clone();
        assert_error(&mut dos, &mut host, &mut memory, 0x4f, 0, DosErrorCode::NoMoreFiles);
        assert_eq!(read_dta(&memory), DTA_SENTINEL);
        assert_eq!(host.search_next_calls, next_calls);
        assert_eq!(host.search_close_calls, [token]);
    }
}

#[test]
fn find_first_exhaustion_does_not_replace_parse_or_open_errors() {
    for (path, open_error, expected, opens) in [
        (b"C:\\MISSING\\*.*".as_slice(), None, DosErrorCode::PathNotFound, 1),
        (b"C:\\LIST\\".as_slice(), None, DosErrorCode::FileNotFound, 0),
        (b"".as_slice(), None, DosErrorCode::InvalidData, 0),
        (b"C:\\LIST\\*.*".as_slice(), Some(DosErrorCode::AccessDenied), DosErrorCode::AccessDenied, 1),
        (b"C:\\LIST\\*.*".as_slice(), Some(DosErrorCode::FileNotFound), DosErrorCode::FileNotFound, 1),
    ] {
        let (mut dos, mut host, mut memory) = fixture(path);
        host.search_open_error = open_error;
        assert_error(&mut dos, &mut host, &mut memory, 0x4e, 0, expected);
        assert_eq!(read_dta(&memory), DTA_SENTINEL);
        assert_eq!(host.search_open_calls.len(), opens);
        assert!(host.search_next_calls.is_empty());
        assert!(host.search_close_calls.is_empty());
        assert!(host.searches.is_empty());
        assert!(dos.searches.is_empty());
    }
}

#[test]
fn find_first_exhaustion_does_not_replace_iteration_error_even_when_close_fails() {
    for close_fails in [false, true] {
        let (mut dos, mut host, mut memory) = fixture(b"C:\\LIST\\*.*");
        host.search_next_error = Some(DosErrorCode::DriveNotReady);
        host.search_close_error = close_fails.then_some(DosErrorCode::AccessDenied);
        assert_error(&mut dos, &mut host, &mut memory, 0x4e, 0, DosErrorCode::DriveNotReady);
        assert_eq!(read_dta(&memory), DTA_SENTINEL);
        let token = DosHostSearch(1);
        assert_eq!(host.search_next_calls, [token]);
        assert_eq!(host.search_close_calls, [token]);
        assert_eq!(host.searches.len(), usize::from(close_fails));
        assert_eq!(dos.searches.len(), usize::from(close_fails));
        if close_fails {
            assert_eq!(dos.searches.values().next().unwrap().host_search, token);
            host.search_close_error = None;
            dos.close_all_searches_checked(&mut host).unwrap();
            assert_eq!(host.search_close_calls, [token, token]);
            assert!(host.searches.is_empty());
            assert!(dos.searches.is_empty());
        }
    }
}

#[test]
fn find_first_exhaustion_retains_failed_close_identity_for_cleanup_retry() {
    let (mut dos, mut host, mut memory) = fixture(b"C:\\LIST\\*.BIN");
    add_test_file(&mut host, b"C:\\LIST\\A.TXT", 0, b"unchanged");
    host.search_close_error = Some(DosErrorCode::AccessDenied);
    assert_error(&mut dos, &mut host, &mut memory, 0x4e, 0, DosErrorCode::AccessDenied);
    assert_eq!(read_dta(&memory), DTA_SENTINEL);
    assert_eq!(host.searches.len(), 1);
    assert_eq!(dos.searches.len(), 1);
    let (key, retained) = dos.searches.first_key_value().map(|(key, state)| (*key, *state)).unwrap();
    let token = retained.host_search;
    assert_eq!(token, DosHostSearch(1));
    assert_ne!(retained.identity, 0);
    assert_eq!(host.searches[&token].next, 1);
    assert_eq!(dos.close_all_searches_checked(&mut host).unwrap_err().code, DosErrorCode::AccessDenied);
    assert_eq!(dos.searches[&key].identity, retained.identity);
    assert_eq!(dos.searches[&key].host_search, token);
    assert!(host.searches.contains_key(&token));
    host.search_close_error = None;
    dos.close_all_searches_checked(&mut host).unwrap();
    assert_eq!(host.search_close_calls, [token, token, token]);
    assert!(host.searches.is_empty());
    assert!(dos.searches.is_empty());
    assert_eq!(read_dta(&memory), DTA_SENTINEL);
}

#[test]
fn find_first_exhaustion_retries_old_close_before_replacement_search() {
    let (mut dos, mut host, mut memory) = fixture(b"C:\\LIST\\*.*");
    host.search_close_error = Some(DosErrorCode::AccessDenied);
    assert_error(&mut dos, &mut host, &mut memory, 0x4e, 0, DosErrorCode::AccessDenied);
    let (key, retained) = dos.searches.first_key_value().map(|(key, state)| (*key, *state)).unwrap();
    assert_error(&mut dos, &mut host, &mut memory, 0x4e, 0, DosErrorCode::AccessDenied);
    assert_eq!(dos.searches[&key].identity, retained.identity);
    assert_eq!(dos.searches[&key].host_search, retained.host_search);
    assert_eq!(host.search_open_calls.len(), 1);
    assert_eq!(host.search_next_calls, [DosHostSearch(1)]);
    assert_eq!(host.search_close_calls, [DosHostSearch(1), DosHostSearch(1)]);
    host.search_close_error = None;
    assert_error(&mut dos, &mut host, &mut memory, 0x4e, 0, DosErrorCode::NoMoreFiles);
    assert_eq!(host.search_open_calls.len(), 2);
    assert_eq!(host.search_next_calls, [DosHostSearch(1), DosHostSearch(2)]);
    assert_eq!(host.search_close_calls, [DosHostSearch(1), DosHostSearch(1), DosHostSearch(1), DosHostSearch(2)]);
    assert_eq!(read_dta(&memory), DTA_SENTINEL);
    assert!(host.searches.is_empty());
    assert!(dos.searches.is_empty());
}

#[test]
fn find_next_exhaustion_preserves_last_dta_and_retries_failed_close() {
    let (mut dos, mut host, mut memory) = fixture(b"C:\\LIST\\*.*");
    add_test_file(&mut host, b"C:\\LIST\\A.TXT", 0x20, b"unchanged");
    let mut regs = registers(0x4e, 0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let result = read_dta(&memory);
    assert_eq!(&result[0x1e..0x24], b"A.TXT\0");
    let (key, retained) = dos.searches.first_key_value().map(|(key, state)| (*key, *state)).unwrap();
    host.search_close_error = Some(DosErrorCode::AccessDenied);
    assert_error(&mut dos, &mut host, &mut memory, 0x4f, 0, DosErrorCode::AccessDenied);
    assert_eq!(read_dta(&memory), result);
    assert_eq!(dos.searches[&key].identity, retained.identity);
    assert_eq!(dos.searches[&key].host_search, retained.host_search);
    assert!(host.searches.contains_key(&retained.host_search));
    host.search_close_error = None;
    assert_error(&mut dos, &mut host, &mut memory, 0x4f, 0, DosErrorCode::NoMoreFiles);
    assert_eq!(read_dta(&memory), result);
    assert_eq!(host.search_next_calls, [retained.host_search; 3]);
    assert_eq!(host.search_close_calls, [retained.host_search; 2]);
    assert!(host.searches.is_empty());
    assert!(dos.searches.is_empty());
    assert_error(&mut dos, &mut host, &mut memory, 0x4f, 0, DosErrorCode::NoMoreFiles);
    assert_eq!(read_dta(&memory), result);
    assert_eq!(host.search_next_calls, [retained.host_search; 3]);
    assert_eq!(host.search_close_calls, [retained.host_search; 2]);
}
