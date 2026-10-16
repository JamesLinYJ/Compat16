//! USER.115 takes a signed LONG and returns void with four-byte Pascal cleanup.
use super::*;

#[test]
fn reply_message_preserves_all_result_bits_void_registers_and_exactly_once_delivery() {
    for result in [0, 0x1234_5678, i32::MIN, -1] {
        for native_result in [false, true] {
            for defer in [0, 1, 2] {
                let mut runtime = fixture();
                let return_to = prepare(&mut runtime, 115, result as u32);
                let before = runtime.cpu.regs.clone();
                let mut host = KeyboardHost {
                    result: Some(Win16MessageCallResult::Boolean(native_result)),
                    fail_readback_once: defer == 1,
                    fail_consume_once: defer == 2,
                    ..Default::default()
                };
                let dispatched = dispatch(&mut runtime, &mut host);
                if defer == 0 {
                    dispatched.unwrap();
                } else {
                    assert_eq!(dispatched.unwrap_err().kind(), Kind::HostFailure);
                    if defer == 1 {
                        assert_eq!(runtime.cpu.regs, before);
                    }
                    assert_eq!((host.calls, host.consumed), (1, 0));
                    resume(&mut runtime, &mut host).unwrap();
                }
                assert_return(&runtime, return_to);
                assert_eq!(host.replies, [result]);
                assert_eq!((host.calls, host.consumed), (1, 1));
                assert_eq!(bytes(&runtime), [0xa7; 258]);
            }
        }
    }
}

#[test]
fn reply_message_failure_or_wrong_native_result_cannot_commit_a_guest_return() {
    for fail_begin in [false, true] {
        let mut runtime = fixture();
        prepare(&mut runtime, 115, 0x8000_1234);
        let before = runtime.cpu.regs.clone();
        let mut host = KeyboardHost {
            result: Some(Win16MessageCallResult::Dword(1)),
            fail_begin,
            ..Default::default()
        };
        let error = dispatch(&mut runtime, &mut host).unwrap_err();
        assert_eq!(
            error.kind(),
            if fail_begin {
                Kind::HostFailure
            } else {
                Kind::InternalInvariant
            }
        );
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(host.replies, [0x8000_1234_u32 as i32]);
        assert_eq!((host.calls, host.consumed), (1, 0));
    }
}
