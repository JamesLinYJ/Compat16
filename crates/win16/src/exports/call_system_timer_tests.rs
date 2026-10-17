//! USER.11 SetSystemTimer and USER.182 KillSystemTimer far-Pascal frames.
//!
//! WINDOWS.H publishes SetTimer and KillTimer and does not publish this pair.
//! The frame matches that published timer pair: three words plus a guest
//! FARPROC, or two words, callee-cleaned, with a WORD result. The callback
//! dword stays the guest selector:offset.

use super::void_text_region_tests::decode;
use crate::{
    ArgumentKind, ExportCallingConvention, ExportLookupTarget, StackCleanup, Win16ApiRequest,
    Win16Error, Win16ExportId, Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
    Win16UserRequest, Win16UserWindowRequest, lookup_export,
};

#[test]
fn system_timer_descriptors_match_the_set_timer_pascal_frame() {
    let set = lookup_export(b"USER", ExportLookupTarget::Ordinal(11)).unwrap();
    assert_eq!(
        lookup_export(b"USER", ExportLookupTarget::Name(b"SetSystemTimer")),
        Some(set)
    );
    assert_eq!(set.id, Win16ExportId::UserSetSystemTimer);
    assert_eq!(set.ordinal(), 11);
    assert_eq!(set.return_kind, Win16ReturnKind::Word);
    assert_eq!(set.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(
        set.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 10,
            caller_pop_bytes: 0,
        })
    );
    let set_parameters: Vec<_> = set
        .parameters
        .iter()
        .map(|parameter| (parameter.kind, parameter.parameter_type))
        .collect();
    assert_eq!(
        set_parameters,
        [
            (ArgumentKind::Word, Win16ParameterType::Scalar),
            (ArgumentKind::Word, Win16ParameterType::Scalar),
            (ArgumentKind::Word, Win16ParameterType::Scalar),
            (ArgumentKind::Dword, Win16ParameterType::FarPointer),
        ]
    );

    let kill = lookup_export(b"USER", ExportLookupTarget::Ordinal(182)).unwrap();
    assert_eq!(
        lookup_export(b"USER", ExportLookupTarget::Name(b"KillSystemTimer")),
        Some(kill)
    );
    assert_eq!(kill.id, Win16ExportId::UserKillSystemTimer);
    assert_eq!(kill.ordinal(), 182);
    assert_eq!(kill.return_kind, Win16ReturnKind::Word);
    assert_eq!(kill.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(
        kill.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 4,
            caller_pop_bytes: 0,
        })
    );
    let kill_parameters: Vec<_> = kill
        .parameters
        .iter()
        .map(|parameter| (parameter.kind, parameter.parameter_type))
        .collect();
    assert_eq!(
        kill_parameters,
        [
            (ArgumentKind::Word, Win16ParameterType::Scalar),
            (ArgumentKind::Word, Win16ParameterType::Scalar),
        ]
    );
}

#[test]
fn system_timer_decode_keeps_the_guest_callback_bits() {
    assert_eq!(
        decode(b"USER", 11, &[0x1234, 0x5678, 0x3333, 0x2222, 0x1111], 14).unwrap(),
        Win16ApiRequest::User(Win16UserRequest::Window(
            Win16UserWindowRequest::SetSystemTimer {
                window: 0x1111,
                timer_id: 0x2222,
                interval: 0x3333,
                callback: 0x5678_1234,
            }
        ))
    );
    assert_eq!(
        decode(b"USER", 11, &[0, 0, 0, 0, 0], 14).unwrap(),
        Win16ApiRequest::User(Win16UserRequest::Window(
            Win16UserWindowRequest::SetSystemTimer {
                window: 0,
                timer_id: 0,
                interval: 0,
                callback: 0,
            }
        ))
    );
    assert_eq!(
        decode(b"USER", 182, &[0x2222, 0x1111], 8).unwrap(),
        Win16ApiRequest::User(Win16UserRequest::Window(
            Win16UserWindowRequest::KillSystemTimer {
                window: 0x1111,
                timer_id: 0x2222,
            }
        ))
    );
}

#[test]
fn system_timer_decode_rejects_a_truncated_frame() {
    for (ordinal, words) in [
        (11, vec![0x1234, 0x5678, 0x3333, 0x2222, 0x1111]),
        (182, vec![0x2222, 0x1111]),
    ] {
        for length in 4..4 + words.len() * 2 {
            assert!(
                matches!(
                    decode(b"USER", ordinal, &words, length as u32),
                    Err(Win16Error::LimitViolation { .. })
                ),
                "ordinal {ordinal}, length {length}"
            );
        }
    }
}
