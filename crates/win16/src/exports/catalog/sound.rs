//! SOUND.DRV and MMSYSTEM sound-call stack layouts.

use super::*;

pub(super) const EMPTY: &[Win16Parameter] = &[];
pub(super) const ONE_WORD: &[Win16Parameter] = &[
    Win16Parameter { name: "value", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const TWO_WORDS: &[Win16Parameter] = &[
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "second", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const THREE_WORDS: &[Win16Parameter] = &[
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "second", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "third", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const FOUR_WORDS: &[Win16Parameter] = &[
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "second", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "third", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "fourth", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const FIVE_WORDS: &[Win16Parameter] = &[
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "second", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "third", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "fourth", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "fifth", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const VOICE_FREQUENCY_DURATION: &[Win16Parameter] = &[
    Win16Parameter { name: "voice", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "frequency", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "duration", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const SND_PLAY_SOUND: &[Win16Parameter] = &[
    Win16Parameter { name: "sound_name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const PLAY_SOUND: &[Win16Parameter] = &[
    Win16Parameter { name: "sound_name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
