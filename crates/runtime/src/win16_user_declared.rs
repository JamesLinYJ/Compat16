//! Runtime results for USER exports whose catalog call was previously absent.
//!
//! Guest handles and far pointers stay in the decoded slots. This module does
//! not turn those bits into host pointers.

use std::collections::BTreeSet;

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};
use win16_abi::Win16UserDeclaredCall;

#[derive(Clone, Debug)]
pub(super) struct UserDeclaredSession {
    hardware_input_enabled: bool,
    reported_gaps: BTreeSet<u16>,
}

impl Default for UserDeclaredSession {
    fn default() -> Self {
        Self {
            // Windows starts with hardware input enabled. The flag is the
            // return value of a later call; it does not gate the host queue.
            hardware_input_enabled: true,
            reported_gaps: BTreeSet::new(),
        }
    }
}

impl Win16State {
    pub(super) fn dispatch_user_declared(
        &mut self,
        call: Win16UserDeclaredCall,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match call.ordinal {
            331 => Ok(self.enable_hardware_input(slot(&call, 0)?)),
            332 => {
                self.kernel_old_yield(host)?;
                Ok(0)
            }
            493 => classify(host, slot(&call, 0)?, Script::Bidi),
            494 => classify(host, slot(&call, 0)?, Script::English),
            600 => Ok(0),
            915 => Ok(self.app_code_page(slot(&call, 0)? as u16, host)),
            922 => Ok(u32::from(ansi_page(host))),
            927 => classify(host, slot(&call, 0)?, Script::Hebrew),
            928 => classify(host, slot(&call, 0)?, Script::French),
            929 => classify(host, slot(&call, 0)?, Script::Arabic),
            ordinal => {
                self.note_declared_gap(ordinal, host);
                Ok(documented_failure(ordinal))
            }
        }
    }

    fn enable_hardware_input(&mut self, requested: u32) -> u32 {
        let previous = self.user_declared.hardware_input_enabled;
        self.user_declared.hardware_input_enabled = requested != 0;
        u32::from(previous)
    }

    fn app_code_page(&self, task: u16, host: &impl RuntimeHost) -> u32 {
        if task != 0 && task != self.instance_handle {
            return 0;
        }
        u32::from(ansi_page(host))
    }

    fn note_declared_gap(&mut self, ordinal: u16, host: &mut impl RuntimeHost) {
        if self.user_declared.reported_gaps.insert(ordinal) {
            let detail = match ordinal {
                3 | 4 | 172 => "has no host side effect",
                333 => "returns FALSE without a host input-queue query",
                620 => "returns DISP_CHANGE_FAILED",
                640 => "returns WAIT_FAILED",
                _ => "returns zero",
            };
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("USER ordinal {ordinal} {detail}"),
            ));
        }
    }
}

fn slot(call: &Win16UserDeclaredCall, index: usize) -> Result<u32, RuntimeError> {
    call.slots.get(index).copied().ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "USER declared call is missing a decoded argument",
        )
    })
}

fn ansi_page(host: &impl RuntimeHost) -> u16 {
    u16::try_from(host.win16_ansi_code_page()).unwrap_or(0)
}

fn documented_failure(ordinal: u16) -> u32 {
    match ordinal {
        // DISP_CHANGE_FAILED and WAIT_FAILED.
        620 | 640 => 0xFFFF_FFFF,
        _ => 0,
    }
}

#[derive(Clone, Copy)]
enum Script {
    English,
    French,
    Hebrew,
    Arabic,
    Bidi,
}

fn classify(host: &impl RuntimeHost, value: u32, script: Script) -> Result<u32, RuntimeError> {
    let Ok(text) = host.decode_win16_ansi(&[value as u8]) else {
        return Ok(0);
    };
    let mut chars = text.chars();
    let Some(ch) = chars.next() else {
        return Ok(0);
    };
    if chars.next().is_some() {
        return Ok(0);
    }
    let hebrew = matches!(ch as u32, 0x0590..=0x05FF);
    let arabic = matches!(ch as u32, 0x0600..=0x06FF | 0x0750..=0x077F | 0x08A0..=0x08FF);
    let yes = match script {
        Script::English => ch.is_ascii_alphabetic(),
        Script::French => {
            ch.is_ascii_alphabetic() || matches!(ch as u32, 0xC0..=0xD6 | 0xD8..=0xF6 | 0xF8..=0xFF)
        }
        Script::Hebrew => hebrew,
        Script::Arabic => arabic,
        Script::Bidi => hebrew || arabic,
    };
    Ok(u32::from(yes))
}
