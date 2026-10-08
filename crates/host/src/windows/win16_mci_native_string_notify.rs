//! Operand-aware MCI string NOTIFY classification.

use runtime::{parse_win16_mci_command, RuntimeError, Win16MciCommandToken};

use super::keyword;

pub(super) fn has_unquoted_notify_token(command: &[u8]) -> Result<Option<bool>, RuntimeError> {
    let tokens = match parse_win16_mci_command(command)? {
        Ok(tokens) => tokens,
        Err(_) => return Ok(Some(false)),
    };
    let Some(verb) = tokens.first() else {
        return Ok(Some(false));
    };
    let known_verb = !verb.quoted
        && [
            b"open".as_slice(),
            b"close",
            b"play",
            b"seek",
            b"stop",
            b"pause",
            b"record",
            b"info",
            b"capability",
            b"getdevcaps",
            b"set",
            b"step",
            b"break",
            b"sound",
            b"save",
            b"load",
            b"status",
            b"window",
            b"update",
            b"put",
            b"where",
            b"freeze",
            b"unfreeze",
            b"delete",
            b"cue",
            b"spin",
            b"resume",
            b"realize",
            b"escape",
            b"sysinfo",
        ]
        .iter()
        .any(|value| keyword(verb, value));
    if !known_verb {
        return if tokens
            .iter()
            .skip(2)
            .any(|token| !token.quoted && keyword(token, b"notify"))
        {
            Ok(None)
        } else {
            Ok(Some(false))
        };
    }

    // Microsoft MCI strings have a command and device identifier before their
    // command-specific flags. Values following those flags are data even when
    // they happen to spell NOTIFY; only unquoted tokens in flag positions can
    // reserve a notification route.
    // OPEN's device identifier is token 1 and the fixed command/device prefix
    // above has already consumed it. Consume command-specific operands at
    // token 2 only where the string grammar defines one; this keeps operand
    // values out of flag classification while allowing LOAD/SAVE to omit a
    // filename before NOTIFY or WAIT.
    let mut index = 2;
    if let Some(operand) = tokens.get(2) {
        match leading_operand_policy(verb) {
            LeadingOperandPolicy::Required => index = 3,
            LeadingOperandPolicy::Optional if !is_unquoted_flag(operand) => index = 3,
            LeadingOperandPolicy::Optional | LeadingOperandPolicy::None => {}
        }
    }
    while index < tokens.len() {
        if !tokens[index].quoted && keyword(&tokens[index], b"notify") {
            return Ok(Some(true));
        }
        index += 1 + string_value_arity(verb, &tokens, index);
    }
    Ok(Some(false))
}

#[derive(Clone, Copy)]
enum LeadingOperandPolicy {
    None,
    Required,
    Optional,
}

fn leading_operand_policy(verb: &Win16MciCommandToken) -> LeadingOperandPolicy {
    if [
        b"capability".as_slice(),
        b"getdevcaps",
        b"sound",
        b"status",
        b"escape",
    ]
    .iter()
    .any(|value| keyword(verb, value))
    {
        LeadingOperandPolicy::Required
    } else if [b"save".as_slice(), b"load"]
        .iter()
        .any(|value| keyword(verb, value))
    {
        LeadingOperandPolicy::Optional
    } else {
        LeadingOperandPolicy::None
    }
}

fn is_unquoted_flag(token: &Win16MciCommandToken) -> bool {
    !token.quoted && (keyword(token, b"notify") || keyword(token, b"wait"))
}

fn string_value_arity(
    verb: &Win16MciCommandToken,
    tokens: &[Win16MciCommandToken],
    index: usize,
) -> usize {
    let token = &tokens[index];
    if token.quoted {
        return 0;
    }
    if keyword(verb, b"open") {
        return if [
            b"type".as_slice(),
            b"alias",
            b"elementname",
            b"buffer",
            b"parent",
            b"style",
        ]
        .iter()
        .any(|value| keyword(token, value))
        {
            1
        } else {
            0
        };
    }
    if keyword(verb, b"window") {
        if keyword(token, b"handle") {
            return match tokens.get(index + 1) {
                Some(value) if !value.quoted && keyword(value, b"hwnd") => 2,
                Some(_) => 1,
                None => 0,
            };
        }
        return if [b"state".as_slice(), b"show", b"text", b"caption"]
            .iter()
            .any(|value| keyword(token, value))
        {
            1
        } else {
            0
        };
    }
    if keyword(verb, b"update") {
        if keyword(token, b"hdc") {
            return 1;
        }
        if keyword(token, b"paint") {
            return if tokens
                .get(index + 1)
                .is_some_and(|value| !value.quoted && keyword(value, b"hdc"))
            {
                2
            } else {
                1
            };
        }
        if keyword(token, b"at")
            && tokens
                .get(index + 1)
                .is_some_and(|value| !value.quoted && keyword(value, b"rect"))
        {
            return 5;
        }
    }
    if keyword(verb, b"status") && (keyword(token, b"track") || keyword(token, b"drive")) {
        return 1;
    }
    if (keyword(verb, b"update") || keyword(verb, b"put") || keyword(verb, b"where"))
        && keyword(token, b"at")
        && tokens
            .get(index + 1)
            .is_some_and(|value| !value.quoted && keyword(value, b"rect"))
    {
        return 5;
    }
    if [
        b"from".as_slice(),
        b"to",
        b"by",
        b"track",
        b"drive",
        b"number",
        b"key",
        b"speed",
        b"frames",
        b"frame",
        b"format",
        b"audio",
        b"input",
        b"output",
        b"volume",
        b"port",
        b"tempo",
        b"offset",
        b"parent",
    ]
    .iter()
    .any(|value| keyword(token, value))
    {
        return 1;
    }
    0
}
