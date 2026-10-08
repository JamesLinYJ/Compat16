//! Parser for the classic OLE1 Execute string envelope.
//!
//! It recognizes only command tokens implemented by the server route. Unknown
//! command tokens are retained as application Execute data; malformed syntax
//! for a recognized OLE command returns OLE_ERROR_SYNTAX instead of being
//! sent to the application's Execute slot.

use super::win16_ole1_server_state::{OLE_ERROR_COMMAND, Ole1Status};

const OLE_ERROR_SYNTAX: Ole1Status = 21;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ServerExecuteCommand {
    OpenDocument {
        document: Vec<u8>,
    },
    NewDocument {
        class_name: Vec<u8>,
        document: Vec<u8>,
    },
    NewFromTemplate {
        class_name: Vec<u8>,
        document: Vec<u8>,
        template: Vec<u8>,
    },
    EditDocument {
        document: Vec<u8>,
    },
    Exit,
    CloseDocument {
        document: Vec<u8>,
    },
    ShowItem {
        document: Vec<u8>,
        item: Vec<u8>,
        activate: bool,
    },
    ApplicationSpecific,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Quoted(Vec<u8>),
    Bare(Vec<u8>),
}

pub(super) fn parse_server_execute(data: &[u8]) -> Result<ServerExecuteCommand, Ole1Status> {
    let Some(body) = data.strip_suffix(&[0]) else {
        return Err(OLE_ERROR_COMMAND);
    };
    if body.contains(&0) || body.first() != Some(&b'[') {
        return Err(OLE_ERROR_SYNTAX);
    }
    let body = &body[1..];
    let command_end = body
        .iter()
        .position(|byte| matches!(*byte, b'(' | b']'))
        .ok_or(OLE_ERROR_SYNTAX)?;
    let name = &body[..command_end];
    let recognized = [
        b"StdOpenDocument".as_slice(),
        b"StdNewDocument",
        b"StdNewFromTemplate",
        b"StdNewfromTemplate",
        b"StdEditDocument",
        b"StdExit",
        b"StdCloseDocument",
        b"StdShowItem",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate));
    if !recognized {
        return Ok(ServerExecuteCommand::ApplicationSpecific);
    }

    let tokens = parse_arguments(&body[command_end..])?;
    let string = |index: usize| -> Result<Vec<u8>, Ole1Status> {
        match tokens.get(index) {
            Some(Token::Quoted(value)) => Ok(value.clone()),
            _ => Err(OLE_ERROR_SYNTAX),
        }
    };
    let no_extra = |count| {
        if tokens.len() == count {
            Ok(())
        } else {
            Err(OLE_ERROR_SYNTAX)
        }
    };

    if name.eq_ignore_ascii_case(b"StdOpenDocument") {
        no_extra(1)?;
        return Ok(ServerExecuteCommand::OpenDocument {
            document: string(0)?,
        });
    }
    if name.eq_ignore_ascii_case(b"StdNewDocument") {
        no_extra(2)?;
        return Ok(ServerExecuteCommand::NewDocument {
            class_name: string(0)?,
            document: string(1)?,
        });
    }
    if name.eq_ignore_ascii_case(b"StdNewFromTemplate")
        || name.eq_ignore_ascii_case(b"StdNewfromTemplate")
    {
        no_extra(3)?;
        return Ok(ServerExecuteCommand::NewFromTemplate {
            class_name: string(0)?,
            document: string(1)?,
            template: string(2)?,
        });
    }
    if name.eq_ignore_ascii_case(b"StdEditDocument") {
        no_extra(1)?;
        return Ok(ServerExecuteCommand::EditDocument {
            document: string(0)?,
        });
    }
    if name.eq_ignore_ascii_case(b"StdExit") {
        no_extra(0)?;
        return Ok(ServerExecuteCommand::Exit);
    }
    if name.eq_ignore_ascii_case(b"StdCloseDocument") {
        no_extra(1)?;
        return Ok(ServerExecuteCommand::CloseDocument {
            document: string(0)?,
        });
    }
    if name.eq_ignore_ascii_case(b"StdShowItem") {
        if !(2..=3).contains(&tokens.len()) {
            return Err(OLE_ERROR_SYNTAX);
        }
        let activate = if tokens.len() == 2 {
            false
        } else {
            parse_bool(&tokens[2])?
        };
        return Ok(ServerExecuteCommand::ShowItem {
            document: string(0)?,
            item: string(1)?,
            activate,
        });
    }
    Err(OLE_ERROR_SYNTAX)
}

/// Parse a standard bracket body beginning with `(` or `]`. Quoted strings
/// deliberately reject an embedded quote, matching the XP OLE1 ScanArg
/// grammar; bare tokens are retained only for recognized optional fields.
fn parse_arguments(input: &[u8]) -> Result<Vec<Token>, Ole1Status> {
    if input.first() == Some(&b']') {
        return if input.len() == 1 {
            Ok(Vec::new())
        } else {
            Err(OLE_ERROR_SYNTAX)
        };
    }
    if input.first() != Some(&b'(') {
        return Err(OLE_ERROR_SYNTAX);
    }
    if input.get(1) == Some(&b')') {
        return if input.get(2) == Some(&b']') && input.len() == 3 {
            Ok(Vec::new())
        } else {
            Err(OLE_ERROR_SYNTAX)
        };
    }
    let mut cursor = 1;
    let mut tokens = Vec::new();
    loop {
        let token = if input.get(cursor) == Some(&b'"') {
            cursor += 1;
            let start = cursor;
            while input.get(cursor).is_some_and(|byte| *byte != b'"') {
                cursor += 1;
            }
            if input.get(cursor) != Some(&b'"') {
                return Err(OLE_ERROR_SYNTAX);
            }
            let value = input[start..cursor].to_vec();
            cursor += 1;
            Token::Quoted(value)
        } else {
            let start = cursor;
            while input
                .get(cursor)
                .is_some_and(|byte| !matches!(*byte, b',' | b')' | b']'))
            {
                cursor += 1;
            }
            if cursor == start {
                return Err(OLE_ERROR_SYNTAX);
            }
            Token::Bare(input[start..cursor].to_vec())
        };
        tokens.push(token);
        match input.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b')') => {
                cursor += 1;
                return if input.get(cursor) == Some(&b']') && cursor + 1 == input.len() {
                    Ok(tokens)
                } else {
                    Err(OLE_ERROR_SYNTAX)
                };
            }
            _ => return Err(OLE_ERROR_SYNTAX),
        }
    }
}

fn parse_bool(token: &Token) -> Result<bool, Ole1Status> {
    let (Token::Quoted(bytes) | Token::Bare(bytes)) = token;
    if bytes.eq_ignore_ascii_case(b"true") {
        Ok(true)
    } else if bytes.eq_ignore_ascii_case(b"false") {
        Ok(false)
    } else {
        Err(OLE_ERROR_SYNTAX)
    }
}
