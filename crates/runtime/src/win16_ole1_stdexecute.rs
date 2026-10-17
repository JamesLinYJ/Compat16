//! Typed builders for the standard OLE 1.0 `StdExecute` command family.
//!
//! The resulting NUL-terminated byte string is data for a checked classic DDE
//! `WM_DDE_EXECUTE` transfer. It is never treated as a pointer or as evidence
//! that the remote server accepted or completed the operation.

const MAX_EXECUTE_BYTES: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1StdExecuteError {
    Syntax,
    SizeLimit,
    ResourceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1StdExecuteCommand<'a> {
    NewDocument {
        class_name: &'a [u8],
        document_name: &'a [u8],
    },
    CloseDocument,
    /// Document-topic `StdShowItem`. The third token is the server activate
    /// flag, sent from `OleShow`'s focus BOOL.
    ShowItem {
        document: &'a [u8],
        item: &'a [u8],
        take_focus: bool,
    },
}

pub(in crate::win16_runtime) fn encode_win16_ole1_std_execute(
    command: Win16Ole1StdExecuteCommand<'_>,
) -> Result<Vec<u8>, Win16Ole1StdExecuteError> {
    let mut output = Vec::new();
    match command {
        Win16Ole1StdExecuteCommand::NewDocument {
            class_name,
            document_name,
        } => {
            encode_call(&mut output, b"StdNewDocument", &[class_name, document_name])?;
        }
        Win16Ole1StdExecuteCommand::CloseDocument => {
            encode_atom_command(&mut output, b"StdCloseDocument")?;
        }
        Win16Ole1StdExecuteCommand::ShowItem {
            document,
            item,
            take_focus,
        } => {
            let focus: &[u8] = if take_focus { b"true" } else { b"false" };
            encode_call(&mut output, b"StdShowItem", &[document, item, focus])?;
        }
    }
    Ok(output)
}

fn encode_atom_command(output: &mut Vec<u8>, name: &[u8]) -> Result<(), Win16Ole1StdExecuteError> {
    let length = name
        .len()
        .checked_add(3)
        .ok_or(Win16Ole1StdExecuteError::SizeLimit)?;
    reserve_command(output, length)?;
    output.extend_from_slice(b"[");
    output.extend_from_slice(name);
    output.extend_from_slice(b"]\0");
    Ok(())
}

fn encode_call(
    output: &mut Vec<u8>,
    name: &[u8],
    arguments: &[&[u8]],
) -> Result<(), Win16Ole1StdExecuteError> {
    let mut length = name
        .len()
        .checked_add(5)
        .ok_or(Win16Ole1StdExecuteError::SizeLimit)?;
    for (index, bytes) in arguments.iter().enumerate() {
        if bytes.contains(&0) || bytes.contains(&b'"') {
            return Err(Win16Ole1StdExecuteError::Syntax);
        }
        length = length
            .checked_add(bytes.len())
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(usize::from(index != 0)))
            .ok_or(Win16Ole1StdExecuteError::SizeLimit)?;
    }
    reserve_command(output, length)?;
    output.push(b'[');
    output.extend_from_slice(name);
    output.push(b'(');
    for (index, bytes) in arguments.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        output.push(b'"');
        output.extend_from_slice(bytes);
        output.push(b'"');
    }
    output.extend_from_slice(b")]\0");
    Ok(())
}

fn reserve_command(output: &mut Vec<u8>, length: usize) -> Result<(), Win16Ole1StdExecuteError> {
    if length > MAX_EXECUTE_BYTES {
        return Err(Win16Ole1StdExecuteError::SizeLimit);
    }
    output
        .try_reserve_exact(length)
        .map_err(|_| Win16Ole1StdExecuteError::ResourceExhausted)
}
