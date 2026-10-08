//! Standard OLE1 environmental host names sent on the document topic.

use super::*;

pub(super) const HOST_NAMES_ITEM: &[u8] = b"StdHostNames";

pub(super) fn poke_message(
    format: u16,
    application: &[u8],
    document: &[u8],
) -> Result<crate::Win16ClassicDdeMessage, Win16Ole1Status> {
    if format == 0 || application.contains(&0) || document.contains(&0) {
        return Err(OLE1_ERROR_ADDRESS);
    }
    let document_offset = application
        .len()
        .checked_add(1)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(OLE1_ERROR_MEMORY)?;
    let size = 8usize
        .checked_add(usize::from(document_offset))
        .and_then(|length| length.checked_add(document.len()))
        .and_then(|length| length.checked_add(1))
        .filter(|length| *length <= usize::from(u16::MAX))
        .ok_or(OLE1_ERROR_MEMORY)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| OLE1_ERROR_MEMORY)?;
    // No host library codec represents this variable-length Win16 structure.
    // The DDEPOKE header precedes HOSTNAMES; its two WORD offsets are relative
    // to the following ANSI data array, as specified by the SDK OLE protocol.
    bytes.extend_from_slice(&0u16.to_le_bytes()); // fRelease = 0, as NTVDM client.
    bytes.extend_from_slice(&format.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // clientNameOffset.
    bytes.extend_from_slice(&document_offset.to_le_bytes());
    bytes.extend_from_slice(application);
    bytes.push(0);
    bytes.extend_from_slice(document);
    bytes.push(0);
    Ok(crate::Win16ClassicDdeMessage::Poke {
        item: None,
        format,
        flags: crate::Win16ClassicDdePokeFlags {
            raw_flags: 0,
            unused_bits: 0,
            release_after_receive: false,
            reserved_bits: 0,
        },
        global: crate::Win16ClassicDdeGlobalBlock {
            transfer: None,
            guest_global: None,
            bytes,
        },
    })
}

pub(super) fn retire_item_atom(
    state: &mut Win16State,
    index: usize,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    if let Some(atom) = state.ole1_client_documents.pending_dde_methods[index].item_atom {
        host.win16_global_delete_atom(atom)?;
        state.ole1_client_documents.pending_dde_methods[index].item_atom = None;
    }
    Ok(())
}
