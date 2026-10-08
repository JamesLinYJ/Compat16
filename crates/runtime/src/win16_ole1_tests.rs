use super::*;
use guest_core::PhysAddr;
use win16_abi::{
    AccessRights, ExportLookupTarget, FAR_EXPORT_RETURN_WIDTH, SegmentedPointer, Win16ApiRequest,
    Win16CallFrame, decode_export_call, lookup_export,
};

fn registered_document(
    documents: &Win16Ole1ClientDocuments,
    handle: Win16Ole1ClientDocHandle,
) -> &Win16Ole1ClientDocument {
    documents.documents.get(&handle).unwrap()
}

#[test]
fn registration_preserves_document_metadata_and_rename_updates_its_name() {
    let mut documents = Win16Ole1ClientDocuments::new();
    let handle = documents
        .register(b"editor".to_vec(), b"draft.doc".to_vec(), -37)
        .unwrap();

    let document = registered_document(&documents, handle);
    assert_eq!(document.class_name, b"editor");
    assert_eq!(document.document_name, b"draft.doc");
    assert_eq!(document.reserved, -37);
    assert!(!document.modified);

    assert_eq!(documents.rename(handle, b"saved.doc".to_vec()), OLE1_OK);
    assert_eq!(
        registered_document(&documents, handle).document_name,
        b"saved.doc"
    );
    assert_eq!(documents.rename(handle, b"saved.doc".to_vec()), OLE1_OK);
    // NTVDM accepts an empty name; the Win3.1 SDK's RenameClientDoc failure
    // list contains only OLE_ERROR_HANDLE.
    assert_eq!(documents.rename(handle, Vec::new()), OLE1_OK);
    assert!(
        registered_document(&documents, handle)
            .document_name
            .is_empty()
    );
    assert_eq!(
        documents.rename(Win16Ole1ClientDocHandle(0), b"x".to_vec()),
        OLE1_ERROR_HANDLE
    );

    assert_eq!(documents.revoke(handle), OLE1_OK);
    assert_eq!(documents.saved(handle), OLE1_ERROR_HANDLE);
}

#[test]
fn saved_and_revert_clear_modified_state_without_reverting_registration_name() {
    let mut documents = Win16Ole1ClientDocuments::new();
    let handle = documents
        .register(b"editor".to_vec(), b"draft.doc".to_vec(), 0)
        .unwrap();

    documents.documents.get_mut(&handle).unwrap().modified = true;
    assert_eq!(documents.saved(handle), OLE1_OK);
    assert!(!registered_document(&documents, handle).modified);

    documents.documents.get_mut(&handle).unwrap().modified = true;
    assert_eq!(documents.rename(handle, b"renamed.doc".to_vec()), OLE1_OK);
    assert_eq!(documents.revert(handle), OLE1_OK);
    assert!(!registered_document(&documents, handle).modified);
    assert_eq!(
        registered_document(&documents, handle).document_name,
        b"renamed.doc"
    );
    assert_eq!(documents.revoke(handle), OLE1_OK);
}

#[test]
fn duplicate_document_names_receive_distinct_runtime_handles() {
    let mut documents = Win16Ole1ClientDocuments::new();
    let first = documents
        .register(b"editor".to_vec(), b"same.doc".to_vec(), 0)
        .unwrap();
    let second = documents
        .register(b"editor".to_vec(), b"same.doc".to_vec(), 0)
        .unwrap();

    assert_ne!(first, second);
}

#[test]
fn rollback_unpublished_registration_reuses_unexposed_handle() {
    let mut documents = Win16Ole1ClientDocuments::new();
    let unpublished = documents
        .register(b"editor".to_vec(), b"draft.doc".to_vec(), 0)
        .unwrap();
    documents.rollback_unpublished_registration(unpublished);

    let published = documents
        .register(b"editor".to_vec(), b"draft.doc".to_vec(), 0)
        .unwrap();
    assert_eq!(published, unpublished);
}

#[test]
fn registration_rejects_empty_document_name_but_accepts_empty_class_name() {
    let mut documents = Win16Ole1ClientDocuments::new();
    assert_eq!(
        documents.register(Vec::new(), b"draft.doc".to_vec(), 0),
        Ok(Win16Ole1ClientDocHandle(1)),
    );
    assert_eq!(
        documents.register(b"editor".to_vec(), Vec::new(), 0),
        Err(OLE1_ERROR_NAME),
    );
}

#[test]
fn bad_register_name_clears_valid_output_before_address_error() {
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], b"C:\\OLE1.NE").unwrap();
    let (state_slot, memory) = (&mut runtime.win16, &mut runtime.memory);
    let state = state_slot.as_mut().expect("NE image has Win16 state");

    let output_selector = state
        .selectors
        .alloc_block(PhysAddr(0x80000), 4, AccessRights::read_write(), memory)
        .unwrap();
    let output_pointer = SegmentedPointer::new(output_selector, 0);
    let class_selector = state
        .selectors
        .alloc_block(PhysAddr(0x81000), 8, AccessRights::read_write(), memory)
        .unwrap();
    let class_pointer = SegmentedPointer::new(class_selector, 0);
    let stack_selector = state
        .selectors
        .alloc_block(PhysAddr(0x82000), 32, AccessRights::read_write(), memory)
        .unwrap();
    let stack_pointer = SegmentedPointer::new(stack_selector, 0);

    state
        .selectors
        .write(memory, output_pointer, &[0xa5; 4])
        .unwrap();
    state
        .selectors
        .write(memory, class_pointer, b"editor\0")
        .unwrap();
    let output_far = output_pointer.far_value();
    let class_far = class_pointer.far_value();
    let invalid_document_far = 0xffff_0000;

    // Pascal arguments are laid out in reverse order after the far return.
    let mut frame = vec![0; 4];
    for argument in [output_far, 0, invalid_document_far, class_far] {
        frame.extend_from_slice(&argument.to_le_bytes());
    }
    state
        .selectors
        .write(memory, stack_pointer, &frame)
        .unwrap();

    let descriptor = lookup_export(b"OLECLI", ExportLookupTarget::Ordinal(41)).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(stack_pointer, FAR_EXPORT_RETURN_WIDTH),
        &state.selectors,
        memory,
    )
    .unwrap();
    let Win16ApiRequest::Ole1(request) = decoded.request else {
        panic!("OLECLI register export did not decode as an OLE1 request");
    };
    assert_eq!(
        request,
        Win16Ole1Request::RegisterClientDocInvalidAddress {
            output: output_far,
            status: OLE1_ERROR_ADDRESS,
        }
    );
    assert_eq!(
        state.ole1_client_document_api(
            Win16Ole1Request::RenameClientDocInvalidAddress {
                document: 0,
                status: OLE1_ERROR_ADDRESS,
            },
            memory,
        ),
        u32::from(OLE1_ERROR_HANDLE)
    );

    assert_eq!(
        state.ole1_client_document_api(request, memory),
        u32::from(OLE1_ERROR_ADDRESS)
    );
    let mut output = [0xff; 4];
    state
        .selectors
        .read(memory, output_pointer, &mut output)
        .unwrap();
    assert_eq!(output, [0; 4]);
}

fn tiny_ne_executable() -> Vec<u8> {
    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    let mut bytes = vec![0; 0x92];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u16(&mut bytes, 0x08, 4);
    bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());

    let ne = 0x40;
    bytes[ne..ne + 2].copy_from_slice(b"NE");
    put_u16(&mut bytes, ne + 0x04, 0x51);
    put_u16(&mut bytes, ne + 0x06, 1);
    put_u16(&mut bytes, ne + 0x0e, 2);
    put_u16(&mut bytes, ne + 0x10, 0x100);
    put_u16(&mut bytes, ne + 0x12, 0x100);
    put_u16(&mut bytes, ne + 0x14, 0);
    put_u16(&mut bytes, ne + 0x16, 1);
    put_u16(&mut bytes, ne + 0x18, 0x80);
    put_u16(&mut bytes, ne + 0x1a, 2);
    put_u16(&mut bytes, ne + 0x1c, 2);
    put_u16(&mut bytes, ne + 0x22, 0x40);
    put_u16(&mut bytes, ne + 0x26, 0x50);
    put_u16(&mut bytes, ne + 0x28, 0x51);
    put_u16(&mut bytes, ne + 0x2a, 0x51);

    put_u16(&mut bytes, 0x80 + 0x04, 0x0000);
    put_u16(&mut bytes, 0x80 + 0x06, 0x0100);
    put_u16(&mut bytes, 0x88 + 0x04, 0x0001);
    put_u16(&mut bytes, 0x88 + 0x06, 0x0100);
    bytes[0x90] = 0;
    bytes[0x91] = 0;
    bytes
}
