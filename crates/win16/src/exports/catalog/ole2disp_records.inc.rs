// The project spec determines stack slots. Except for ordinals explicitly
// marked `-ret16`, its unmodified return-width default is Dword. Pointer-shaped
// allocation results retain their FAR-pointer meaning within that 32-bit shape;
// the SDK 3.1 bundle contains no OLE2DISP Win16 declarations to independently
// establish these historical return widths.
macro_rules! export_catalog_with_ole2disp {
    ($($existing:tt)*) => {
        export_catalog_with_midi! {
            $($existing)*
            Ole2DispSysAllocString => OLE2DISP_SYS_ALLOC_STRING:
                ("OLE2DISP", 2u16, Stack, ole2disp::SYS_ALLOC_STRING, FarPointer);
            Ole2DispSysReallocString => OLE2DISP_SYS_REALLOC_STRING:
                ("OLE2DISP", 3u16, Stack, ole2disp::SYS_REALLOC_STRING, Dword);
            Ole2DispSysAllocStringLen => OLE2DISP_SYS_ALLOC_STRING_LEN:
                ("OLE2DISP", 4u16, Stack, ole2disp::SYS_ALLOC_STRING_LEN, FarPointer);
            Ole2DispSysReAllocStringLen => OLE2DISP_SYS_REALLOC_STRING_LEN:
                ("OLE2DISP", 5u16, Stack, ole2disp::SYS_REALLOC_STRING_LEN, Dword);
            // Win32 docs declare SysFreeString void; the Win16 project spec
            // leaves its return modifier unspecified (default Dword). SDK 3.1
            // has no OLE2DISP declaration, so this remains a documented ABI gap.
            Ole2DispSysFreeString => OLE2DISP_SYS_FREE_STRING:
                ("OLE2DISP", 6u16, Stack, ole2disp::SYS_FREE_STRING, Void);
            Ole2DispSysStringLen => OLE2DISP_SYS_STRING_LEN:
                ("OLE2DISP", 7u16, Stack, ole2disp::SYS_STRING_LEN, Dword);
            // VariantInit is void in the later Win32 Automation contract; the
            // Win16 project spec has no -ret16 marker and SDK 3.1 has no
            // OLE2DISP declaration. The historical Win16 return remains unproven.
            Ole2DispVariantInit => OLE2DISP_VARIANT_INIT:
                ("OLE2DISP", 8u16, Stack, ole2disp::VARIANT_INIT, Void);
            Ole2DispVariantClear => OLE2DISP_VARIANT_CLEAR:
                ("OLE2DISP", 9u16, Stack, ole2disp::VARIANT_CLEAR, Dword);
            Ole2DispVariantCopy => OLE2DISP_VARIANT_COPY:
                ("OLE2DISP", 10u16, Stack, ole2disp::VARIANT_COPY, Dword);
            Ole2DispVariantCopyInd => OLE2DISP_VARIANT_COPY_IND:
                ("OLE2DISP", 11u16, Stack, ole2disp::VARIANT_COPY_IND, Dword);
            Ole2DispSafeArrayCreate => OLE2DISP_SAFE_ARRAY_CREATE:
                ("OLE2DISP", 15u16, Stack, ole2disp::SAFE_ARRAY_CREATE, FarPointer);
            Ole2DispSafeArrayDestroy => OLE2DISP_SAFE_ARRAY_DESTROY:
                ("OLE2DISP", 16u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
            // The Win16 spec explicitly marks these two returns `-ret16`.
            Ole2DispSafeArrayGetDim => OLE2DISP_SAFE_ARRAY_GET_DIM:
                ("OLE2DISP", 17u16, Stack, ole2disp::SAFE_ARRAY_ONE, Word);
            Ole2DispSafeArrayGetElemsize => OLE2DISP_SAFE_ARRAY_GET_ELEMSIZE:
                ("OLE2DISP", 18u16, Stack, ole2disp::SAFE_ARRAY_ONE, Word);
            Ole2DispSafeArrayGetUBound => OLE2DISP_SAFE_ARRAY_GET_UBOUND:
                ("OLE2DISP", 19u16, Stack, ole2disp::SAFE_ARRAY_BOUND, Dword);
            Ole2DispSafeArrayGetLBound => OLE2DISP_SAFE_ARRAY_GET_LBOUND:
                ("OLE2DISP", 20u16, Stack, ole2disp::SAFE_ARRAY_BOUND, Dword);
            Ole2DispSafeArrayLock => OLE2DISP_SAFE_ARRAY_LOCK:
                ("OLE2DISP", 21u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
            Ole2DispSafeArrayUnlock => OLE2DISP_SAFE_ARRAY_UNLOCK:
                ("OLE2DISP", 22u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
            Ole2DispSafeArrayAccessData => OLE2DISP_SAFE_ARRAY_ACCESS_DATA:
                ("OLE2DISP", 23u16, Stack, ole2disp::SAFE_ARRAY_ACCESS_DATA, Dword);
            Ole2DispSafeArrayUnaccessData => OLE2DISP_SAFE_ARRAY_UNACCESS_DATA:
                ("OLE2DISP", 24u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
            Ole2DispSafeArrayGetElement => OLE2DISP_SAFE_ARRAY_GET_ELEMENT:
                ("OLE2DISP", 25u16, Stack, ole2disp::SAFE_ARRAY_ELEMENT, Dword);
            Ole2DispSafeArrayPutElement => OLE2DISP_SAFE_ARRAY_PUT_ELEMENT:
                ("OLE2DISP", 26u16, Stack, ole2disp::SAFE_ARRAY_PUT_ELEMENT, Dword);
            Ole2DispSafeArrayPtrOfIndex => OLE2DISP_SAFE_ARRAY_PTR_OF_INDEX:
                ("OLE2DISP", 109u16, Stack, ole2disp::SAFE_ARRAY_ELEMENT, Dword);
            Ole2DispSafeArrayCopy => OLE2DISP_SAFE_ARRAY_COPY:
                ("OLE2DISP", 27u16, Stack, ole2disp::SAFE_ARRAY_COPY, Dword);
            Ole2DispSafeArrayAllocDescriptor => OLE2DISP_SAFE_ARRAY_ALLOC_DESCRIPTOR:
                ("OLE2DISP", 38u16, Stack, ole2disp::SAFE_ARRAY_ALLOC_DESCRIPTOR, Dword);
            Ole2DispSafeArrayAllocData => OLE2DISP_SAFE_ARRAY_ALLOC_DATA:
                ("OLE2DISP", 39u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
            Ole2DispSafeArrayDestroyDescriptor => OLE2DISP_SAFE_ARRAY_DESTROY_DESCRIPTOR:
                ("OLE2DISP", 40u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
            Ole2DispSafeArrayDestroyData => OLE2DISP_SAFE_ARRAY_DESTROY_DATA:
                ("OLE2DISP", 41u16, Stack, ole2disp::SAFE_ARRAY_ONE, Dword);
        }
    };
}
