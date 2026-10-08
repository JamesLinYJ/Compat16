use super::*;

pub(in crate::win16_automation::guest_ops) fn read_variant(
    selectors: &SelectorTable,
    memory: &Memory,
    far: u32,
) -> Result<Variant16, RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 VARIANT pointer is null",
        ));
    }
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    let bytes = read_guest_far_bytes(selectors, memory, pointer, 16)?;
    Variant16::decode(&bytes)
        .map_err(|_| RuntimeError::new(Kind::InvalidInput, "invalid Win16 VARIANT record"))
}

pub(in crate::win16_automation::guest_ops) fn write_variant(
    selectors: &SelectorTable,
    memory: &mut Memory,
    far: u32,
    value: Variant16,
) -> Result<(), RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 VARIANT output pointer is null",
        ));
    }
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    write_guest_far_bytes(selectors, memory, pointer, &value.encode())
}

pub(in crate::win16_automation::guest_ops) fn with_guest_far(
    mut value: Variant16,
    far: u32,
) -> Variant16 {
    value.payload = [0; 8];
    value.payload[..4].copy_from_slice(&far.to_le_bytes());
    value
}

pub(in crate::win16_automation::guest_ops) fn read_u32(
    selectors: &SelectorTable,
    memory: &Memory,
    far: u32,
) -> Result<u32, RuntimeError> {
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    let bytes = read_guest_far_bytes(selectors, memory, pointer, 4)?;
    Ok(u32::from_le_bytes(bytes.as_slice().try_into().map_err(
        |_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 Automation DWORD copy has an unexpected length",
            )
        },
    )?))
}

pub(in crate::win16_automation::guest_ops) fn write_u32(
    selectors: &SelectorTable,
    memory: &mut Memory,
    far: u32,
    value: u32,
) -> Result<(), RuntimeError> {
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    write_guest_far_bytes(selectors, memory, pointer, &value.to_le_bytes())
}

pub(in crate::win16_automation::guest_ops) fn validate_writable_range(
    selectors: &SelectorTable,
    memory: &Memory,
    far: u32,
    length: usize,
) -> Result<(), RuntimeError> {
    super::super::super::validate_guest_far_range(
        selectors,
        memory,
        far,
        length,
        win16_abi::Access::Write,
    )
}

pub(in crate::win16_automation::guest_ops) fn zeroed(
    length: usize,
) -> Result<Vec<u8>, AutomationFailure> {
    if length > MAX_AUTOMATION_ALLOCATION {
        return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| AutomationFailure::HResult(E_OUTOFMEMORY))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub(in crate::win16_automation::guest_ops) fn clone_raw_bytes(
    source: &[u8],
) -> Result<Vec<u8>, AutomationFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(source.len())
        .map_err(|_| AutomationFailure::HResult(E_OUTOFMEMORY))?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}
