//! WOW's DM31 envelope keeps later native DEVMODE fields in Win16 driver extra.
use super::{DEVMODE16_SIZE, DevMode16Error};

// WALIAS.H spells the tag as the numeric DWORD 0x444D3331. Its byte order
// is deliberately preserved, rather than substituting an ASCII byte string.
const SIGNATURE: [u8; 4] = 0x444d_3331_u32.to_le_bytes();
const TRAILER_SIZE: usize = 12;

/// Current pointer-free DEVMODEA layout restored by the Unicode host adapter.
pub const WOW_DEVMODE_PUBLIC_SIZE: usize = 156;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WowDevModeExtra<'a> {
    pub native_spec_version: u16,
    pub native_public_size: u16,
    pub public_extension: &'a [u8],
    pub driver_extra: &'a [u8],
}

/// Inspect the original WOW32 trailer, after validating every length before
/// taking a slice. Only an exact Win3.1 public prefix participates. Arbitrary
/// legacy driver data is left opaque when the signature is absent.
pub fn decode_wow_devmode_extra(
    public_size: u16,
    extra: &[u8],
) -> Result<Option<WowDevModeExtra<'_>>, DevMode16Error> {
    if usize::from(public_size) != DEVMODE16_SIZE || extra.len() < TRAILER_SIZE {
        return Ok(None);
    }
    let trailer = &extra[extra.len() - TRAILER_SIZE..];
    if trailer[..4] != SIGNATURE {
        return Ok(None);
    }
    let native_spec_version = u16::from_le_bytes([trailer[4], trailer[5]]);
    let native_public_size = u16::from_le_bytes([trailer[6], trailer[7]]);
    let native_extra_size = usize::from(u16::from_le_bytes([trailer[8], trailer[9]]));
    let extension_size = usize::from(native_public_size)
        .checked_sub(DEVMODE16_SIZE)
        .ok_or(DevMode16Error::InvalidPublicSize)?;
    if extension_size
        .checked_add(native_extra_size)
        .and_then(|n| n.checked_add(TRAILER_SIZE))
        != Some(extra.len())
    {
        return Err(DevMode16Error::IncompleteBytes);
    }
    Ok(Some(WowDevModeExtra {
        native_spec_version,
        native_public_size,
        public_extension: &extra[..extension_size],
        driver_extra: &extra[extension_size..extra.len() - TRAILER_SIZE],
    }))
}

/// Native public bytes beyond the Win3.1 prefix precede the real private data,
/// then the original spec/size/extra WORDs follow the DM31 signature. Padding
/// is written as zero; the decoder accepts historical unspecified padding.
pub fn encode_wow_devmode_extra(
    native_spec_version: u16,
    public_extension: &[u8],
    driver_extra: &[u8],
) -> Result<Vec<u8>, DevMode16Error> {
    let public_size = DEVMODE16_SIZE
        .checked_add(public_extension.len())
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(DevMode16Error::InvalidPublicSize)?;
    let private_size =
        u16::try_from(driver_extra.len()).map_err(|_| DevMode16Error::InvalidPublicSize)?;
    let total = public_extension
        .len()
        .checked_add(driver_extra.len())
        .and_then(|n| n.checked_add(TRAILER_SIZE))
        .filter(|n| *n <= usize::from(u16::MAX))
        .ok_or(DevMode16Error::InvalidPublicSize)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| DevMode16Error::AllocationFailed)?;
    bytes.extend_from_slice(public_extension);
    bytes.extend_from_slice(driver_extra);
    bytes.extend_from_slice(&SIGNATURE);
    for word in [native_spec_version, public_size, private_size, 0] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow_devmode_original_numeric_signature_and_lengths_round_trip() {
        let bytes = encode_wow_devmode_extra(0x0401, &[1, 2, 3, 4], &[0, 0xff, 7]).unwrap();
        assert_eq!(&bytes[7..11], &[0x31, 0x33, 0x4d, 0x44]);
        let extra = decode_wow_devmode_extra(68, &bytes).unwrap().unwrap();
        assert_eq!(extra.native_spec_version, 0x0401);
        assert_eq!(extra.native_public_size, 72);
        assert_eq!(extra.public_extension, [1, 2, 3, 4]);
        assert_eq!(extra.driver_extra, [0, 0xff, 7]);
    }

    #[test]
    fn wow_devmode_absent_tag_and_partial_public_layout_stay_opaque() {
        let mut bytes = encode_wow_devmode_extra(0x0401, &[0; 88], &[]).unwrap();
        for size in [40, 64, 67, 69, 156] {
            assert_eq!(decode_wow_devmode_extra(size, &bytes), Ok(None));
        }
        bytes[88..92].copy_from_slice(b"DM31");
        assert_eq!(decode_wow_devmode_extra(68, &bytes), Ok(None));
        assert_eq!(decode_wow_devmode_extra(68, &[0; 11]), Ok(None));
    }

    #[test]
    fn wow_devmode_historical_padding_is_not_a_length_or_signature() {
        let mut bytes = encode_wow_devmode_extra(0x0401, &[0; 88], &[3]).unwrap();
        let end = bytes.len();
        bytes[end - 2..].copy_from_slice(&[0xa5, 0x5a]);
        assert!(decode_wow_devmode_extra(68, &bytes).unwrap().is_some());
    }

    #[test]
    fn wow_devmode_recognized_trailer_rejects_truncated_private_data() {
        let mut bytes = encode_wow_devmode_extra(0x0401, &[0; 88], &[3]).unwrap();
        let end = bytes.len();
        bytes[end - 4..end - 2].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            decode_wow_devmode_extra(68, &bytes),
            Err(DevMode16Error::IncompleteBytes)
        );
    }

    #[test]
    fn wow_devmode_native_public_size_cannot_underflow_prefix() {
        let mut bytes = encode_wow_devmode_extra(0x0401, &[], &[]).unwrap();
        bytes[6..8].copy_from_slice(&67_u16.to_le_bytes());
        assert_eq!(
            decode_wow_devmode_extra(68, &bytes),
            Err(DevMode16Error::InvalidPublicSize)
        );
    }

    #[test]
    fn wow_devmode_public_private_and_combined_lengths_cannot_wrap() {
        let too_large = vec![0; 65536];
        assert!(encode_wow_devmode_extra(0x0401, &too_large, &[]).is_err());
        assert!(encode_wow_devmode_extra(0x0401, &[], &too_large).is_err());
        assert!(encode_wow_devmode_extra(0x0401, &[0; 88], &too_large[..65500]).is_err());
    }
}
