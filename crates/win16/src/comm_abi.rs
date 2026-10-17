//! Windows 3.1 communications control block.
//!
//! `windows.h` packs this structure at byte alignment. The flag word is the
//! one `UINT` formed by the consecutive `UINT` bit-fields in the SDK `DCB`:
//! Microsoft C assigns those bits from the low end of that word. Baud values
//! are the SDK `CBR_*` constants, not the numeric rate. No UART register image
//! is stored here.

pub const DCB16_LEN: usize = 25;
pub const COMSTAT16_LEN: usize = 5;

pub const IE_BADID: i16 = -1;
pub const IE_OPEN: i16 = -2;
pub const IE_NOPEN: i16 = -3;
pub const IE_MEMORY: i16 = -4;
pub const IE_DEFAULT: i16 = -5;
pub const IE_HARDWARE: i16 = -6;
pub const IE_BYTESIZE: i16 = -7;
pub const IE_BAUDRATE: i16 = -8;

pub const CBR_110: u16 = 0xFF10;
pub const CBR_300: u16 = 0xFF11;
pub const CBR_600: u16 = 0xFF12;
pub const CBR_1200: u16 = 0xFF13;
pub const CBR_2400: u16 = 0xFF14;
pub const CBR_4800: u16 = 0xFF15;
pub const CBR_9600: u16 = 0xFF16;
pub const CBR_14400: u16 = 0xFF17;
pub const CBR_19200: u16 = 0xFF18;
pub const CBR_38400: u16 = 0xFF1B;
pub const CBR_56000: u16 = 0xFF1F;
pub const CBR_128000: u16 = 0xFF23;
pub const CBR_256000: u16 = 0xFF27;

pub const CE_IOE: u16 = 0x0400;
pub const CE_MODE: u16 = 0x8000;

pub const EV_RXCHAR: u16 = 0x0001;
pub const EV_TXEMPTY: u16 = 0x0004;

pub const SETXOFF: i16 = 1;
pub const SETXON: i16 = 2;
pub const SETRTS: i16 = 3;
pub const CLRRTS: i16 = 4;
pub const SETDTR: i16 = 5;
pub const CLRDTR: i16 = 6;
pub const RESETDEV: i16 = 7;
pub const GETMAXLPT: i16 = 8;
pub const GETMAXCOM: i16 = 9;

/// Highest `OpenComm` id for `COM1`–`COM9`. The SDK's `GETMAXCOM` example
/// (3 when `COM1` through `COM4` exist) is the 0-based id, so `COM1` is 0.
pub const MAX_COM_ID: u16 = 8;
/// `LPT1`–`LPT3` use `0x80 + (n - 1)` so a `DCB.Id` byte cannot collide with a
/// COM id. The SDK names the id but does not publish this LPT base.
pub const MAX_LPT_ID: u16 = 0x82;

const F_BINARY: u16 = 1 << 0;

const XON_CHAR: u8 = 0x11;
const XOFF_CHAR: u8 = 0x13;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommDeviceName {
    Com(u8),
    Lpt(u8),
}

pub fn guest_comm_id(device: CommDeviceName) -> u16 {
    match device {
        CommDeviceName::Com(number) => u16::from(number - 1),
        CommDeviceName::Lpt(number) => 0x80 + u16::from(number - 1),
    }
}

/// `COMn` / `LPTn` with an optional colon. The bytes stay the guest ANSI
/// spelling; only the ASCII device token is accepted.
pub fn parse_device_name(bytes: &[u8]) -> Option<CommDeviceName> {
    let text = trim_ascii(bytes);
    if text.is_empty() || text.iter().any(|byte| !byte.is_ascii()) {
        return None;
    }
    let (kind, rest) = if has_prefix(text, b"COM") {
        (true, &text[3..])
    } else if has_prefix(text, b"LPT") {
        (false, &text[3..])
    } else {
        return None;
    };
    let mut digits = rest;
    let number = digits.first().copied().filter(u8::is_ascii_digit)?;
    digits = &digits[1..];
    if let Some((b':', tail)) = digits.split_first() {
        digits = tail;
    }
    if !digits.is_empty() {
        return None;
    }
    let number = number - b'0';
    match (kind, number) {
        (true, 1..=9) => Some(CommDeviceName::Com(number)),
        (false, 1..=3) => Some(CommDeviceName::Lpt(number)),
        _ => None,
    }
}

pub fn default_dcb(id: u16, in_queue: u16) -> [u8; DCB16_LEN] {
    let mut dcb = [0_u8; DCB16_LEN];
    set_id(&mut dcb, id as u8);
    set_u16(&mut dcb, 1, CBR_9600);
    dcb[3] = 8;
    let threshold = in_queue / 4;
    set_u16(&mut dcb, 12, F_BINARY);
    dcb[14] = XON_CHAR;
    dcb[15] = XOFF_CHAR;
    set_u16(&mut dcb, 16, threshold);
    set_u16(&mut dcb, 18, threshold);
    dcb
}

pub fn dcb_id(dcb: &[u8; DCB16_LEN]) -> u8 {
    dcb[0]
}

pub fn dcb_baud(dcb: &[u8; DCB16_LEN]) -> u16 {
    u16::from_le_bytes([dcb[1], dcb[2]])
}

pub fn validate_dcb(dcb: &[u8; DCB16_LEN]) -> Result<(), i16> {
    if baud_rate(dcb_baud(dcb)).is_none() {
        return Err(IE_BAUDRATE);
    }
    if !(4..=8).contains(&dcb[3]) {
        return Err(IE_BYTESIZE);
    }
    if dcb[4] > 4 || dcb[5] > 2 {
        return Err(IE_DEFAULT);
    }
    Ok(())
}

/// Parse a DOS `MODE` device-control string into a packed `DCB`.
pub fn build_dcb(definition: &[u8]) -> Result<[u8; DCB16_LEN], i16> {
    let text = trim_ascii(definition);
    if text.is_empty() || text.iter().any(|byte| !byte.is_ascii()) {
        return Err(IE_DEFAULT);
    }
    let (device, params) = split_device(text)?;
    let mut fields = Vec::new();
    for field in params.split(|byte| *byte == b',') {
        fields.push(trim_ascii(field));
    }
    if fields.len() > 4 {
        return Err(IE_DEFAULT);
    }
    let baud = parse_baud(fields.first().copied().unwrap_or(b""))?;
    let parity = parse_parity(fields.get(1).copied().unwrap_or(b""))?;
    let data = parse_data(fields.get(2).copied().unwrap_or(b""))?;
    let stop = parse_stop(fields.get(3).copied().unwrap_or(b""))?;
    let mut dcb = [0_u8; DCB16_LEN];
    if let Some(device) = device {
        set_id(&mut dcb, guest_comm_id(device) as u8);
    }
    set_u16(&mut dcb, 1, baud);
    dcb[3] = data;
    dcb[4] = parity;
    dcb[5] = stop;
    set_u16(&mut dcb, 12, F_BINARY);
    dcb[14] = XON_CHAR;
    dcb[15] = XOFF_CHAR;
    Ok(dcb)
}

pub fn encode_comstat(status: u8, in_queue: u16, out_queue: u16) -> [u8; COMSTAT16_LEN] {
    let mut bytes = [0_u8; COMSTAT16_LEN];
    bytes[0] = status;
    bytes[1..3].copy_from_slice(&in_queue.to_le_bytes());
    bytes[3..5].copy_from_slice(&out_queue.to_le_bytes());
    bytes
}

pub fn known_baud(code: u16) -> bool {
    baud_rate(code).is_some()
}

/// Numeric rate for a Win16 `CBR_*` constant. Win32 device control takes this rate.
pub fn numeric_baud(code: u16) -> Option<u32> {
    baud_rate(code)
}

fn baud_rate(code: u16) -> Option<u32> {
    Some(match code {
        CBR_110 => 110,
        CBR_300 => 300,
        CBR_600 => 600,
        CBR_1200 => 1200,
        CBR_2400 => 2400,
        CBR_4800 => 4800,
        CBR_9600 => 9600,
        CBR_14400 => 14400,
        CBR_19200 => 19200,
        CBR_38400 => 38400,
        CBR_56000 => 56000,
        CBR_128000 => 128000,
        CBR_256000 => 256000,
        _ => return None,
    })
}

fn baud_code(rate: u32) -> Option<u16> {
    Some(match rate {
        110 => CBR_110,
        300 => CBR_300,
        600 => CBR_600,
        1200 => CBR_1200,
        2400 => CBR_2400,
        4800 => CBR_4800,
        9600 => CBR_9600,
        14400 => CBR_14400,
        19200 => CBR_19200,
        38400 => CBR_38400,
        56000 => CBR_56000,
        128000 => CBR_128000,
        256000 => CBR_256000,
        _ => return None,
    })
}

fn split_device(text: &[u8]) -> Result<(Option<CommDeviceName>, &[u8]), i16> {
    let (kind, rest) = if has_prefix(text, b"COM") {
        (Some(true), &text[3..])
    } else if has_prefix(text, b"LPT") {
        (Some(false), &text[3..])
    } else {
        (None, text)
    };
    let Some(kind) = kind else {
        return Ok((None, text));
    };
    let number = rest
        .first()
        .copied()
        .filter(u8::is_ascii_digit)
        .ok_or(IE_DEFAULT)?;
    let mut rest = &rest[1..];
    if let Some((b':', tail)) = rest.split_first() {
        rest = tail;
    }
    let number = number - b'0';
    let device = match (kind, number) {
        (true, 1..=9) => CommDeviceName::Com(number),
        (false, 1..=3) => CommDeviceName::Lpt(number),
        _ => return Err(IE_DEFAULT),
    };
    Ok((Some(device), rest))
}

fn parse_baud(field: &[u8]) -> Result<u16, i16> {
    if field.is_empty() {
        return Ok(CBR_9600);
    }
    if field.len() == 2 && field.iter().all(u8::is_ascii_digit) {
        let rate = match field {
            b"11" => 110,
            b"30" => 300,
            b"60" => 600,
            b"12" => 1200,
            b"24" => 2400,
            b"48" => 4800,
            b"96" => 9600,
            b"19" => 19200,
            _ => return Err(IE_BAUDRATE),
        };
        return baud_code(rate).ok_or(IE_BAUDRATE);
    }
    let text = std::str::from_utf8(field).map_err(|_| IE_BAUDRATE)?;
    let rate: u32 = text.parse().map_err(|_| IE_BAUDRATE)?;
    baud_code(rate).ok_or(IE_BAUDRATE)
}

fn parse_parity(field: &[u8]) -> Result<u8, i16> {
    match field {
        b"" | b"n" | b"N" => Ok(0),
        b"o" | b"O" => Ok(1),
        b"e" | b"E" => Ok(2),
        b"m" | b"M" => Ok(3),
        b"s" | b"S" => Ok(4),
        _ => Err(IE_DEFAULT),
    }
}

fn parse_data(field: &[u8]) -> Result<u8, i16> {
    if field.is_empty() {
        return Ok(8);
    }
    match field {
        b"4" | b"5" | b"6" | b"7" | b"8" => Ok(field[0] - b'0'),
        _ => Err(IE_BYTESIZE),
    }
}

fn parse_stop(field: &[u8]) -> Result<u8, i16> {
    match field {
        b"" | b"1" => Ok(0),
        b"1.5" => Ok(1),
        b"2" => Ok(2),
        _ => Err(IE_DEFAULT),
    }
}

fn set_id(dcb: &mut [u8; DCB16_LEN], id: u8) {
    dcb[0] = id;
}

fn set_u16(dcb: &mut [u8; DCB16_LEN], offset: usize, value: u16) {
    dcb[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn has_prefix(text: &[u8], prefix: &[u8]) -> bool {
    text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_string_fills_packed_dcb() {
        let dcb = build_dcb(b"COM2:2400,e,7,2").unwrap();
        assert_eq!(dcb.len(), DCB16_LEN);
        assert_eq!(dcb_id(&dcb), 1);
        assert_eq!(dcb_baud(&dcb), CBR_2400);
        assert_eq!(dcb[3], 7);
        assert_eq!(dcb[4], 2);
        assert_eq!(dcb[5], 2);
        assert_eq!(u16::from_le_bytes([dcb[12], dcb[13]]) & F_BINARY, F_BINARY);
        assert_eq!((dcb[14], dcb[15]), (XON_CHAR, XOFF_CHAR));
    }

    #[test]
    fn omitted_device_and_mode_abbreviation_use_sdk_defaults() {
        let dcb = build_dcb(b"96,n,8,1").unwrap();
        assert_eq!(dcb_id(&dcb), 0);
        assert_eq!(dcb_baud(&dcb), CBR_9600);
        assert_eq!((dcb[3], dcb[4], dcb[5]), (8, 0, 0));
        let lpt = build_dcb(b"LPT2").unwrap();
        assert_eq!(dcb_id(&lpt), 0x81);
        assert_eq!(dcb_baud(&lpt), CBR_9600);
    }

    #[test]
    fn unknown_baud_and_device_stay_errors() {
        assert_eq!(build_dcb(b"COM1:15,n,8,1"), Err(IE_BAUDRATE));
        assert_eq!(build_dcb(b"COM1:150,n,8,1"), Err(IE_BAUDRATE));
        assert_eq!(build_dcb(b"nope"), Err(IE_BAUDRATE));
        assert_eq!(parse_device_name(b"COM1:"), Some(CommDeviceName::Com(1)));
        assert_eq!(parse_device_name(b"lpt1"), Some(CommDeviceName::Lpt(1)));
        assert_eq!(parse_device_name(b"COM10"), None);
        assert_eq!(guest_comm_id(CommDeviceName::Com(1)), 0);
        assert_eq!(guest_comm_id(CommDeviceName::Lpt(1)), 0x80);
    }
}
