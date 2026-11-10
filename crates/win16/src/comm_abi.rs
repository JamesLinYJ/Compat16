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

pub const CE_RXOVER: u16 = 0x0001;
pub const CE_CTSTO: u16 = 0x0020;
pub const CE_DSRTO: u16 = 0x0040;
pub const CE_RLSDTO: u16 = 0x0080;
pub const CE_IOE: u16 = 0x0400;
pub const CE_MODE: u16 = 0x8000;

pub const EV_RXCHAR: u16 = 0x0001;
pub const EV_RXFLAG: u16 = 0x0002;
pub const EV_TXEMPTY: u16 = 0x0004;

pub const CSTF_XOFFHOLD: u8 = 1 << 3;
pub const CSTF_EOF: u8 = 1 << 5;

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
const EVEN_PARITY: u8 = 2;

const XON_CHAR: u8 = 0x11;
const XOFF_CHAR: u8 = 0x13;
/// `BuildCommDCB` threshold from KB Q101419. It is not a fraction of the queue.
const XON_LIMIT: u16 = 10;
/// 16-bit `-1`. Q101419 calls this about 65 seconds; the article's 65536 is the
/// width of that bit pattern, whose stored value is `0xFFFF`.
const INFINITE_TIMEOUT: u16 = 0xFFFF;

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

/// DCB `OpenComm` stores. KB Q101419 builds it with `BuildCommDCB("COM1:9600,E,7,1")`
/// and then applies that block. The id is the opened device, not always `COM1`.
pub fn default_dcb(id: u16) -> [u8; DCB16_LEN] {
    let mut dcb = [0_u8; DCB16_LEN];
    set_id(&mut dcb, id as u8);
    set_u16(&mut dcb, 1, CBR_9600);
    dcb[3] = 7;
    dcb[4] = EVEN_PARITY;
    set_u16(&mut dcb, 12, F_BINARY);
    dcb[14] = XON_CHAR;
    dcb[15] = XOFF_CHAR;
    set_u16(&mut dcb, 16, XON_LIMIT);
    set_u16(&mut dcb, 18, XON_LIMIT);
    dcb
}

pub fn dcb_id(dcb: &[u8; DCB16_LEN]) -> u8 {
    dcb[0]
}

pub fn dcb_baud(dcb: &[u8; DCB16_LEN]) -> u16 {
    u16::from_le_bytes([dcb[1], dcb[2]])
}

pub fn validate_dcb(dcb: &[u8; DCB16_LEN]) -> Result<(), i16> {
    if numeric_baud(dcb_baud(dcb)).is_none() {
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
///
/// KB Q101419 is the Windows 3.1 contract: the baud code is the first two
/// digits, omitted parity/data/stop become even, 7, and 1, and a final `P`
/// arms infinite RLSD, CTS, and DSR timeouts. `110` with omitted stop bits
/// uses 2 stop bits, matching the mode command and the Win32 description of
/// this older syntax. The keyword form and the `x` flow suffix belong to the
/// later Win32 `BuildCommDCB`.
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
    if fields.len() > 5 {
        return Err(IE_DEFAULT);
    }
    let baud = parse_baud(fields.first().copied().unwrap_or(b""))?;
    let parity = parse_parity(fields.get(1).copied().unwrap_or(b""))?;
    let data = parse_data(fields.get(2).copied().unwrap_or(b""))?;
    let stop = parse_stop(fields.get(3).copied().unwrap_or(b""), baud == CBR_110)?;
    let timeouts = parse_timeout(fields.get(4).copied().unwrap_or(b""))?;
    let mut dcb = [0_u8; DCB16_LEN];
    if let Some(device) = device {
        set_id(&mut dcb, guest_comm_id(device) as u8);
    }
    set_u16(&mut dcb, 1, baud);
    dcb[3] = data;
    dcb[4] = parity;
    dcb[5] = stop;
    set_u16(&mut dcb, 6, timeouts);
    set_u16(&mut dcb, 8, timeouts);
    set_u16(&mut dcb, 10, timeouts);
    set_u16(&mut dcb, 12, F_BINARY);
    dcb[14] = XON_CHAR;
    dcb[15] = XOFF_CHAR;
    set_u16(&mut dcb, 16, XON_LIMIT);
    set_u16(&mut dcb, 18, XON_LIMIT);
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
    numeric_baud(code).is_some()
}

/// Numeric rate for a Win16 baud word.
///
/// KB Q101419 accepts a `CBR_*` constant or any number greater than 2 and
/// less than `CBR_110`. `SetCommState` returns `IE_BAUDRATE` outside that set.
pub fn numeric_baud(code: u16) -> Option<u32> {
    if let Some(rate) = cbr_baud(code) {
        return Some(rate);
    }
    if code > 2 && code < CBR_110 {
        Some(u32::from(code))
    } else {
        None
    }
}

fn cbr_baud(code: u16) -> Option<u32> {
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

fn mode_baud(rate: u32) -> Result<u16, i16> {
    // The 3.1 `CBR_*` list has no code for 150. Q101419 still accepts 150,
    // and that literal is a legal `SetCommState` baud word.
    Ok(match rate {
        110 => CBR_110,
        150 => 150,
        300 => CBR_300,
        600 => CBR_600,
        1200 => CBR_1200,
        2400 => CBR_2400,
        4800 => CBR_4800,
        9600 => CBR_9600,
        19200 => CBR_19200,
        _ => return Err(IE_BAUDRATE),
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
    if rest.first().is_some_and(u8::is_ascii_digit) {
        return Err(IE_DEFAULT);
    }
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
    if field.len() >= 2 && field.iter().all(u8::is_ascii_digit) {
        let rate = match &field[..2] {
            b"11" => 110,
            b"15" => 150,
            b"30" => 300,
            b"60" => 600,
            b"12" => 1200,
            b"24" => 2400,
            b"48" => 4800,
            b"96" => 9600,
            b"19" => 19200,
            _ => return Err(IE_BAUDRATE),
        };
        return mode_baud(rate);
    }
    Err(IE_BAUDRATE)
}

fn parse_parity(field: &[u8]) -> Result<u8, i16> {
    match field {
        b"" | b"e" | b"E" => Ok(EVEN_PARITY),
        b"n" | b"N" => Ok(0),
        b"o" | b"O" => Ok(1),
        b"m" | b"M" => Ok(3),
        b"s" | b"S" => Ok(4),
        _ => Err(IE_DEFAULT),
    }
}

fn parse_data(field: &[u8]) -> Result<u8, i16> {
    if field.is_empty() {
        return Ok(7);
    }
    match field {
        b"7" | b"8" => Ok(field[0] - b'0'),
        _ => Err(IE_BYTESIZE),
    }
}

fn parse_stop(field: &[u8], baud_110: bool) -> Result<u8, i16> {
    match field {
        b"" if baud_110 => Ok(2),
        b"" | b"1" => Ok(0),
        b"2" => Ok(2),
        _ => Err(IE_DEFAULT),
    }
}

fn parse_timeout(field: &[u8]) -> Result<u16, i16> {
    match field {
        b"" => Ok(0),
        b"p" | b"P" => Ok(INFINITE_TIMEOUT),
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
        assert_eq!(u16::from_le_bytes([dcb[12], dcb[13]]), F_BINARY);
        assert_eq!((dcb[14], dcb[15]), (XON_CHAR, XOFF_CHAR));
        assert_eq!(u16::from_le_bytes([dcb[16], dcb[17]]), XON_LIMIT);
        assert_eq!(u16::from_le_bytes([dcb[18], dcb[19]]), XON_LIMIT);
        assert_eq!(default_dcb(0), build_dcb(b"COM1:9600, E, 7, 1").unwrap());
    }

    #[test]
    fn omitted_device_and_mode_abbreviation_use_sdk_defaults() {
        let dcb = build_dcb(b"96,n,8,1").unwrap();
        assert_eq!(dcb_id(&dcb), 0);
        assert_eq!(dcb_baud(&dcb), CBR_9600);
        assert_eq!((dcb[3], dcb[4], dcb[5]), (8, 0, 0));
        let assumed = build_dcb(b"COM2:96").unwrap();
        assert_eq!(dcb_id(&assumed), 1);
        assert_eq!(dcb_baud(&assumed), CBR_9600);
        assert_eq!((assumed[3], assumed[4], assumed[5]), (7, EVEN_PARITY, 0));
        let slow = build_dcb(b"11").unwrap();
        assert_eq!(dcb_baud(&slow), CBR_110);
        assert_eq!(slow[5], 2);
        assert_eq!(build_dcb(b"11,n,8,1").unwrap()[5], 0);
        let lpt = build_dcb(b"LPT2").unwrap();
        assert_eq!(dcb_id(&lpt), 0x81);
        assert_eq!(dcb_baud(&lpt), CBR_9600);
        let paced = build_dcb(b"COM1:96,n,8,1,P").unwrap();
        assert_eq!(u16::from_le_bytes([paced[6], paced[7]]), INFINITE_TIMEOUT);
        assert_eq!(u16::from_le_bytes([paced[8], paced[9]]), INFINITE_TIMEOUT);
        assert_eq!(u16::from_le_bytes([paced[10], paced[11]]), INFINITE_TIMEOUT);
    }

    #[test]
    fn unknown_baud_and_device_stay_errors() {
        let slow = build_dcb(b"COM1:15,n,8,1").unwrap();
        assert_eq!(dcb_baud(&slow), 150);
        assert_eq!(dcb_baud(&build_dcb(b"COM1:150,n,8,1").unwrap()), 150);
        assert_eq!(numeric_baud(150), Some(150));
        assert_eq!(numeric_baud(9600), Some(9600));
        assert_eq!(numeric_baud(1), None);
        assert_eq!(numeric_baud(CBR_9600), Some(9600));
        assert_eq!(build_dcb(b"COM1:14400,n,8,1"), Err(IE_BAUDRATE));
        assert_eq!(build_dcb(b"COM1:9600,n,5,1"), Err(IE_BYTESIZE));
        assert_eq!(build_dcb(b"COM1:9600,n,8,1.5"), Err(IE_DEFAULT));
        assert_eq!(build_dcb(b"COM1:9600,n,8,1,x"), Err(IE_DEFAULT));
        assert_eq!(build_dcb(b"COM10:96,n,8,1"), Err(IE_DEFAULT));
        assert_eq!(build_dcb(b"nope"), Err(IE_BAUDRATE));
        assert_eq!(parse_device_name(b"COM1:"), Some(CommDeviceName::Com(1)));
        assert_eq!(parse_device_name(b"lpt1"), Some(CommDeviceName::Lpt(1)));
        assert_eq!(parse_device_name(b"COM10"), None);
        assert_eq!(guest_comm_id(CommDeviceName::Com(1)), 0);
        assert_eq!(guest_comm_id(CommDeviceName::Lpt(1)), 0x80);
    }
}
