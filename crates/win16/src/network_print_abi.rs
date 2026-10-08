//! Windows for Workgroups 3.1 WNet spool ABI constants.
//!
//! Values are declared by the Windows for Workgroups 3.1 SDK `WINNET.H_`
//! sections “SPOOLING - QUEUE AND JOB INFO” and “STATUS CODES”.

// WNPRQ queue status values.
pub const WNPRQ_ACTIVE: u16 = 0x0000;
pub const WNPRQ_PAUSE: u16 = 0x0001;
pub const WNPRQ_ERROR: u16 = 0x0002;
pub const WNPRQ_PENDING: u16 = 0x0003;
pub const WNPRQ_PROBLEM: u16 = 0x0004;

// WNPRJ job queue and device status masks.
pub const WNPRJ_QSTATUS: u16 = 0x0007;
pub const WNPRJ_QS_QUEUED: u16 = 0x0000;
pub const WNPRJ_QS_PAUSED: u16 = 0x0001;
pub const WNPRJ_QS_SPOOLING: u16 = 0x0002;
pub const WNPRJ_QS_PRINTING: u16 = 0x0003;
pub const WNPRJ_DEVSTATUS: u16 = 0x0ff8;
pub const WNPRJ_DS_COMPLETE: u16 = 0x0008;
pub const WNPRJ_DS_INTERV: u16 = 0x0010;
pub const WNPRJ_DS_ERROR: u16 = 0x0020;
pub const WNPRJ_DS_DESTOFFLINE: u16 = 0x0040;
pub const WNPRJ_DS_DESTPAUSED: u16 = 0x0080;
pub const WNPRJ_DS_NOTIFY: u16 = 0x0100;
pub const WNPRJ_DS_DESTNOPAPER: u16 = 0x0200;
pub const WNPRJ_DS_DESTFORMCHG: u16 = 0x0400;
pub const WNPRJ_DS_DESTCRTCHG: u16 = 0x0800;
pub const WNPRJ_DS_DESTPENCHG: u16 = 0x1000;
pub const SP_QUEUECHANGED: u16 = 0x0500;

// WN status codes.
pub const WN_SUCCESS: u16 = 0x0000;
pub const WN_NOT_SUPPORTED: u16 = 0x0001;
pub const WN_NET_ERROR: u16 = 0x0002;
pub const WN_MORE_DATA: u16 = 0x0003;
pub const WN_BAD_POINTER: u16 = 0x0004;
pub const WN_BAD_VALUE: u16 = 0x0005;
pub const WN_BAD_PASSWORD: u16 = 0x0006;
pub const WN_ACCESS_DENIED: u16 = 0x0007;
pub const WN_FUNCTION_BUSY: u16 = 0x0008;
pub const WN_WINDOWS_ERROR: u16 = 0x0009;
pub const WN_BAD_USER: u16 = 0x000a;
pub const WN_OUT_OF_MEMORY: u16 = 0x000b;
pub const WN_CANCEL: u16 = 0x000c;
pub const WN_CONTINUE: u16 = 0x000d;
pub const WN_NOT_CONNECTED: u16 = 0x0030;
pub const WN_OPEN_FILES: u16 = 0x0031;
pub const WN_BAD_NETNAME: u16 = 0x0032;
pub const WN_BAD_LOCALNAME: u16 = 0x0033;
pub const WN_ALREADY_CONNECTED: u16 = 0x0034;
pub const WN_DEVICE_ERROR: u16 = 0x0035;
pub const WN_CONNECTION_CLOSED: u16 = 0x0036;
pub const WN_BAD_JOBID: u16 = 0x0040;
pub const WN_JOB_NOT_FOUND: u16 = 0x0041;
pub const WN_JOB_NOT_HELD: u16 = 0x0042;
pub const WN_BAD_QUEUE: u16 = 0x0043;
pub const WN_BAD_FILE_HANDLE: u16 = 0x0044;
pub const WN_CANT_SET_COPIES: u16 = 0x0045;
pub const WN_ALREADY_LOCKED: u16 = 0x0046;
pub const WN_NO_ERROR: u16 = 0x0050;
