//! Microsoft Win16 NetBIOS NCB wire records.
//!
//! The 64-byte NCB and the status records below follow the Microsoft LAN
//! Manager 3.1 SDK `INCLUDE/NCB.H` definitions in the WFW 3.1 SDK reference.
//! These are guest wire layouts, not `windows-sys` host layouts. The runtime
//! decodes pointers before creating any native NCB.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub(crate) const NCB16_BYTES: usize = 64;
pub(crate) const NCB16_NAME_BYTES: usize = 16;
pub(crate) const ASTATBUF16_BYTES: usize = 60;
pub(crate) const NAMEBUF16_BYTES: usize = 18;
pub(crate) const SESSBUFHDR16_BYTES: usize = 4;
pub(crate) const SESSBUF16_BYTES: usize = 36;
pub(crate) const FINDNAMEHDR16_BYTES: usize = 4;
pub(crate) const FINDNAMEBUF16_BYTES: usize = 33;

/// Packed Win16 NCB. The reserved tail is guest-owned and is never passed to
/// or replaced with the host's pointer-bearing NCB tail.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct Ncb16Wire {
    pub(crate) command: u8,
    pub(crate) retcode: u8,
    pub(crate) lsn: u8,
    pub(crate) num: u8,
    /// Little-endian guest FAR value: low WORD offset, high WORD segment.
    pub(crate) buffer_far: U32,
    pub(crate) length: U16,
    pub(crate) callname: [u8; NCB16_NAME_BYTES],
    pub(crate) name: [u8; NCB16_NAME_BYTES],
    pub(crate) rto: u8,
    pub(crate) sto: u8,
    /// WFW 3.1 calls this an asynchronous notification handle. It is an
    /// opaque guest DWORD and must never be treated as a Win32 callback.
    pub(crate) post: U32,
    pub(crate) lana_num: u8,
    pub(crate) cmd_cplt: u8,
    pub(crate) reserved: [u8; 14],
}

impl Ncb16Wire {
    pub(crate) fn command_code(&self) -> u8 {
        self.command & !ASYNCH
    }

    pub(crate) fn is_asynchronous(&self) -> bool {
        self.command & ASYNCH != 0
    }

    pub(crate) fn buffer_far_value(&self) -> u32 {
        self.buffer_far.get()
    }

    pub(crate) fn set_length(&mut self, length: u16) {
        self.length.set(length);
    }
}

/// WFW 3.1 and Windows NCB values used by the implemented guest translations.
pub(crate) const ASYNCH: u8 = 0x80;
/// NCB completion status while an asynchronous request remains pending.
pub(crate) const NRC_PENDING: u8 = 0xff;
pub(crate) const NCBLISTEN: u8 = 0x11;
pub(crate) const NCBSEND: u8 = 0x14;
pub(crate) const NCBRECV: u8 = 0x15;
pub(crate) const NCBRECVANY: u8 = 0x16;
pub(crate) const NCBCHAINSEND: u8 = 0x17;
pub(crate) const NCBDGSEND: u8 = 0x20;
pub(crate) const NCBDGRECV: u8 = 0x21;
pub(crate) const NCBDGSENDBC: u8 = 0x22;
pub(crate) const NCBDGRECVBC: u8 = 0x23;
pub(crate) const NCBRESET: u8 = 0x32;
pub(crate) const NCBASTAT: u8 = 0x33;
pub(crate) const NCBSSTAT: u8 = 0x34;
pub(crate) const NCBCANCEL: u8 = 0x35;
/// Windows NetBIOS extension (not part of the WFW 3.1 SDK command list).
pub(crate) const NCBENUM: u8 = 0x37;
/// Windows `nb30.h` extension using an opaque ACTION_HEADER and optional tail;
/// WFW 3.1 does not define this command or guest buffer record.
pub(crate) const NCBACTION: u8 = 0x77;
/// `ACTION_HEADER` is ULONG + USHORT + USHORT in the Windows host contract.
pub(crate) const ACTION_HEADER_BYTES: u16 = 8;
pub(crate) const NCBSENDNA: u8 = 0x71;
pub(crate) const NCBCHAINSENDNA: u8 = 0x72;
pub(crate) const NCBFINDNAME: u8 = 0x78;

/// Win16 ADAPTER_STATUS prefix followed by `name_count` NAMEBUF16 records.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct AdapterStatus16Wire {
    pub(crate) adapter_address: [u8; 6],
    pub(crate) rev_major: u8,
    pub(crate) reserved0: u8,
    pub(crate) adapter_type: u8,
    pub(crate) rev_minor: u8,
    pub(crate) duration: U16,
    pub(crate) frmr_recv: U16,
    pub(crate) frmr_xmit: U16,
    pub(crate) iframe_recv_err: U16,
    pub(crate) xmit_aborts: U16,
    pub(crate) xmit_success: U32,
    pub(crate) recv_success: U32,
    pub(crate) iframe_xmit_err: U16,
    pub(crate) recv_buff_unavail: U16,
    pub(crate) t1_timeouts: U16,
    pub(crate) ti_timeouts: U16,
    pub(crate) reserved1: U32,
    pub(crate) free_ncbs: U16,
    pub(crate) max_cfg_ncbs: U16,
    pub(crate) max_ncbs: U16,
    pub(crate) xmit_buf_unavail: U16,
    pub(crate) max_dgram_size: U16,
    pub(crate) pending_sess: U16,
    pub(crate) max_cfg_sess: U16,
    pub(crate) max_sess: U16,
    pub(crate) max_sess_pkt_size: U16,
    pub(crate) name_count: U16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct NameBuffer16Wire {
    pub(crate) name: [u8; NCB16_NAME_BYTES],
    pub(crate) name_num: u8,
    pub(crate) name_flags: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct SessionStatusHeader16Wire {
    pub(crate) sess_name: u8,
    pub(crate) num_sess: u8,
    pub(crate) recv_dg_outstanding: u8,
    pub(crate) recv_any_outstanding: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct SessionBuffer16Wire {
    pub(crate) lsn: u8,
    pub(crate) state: u8,
    pub(crate) local_name: [u8; NCB16_NAME_BYTES],
    pub(crate) remote_name: [u8; NCB16_NAME_BYTES],
    pub(crate) recvs_outstanding: u8,
    pub(crate) sends_outstanding: u8,
}

/// IBM/Microsoft NCBFINDNAME result header. The following entries are a
/// variable count of fixed 33-byte buffers, so the runtime validates the
/// count against the actual returned extent before copying them.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct FindNameHeader16Wire {
    pub(crate) node_count: U16,
    pub(crate) reserved: u8,
    pub(crate) unique_group: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct FindNameBuffer16Wire {
    pub(crate) length: u8,
    pub(crate) access_control: u8,
    pub(crate) frame_control: u8,
    pub(crate) destination_addr: [u8; 6],
    pub(crate) source_addr: [u8; 6],
    pub(crate) routing_info: [u8; 18],
}

const _: () = {
    assert!(core::mem::size_of::<Ncb16Wire>() == NCB16_BYTES);
    assert!(core::mem::align_of::<Ncb16Wire>() == 1);
    assert!(core::mem::offset_of!(Ncb16Wire, command) == 0);
    assert!(core::mem::offset_of!(Ncb16Wire, retcode) == 1);
    assert!(core::mem::offset_of!(Ncb16Wire, lsn) == 2);
    assert!(core::mem::offset_of!(Ncb16Wire, num) == 3);
    assert!(core::mem::offset_of!(Ncb16Wire, buffer_far) == 4);
    assert!(core::mem::offset_of!(Ncb16Wire, length) == 8);
    assert!(core::mem::offset_of!(Ncb16Wire, callname) == 10);
    assert!(core::mem::offset_of!(Ncb16Wire, name) == 26);
    assert!(core::mem::offset_of!(Ncb16Wire, rto) == 42);
    assert!(core::mem::offset_of!(Ncb16Wire, sto) == 43);
    assert!(core::mem::offset_of!(Ncb16Wire, post) == 44);
    assert!(core::mem::offset_of!(Ncb16Wire, lana_num) == 48);
    assert!(core::mem::offset_of!(Ncb16Wire, cmd_cplt) == 49);
    assert!(core::mem::offset_of!(Ncb16Wire, reserved) == 50);
    assert!(core::mem::size_of::<AdapterStatus16Wire>() == ASTATBUF16_BYTES);
    assert!(core::mem::align_of::<AdapterStatus16Wire>() == 1);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, adapter_address) == 0);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, rev_major) == 6);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, adapter_type) == 8);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, duration) == 10);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, xmit_success) == 20);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, recv_success) == 24);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, reserved1) == 36);
    assert!(core::mem::offset_of!(AdapterStatus16Wire, name_count) == 58);
    assert!(core::mem::size_of::<NameBuffer16Wire>() == NAMEBUF16_BYTES);
    assert!(core::mem::align_of::<NameBuffer16Wire>() == 1);
    assert!(core::mem::offset_of!(NameBuffer16Wire, name) == 0);
    assert!(core::mem::offset_of!(NameBuffer16Wire, name_num) == 16);
    assert!(core::mem::offset_of!(NameBuffer16Wire, name_flags) == 17);
    assert!(core::mem::size_of::<SessionStatusHeader16Wire>() == SESSBUFHDR16_BYTES);
    assert!(core::mem::align_of::<SessionStatusHeader16Wire>() == 1);
    assert!(core::mem::offset_of!(SessionStatusHeader16Wire, num_sess) == 1);
    assert!(core::mem::size_of::<SessionBuffer16Wire>() == SESSBUF16_BYTES);
    assert!(core::mem::align_of::<SessionBuffer16Wire>() == 1);
    assert!(core::mem::offset_of!(SessionBuffer16Wire, lsn) == 0);
    assert!(core::mem::offset_of!(SessionBuffer16Wire, state) == 1);
    assert!(core::mem::offset_of!(SessionBuffer16Wire, local_name) == 2);
    assert!(core::mem::offset_of!(SessionBuffer16Wire, remote_name) == 18);
    assert!(core::mem::offset_of!(SessionBuffer16Wire, recvs_outstanding) == 34);
    assert!(core::mem::offset_of!(SessionBuffer16Wire, sends_outstanding) == 35);
    assert!(core::mem::size_of::<FindNameHeader16Wire>() == FINDNAMEHDR16_BYTES);
    assert!(core::mem::align_of::<FindNameHeader16Wire>() == 1);
    assert!(core::mem::offset_of!(FindNameHeader16Wire, node_count) == 0);
    assert!(core::mem::offset_of!(FindNameHeader16Wire, reserved) == 2);
    assert!(core::mem::offset_of!(FindNameHeader16Wire, unique_group) == 3);
    assert!(core::mem::size_of::<FindNameBuffer16Wire>() == FINDNAMEBUF16_BYTES);
    assert!(core::mem::align_of::<FindNameBuffer16Wire>() == 1);
    assert!(core::mem::offset_of!(FindNameBuffer16Wire, destination_addr) == 3);
    assert!(core::mem::offset_of!(FindNameBuffer16Wire, source_addr) == 9);
    assert!(core::mem::offset_of!(FindNameBuffer16Wire, routing_info) == 15);
};
