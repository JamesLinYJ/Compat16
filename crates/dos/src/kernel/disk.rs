use crate::{DosAction, DosDiskSpace, DosError, DosHost};
use guest_core::Registers;

use super::DosKernel;

const DOS_SECTOR_BYTES: u64 = 512;
const MAX_SECTORS_PER_CLUSTER: u64 = 64;
const MAX_DOS_CLUSTERS: u64 = u16::MAX as u64;
const DOS_5_VOLUME_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const MAX_REPRESENTABLE_BYTES: u64 =
    MAX_DOS_CLUSTERS * MAX_SECTORS_PER_CLUSTER * DOS_SECTOR_BYTES;

impl DosKernel {
    /// INT 21h/AH=36h reports DOS allocation units for a mapped drive.
    ///
    /// The host supplies byte counts only. DOS presents 512-byte sectors and
    /// power-of-two clusters, capped at the DOS 5 FAT16 limit. This is a
    /// compatibility view and does not expose host filesystem geometry.
    pub(super) fn disk_space(
        &self,
        regs: &mut Registers,
        host: &impl DosHost,
    ) -> Result<DosAction, DosError> {
        let requested = regs.dl();
        let drive = match requested {
            0 => host.current_drive(),
            1..=26 => requested - 1,
            _ => return Ok(Self::invalid_disk(regs)),
        };
        if drive > 25 {
            return Err(DosError::HostContractViolation(
                "host returned a drive number outside the DOS drive-letter range",
            ));
        }

        match host.disk_space(drive) {
            Ok(space) => match geometry(space) {
                Some((sectors_per_cluster, free_clusters, total_clusters)) => {
                    regs.set_ax(sectors_per_cluster);
                    regs.set_bx(free_clusters);
                    regs.set_cx(DOS_SECTOR_BYTES as u16);
                    regs.set_dx(total_clusters);
                    Self::success(regs);
                }
                None => return Ok(Self::invalid_disk(regs)),
            },
            // AH=36h has its own AX=FFFFh failure convention, including a
            // mapped drive whose volume information cannot be queried.
            Err(_) => return Ok(Self::invalid_disk(regs)),
        }
        Ok(DosAction::Continue)
    }

    fn invalid_disk(regs: &mut Registers) -> DosAction {
        regs.set_ax(u16::MAX);
        Self::success(regs);
        DosAction::Continue
    }
}

fn geometry(space: DosDiskSpace) -> Option<(u16, u16, u16)> {
    if space.total_bytes == 0 {
        return None;
    }

    // A 16-bit cluster count with clusters no larger than 32 KiB represents
    // just under 2 GiB. Saturate there, even if the host volume is larger.
    let total_bytes = space
        .total_bytes
        .min(DOS_5_VOLUME_LIMIT)
        .min(MAX_REPRESENTABLE_BYTES);
    let mut sectors_per_cluster = 1_u64;
    let total_clusters = loop {
        let cluster_bytes = DOS_SECTOR_BYTES * sectors_per_cluster;
        let clusters = total_bytes / cluster_bytes;
        if clusters <= MAX_DOS_CLUSTERS || sectors_per_cluster == MAX_SECTORS_PER_CLUSTER {
            break clusters.min(MAX_DOS_CLUSTERS);
        }
        sectors_per_cluster *= 2;
    };
    let cluster_bytes = DOS_SECTOR_BYTES * sectors_per_cluster;
    let available_bytes = space.available_bytes.min(total_bytes);
    let free_clusters = (available_bytes / cluster_bytes).min(total_clusters);

    Some((
        sectors_per_cluster as u16,
        free_clusters as u16,
        total_clusters as u16,
    ))
}
