//! Signed HPJOB allocation shares task storage without sharing WNet semantics.
use super::*;

fn token(value: u64) -> Win16HostSpoolJob {
    Win16HostSpoolJob::new(value)
}

#[test]
fn gdi_spool_ids_stay_positive_after_high_network_ids() {
    let mut jobs = Win16NetworkPrintJobs::default();
    jobs.next_job_id = 0xfffa;
    let network = jobs.guest_job_id_for(token(1)).unwrap();
    assert_eq!(network, 0xfffa);
    let gdi = jobs.gdi_guest_job_id_for(token(2)).unwrap();
    assert_eq!(gdi, 1);
    assert_eq!(jobs.host_gdi_job_for_id(network), None);
    assert_eq!(jobs.host_job_for_id(gdi), None);
    assert_eq!(jobs.host_gdi_job_for_id(gdi), Some(token(2)));
    assert_eq!(jobs.host_job_for_id(network), Some(token(1)));
}

#[test]
fn gdi_spool_id_wrap_skips_live_network_and_reserved_aliases() {
    let mut jobs = Win16NetworkPrintJobs::default();
    jobs.reserved_guest_job_ids.insert(1, token(10));
    jobs.next_job_id = 2;
    assert_eq!(jobs.guest_job_id_for(token(11)).unwrap(), 2);
    jobs.next_job_id = i16::MAX as u16;
    assert_eq!(jobs.gdi_guest_job_id_for(token(12)).unwrap(), 0x7fff);
    jobs.next_job_id = i16::MAX as u16;
    assert_eq!(jobs.gdi_guest_job_id_for(token(13)).unwrap(), 3);
    assert_eq!(jobs.reserved_guest_job_ids.get(&1), Some(&token(10)));
}

#[test]
fn gdi_spool_exhaustion_never_allocates_a_negative_status_word() {
    let mut jobs = Win16NetworkPrintJobs::default();
    for id in 1..=i16::MAX as u16 {
        jobs.reserved_guest_job_ids.insert(id, token(u64::from(id)));
    }
    jobs.next_job_id = 0x8000;
    let error = jobs.gdi_guest_job_id_for(token(0x10000)).unwrap_err();
    assert_eq!(error.kind(), Kind::ResourceExhausted);
    assert!(jobs.guest_jobs.is_empty());
    assert!(jobs.job_ids_by_host.is_empty());
    // WNet retains its complete nonzero WORD space independently of GDI.
    assert_eq!(jobs.guest_job_id_for(token(0x10001)).unwrap(), 0x8000);
}

#[test]
fn gdi_spool_kind_checks_preserve_the_other_family_until_owner_cleanup() {
    let mut jobs = Win16NetworkPrintJobs::default();
    let gdi = jobs.gdi_guest_job_id_for(token(1)).unwrap();
    let network = jobs.guest_job_id_for(token(2)).unwrap();
    assert!(jobs.guest_job_id_for(token(1)).is_err());
    assert!(jobs.gdi_guest_job_id_for(token(2)).is_err());
    assert_eq!(jobs.retire_guest_job(gdi), None);
    assert_eq!(jobs.retire_gdi_guest_job(network), None);
    assert_eq!(jobs.host_gdi_job_for_id(gdi), Some(token(1)));
    assert_eq!(jobs.host_job_for_id(network), Some(token(2)));
    jobs.retire_all_owned_jobs();
    assert!(jobs.is_empty());
    assert_eq!(jobs.host_gdi_job_for_id(gdi), None);
    assert_eq!(jobs.host_job_for_id(network), None);
}
