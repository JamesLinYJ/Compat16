//! Ownership of one protected Win16 PDB prefix backed by DOS MCB storage.
//!
//! The canonical DOS PSP remains a separate real-mode object. This view gives
//! Win16 code a selector for a task-owned 256-byte prefix, while the canonical
//! PSP's real JFT pointer and the PDB's selector JFT pointer can reach the same
//! twenty bytes. See `work/win16-pdb-contract.md` for the address-domain and
//! compatibility boundary.

use std::error::Error;
use std::fmt;

use dos_kernel::{DosBlockLease, DosKernel};
use guest_core::memory::Memory;
use guest_core::{GuestMemory, PhysAddr, real_address};
use win16_abi::pdb::{PDB_PREFIX_LEN, PdbPrefix, RealModeParagraph};
use win16_abi::{AccessRights, SegmentedPointer, SelectorRef, SelectorTable};

use crate::{DiagnosticKind as Kind, RuntimeError};

const PSP_NEXT_PARAGRAPH_OFFSET: u16 = 0x02;
const PSP_INLINE_JFT_OFFSET: u16 = 0x18;
const PSP_ENVIRONMENT_OFFSET: u16 = 0x2c;
const PSP_JFT_COUNT_OFFSET: u16 = 0x32;
const PSP_JFT_POINTER_OFFSET: u16 = 0x34;
const PSP_COMMAND_TAIL_OFFSET: u16 = 0x80;
const PSP_INLINE_JFT_BYTES: usize = 20;
const PSP_JFT_METADATA_BYTES: usize =
    (PSP_JFT_POINTER_OFFSET + 4 - PSP_JFT_COUNT_OFFSET) as usize;
const DOS_PARAGRAPH_BYTES: usize = 16;
const PDB_BACKING_PARAGRAPHS: u16 =
    ((PDB_PREFIX_LEN + DOS_PARAGRAPH_BYTES - 1) / DOS_PARAGRAPH_BYTES) as u16;

/// A task-owned protected view of the process prefix.
///
/// The selector and backing lease remain live until one of the explicit
/// release methods completes. There is no `Drop` cleanup because releasing
/// DOS memory needs the owning kernel and guest-memory bus.
#[derive(Debug)]
pub(super) struct Win16Pdb {
    canonical_psp: u16,
    selector: SelectorRef,
    selector_live: bool,
    backing: Option<DosBlockLease>,
    old_jft_metadata: [u8; PSP_JFT_METADATA_BYTES],
    jft_redirect_attempted: bool,
}

impl Win16Pdb {
    /// Allocate and publish a separate PDB. The supplied environment selector
    /// must be the live alias already owned by `Win16CompatState`.
    pub(super) fn create(
        dos: &mut DosKernel,
        selectors: &mut SelectorTable,
        canonical_psp: u16,
        environment_selector: SelectorRef,
        memory: &mut Memory,
    ) -> Result<Self, RuntimeError> {
        let (next_paragraph, command_tail, jft_slots, old_jft_metadata) =
            read_bootstrap_fields(canonical_psp, environment_selector, dos, selectors, memory)?;

        let lease = dos
            .allocate_pinned_block(memory, canonical_psp, PDB_BACKING_PARAGRAPHS)
            .map_err(|error| {
                crate::runtime_error(error).with_context("allocate pinned Win16 PDB backing")
            })?;
        let extent = lease.extent();
        if extent.owner_psp_segment() != canonical_psp
            || extent.paragraphs() < PDB_BACKING_PARAGRAPHS
        {
            let cause = RuntimeError::with_source(
                Kind::InternalInvariant,
                "DOS returned an unexpected Win16 PDB backing extent",
                PdbLayoutError::UnexpectedPdbExtent {
                    owner: extent.owner_psp_segment(),
                    expected_owner: canonical_psp,
                    paragraphs: extent.paragraphs(),
                    minimum_paragraphs: PDB_BACKING_PARAGRAPHS,
                },
            );
            return Err(release_unmapped_lease(dos, memory, lease, cause));
        }
        let backing_base = match extent.guest_base() {
            Some(address) => address,
            None => {
                let cause = RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "DOS returned an unrepresentable Win16 PDB backing address",
                    PdbLayoutError::PdbAddressOverflow,
                );
                return Err(release_unmapped_lease(dos, memory, lease, cause));
            }
        };
        if let Err(error) = preflight_pdb_backing(memory, backing_base) {
            return Err(release_unmapped_lease(dos, memory, lease, error));
        }

        let selector = match selectors.alloc_block(
            backing_base,
            PDB_PREFIX_LEN as u32,
            AccessRights::read_write(),
            memory,
        ) {
            Ok(selector) => selector,
            Err(error) => {
                let cause = crate::runtime_error(error)
                    .with_context("allocate protected Win16 PDB selector");
                return Err(release_unmapped_lease(dos, memory, lease, cause));
            }
        };

        let mut pdb = Self {
            canonical_psp,
            selector,
            selector_live: true,
            backing: Some(lease),
            old_jft_metadata,
            jft_redirect_attempted: false,
        };

        if selector == environment_selector {
            let cause = RuntimeError::with_source(
                Kind::InternalInvariant,
                "Win16 PDB and environment unexpectedly share one selector identity",
                PdbLayoutError::AliasedSelectors,
            );
            return Err(pdb.abort_create(dos, selectors, memory, cause));
        }

        // The environment word in the protected view is selector-valued. Its
        // raw word comes from the checked alias retained by Win16CompatState.
        let prefix = PdbPrefix::bootstrap(
            next_paragraph,
            &command_tail,
            &jft_slots,
            environment_selector.raw(),
            SegmentedPointer::new(selector, PSP_INLINE_JFT_OFFSET),
        );
        if let Err(error) = selectors.write(
            memory,
            SegmentedPointer::new(selector, 0),
            prefix.as_bytes(),
        ) {
            let cause =
                crate::runtime_error(error).with_context("initialize protected Win16 PDB prefix");
            return Err(pdb.abort_create(dos, selectors, memory, cause));
        }

        // Commit the DOS-real JFT edge only after the PDB bytes and selector
        // are valid. The selector itself is never written to canonical PSP.
        let psp_jft_segment = pdb.backing_extent()?.data_segment();
        let new_metadata = jft_metadata(PSP_INLINE_JFT_OFFSET, psp_jft_segment);
        pdb.jft_redirect_attempted = true;
        if let Err(error) = memory.write(
            real_address(canonical_psp, PSP_JFT_COUNT_OFFSET),
            &new_metadata,
        ) {
            let cause = crate::runtime_error(error)
                .with_context("publish canonical DOS PSP JFT pointer to PDB backing");
            return Err(pdb.abort_create(dos, selectors, memory, cause));
        }

        Ok(pdb)
    }

    /// Current retained selector identity. The caller may serialize its raw
    /// word while this PDB lease is live; the `SelectorRef` remains the proof
    /// of generation and table ownership.
    pub(super) fn selector(&self) -> SelectorRef {
        self.selector
    }

    /// Roll back an unpublished construction or release a PDB before guest
    /// execution. A stale selector is an error; only a successful exact
    /// generation invalidation allows the backing lease to be released.
    pub(super) fn release(
        &mut self,
        dos: &mut DosKernel,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if self.selector_live {
            selectors.free_block(self.selector).map_err(|error| {
                crate::runtime_error(error).with_context("invalidate Win16 PDB selector")
            })?;
            self.selector_live = false;
        }
        self.restore_canonical_jft(memory)?;
        self.release_backing(dos, memory)
    }

    /// Release backing after the owner has closed native windows/callbacks and
    /// invalidated the entire selector table, including guest-created aliases.
    /// The caller must run `SelectorTable::invalidate_all()` first. This method
    /// intentionally does not interpret a stale selector as proof of teardown.
    pub(super) fn release_after_selector_teardown(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        self.selector_live = false;
        self.restore_canonical_jft(memory)?;
        self.release_backing(dos, memory)
    }

    fn abort_create(
        &mut self,
        dos: &mut DosKernel,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        cause: RuntimeError,
    ) -> RuntimeError {
        match self.release(dos, selectors, memory) {
            Ok(()) => cause,
            Err(cleanup) => RuntimeError::with_source(
                Kind::InternalInvariant,
                "Win16 PDB creation failed and rollback remains incomplete",
                PdbRollbackFailure { cause, cleanup },
            ),
        }
    }

    fn backing_extent(&self) -> Result<dos_kernel::DosBlockExtent, RuntimeError> {
        self.backing
            .as_ref()
            .map(DosBlockLease::extent)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 PDB backing lease has already been released",
                )
            })
    }

    fn restore_canonical_jft(&mut self, memory: &mut Memory) -> Result<(), RuntimeError> {
        if !self.jft_redirect_attempted {
            return Ok(());
        }
        let extent = self.backing_extent()?;
        let base = extent.guest_base().ok_or_else(|| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "Win16 PDB backing address became unrepresentable during cleanup",
                PdbLayoutError::PdbAddressOverflow,
            )
        })?;
        let source = offset_address(base, PSP_INLINE_JFT_OFFSET as u32)?;
        let canonical_slots = real_address(self.canonical_psp, PSP_INLINE_JFT_OFFSET);
        let canonical_metadata = real_address(self.canonical_psp, PSP_JFT_COUNT_OFFSET);

        // Preflight every read and write before changing either canonical PSP
        // range. The live JFT slots are copied back before restoring the old
        // count/pointer so DOS handles opened during the task are retained.
        memory
            .validate_read(source, PSP_INLINE_JFT_BYTES)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("preflight live PDB JFT read"))?;
        memory
            .validate_write(canonical_slots, PSP_INLINE_JFT_BYTES)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("preflight canonical PSP JFT restore"))?;
        memory
            .validate_write(canonical_metadata, PSP_JFT_METADATA_BYTES)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("preflight canonical PSP JFT metadata restore"))?;

        let mut live_slots = [0u8; PSP_INLINE_JFT_BYTES];
        memory
            .read(source, &mut live_slots)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("read live PDB JFT slots during cleanup"))?;
        memory
            .write(canonical_slots, &live_slots)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("restore live JFT slots to canonical PSP"))?;
        memory
            .write(canonical_metadata, &self.old_jft_metadata)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("restore canonical PSP JFT count and pointer"))?;

        self.jft_redirect_attempted = false;
        Ok(())
    }

    fn release_backing(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let Some(lease) = self.backing.as_ref() else {
            return Ok(());
        };
        dos.release_block_lease(memory, lease, true)
            .map_err(crate::runtime_error)
            .map_err(|error| error.with_context("release pinned Win16 PDB backing"))?;
        self.backing = None;
        Ok(())
    }
}

fn read_bootstrap_fields(
    canonical_psp: u16,
    environment_selector: SelectorRef,
    dos: &mut DosKernel,
    selectors: &SelectorTable,
    memory: &mut Memory,
) -> Result<(RealModeParagraph, [u8; 128], [u8; 20], [u8; 6]), RuntimeError> {
    let mut next_paragraph_bytes = [0u8; 2];
    let mut jft_slots = [0u8; PSP_INLINE_JFT_BYTES];
    let mut jft_metadata = [0u8; PSP_JFT_METADATA_BYTES];
    let mut command_tail = [0u8; 128];
    memory
        .read(
            real_address(canonical_psp, PSP_NEXT_PARAGRAPH_OFFSET),
            &mut next_paragraph_bytes,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("read canonical DOS PSP end paragraph"))?;
    memory
        .read(
            real_address(canonical_psp, PSP_INLINE_JFT_OFFSET),
            &mut jft_slots,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("read canonical DOS PSP inline JFT"))?;
    memory
        .read(
            real_address(canonical_psp, PSP_JFT_COUNT_OFFSET),
            &mut jft_metadata,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("read canonical DOS PSP JFT metadata"))?;
    memory
        .read(
            real_address(canonical_psp, PSP_COMMAND_TAIL_OFFSET),
            &mut command_tail,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("read canonical DOS PSP command tail"))?;

    // PSP:32 is a DOS byte-count word followed by PSP:34's DOS real-mode
    // far pointer. Keep this local codec byte-based so it cannot accidentally
    // reinterpret the segment word as a Win16 selector.
    let count = u16::from_le_bytes([jft_metadata[0], jft_metadata[1]]);
    let offset = u16::from_le_bytes([jft_metadata[2], jft_metadata[3]]);
    let segment = u16::from_le_bytes([jft_metadata[4], jft_metadata[5]]);
    if count != PSP_INLINE_JFT_BYTES as u16 {
        return Err(layout_error(PdbLayoutError::UnsupportedInitialJftCount {
            count,
        }));
    }
    if offset != PSP_INLINE_JFT_OFFSET || segment != canonical_psp {
        return Err(layout_error(PdbLayoutError::UnsupportedInitialJftPointer {
            offset,
            segment,
            expected_segment: canonical_psp,
        }));
    }

    // Validate publication and later teardown destinations before any PDB
    // allocation or prefix write. A successful read above does not imply that
    // the real DOS PSP bytes can be committed/restored.
    memory
        .validate_write(
            real_address(canonical_psp, PSP_INLINE_JFT_OFFSET),
            PSP_INLINE_JFT_BYTES,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("preflight canonical DOS PSP inline JFT write"))?;
    memory
        .validate_write(
            real_address(canonical_psp, PSP_JFT_COUNT_OFFSET),
            PSP_JFT_METADATA_BYTES,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("preflight canonical DOS PSP JFT metadata write"))?;

    let mut environment_segment_bytes = [0u8; 2];
    memory
        .read(
            real_address(canonical_psp, PSP_ENVIRONMENT_OFFSET),
            &mut environment_segment_bytes,
        )
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("read canonical DOS PSP environment segment"))?;
    let environment_segment = u16::from_le_bytes(environment_segment_bytes);
    if environment_segment == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 bootstrap canonical DOS PSP has a null environment segment",
        ));
    }

    let environment_identity = selectors
        .reference(environment_selector.raw())
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("validate Win16 environment selector identity"))?;
    if environment_identity != environment_selector {
        return Err(RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 environment selector identity changed before PDB creation",
            PdbLayoutError::StaleEnvironmentSelector,
        ));
    }
    let environment_info = selectors
        .describe(environment_selector)
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("inspect Win16 environment selector"))?;
    let expected_environment_base = real_address(environment_segment, 0);
    if !environment_info.present
        || !environment_info.rights.readable()
        || !environment_info.rights.writable()
        || environment_info.base != expected_environment_base
    {
        return Err(RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 environment selector does not alias the canonical DOS environment block",
            PdbLayoutError::EnvironmentAliasMismatch {
                environment_segment,
                selector_base: environment_info.base.0,
                expected_base: expected_environment_base.0,
                present: environment_info.present,
                readable: environment_info.rights.readable(),
                writable: environment_info.rights.writable(),
            },
        ));
    }
    let extent = dos
        .owned_block_extent(memory, environment_segment, canonical_psp)
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("validate canonical DOS environment MCB"))?
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "canonical DOS environment has no owner-matched MCB allocation",
            )
        })?;
    let allocation_bytes = extent.byte_length().ok_or_else(|| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "canonical DOS environment MCB extent overflows the runtime size",
            PdbLayoutError::EnvironmentExtentOverflow,
        )
    })?;
    let selector_bytes = selectors
        .allocation_size(environment_selector)
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("read Win16 environment selector extent"))?;
    if usize::try_from(selector_bytes).ok() != Some(allocation_bytes) {
        return Err(RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 environment selector does not cover its complete MCB allocation",
            PdbLayoutError::EnvironmentExtentMismatch {
                selector_bytes,
                allocation_bytes,
            },
        ));
    }

    Ok((
        RealModeParagraph(u16::from_le_bytes(next_paragraph_bytes)),
        command_tail,
        jft_slots,
        jft_metadata,
    ))
}

fn preflight_pdb_backing(memory: &Memory, base: PhysAddr) -> Result<(), RuntimeError> {
    memory
        .validate_read(base, PDB_PREFIX_LEN)
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("preflight Win16 PDB backing read"))?;
    memory
        .validate_write(base, PDB_PREFIX_LEN)
        .map_err(crate::runtime_error)
        .map_err(|error| error.with_context("preflight Win16 PDB backing write"))
}

fn release_unmapped_lease(
    dos: &mut DosKernel,
    memory: &mut Memory,
    lease: DosBlockLease,
    cause: RuntimeError,
) -> RuntimeError {
    // This helper is used only before the Win16 runtime is published. A failed
    // free keeps the DOS lease pinned and is returned as a fatal loader
    // rollback error; the loader drops that DOS arena and Memory together.
    // Do not unpin and expose this backing to a later allocator as a fallback.
    match dos.release_block_lease(memory, &lease, true) {
        Ok(()) => cause,
        Err(cleanup) => rollback_failure(
            cause,
            crate::runtime_error(cleanup).with_context("release unexposed Win16 PDB allocation"),
        ),
    }
}

fn rollback_failure(cause: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        "Win16 PDB creation failed and rollback remains incomplete",
        PdbRollbackFailure { cause, cleanup },
    )
}

fn layout_error(error: PdbLayoutError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        "canonical DOS process view cannot initialize a Win16 PDB",
        error,
    )
}

fn jft_metadata(offset: u16, segment: u16) -> [u8; PSP_JFT_METADATA_BYTES] {
    let mut bytes = [0u8; PSP_JFT_METADATA_BYTES];
    bytes[..2].copy_from_slice(&(PSP_INLINE_JFT_BYTES as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&offset.to_le_bytes());
    bytes[4..6].copy_from_slice(&segment.to_le_bytes());
    bytes
}

fn offset_address(base: PhysAddr, offset: u32) -> Result<PhysAddr, RuntimeError> {
    base.0.checked_add(offset).map(PhysAddr).ok_or_else(|| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 PDB backing address overflow",
            PdbLayoutError::PdbAddressOverflow,
        )
    })
}

#[derive(Debug)]
enum PdbLayoutError {
    UnsupportedInitialJftCount {
        count: u16,
    },
    UnsupportedInitialJftPointer {
        offset: u16,
        segment: u16,
        expected_segment: u16,
    },
    UnexpectedPdbExtent {
        owner: u16,
        expected_owner: u16,
        paragraphs: u16,
        minimum_paragraphs: u16,
    },
    EnvironmentAliasMismatch {
        environment_segment: u16,
        selector_base: u32,
        expected_base: u32,
        present: bool,
        readable: bool,
        writable: bool,
    },
    EnvironmentExtentMismatch {
        selector_bytes: u32,
        allocation_bytes: usize,
    },
    StaleEnvironmentSelector,
    PdbAddressOverflow,
    EnvironmentExtentOverflow,
    AliasedSelectors,
}

impl fmt::Display for PdbLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedInitialJftCount { count } => write!(
                formatter,
                "initial DOS PSP JFT count is {count}, expected 20",
            ),
            Self::UnsupportedInitialJftPointer {
                offset,
                segment,
                expected_segment,
            } => write!(
                formatter,
                "initial DOS PSP JFT is {segment:04X}:{offset:04X}, expected {expected_segment:04X}:0018",
            ),
            Self::UnexpectedPdbExtent {
                owner,
                expected_owner,
                paragraphs,
                minimum_paragraphs,
            } => write!(
                formatter,
                "PDB MCB owner/size is {owner:04X}/{paragraphs} paragraphs, expected owner {expected_owner:04X} and at least {minimum_paragraphs} paragraphs",
            ),
            Self::EnvironmentAliasMismatch {
                environment_segment,
                selector_base,
                expected_base,
                present,
                readable,
                writable,
            } => write!(
                formatter,
                "environment selector for DOS segment {environment_segment:04X} maps base {selector_base:08X} (expected {expected_base:08X}, present={present}, read={readable}, write={writable})",
            ),
            Self::EnvironmentExtentMismatch {
                selector_bytes,
                allocation_bytes,
            } => write!(
                formatter,
                "environment selector extent is {selector_bytes} bytes, MCB allocation is {allocation_bytes} bytes",
            ),
            Self::StaleEnvironmentSelector => formatter.write_str(
                "environment selector no longer resolves to its retained table generation",
            ),
            Self::PdbAddressOverflow => {
                formatter.write_str("PDB allocation address cannot be represented in guest memory")
            }
            Self::EnvironmentExtentOverflow => formatter.write_str(
                "environment MCB paragraph extent cannot be represented as a byte length",
            ),
            Self::AliasedSelectors => {
                formatter.write_str("PDB and environment were assigned the same selector identity")
            }
        }
    }
}

impl Error for PdbLayoutError {}

#[derive(Debug)]
struct PdbRollbackFailure {
    cause: RuntimeError,
    cleanup: RuntimeError,
}

impl fmt::Display for PdbRollbackFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; rollback failure: {}",
            self.cause, self.cleanup
        )
    }
}

impl Error for PdbRollbackFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
