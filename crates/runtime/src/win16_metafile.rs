//! Classic WMF APIs backed by real checked Win16 HGLOBAL allocations.

use guest_core::{Registers, memory::Memory};
use win16_abi::{Win16GdiObjectsRequest as Request, global::{GMEM_DDESHARE, GMEM_MOVEABLE, GMEM_ZEROINIT}};

use super::{Win16State, global_memory::GlobalMemoryCaller};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMetafileOperation as Operation, Win16HostMetafileResult as ResultValue};

// Win16 metafile allocations include one extra METAHEADER beyond the logical
// WMF stream. This is observable through GlobalSize; it is not written to disk.
const METAHEADER_SIZE: u32 = 18;

impl Win16State {
    pub(super) fn execute_metafile(
        &mut self,
        request: Request,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let maximum_bytes = memory.size_bytes().saturating_sub(METAHEADER_SIZE);
        let result = match request {
            Request::GetMetaFile { path } => {
                let Some(path) = self.metafile_path(&path, host)? else { return Ok(0); };
                host.win16_metafile(Operation::Get { path, maximum_bytes })?
            }
            Request::CopyMetaFile { metafile, path } => {
                let bits = self.copy_global_bytes(metafile, memory)?;
                // The original GlobalLock/GlobalUnlock callbacks leave ES zero.
                registers.es = 0;
                let Some(bits) = bits else { return Ok(0); };
                let Some(path) = path else {
                    // Native Win16 memory copies preserve the complete global
                    // allocation, including bytes beyond mtSize. Applications
                    // can build these blocks themselves via GlobalAlloc.
                    return self.allocate_metafile_global(&bits, 0, registers, memory, host)
                        .map(u32::from);
                };
                let Some(path) = self.metafile_path(&path, host)? else { return Ok(0); };
                host.win16_metafile(Operation::CopyToFile { bits, path, maximum_bytes })?
            }
            Request::PlayMetaFile { dc, metafile } => {
                let bits = self.copy_global_bytes(metafile, memory)?;
                registers.es = 0;
                let Some(bits) = bits else { return Ok(0); };
                let Some(dc) = self.guest_gdi.dc(dc) else { return Ok(0); };
                return match host.win16_metafile(Operation::Play { dc, bits })? {
                    ResultValue::Played(success) => Ok(u32::from(success)),
                    _ => Err(invariant("metafile playback returned a non-Boolean result")),
                };
            }
            Request::DeleteMetaFile { metafile } => {
                // HMETAFILE16 is an HGLOBAL, including an application-created
                // block. A null, discarded, or invalid allocation cannot be
                // deleted as a live metafile; no native GDI object is retained.
                registers.es = 0;
                let Some(identity) = self.global_handles.get(&metafile).copied() else {
                    return Ok(0);
                };
                if self.heap.info(identity).map_err(crate::runtime_error)?.discarded {
                    return Ok(0);
                }
                let freed = self.global_free(metafile)? == 0;
                super::dispatch_kernel::finish_global_heap_call(registers);
                return Ok(u32::from(freed));
            }
            _ => return Err(invariant("non-metafile request reached the WMF bridge")),
        };
        let ResultValue::Bits(bits) = result else {
            return Err(invariant("metafile loading returned a non-byte result"));
        };
        match bits {
            Some(bits) => self.allocate_metafile_global(
                &bits, METAHEADER_SIZE, registers, memory, host,
            ).map(u32::from),
            None => Ok(0),
        }
    }

    fn metafile_path(&self, bytes: &[u8], host: &impl RuntimeHost)
        -> Result<Option<crate::Win16GuestPath>, RuntimeError> {
        let owner = self.current_task_owner()?;
        let path = host.decode_win16_ansi(bytes).and_then(|text|
            self.kernel_file_system.resolve_guest_path_text(owner, &text, false));
        match path {
            Ok(path) => Ok(Some(path)),
            Err(error) if matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn allocate_metafile_global(
        &mut self, bytes: &[u8], extra: u32,
        registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(size) = u32::try_from(bytes.len()).ok().and_then(|size| size.checked_add(extra))
            else { return Ok(0); };
        if size == 0 { return Ok(0); }
        // WOW creates these shared blocks through KERNEL's GlobalAllocLock16
        // callback, so their guest owner is the live builtin KERNEL module.
        // The ordinary global-allocation path owns selector generations and
        // task/module teardown; a second metafile handle registry is unsound.
        let caller = self.modules.by_name(b"KERNEL").map(GlobalMemoryCaller::BuiltinModule);
        let handle = self.global_alloc_with_context(
            GMEM_MOVEABLE | GMEM_DDESHARE | GMEM_ZEROINIT, size, caller, memory, host,
        )?;
        super::dispatch_kernel::finish_global_heap_call(registers);
        if handle == 0 { return Ok(0); }
        let written = (|| {
            let selector = self.global_selectors.get(&handle).copied()
                .ok_or_else(|| invariant("metafile allocation has no primary selector"))?;
            let pointer = self.selectors.pointer_from_raw(selector.raw(), 0)
                .map_err(crate::runtime_error)?;
            self.write_text_bytes(memory, pointer, bytes)
        })();
        if let Err(error) = written {
            return match self.global_free(handle) {
                Ok(0) => Err(error),
                Ok(_) => Err(error.with_cleanup("retire unpublished metafile allocation",
                    invariant("unpublished metafile allocation remains owned by the global heap"))),
                Err(cleanup) => Err(error.with_cleanup("retire unpublished metafile allocation", cleanup)),
            };
        }
        Ok(handle)
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
