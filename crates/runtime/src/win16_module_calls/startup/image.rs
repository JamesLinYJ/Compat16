//! Relink the executable's original NE image before its first guest entry.
//! Its static selectors belong to bootstrap, never to the DLL heap allocator.

use super::*;
use formats::{NeImportTarget, NeImportValue, NeLoadResolver};
use win16_abi::Access;

impl Win16State {
    pub(super) fn relocate_startup_program(
        &mut self,
        definition: &NeModule,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<(), u16>, RuntimeError> {
        let imports = match self.resolve_module_import_bindings(definition, host)? {
            Ok(imports) => imports,
            Err(code) => return Ok(Err(code)),
        };
        let record = self
            .modules
            .records
            .get(&self.modules.main)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "startup executable disappeared before relocation",
                )
            })?;
        let plan = record.loaded.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "startup executable has no selector plan",
            )
        })?;
        let mut resolver = StartupProgramResolver {
            definition,
            plan,
            selectors: &self.selectors,
            memory_len: memory.len(),
            imports: &imports,
        };
        // No program or DLL guest code has run yet. Re-expand the pristine
        // image so chained/additive fixups never read previously patched
        // links or overwrite LibMain effects. The formats loader stages and
        // validates every write and rolls back committed bytes on failure.
        let loaded = load_ne_segments(&record.image, definition, &mut resolver, memory)
            .map_err(crate::runtime_error)?;
        self.modules
            .records
            .get_mut(&self.modules.main)
            .expect("startup executable")
            .loaded = Some(loaded.clone());
        self.loaded = loaded;
        Ok(Ok(()))
    }
}

struct StartupProgramResolver<'a> {
    definition: &'a NeModule,
    plan: &'a NeLoadedModule,
    selectors: &'a SelectorTable,
    memory_len: u32,
    imports: &'a super::super::super::module_loading::ModuleImportBindings,
}

impl NeLoadResolver for StartupProgramResolver<'_> {
    fn allocate_segment(
        &mut self,
        module: &NeModule,
        number: u16,
        size: u32,
        flags: u16,
    ) -> Result<Selector, FormatError> {
        let index = usize::from(number.checked_sub(1).ok_or(FormatError::InvalidNeLoad(
            "startup NE segment number zero is invalid",
        ))?);
        let definition = self
            .definition
            .segments
            .get(index)
            .ok_or(FormatError::InvalidNeLoad(
                "startup NE segment definition is missing",
            ))?;
        let segment = self
            .plan
            .segments
            .get(index)
            .ok_or(FormatError::InvalidNeLoad(
                "startup NE segment allocation is missing",
            ))?;
        if module != self.definition
            || definition.number != number
            || definition.flags != flags
            || segment.number != number
            || segment.memory_size != size
        {
            return Err(FormatError::InvalidNeLoad(
                "startup NE segment differs from its bootstrap plan",
            ));
        }
        self.selector_range(
            segment.selector,
            0,
            usize::try_from(size).map_err(|_| FormatError::ArithmeticOverflow)?,
        )?;
        Ok(segment.selector)
    }

    fn selector_range(
        &self,
        selector: Selector,
        offset: u32,
        length: usize,
    ) -> Result<PhysAddr, FormatError> {
        if !self
            .plan
            .segments
            .iter()
            .any(|segment| segment.selector == selector)
        {
            return Err(FormatError::InvalidNeLoad(
                "startup resolver does not own this selector",
            ));
        }
        let offset = u16::try_from(offset)
            .map_err(|_| FormatError::InvalidNeLoad("startup NE offset exceeds 16 bits"))?;
        let pointer = self
            .selectors
            .pointer_from_raw(selector, offset)
            .map_err(|_| FormatError::InvalidNeLoad("startup NE selector is not present"))?;
        self.selectors
            .address_within(pointer, Access::Read, length, self.memory_len)
            .map_err(|_| FormatError::InvalidNeLoad("startup NE write exceeds its segment"))
    }

    fn release_segment(&mut self, _selector: Selector) {
        // Borrowed bootstrap selectors remain owned by the executable. The
        // transactional formats loader restores bytes; it must not free the
        // caller's pre-existing segments when an import or write fails.
    }

    fn resolve_import(
        &mut self,
        module: &[u8],
        target: &NeImportTarget,
    ) -> Result<NeImportValue, FormatError> {
        self.imports
            .iter()
            .find(|(name, symbol, _)| name.eq_ignore_ascii_case(module) && symbol == target)
            .map(|(_, _, value)| *value)
            .ok_or_else(|| FormatError::UnresolvedNeImport {
                module: module.to_vec(),
                target: target.clone(),
            })
    }
}
