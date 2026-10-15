//! Publish the exact API owner before resource-cache, heap or guest effects.
use super::super::far_callback::{
    Win16FarCallbackArgument as A, Win16FarCallbackConvention, Win16FarCallbackReturn,
};
use super::*;

impl Win16State {
    fn publish_resource_call(
        &mut self,
        cpu: &Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        result: ResourceReturn,
        return_to: (u16, u16, u32),
    ) -> Result<(), RuntimeError> {
        let callback_id = self.reserve_callback_frame_id()?;
        self.resource_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve resource API continuation",
                error,
            )
        })?;
        self.push_callback_kind(CallbackKind::Resource, callback_id)?;
        self.resource_callbacks.push(ResourceCallFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to,
            key: None,
            procedure: None,
            result,
            caller: None,
            parked: None,
            callback: None,
            phase: ResourceCallPhase::Preparing,
            completion: None,
            terminal: false,
        });
        let caller = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
        self.resource_callbacks
            .last_mut()
            .expect("published resource caller")
            .caller = Some(caller);
        let parked = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
        self.resource_callbacks
            .last_mut()
            .expect("published resource wait")
            .parked = Some(parked);
        Ok(())
    }

    fn resource_direct_return(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        value: u32,
        kind: Win16ReturnKind,
        operation: Option<&'static str>,
    ) -> Result<Option<u8>, RuntimeError> {
        let frame = self
            .resource_callbacks
            .last_mut()
            .expect("published resource API");
        frame.completion = Some(ResourceCompletion::Ready {
            value,
            kind,
            operation,
            reported: false,
        });
        frame.phase = ResourceCallPhase::Complete;
        self.complete_resource_call(cpu, dos, memory, host)?;
        Ok(None)
    }

    pub(in crate::win16_runtime) fn begin_load_resource(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        module: u16,
        info: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.publish_resource_call(cpu, dos, memory, ResourceReturn::Load, return_to)?;
        let Some(metadata) = self.resource_metadata(module, info) else {
            return self.resource_direct_return(
                cpu,
                dos,
                memory,
                host,
                0,
                Win16ReturnKind::Word,
                None,
            );
        };
        self.resource_callbacks
            .last_mut()
            .expect("resource metadata owner")
            .key = Some(metadata.key);
        if let Some(data) = self.retain_loaded_resource(metadata.key)? {
            return self.resource_direct_return(
                cpu,
                dos,
                memory,
                host,
                u32::from(data),
                Win16ReturnKind::Word,
                Some("resource-load-cached"),
            );
        }
        let data = self.prior_resource_handle(metadata.key);
        self.begin_resource_loader(cpu, dos, memory, host, metadata, data)
    }

    pub(in crate::win16_runtime) fn begin_lock_resource(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        data: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.publish_resource_call(cpu, dos, memory, ResourceReturn::Lock, return_to)?;
        let pointer = self.global_lock(data, memory)?;
        // A failed lock alone does not establish that its data was discarded.
        if pointer != 0 || !self.discarded_handles.contains(&data) {
            return self.resource_direct_return(
                cpu,
                dos,
                memory,
                host,
                pointer,
                Win16ReturnKind::FarPointer,
                None,
            );
        }
        let metadata = self
            .resource_key_for_data(data)
            .and_then(|key| self.resource_metadata(key.module, key.info));
        let Some(metadata) = metadata else {
            return self.resource_direct_return(
                cpu,
                dos,
                memory,
                host,
                0,
                Win16ReturnKind::FarPointer,
                None,
            );
        };
        self.resource_callbacks
            .last_mut()
            .expect("resource reload owner")
            .key = Some(metadata.key);
        self.begin_resource_loader(cpu, dos, memory, host, metadata, data)
    }

    fn begin_resource_loader(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        metadata: ResourceMetadata,
        data: u16,
    ) -> Result<Option<u8>, RuntimeError> {
        let procedure = self
            .resource_handlers
            .get(&(metadata.key.module, metadata.type_index))
            .copied();
        let Some(procedure) = procedure else {
            let loaded = self.default_resource_load(data, metadata.key, memory, host)?;
            let frame = self
                .resource_callbacks
                .last_mut()
                .expect("default resource owner");
            frame.completion = Some(ResourceCompletion::Commit {
                data: loaded,
                operation: "resource-default-complete",
            });
            frame.phase = ResourceCallPhase::Complete;
            self.complete_resource_call(cpu, dos, memory, host)?;
            return Ok(None);
        };
        if procedure == 0 {
            let kind = match self
                .resource_callbacks
                .last()
                .expect("disabled resource owner")
                .result
            {
                ResourceReturn::Load => Win16ReturnKind::Word,
                ResourceReturn::Lock => Win16ReturnKind::FarPointer,
            };
            return self.resource_direct_return(cpu, dos, memory, host, 0, kind, None);
        }
        let instance = self
            .modules
            .records
            .get(&metadata.key.module)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resource loader lost its module owner",
                )
            })?
            .instance;
        self.resource_callbacks
            .last_mut()
            .expect("resource procedure owner")
            .procedure = Some(procedure);
        let mut entry = cpu.regs.clone();
        // Windows resource handlers address their arguments through the
        // caller's stack segment; the CPU owner retains the original DS/ES.
        entry.ds = entry.ss;
        entry.es = entry.ss;
        let callback = self.enter_guest_far_callback_checked_with_registers(
            cpu,
            dos,
            memory,
            procedure,
            &[A::Word(data), A::Word(instance), A::Word(metadata.key.info)],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
            entry,
        )?;
        let frame = self
            .resource_callbacks
            .last_mut()
            .expect("entered resource source");
        frame.callback = Some(callback);
        frame.phase = ResourceCallPhase::AwaitHandler;
        Ok(None)
    }
}
