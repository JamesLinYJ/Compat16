impl Win16State {
    pub(in crate::win16_runtime) fn retry_ole1_server_release_callback(
        &mut self,
        callback_id: CallbackFrameId,
        target: super::super::win16_ole1_server_state::Ole1ReleaseTarget,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let top = self.require_callback_top(CallbackKind::Ole1)?;
        let frame = self.ole1_callbacks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 Release retry has no exact callback continuation",
            )
        })?;
        if top != callback_id
            || frame.callback_id != callback_id
            || !matches!(
                frame.stage,
                Win16Ole1CallbackStage::ServerRelease(candidate) if candidate == target
            )
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 Release retry does not own the exact top callback continuation",
            ));
        }
        self.finish_ole1_callback(cpu, dos, memory, host)
    }
}
