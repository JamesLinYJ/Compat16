//! MDI child callback provenance, checked guest updates, and typed result projection.

use super::super::{
    messages::MessageOutput,
    windows::{WindowProcedure, WindowReturn},
};
use super::*;
use crate::Win16HostMdiChildCreation;
use win16_abi::CreateStruct16;

impl Win16State {
    /// Validate a reentrant child callback against the currently suspended
    /// WM_MDICREATE operation and its runtime-owned creation identity.
    pub(in crate::win16_runtime) fn mdi_creation_plan_for_callback(
        &self,
        callback_creation: Option<Win16CreationId>,
        data: &Win16HostMdiChildCreation,
    ) -> Result<&MdiCreateOutputPlan, RuntimeError> {
        let Some(callback_creation) = callback_creation else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 MDI child callback has no runtime creation identity",
            ));
        };
        let Some(WindowReturn::Message {
            output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))),
        }) = self
            .window_operations
            .last()
            .and_then(|frame| frame.continuation())
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 MDI child callback is not owned by the top WM_MDICREATE operation",
            ));
        };
        if plan.creation != callback_creation
            || plan.mdi.creation != callback_creation
            || data.mdi.creation != callback_creation
            || data.mdi.class != plan.mdi.class
            || data.mdi.guest_class_name != plan.mdi.guest_class_name
            || data.mdi.owner_instance != plan.owner_instance
            || data.creation.class != plan.mdi.class
            || data.creation.guest_class_name != plan.mdi.guest_class_name
            || data.creation.guest_instance != plan.owner_instance
            || data.creation.parent != Some(plan.mdi_client_native)
            || data.creation.create_parameter != data.mdi.parameter
            || data.creation.ex_style & 0x0000_0040 == 0
            || data.creation.child_id != Some(data.creation.guest_menu)
            || plan.child_procedure == 0
            || plan.system_kind.is_some()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 MDI child callback does not match its exact guest-class creation plan",
            ));
        }
        Ok(plan)
    }

    /// Read the currently executing Win16 CREATESTRUCT16 and its nested
    /// MDICREATESTRUCT16 after guest code may have edited their copied fields.
    /// The embedded MCS FAR must still identify the exact adjacent record in
    /// this callback's checked payload; arbitrary LPARAMs never reach USER.
    pub(in crate::win16_runtime) fn live_mdi_child_creation_data(
        &self,
        original: &Win16HostMdiChildCreation,
        outer_far: u32,
        memory: &Memory,
    ) -> Result<Option<Win16HostMdiChildCreation>, RuntimeError> {
        let plan = self.mdi_creation_plan_for_callback(Some(original.mdi.creation), original)?;
        let Ok(outer_pointer) = self.selectors.pointer_from_far(outer_far) else {
            return Ok(None);
        };
        let outer = match CreateStruct16::read_from(&self.selectors, memory, outer_pointer) {
            Ok(outer) => outer,
            Err(_) => return Ok(None),
        };
        let expected_mdi_pointer = self
            .selectors
            .add_bytes(outer_pointer, CreateStruct16::SIZE as u32)
            .map_err(crate::runtime_error)?;
        if outer.lp_create_params != expected_mdi_pointer.far_value()
            || outer.h_instance != plan.owner_instance
            || outer.hwnd_parent != plan.mdi_client_guest
            || outer.dw_ex_style & 0x0000_0040 == 0
        {
            return Ok(None);
        }

        let mut bytes = [0_u8; MDICREATESTRUCT16_SIZE];
        if self
            .selectors
            .read(memory, expected_mdi_pointer, &mut bytes)
            .is_err()
        {
            return Ok(None);
        }
        let Ok(wire) = MdiCreateStruct16Wire::read_from_bytes(&bytes) else {
            return Ok(None);
        };
        if wire.owner_instance.get() != plan.owner_instance {
            return Ok(None);
        }
        let Ok(class_name) = self.read_mdi_class_name(memory, wire.class_far.get()) else {
            return Ok(None);
        };
        let Ok(outer_class_name) = self.read_mdi_class_name(memory, outer.lpsz_class) else {
            return Ok(None);
        };
        if class_name != plan.mdi.guest_class_name || outer_class_name != class_name {
            return Ok(None);
        }
        let Ok(title) = self.read_mdi_title(memory, wire.title_far.get()) else {
            return Ok(None);
        };
        let Ok(outer_title) = self.read_mdi_title(memory, outer.lpsz_name) else {
            return Ok(None);
        };
        // CREATESTRUCT and its nested MDI record carry separate editable
        // titles. Read each through checked guest memory without requiring
        // the guest to update both copies before default processing.
        let parent = self.window_handles.get(&outer.hwnd_parent).copied();
        if parent != Some(plan.mdi_client_native) {
            return Ok(None);
        }

        let mdi = Win16HostMdiCreate {
            creation: original.mdi.creation,
            class: original.mdi.class,
            guest_class_name: class_name.clone(),
            owner_instance: wire.owner_instance.get(),
            title: title.clone(),
            x: wire.x.get(),
            y: wire.y.get(),
            cx: wire.cx.get(),
            cy: wire.cy.get(),
            style: wire.style.get(),
            parameter: wire.parameter.get(),
        };
        let creation = crate::Win16HostCreationData {
            class: original.creation.class,
            guest_instance: outer.h_instance,
            guest_class_name: outer_class_name,
            guest_menu: outer.h_menu,
            class_menu_template: None,
            create_parameter: mdi.parameter,
            creation_data: None,
            mdi_client: None,
            dialog_root: false,
            menu: None,
            title: outer_title,
            style: outer.style,
            ex_style: outer.dw_ex_style,
            x: outer.x,
            y: outer.y,
            width: outer.cx,
            height: outer.cy,
            parent,
            child_id: Some(outer.h_menu),
        };
        Ok(Some(Win16HostMdiChildCreation { creation, mdi }))
    }

    fn read_mdi_class_name(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<Win16HostClassName, RuntimeError> {
        if far >> 16 == 0 {
            let atom = far as u16;
            return Ok(Win16HostClassName::Atom(atom));
        }
        Ok(Win16HostClassName::Name(
            read_ansi_z(&self.selectors, memory, far, MAX_WIN16_STRING_BYTES)
                .map_err(crate::runtime_error)?,
        ))
    }

    fn read_mdi_title(&self, memory: &Memory, far: u32) -> Result<Option<Vec<u8>>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        Ok(Some(
            read_ansi_z(&self.selectors, memory, far, MAX_WIN16_STRING_BYTES)
                .map_err(crate::runtime_error)?,
        ))
    }

    /// Project a host MDI result into Win16 return bits and commit the
    /// MDICREATESTRUCT16 tail through its original selector-generation token.
    pub(in crate::win16_runtime) fn finish_mdi_message(
        &mut self,
        output: Option<MdiOutputPlan>,
        result: Option<crate::Win16HostMdiMessageResult>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        self.finish_mdi_message_with_retirements(output, result, None, memory)
    }

    pub(in crate::win16_runtime) fn finish_mdi_message_with_retirements(
        &mut self,
        output: Option<MdiOutputPlan>,
        result: Option<crate::Win16HostMdiMessageResult>,
        enclosing_retirements: Option<&crate::Win16HostWindowRetirementBatch>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let enclosing_receipts = enclosing_retirements
            .map_or(&[][..], |batch| batch.receipts.as_slice());
        let enclosing_has_effects = enclosing_retirements.is_some_and(|batch| {
            !batch.receipts.is_empty() || !batch.invalidated_menus.is_empty()
        });
        if result.is_none() && enclosing_has_effects {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native dispatch returned retirement effects without its typed result",
            ));
        }
        let Some(result) = result else {
            if let Some(MdiOutputPlan::Create(plan)) = output.as_ref() {
                self.retire_mdi_creation_claims(plan.creation)?;
            }
            return Ok(0);
        };

        if let crate::Win16HostMdiOutput::Destroyed {
            receipt,
            additional_retirements,
            invalidated_menus,
        } = &result.output
        {
            let Some(MdiOutputPlan::Destroy(plan)) = output.as_ref() else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "host MDI retirement result has no exact WM_MDIDESTROY plan",
                ));
            };
            let receipt_count = additional_retirements
                .len()
                .checked_add(enclosing_receipts.len())
                .and_then(|count| count.checked_add(if receipt.is_some() { 1 } else { 0 }))
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "MDI window retirement receipt count overflowed",
                    )
                })?;
            let mut receipts = Vec::new();
            receipts.try_reserve_exact(receipt_count).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve the complete MDI window retirement receipt batch",
                    error,
                )
            })?;
            receipts.extend(receipt.iter().copied());
            receipts.extend(additional_retirements.iter().copied());
            receipts.extend(enclosing_receipts.iter().copied());

            self.validate_mdi_child_retirement_plan(*plan, *receipt, additional_retirements)?;
            let claims = self.prevalidate_window_retirement_batch(&receipts)?;
            self.retire_prevalidated_window_claims(claims)?;
            self.guest_menus.invalidate(invalidated_menus);
            if let Some(batch) = enclosing_retirements {
                self.guest_menus.invalidate(&batch.invalidated_menus);
            }
            return Ok(result.value);
        }

        let retirement_claims =
            self.prevalidate_window_retirement_batch(enclosing_receipts)?;
        let active_guest_child = self.validate_mdi_result_before_retirement(
            output.as_ref(),
            &result.output,
            enclosing_retirements,
            &retirement_claims,
        )?;

        // A successful create must claim its exact child before applying an
        // independent retirement batch. If retirement or guest copyback then
        // fails, the cached result can retry against the same registered
        // claim without allocating or initializing the child a second time.
        if let (
            Some(MdiOutputPlan::Create(plan)),
            crate::Win16HostMdiOutput::Created {
                child: Some(native),
                fields,
            },
        ) = (output.as_ref(), &result.output)
        {
            let guest_child = self.finish_mdi_child_creation(plan, *native)?;
            if enclosing_has_effects {
                self.retire_prevalidated_window_claims(retirement_claims)?;
                if let Some(batch) = enclosing_retirements {
                    self.guest_menus.invalidate(&batch.invalidated_menus);
                }
            }
            plan.commit(self, memory, *fields)?;
            return Ok(u32::from(guest_child));
        }

        if enclosing_has_effects {
            self.retire_prevalidated_window_claims(retirement_claims)?;
            if let Some(batch) = enclosing_retirements {
                self.guest_menus.invalidate(&batch.invalidated_menus);
            }
        }

        match (output, result.output) {
            (
                Some(MdiOutputPlan::Create(output)),
                crate::Win16HostMdiOutput::Created {
                    child: None,
                    fields,
                },
            ) => {
                if output.creation != output.mdi.creation {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "WM_MDICREATE output plan lost its shared creation identity",
                    ));
                }
                self.retire_mdi_creation_claims(output.creation)?;
                output.commit(self, memory, fields)?;
                Ok(0)
            }
            (
                Some(MdiOutputPlan::Create(_)),
                crate::Win16HostMdiOutput::Created {
                    child: Some(_), ..
                },
            ) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "successful MDI child completion bypassed its validated claim path",
            )),
            (Some(MdiOutputPlan::Destroy(_)), crate::Win16HostMdiOutput::Destroyed { .. }) => {
                Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "validated MDI retirement result reached scalar projection twice",
                ))
            }
            (Some(MdiOutputPlan::Destroy(_)), crate::Win16HostMdiOutput::None) => Ok(result.value),
            (None, crate::Win16HostMdiOutput::Active { maximized, .. }) => {
                let guest_child = active_guest_child.unwrap_or(0);
                Ok(u32::from(guest_child) | (u32::from(maximized) << 16))
            }
            (None, crate::Win16HostMdiOutput::ReplacedFrameMenu(menu)) => {
                let guest_menu = menu
                    .map(|menu| {
                        self.guest_menus.intern(menu).ok_or_else(|| {
                            RuntimeError::new(
                                Kind::ResourceExhausted,
                                "Win16 guest HMENU namespace is full for WM_MDISETMENU result",
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(0);
                Ok(u32::from(guest_menu))
            }
            (None, crate::Win16HostMdiOutput::None) => Ok(result.value),
            (Some(_), _) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 MDI output plan does not match the typed host result",
            )),
            (None, crate::Win16HostMdiOutput::Destroyed { .. }) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host MDI retirement result has no exact WM_MDIDESTROY plan",
            )),
            (None, crate::Win16HostMdiOutput::Created { .. }) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host MDI create result has no captured MDICREATESTRUCT16 output plan",
            )),
        }
    }

    fn validate_mdi_result_before_retirement(
        &self,
        plan: Option<&MdiOutputPlan>,
        result: &crate::Win16HostMdiOutput,
        retirement_batch: Option<&crate::Win16HostWindowRetirementBatch>,
        retirement_claims: &[u16],
    ) -> Result<Option<u16>, RuntimeError> {
        let has_retirement_effects = retirement_batch.is_some_and(|batch| {
            !batch.receipts.is_empty() || !batch.invalidated_menus.is_empty()
        });
        match (plan, result) {
            (
                Some(MdiOutputPlan::Create(plan)),
                crate::Win16HostMdiOutput::Created { child, .. },
            ) => {
                if plan.creation != plan.mdi.creation {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "WM_MDICREATE output plan lost its shared creation identity",
                    ));
                }
                if let Some(native) = child {
                    self.validate_mdi_created_child_before_retirement(
                        plan,
                        *native,
                        retirement_batch,
                        retirement_claims,
                    )?;
                }
                Ok(None)
            }
            (Some(MdiOutputPlan::Destroy(plan)), crate::Win16HostMdiOutput::None) => {
                if has_retirement_effects {
                    self.validate_mdi_child_retirement_plan(*plan, None, &[])?;
                }
                Ok(None)
            }
            (None, crate::Win16HostMdiOutput::Active { child, .. }) => {
                let Some(native) = child else {
                    return Ok(None);
                };
                let guest = self
                    .existing_mdi_child_guest_handle(*native)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "host MDI active result is not a live runtime-claimed MDI child",
                        )
                    })?;
                if self.retirement_claims_guest_tree(guest, retirement_claims)? {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "MDI active child is also covered by the native retirement batch",
                    ));
                }
                Ok(Some(guest))
            }
            (None, crate::Win16HostMdiOutput::ReplacedFrameMenu(menu)) => {
                if let Some(menu) = menu
                    && retirement_batch.is_some_and(|batch| {
                        batch.invalidated_menus.contains(menu)
                    })
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "MDI returned a frame menu that the same batch marks invalid",
                    ));
                }
                Ok(None)
            }
            (None, crate::Win16HostMdiOutput::None) => Ok(None),
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 MDI output plan does not match the typed host result",
            )),
        }
    }

    fn validate_mdi_created_child_claim(
        &self,
        plan: &MdiCreateOutputPlan,
        native: Win16HostWindow,
    ) -> Result<Option<u16>, RuntimeError> {
        if native == plan.mdi_client_native
            || self.window_handles.get(&plan.mdi_client_guest) != Some(&plan.mdi_client_native)
            || self.window_system_classes.get(&plan.mdi_client_guest)
                != Some(&Win16HostSystemClass::MdiClient)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MDI child result does not preserve its exact live MDI client identity",
            ));
        }

        let mut matching_guest = None;
        for (&guest, &mapped_native) in &self.window_handles {
            if mapped_native == native && matching_guest.replace(guest).is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MDI child has multiple live Win16 HWND aliases",
                ));
            }
        }

        if self.window_creations.iter().any(|(&guest, &creation)| {
            creation == plan.creation && Some(guest) != matching_guest
        }) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MDI child creation identity is already attached to a different guest HWND",
            ));
        }

        let Some(guest) = matching_guest else {
            if plan.child_procedure == 0 && plan.system_kind.is_some() {
                return Ok(None);
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "successful guest-class MDI creation has no exact child callback claim",
            ));
        };

        let procedure_matches = if plan.child_procedure == 0 && plan.system_kind.is_some() {
            // Predefined native system children do not enter a guest WndProc.
            // Their exact claim is represented by an absent procedure entry.
            !self.window_procedures.contains_key(&guest)
        } else {
            self.window_procedures.get(&guest).copied()
                == Some(WindowProcedure {
                    class: plan.mdi.class,
                    address: plan.child_procedure,
                    instance: plan.child_instance,
                })
        };
        if !self.mdi_children.contains(&guest)
            || self.window_creations.get(&guest) != Some(&plan.creation)
            || self.window_parents.get(&guest).copied() != Some(plan.mdi_client_guest)
            || self.window_system_classes.get(&guest) != plan.system_kind.as_ref()
            || !procedure_matches
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "successful WM_MDICREATE child does not match its exact runtime claim",
            ));
        }
        Ok(Some(guest))
    }

    fn validate_mdi_created_child_before_retirement(
        &self,
        plan: &MdiCreateOutputPlan,
        native: Win16HostWindow,
        retirement_batch: Option<&crate::Win16HostWindowRetirementBatch>,
        retirement_claims: &[u16],
    ) -> Result<(), RuntimeError> {
        let guest = self.validate_mdi_created_child_claim(plan, native)?;
        if let Some(batch) = retirement_batch {
            if batch.receipts.iter().any(|receipt| receipt.window == native) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "newly created MDI child is also named by the retirement batch",
                ));
            }
            let client_retired =
                self.retirement_claims_guest_tree(plan.mdi_client_guest, retirement_claims)?;
            let child_retired = match guest {
                Some(guest) => self.retirement_claims_guest_tree(guest, retirement_claims)?,
                None => false,
            };
            if client_retired || child_retired {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "newly created MDI child or its ancestor is covered by the retirement batch",
                ));
            }
        }
        Ok(())
    }

    fn retirement_claims_guest_tree(
        &self,
        guest: u16,
        retirement_claims: &[u16],
    ) -> Result<bool, RuntimeError> {
        let mut current = Some(guest);
        let mut remaining = self.window_parents.len().saturating_add(1);
        while let Some(window) = current {
            if retirement_claims.contains(&window) {
                return Ok(true);
            }
            if remaining == 0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "runtime window parent ledger contains a cycle",
                ));
            }
            remaining -= 1;
            current = self.window_parents.get(&window).copied();
        }
        Ok(false)
    }

    fn validate_mdi_child_retirement_plan(
        &self,
        expected: MdiChildRetirementPlan,
        receipt: Option<crate::Win16HostWindowRetirementReceipt>,
        additional_retirements: &[crate::Win16HostWindowRetirementReceipt],
    ) -> Result<(), RuntimeError> {
        if receipt.is_some_and(|receipt| receipt.window != expected.native) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host MDI retirement receipt does not match the exact WM_MDIDESTROY target",
            ));
        }
        if additional_retirements
            .iter()
            .any(|receipt| receipt.window == expected.native)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MDI additional retirement list contains its root window",
            ));
        }

        if self
            .window_creations
            .iter()
            .any(|(&guest, &creation)| creation == expected.creation && guest != expected.guest)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MDI destroy creation identity is attached to a different guest HWND",
            ));
        }

        match self.window_handles.get(&expected.guest).copied() {
            // A reused guest HWND slot now refers to another never-reused
            // native token. Receipts for the captured incarnation are stale.
            Some(native) if native != expected.native => {
                if self.window_creations.get(&expected.guest) == Some(&expected.creation) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "MDI destroy creation identity maps to a different host window",
                    ));
                }
                Ok(())
            }
            Some(_) => {
                if self.window_creations.get(&expected.guest) != Some(&expected.creation)
                    || !self.mdi_children.contains(&expected.guest)
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "live MDI destroy target does not match its captured creation identity",
                    ));
                }
                Ok(())
            }
            None => {
                if self.window_creations.contains_key(&expected.guest)
                    || self.mdi_children.contains(&expected.guest)
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired MDI destroy target retains partial runtime identity state",
                    ));
                }
                // WM_NCDESTROY or an earlier exact retirement already removed
                // this incarnation, or the guest handle has since been reused.
                Ok(())
            }
        }
    }

    fn retire_mdi_creation_claims(
        &mut self,
        creation: Win16CreationId,
    ) -> Result<(), RuntimeError> {
        let claims: Vec<u16> = self
            .window_creations
            .iter()
            .filter_map(|(&guest, &candidate)| {
                (candidate == creation && self.mdi_children.contains(&guest)).then_some(guest)
            })
            .collect();
        for guest in claims {
            self.retire_window_tree(guest)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn retire_window_retirement_batch(
        &mut self,
        batch: &crate::Win16HostWindowRetirementBatch,
    ) -> Result<(), RuntimeError> {
        let claims = self.prevalidate_window_retirement_batch(&batch.receipts)?;
        self.retire_prevalidated_window_claims(claims)?;
        self.guest_menus.invalidate(&batch.invalidated_menus);
        Ok(())
    }

    fn prevalidate_window_retirement_batch(
        &self,
        receipts: &[crate::Win16HostWindowRetirementReceipt],
    ) -> Result<Vec<u16>, RuntimeError> {
        let mut tokens = Vec::new();
        tokens.try_reserve_exact(receipts.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact native window tokens for retirement validation",
                error,
            )
        })?;
        tokens.extend(receipts.iter().map(|receipt| receipt.window));
        tokens.sort_unstable();
        if tokens.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native message returned a duplicate window retirement token",
            ));
        }

        let mut claims = Vec::new();
        claims.try_reserve_exact(self.window_handles.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact guest HWND aliases for native retirement tokens",
                error,
            )
        })?;
        for receipt in receipts {
            for (&guest, &window) in &self.window_handles {
                if window == receipt.window {
                    claims.push(guest);
                }
            }
        }
        Ok(claims)
    }

    fn retire_prevalidated_window_claims(&mut self, claims: Vec<u16>) -> Result<(), RuntimeError> {
        // Every token and alias in the full batch was validated before any
        // tree retirement. Parent receipts may retire later descendants first.
        for guest in claims {
            self.retire_window_tree(guest)?;
        }
        Ok(())
    }

    fn finish_mdi_child_creation(
        &mut self,
        plan: &MdiCreateOutputPlan,
        native: Win16HostWindow,
    ) -> Result<u16, RuntimeError> {
        if let Some(guest) = self.validate_mdi_created_child_claim(plan, native)? {
            return Ok(guest);
        }

        let system_kind = plan.system_kind.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "callback-free MDI child has no native system class identity",
            )
        })?;
        let guest = self.allocate_window_handle(native).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 window handle table is full while claiming native MDI child",
            )
        })?;
        self.window_system_classes.insert(guest, system_kind);
        if let Err(error) = self.initialize_window_data(
            guest,
            Some(plan.mdi.class),
            plan.child_instance,
            false,
            self.window_classes.window_extra_bytes(plan.mdi.class),
        ) {
            return Err(self.cleanup_failed_mdi_child_claim(guest, error, false));
        }
        if let Err(error) = self.link_window_parent(guest, plan.mdi_client_guest) {
            return Err(self.cleanup_failed_mdi_child_claim(guest, error, false));
        }
        if let Err(error) = self.associate_window_creation(guest, native, plan.creation) {
            return Err(self.cleanup_failed_mdi_child_claim(guest, error, true));
        }
        self.mdi_children.insert(guest);
        Ok(guest)
    }

    fn cleanup_failed_mdi_child_claim(
        &mut self,
        guest: u16,
        error: RuntimeError,
        tree: bool,
    ) -> RuntimeError {
        let cleanup = if tree {
            self.retire_window_tree(guest)
        } else {
            self.retire_window_handle(guest)
        };
        match cleanup {
            Ok(()) => error,
            Err(cleanup_error) => RuntimeError::with_source(
                Kind::InternalInvariant,
                "native MDI child registration failed and guest HWND cleanup also failed",
                cleanup_error,
            ),
        }
    }

}
