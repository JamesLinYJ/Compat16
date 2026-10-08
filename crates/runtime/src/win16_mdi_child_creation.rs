//! Win16 CREATESTRUCT16 marshalling for a child created by native WM_MDICREATE.
//!
//! The callback owns one temporary guest block containing CREATESTRUCT16,
//! MDICREATESTRUCT16, and any class/title strings. Its lpCreateParams points to
//! the nested MDI record in that same selector lease; the original guest owner
//! and application parameter remain guest values.

use guest_core::memory::Memory;
use win16_abi::CreateStruct16;

use super::{Win16State, window_payloads::GuestWindowPayload};
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostClassName, Win16HostMdiChildCreation,
    Win16HostSystemClass,
};

const WM_CREATE16: u16 = 0x0001;
const WM_NCCREATE16: u16 = 0x0081;
const WS_EX_MDICHILD: u32 = 0x0000_0040;

impl Win16State {
    /// Build the Win16 child-creation callback payload while its exact callback
    /// frame is Preparing. `allocate_window_payload` retains the allocation and
    /// selector lease there; callback lifecycle cleanup owns all error paths.
    pub(in crate::win16_runtime) fn prepare_mdi_child_creation_payload(
        &mut self,
        non_client: bool,
        data: &Win16HostMdiChildCreation,
        memory: &mut Memory,
    ) -> Result<GuestWindowPayload, RuntimeError> {
        if self.preparing_window_callback_id().is_none() {
            return Err(mdi_payload_error(
                Kind::InternalInvariant,
                "Win16 MDI child creation payload has no Preparing callback owner",
            ));
        }
        validate_creation(data)?;
        let parent = data.creation.parent.ok_or_else(|| {
            mdi_payload_error(
                Kind::InvalidInput,
                "Win16 MDI child has no MDI client parent",
            )
        })?;
        let parent_guest = guest_mdi_client_handle(self, parent)?;

        let class_bytes = match &data.mdi.guest_class_name {
            Win16HostClassName::Name(bytes) => Some(terminated_bytes(bytes, "class name", false)?),
            Win16HostClassName::Atom(atom) if *atom != 0 => None,
            Win16HostClassName::Atom(_) => {
                return Err(mdi_payload_error(
                    Kind::InvalidInput,
                    "Win16 MDI child class atom is zero",
                ));
            }
        };
        let title_bytes = data
            .mdi
            .title
            .as_deref()
            .map(|bytes| terminated_bytes(bytes, "title", true))
            .transpose()?;

        let class_offset = CreateStruct16::SIZE
            .checked_add(super::messages_mdi::MDICREATESTRUCT16_SIZE)
            .ok_or_else(|| {
                mdi_payload_error(
                    Kind::ResourceExhausted,
                    "Win16 MDI child payload offset overflow",
                )
            })?;
        let title_offset = class_offset
            .checked_add(class_bytes.as_ref().map_or(0, Vec::len))
            .ok_or_else(|| {
                mdi_payload_error(
                    Kind::ResourceExhausted,
                    "Win16 MDI child title offset overflow",
                )
            })?;
        let allocation_size = title_offset
            .checked_add(title_bytes.as_ref().map_or(0, Vec::len))
            .filter(|size| *size <= usize::from(u16::MAX))
            .ok_or_else(|| {
                mdi_payload_error(
                    Kind::ResourceExhausted,
                    "Win16 MDI child payload exceeds one guest segment",
                )
            })?;

        // Allocate all ordinary host bytes before the guest owner is installed.
        // After allocate_window_payload succeeds, the callback frame owns every
        // resource, including any later selector/write error.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(allocation_size).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate the Win16 MDI child callback bytes",
                error,
            )
        })?;
        bytes.resize(allocation_size, 0);

        let (allocation, base) = self.allocate_window_payload(memory, allocation_size)?;
        let mdi_far = checked_far(self, base, CreateStruct16::SIZE)?;
        let class_far = match (&data.mdi.guest_class_name, class_bytes.as_ref()) {
            (Win16HostClassName::Atom(atom), None) => u32::from(*atom),
            (Win16HostClassName::Name(_), Some(_)) => checked_far(self, base, class_offset)?,
            _ => {
                return Err(mdi_payload_error(
                    Kind::InternalInvariant,
                    "Win16 MDI class storage does not match its class kind",
                ));
            }
        };
        let title_far = match title_bytes.as_ref() {
            Some(_) => checked_far(self, base, title_offset)?,
            None => 0,
        };

        let outer = CreateStruct16 {
            lp_create_params: mdi_far,
            h_instance: data.mdi.owner_instance,
            h_menu: data.creation.guest_menu,
            hwnd_parent: parent_guest,
            cy: data.creation.height,
            cx: data.creation.width,
            y: data.creation.y,
            x: data.creation.x,
            style: data.creation.style,
            lpsz_name: title_far,
            lpsz_class: class_far,
            dw_ex_style: data.creation.ex_style,
        };
        bytes[..CreateStruct16::SIZE].copy_from_slice(&outer.encode());
        let mdi_wire = super::messages_mdi::encode_mdi_create_wire(&data.mdi, class_far, title_far);
        bytes[CreateStruct16::SIZE..class_offset].copy_from_slice(&mdi_wire);
        if let Some(class) = class_bytes.as_ref() {
            bytes[class_offset..class_offset + class.len()].copy_from_slice(class);
        }
        if let Some(title) = title_bytes.as_ref() {
            bytes[title_offset..title_offset + title.len()].copy_from_slice(title);
        }
        self.selectors
            .write(memory, base, &bytes)
            .map_err(crate::runtime_error)?;

        Ok(GuestWindowPayload {
            message: if non_client {
                WM_NCCREATE16
            } else {
                WM_CREATE16
            },
            w_param: 0,
            l_param: base.far_value(),
            allocation: Some(allocation),
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        })
    }
}

fn validate_creation(data: &Win16HostMdiChildCreation) -> Result<(), RuntimeError> {
    let creation = &data.creation;
    let mdi = &data.mdi;
    if creation.class != mdi.class
        || creation.guest_instance != mdi.owner_instance
        || creation.guest_class_name != mdi.guest_class_name
        || creation.title != mdi.title
        || creation.create_parameter != mdi.parameter
        || creation.child_id != Some(creation.guest_menu)
        || creation.creation_data.is_some()
        || creation.mdi_client.is_some()
        || creation.dialog_root
        || creation.class_menu_template.is_some()
        || creation.menu.is_some()
        || creation.ex_style & WS_EX_MDICHILD == 0
    {
        return Err(mdi_payload_error(
            Kind::InvalidInput,
            "Win16 MDI child creation fields do not match their exact MDI request",
        ));
    }
    Ok(())
}

fn guest_mdi_client_handle(
    state: &Win16State,
    parent: crate::Win16HostWindow,
) -> Result<u16, RuntimeError> {
    let mut found = None;
    for (&guest, &native) in &state.window_handles {
        if native != parent
            || state.window_system_classes.get(&guest) != Some(&Win16HostSystemClass::MdiClient)
        {
            continue;
        }
        if found.replace(guest).is_some() {
            return Err(mdi_payload_error(
                Kind::InternalInvariant,
                "Win16 MDI client identity has multiple guest HWND aliases",
            ));
        }
    }
    found.ok_or_else(|| {
        mdi_payload_error(
            Kind::InvalidInput,
            "Win16 MDI child parent is not a mapped MDI client",
        )
    })
}

fn terminated_bytes(
    source: &[u8],
    what: &'static str,
    allow_empty: bool,
) -> Result<Vec<u8>, RuntimeError> {
    if (!allow_empty && source.is_empty()) || source.contains(&0) {
        return Err(mdi_payload_error(
            Kind::InvalidInput,
            format!("Win16 MDI child {what} is empty or contains an embedded NUL"),
        ));
    }
    let capacity = source.len().checked_add(1).ok_or_else(|| {
        mdi_payload_error(
            Kind::ResourceExhausted,
            format!("Win16 MDI child {what} size overflow"),
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            format!("allocate Win16 MDI child {what}"),
            error,
        )
    })?;
    bytes.extend_from_slice(source);
    bytes.push(0);
    Ok(bytes)
}

fn checked_far(
    state: &Win16State,
    base: win16_abi::SegmentedPointer,
    offset: usize,
) -> Result<u32, RuntimeError> {
    let offset = u32::try_from(offset).map_err(|_| {
        mdi_payload_error(
            Kind::ResourceExhausted,
            "Win16 MDI child selector offset is not representable",
        )
    })?;
    state
        .selectors
        .add_bytes(base, offset)
        .map(|pointer| pointer.far_value())
        .map_err(crate::runtime_error)
}

fn mdi_payload_error(kind: Kind, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(kind, message)
}
