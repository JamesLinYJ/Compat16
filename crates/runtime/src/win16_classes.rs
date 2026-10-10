//! Guest USER window classes and their Win16 identities.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16ClassName, Win16ResourceName, WndClass16, wndclass16_offsets};

use super::Win16State;
use super::module_registry::ModuleState;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16ClassBackground, Win16HostClass, Win16HostClassSpec, Win16HostSystemClass,
};

// RegisterClassA accepts at most 255 class-name characters plus the terminator.
const MAX_CLASS_NAME_BYTES: usize = 255;
// Win32's COLOR_MENUBAR is the last documented system-color index accepted
// for a class background; Win16 passes COLOR_* + 1 as an HBRUSH value.
const LAST_SYSTEM_COLOR_INDEX: u16 = 30;

#[path = "win16_unregister_class.rs"]
mod unregister;

struct GuestWindowClass {
    instance: u16,
    atom: u16,
    source_name_atom: Option<u16>,
    name: Vec<u8>,
    host_class: Win16HostClass,
    lower_name: Option<Vec<u8>>,
    info: WndClass16,
    menu_name: Option<Win16ResourceName>,
    /// Guest cbClsExtra bytes belong to this registration, not its HWNDs.
    /// They never alias native superclass/private class storage.
    extra_bytes: Vec<u8>,
}

pub(super) struct ResolvedWindowClass {
    pub host_class: Win16HostClass,
    pub system_kind: Option<Win16HostSystemClass>,
    pub wnd_proc: u32,
    pub has_menu_resource: bool,
    pub instance: u16,
    pub window_extra_bytes: usize,
}

pub(super) struct GuestWindowClasses {
    entries: Vec<GuestWindowClass>,
    system_classes: Vec<CachedSystemClass>,
}

struct CachedSystemClass {
    kind: Win16HostSystemClass,
    host_class: Win16HostClass,
    metadata: crate::Win16HostSystemClassInfo,
    guest_info: Option<WndClass16>,
}

/// Read-only guest-facing identity for TOOLHELP class enumeration.
///
/// The projection deliberately omits the native class token, cached lookup
/// key, and callback/resource bookkeeping. `name` borrows the original
/// Win16 class-name bytes for the duration of the iterator item.
pub(super) struct GuestWindowClassEntry<'a> {
    pub instance: u16,
    pub atom: u16,
    pub name: &'a [u8],
}

impl GuestWindowClasses {
    pub(super) fn new() -> Self {
        Self { entries: Vec::new(), system_classes: Vec::new() }
    }

    /// Iterate registered guest classes in registration order without
    /// exposing the registry's mutable storage or native host identities.
    pub(super) fn entries(&self) -> impl Iterator<Item = GuestWindowClassEntry<'_>> {
        self.entries.iter().map(|entry| GuestWindowClassEntry {
            instance: entry.instance,
            atom: entry.atom,
            name: entry.name.as_slice(),
        })
    }

    pub(super) fn class_name_for_host_class(&self, host_class: Win16HostClass) -> Option<&[u8]> {
        if let Some(entry) = self.entries.iter().find(|entry| entry.host_class == host_class) {
            return Some(entry.name.as_slice());
        }
        // Predefined aliases have no GuestWindowClass entry, but GetClassName
        // still needs to project the guest-visible system class names.
        let cached = self.system_classes.iter().find(|entry| entry.host_class == host_class)?;
        Some(system_class_name(cached.kind))
    }

    pub(super) fn window_extra_bytes(&self, host_class: Win16HostClass) -> Option<usize> {
        if let Some(entry) = self.entries.iter().find(|entry| entry.host_class == host_class) {
            return usize::try_from(entry.info.cb_wnd_extra).ok();
        }
        let entry = self.system_classes.iter().find(|entry| entry.host_class == host_class)?;
        usize::try_from(entry.metadata.spec.window_extra).ok()
    }

    /// Only guest registrations have a Win16 class-data layout. Predefined
    /// aliases must not expose the native class's private extra bytes.
    pub(super) fn guest_class_extra_mut(
        &mut self,
        host_class: Win16HostClass,
    ) -> Option<&mut [u8]> {
        Some(self.entries.iter_mut().find(|entry| entry.host_class == host_class)?
            .extra_bytes.as_mut_slice())
    }

    /// Return copied guest metadata and the actual registration atom. The
    /// source name atom can differ, and neither atom is a native pointer.
    pub(super) fn guest_class_info(
        &self,
        host_class: Win16HostClass,
    ) -> Option<(u16, WndClass16)> {
        let entry = self.entries.iter().find(|entry| entry.host_class == host_class)?;
        Some((entry.atom, entry.info))
    }

    /// Resolve only class aliases backed by an exact predefined system class.
    /// Guest-registered classes, even when their names resemble system names,
    /// deliberately return `None`.
    pub(super) fn system_kind_for_host_class(
        &self,
        host_class: Win16HostClass,
    ) -> Option<Win16HostSystemClass> {
        self.system_classes.iter()
            .find(|entry| entry.host_class == host_class)
            .map(|entry| entry.kind)
    }

    pub(super) fn resolve_registered_host_class(
        &self,
        host_class: Win16HostClass,
    ) -> Option<ResolvedWindowClass> {
        let entry = self.entries.iter().find(|entry| entry.host_class == host_class)?;
        Some(ResolvedWindowClass {
            host_class,
            system_kind: None,
            wnd_proc: entry.info.lpfn_wnd_proc,
            has_menu_resource: entry.menu_name.is_some(),
            instance: entry.instance,
            window_extra_bytes: usize::try_from(entry.info.cb_wnd_extra).ok()?,
        })
    }

    /// Resolve a global USER class selector across every loaded guest module.
    /// FindWindow is process-wide and must not be scoped to the main module.
    pub(super) fn host_class_for_name(
        &self,
        name: &Win16ClassName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16HostClass>, RuntimeError> {
        let lower = match name {
            Win16ClassName::Name(bytes) => Some(host.win16_ansi_lower_string(bytes)?),
            Win16ClassName::Atom(_) => None,
        };
        Ok(self.entries.iter().find(|entry| match name {
            Win16ClassName::Atom(atom) => entry.atom == *atom
                || entry.source_name_atom == Some(*atom),
            Win16ClassName::Name(_) => entry.lower_name.as_deref() == lower.as_deref(),
        }).map(|entry| entry.host_class))
    }

    pub(super) fn menu_resource_for_host_class(
        &self,
        host_class: Win16HostClass,
    ) -> Option<Win16ResourceName> {
        self.entries
            .iter()
            .find(|entry| entry.host_class == host_class)?
            .menu_name
            .clone()
    }
}

impl Win16State {
    /// Resolve an instance or module handle to the owning loaded module.
    /// A null instance selects the task's main module for APIs that permit it.
    pub(super) fn module_handle_for_instance(&self, instance: u16) -> Option<u16> {
        let handle = if instance == 0 {
            self.modules.main
        } else {
            self.modules.by_handle(instance)?
        };
        self.modules.records.get(&handle)
            .filter(|record| record.external_application.is_none()
                && !matches!(record.state, ModuleState::Unloading | ModuleState::Retired))
            .map(|record| record.handle)
    }

    fn class_instance(&self, instance: u16) -> Option<u16> {
        let handle = self.module_handle_for_instance(instance)?;
        self.modules.records.get(&handle).map(|record| record.instance)
    }

    pub(super) fn get_class_info(
        &mut self,
        instance: u16,
        name: Win16ClassName,
        output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let owner = (instance != 0).then(|| self.class_instance(instance)).flatten();
        let lower_name = match &name {
            Win16ClassName::Name(bytes) => Some(host.win16_ansi_lower_string(bytes)?),
            Win16ClassName::Atom(_) => None,
        };
        let registered = self.window_classes.entries.iter().find(|entry| {
            Some(entry.instance) == owner && match &name {
                Win16ClassName::Atom(atom) => *atom == entry.atom
                    || entry.source_name_atom == Some(*atom),
                Win16ClassName::Name(_) => entry.lower_name.as_ref() == lower_name.as_ref(),
            }
        }).map(|entry| entry.info);
        let info = if let Some(info) = registered { info } else {
            let Win16ClassName::Name(bytes) = &name else { return Ok(0); };
            let Some(kind) = system_control_class(bytes) else { return Ok(0); };
            let Some(info) = self.system_class_guest_info(kind, memory, host)? else { return Ok(0); };
            info
        };

        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        // Windows 3.1 SDK Volume 2, GetClassInfo, pp. 333–334: hInstance
        // is returned starting with 3.1; only the two name pointers remain
        // untouched. Use the runtime's reported ABI version for this rule.
        self.selectors.translate(pointer, Access::Write, WndClass16::SIZE, memory)
            .map_err(crate::runtime_error)?;
        let encoded = info.encode();
        let prefix_end = if win16_abi::version::WINDOWS_COMPATIBILITY_PROFILE
            .win31_check_word() >= 0x030a
        {
            wndclass16_offsets::H_ICON
        } else {
            wndclass16_offsets::H_INSTANCE
        };
        self.selectors.write(memory, pointer, &encoded[..prefix_end])
            .map_err(crate::runtime_error)?;
        let resources = self.selectors.add_bytes(pointer, wndclass16_offsets::H_ICON as u32)
            .map_err(crate::runtime_error)?;
        self.selectors.write(memory, resources,
            &encoded[wndclass16_offsets::H_ICON..wndclass16_offsets::LPSZ_MENU_NAME])
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn register_class(
        &mut self,
        info: WndClass16,
        name: Win16ClassName,
        menu_name: Option<Win16ResourceName>,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(owner) = self.class_instance(info.h_instance) else { return Ok(0) };
        if info.cb_cls_extra < 0 || info.cb_wnd_extra < 0 { return Ok(0); }
        if info.lpfn_wnd_proc == 0 { return Ok(0); }
        let Ok(procedure) = self.selectors.pointer_from_far(info.lpfn_wnd_proc) else {
            return Ok(0);
        };
        if self.selectors.translate(procedure, Access::Execute, 1, memory).is_err() {
            return Ok(0);
        }
        let (source_name_atom, class_name) = match name {
            Win16ClassName::Name(bytes) => (None, bytes),
            Win16ClassName::Atom(atom) => {
                if atom == 0 { return Ok(0); }
                let (bytes, copied) = host.win16_global_get_atom_name(atom, 256)?;
                if copied == 0 { return Ok(0); }
                let prefix = bytes.get(..usize::from(copied)).ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "host atom name count exceeds its copied bytes"))?;
                (Some(atom), prefix.to_vec())
            }
        };
        if class_name.is_empty() || class_name.len() > MAX_CLASS_NAME_BYTES {
            return Ok(0);
        }
        let lower_name = Some(host.win16_ansi_lower_string(&class_name)?);
        if self.window_classes.entries.iter().any(|entry| {
            entry.instance == owner && (entry.lower_name.as_ref() == lower_name.as_ref()
                || source_name_atom.is_some() && entry.source_name_atom == source_name_atom)
        }) {
            return Ok(0);
        }
        self.window_classes.entries.try_reserve(1).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 window class registry cannot grow"))?;
        let icon = if info.h_icon == 0 { None } else {
            match self.guest_images.icon(info.h_icon) {
                Some(icon) => Some(icon),
                None => return Ok(0),
            }
        };
        let cursor = if info.h_cursor == 0 { None } else {
            match self.guest_images.cursor(info.h_cursor) {
                Some(cursor) => Some(cursor),
                None => return Ok(0),
            }
        };
        let background = if info.hbr_background == 0 { None }
        else if info.hbr_background <= LAST_SYSTEM_COLOR_INDEX + 1 {
            Some(Win16ClassBackground::SystemColor(info.hbr_background - 1))
        } else {
            match self.guest_gdi.object(info.hbr_background) {
                Some(brush) => Some(Win16ClassBackground::Brush(brush)),
                None => return Ok(0),
            }
        };
        // Reserve and zero guest-owned class bytes before native registration.
        // A failed allocation must not leave a native class without its guest
        // storage. Removing the acknowledged registration releases both.
        let extra_len = info.cb_cls_extra as usize; // nonnegative checked above
        let mut extra_bytes = Vec::new();
        extra_bytes.try_reserve_exact(extra_len).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 class extra-data storage cannot grow"))?;
        extra_bytes.resize(extra_len, 0);
        let Some(registered) = host.win16_register_window_class(Win16HostClassSpec {
            style: info.style,
            class_extra: info.cb_cls_extra,
            window_extra: info.cb_wnd_extra,
            icon,
            cursor,
            background,
            system_class: None,
        })? else { return Ok(0); };
        self.window_classes.entries.push(GuestWindowClass {
            instance: owner, atom: registered.atom,
            source_name_atom, name: class_name,
            host_class: registered.class,
            lower_name, info, menu_name, extra_bytes,
        });
        Ok(registered.atom)
    }

    pub(super) fn registered_class_name(&self, atom: u16) -> Option<&[u8]> {
        self.window_classes.entries.iter().find(|class| class.atom == atom)
            .map(|class| class.name.as_slice())
    }

    pub(super) fn is_registered_class_atom(&self, atom: u16) -> bool {
        self.window_classes.entries.iter().any(|class| class.atom == atom)
    }

    pub(super) fn registered_class_atom_by_lower_name(&self, lower: &[u8]) -> Option<u16> {
        self.window_classes.entries.iter()
            .find(|class| class.lower_name.as_deref() == Some(lower))
            .map(|class| class.atom)
    }

    pub(super) fn resolve_window_class(
        &self,
        instance: u16,
        name: &Win16ClassName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<ResolvedWindowClass>, RuntimeError> {
        let Some(owner) = self.class_instance(instance) else { return Ok(None); };
        let lower = match name {
            Win16ClassName::Name(bytes) => Some(host.win16_ansi_lower_string(bytes)?),
            Win16ClassName::Atom(_) => None,
        };
        let class = self.window_classes.entries.iter().find(|class| {
            class.instance == owner && match name {
                Win16ClassName::Atom(atom) => class.atom == *atom
                    || class.source_name_atom == Some(*atom),
                Win16ClassName::Name(_) => class.lower_name.as_ref() == lower.as_ref(),
            }
        });
        Ok(class.map(|class| ResolvedWindowClass {
            host_class: class.host_class,
            system_kind: None,
            wnd_proc: class.info.lpfn_wnd_proc,
            has_menu_resource: class.menu_name.is_some(),
            instance: owner,
            window_extra_bytes: usize::try_from(class.info.cb_wnd_extra).unwrap_or(0),
        }))
    }

    /// Resolve predefined controls through a native alias owned by USER.
    /// The alias is separate from guest registrations and has no guest WndProc.
    pub(super) fn resolve_window_class_for_create(
        &mut self,
        instance: u16,
        name: &Win16ClassName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<ResolvedWindowClass>, RuntimeError> {
        if let Some(class) = self.resolve_window_class(instance, name, host)? {
            return Ok(Some(class));
        }
        let Some(owner) = self.class_instance(instance) else { return Ok(None); };
        let Win16ClassName::Name(bytes) = name else { return Ok(None); };
        let Some(kind) = system_control_class(bytes) else { return Ok(None); };
        let Some(index) = self.ensure_system_class(kind, host)? else { return Ok(None); };
        let cached = &self.window_classes.system_classes[index];
        Ok(Some(ResolvedWindowClass {
            host_class: cached.host_class,
            system_kind: Some(kind),
            wnd_proc: 0,
            has_menu_resource: false,
            instance: owner,
            window_extra_bytes: usize::try_from(cached.metadata.spec.window_extra)
                .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                    "predefined class has negative guest extra-byte capacity"))?,
        }))
    }

    fn ensure_system_class(
        &mut self, kind: Win16HostSystemClass, host: &mut impl RuntimeHost,
    ) -> Result<Option<usize>, RuntimeError> {
        if let Some(index) = self.window_classes.system_classes.iter()
            .position(|entry| entry.kind == kind) { return Ok(Some(index)); }
        let Some(metadata) = host.win16_system_class_info(kind)? else { return Ok(None); };
        if metadata.spec.class_extra < 0 || metadata.spec.window_extra < 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "predefined class metadata has negative guest storage"));
        }
        self.window_classes.system_classes.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve predefined Win16 control-class aliases", error))?;
        let Some(registered) = host.win16_register_window_class(metadata.spec)? else { return Ok(None); };
        let index = self.window_classes.system_classes.len();
        self.window_classes.system_classes.push(CachedSystemClass {
            kind, host_class: registered.class, metadata, guest_info: None,
        });
        Ok(Some(index))
    }

    fn system_class_guest_info(
        &mut self, kind: Win16HostSystemClass, memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<WndClass16>, RuntimeError> {
        let Some(index) = self.ensure_system_class(kind, host)? else { return Ok(None); };
        if let Some(info) = self.window_classes.system_classes[index].guest_info {
            return Ok(Some(info));
        }
        let metadata = self.window_classes.system_classes[index].metadata;
        let spec = metadata.spec;
        let Some(user_module) = self.modules.by_name(b"USER") else { return Ok(None); };
        let Some(instance) = self.modules.records.get(&user_module).map(|record| record.instance)
            else { return Ok(None); };
        // The guest saves a checked executable gate, never a native WNDPROC.
        // Borrowed class images/brushes are mapped through existing tables.
        let procedure = self.native_procedure_gate(metadata.procedure, memory)?;
        if procedure == 0 { return Ok(None); }
        let icon = match spec.icon {
            Some(icon) => match self.guest_images.allocate_class_icon(icon) {
                Some(handle) => handle, None => return Ok(None),
            }, None => 0,
        };
        let cursor = match spec.cursor {
            Some(cursor) => match self.guest_images.allocate_class_cursor(cursor) {
                Some(handle) => handle, None => return Ok(None),
            }, None => 0,
        };
        let background = match spec.background {
            Some(Win16ClassBackground::SystemColor(color)) => color + 1,
            Some(Win16ClassBackground::Brush(brush)) => match self.guest_gdi.existing_object(brush)
                .or_else(|| self.guest_gdi.allocate_object(brush)) {
                Some(handle) => handle, None => return Ok(None),
            }, None => 0,
        };
        let info = WndClass16 {
            style: spec.style, lpfn_wnd_proc: procedure,
            cb_cls_extra: spec.class_extra, cb_wnd_extra: spec.window_extra,
            h_instance: instance, h_icon: icon, h_cursor: cursor, hbr_background: background,
            lpsz_menu_name: 0, lpsz_class_name: 0,
        };
        self.window_classes.system_classes[index].guest_info = Some(info);
        Ok(Some(info))
    }
    pub(super) fn class_code_references(&self) -> Vec<u32> {
        self.window_classes.entries.iter()
            .map(|class| class.info.lpfn_wnd_proc)
            .collect()
    }

    pub(super) fn class_owner_modules(&self) -> Vec<u16> {
        self.window_classes.entries.iter().filter_map(|class|
            self.modules.retained_owner(class.instance, &self.selectors)).collect()
    }

    pub(super) fn release_module_classes(
        &mut self,
        modules: &[u16],
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        for &module in modules {
            let Some(instance) = self.modules.records.get(&module)
                .map(|record| record.instance)
            else {
                continue;
            };
            for index in (0..self.window_classes.entries.len()).rev() {
                let class = &self.window_classes.entries[index];
                if class.instance != instance {
                    continue;
                }
                if host.win16_unregister_window_class(class.host_class)? {
                    self.window_classes.entries.remove(index);
                } else {
                    // Keep the registered class and its WndProc as a code root
                    // while native windows still depend on it.
                }
            }
        }
        Ok(())
    }

    pub(super) fn close_classes(&mut self, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        for index in (0..self.window_classes.entries.len()).rev() {
            let class = &self.window_classes.entries[index];
            if !host.win16_unregister_window_class(class.host_class)? {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native Win16 window class could not be unregistered"));
            }
            // Keep failed registrations as live code roots. A later cleanup
            // attempt must retry the native operation, not see an empty table.
            self.window_classes.entries.remove(index);
        }
        for index in (0..self.window_classes.system_classes.len()).rev() {
            let class = self.window_classes.system_classes[index].host_class;
            if !host.win16_unregister_window_class(class)? {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "predefined Win16 control-class alias could not be retired"));
            }
            self.window_classes.system_classes.remove(index);
        }
        Ok(())
    }
}

fn system_control_class(name: &[u8]) -> Option<Win16HostSystemClass> {
    if name.eq_ignore_ascii_case(b"BUTTON") { Some(Win16HostSystemClass::Button) }
    else if name.eq_ignore_ascii_case(b"EDIT") { Some(Win16HostSystemClass::Edit) }
    else if name.eq_ignore_ascii_case(b"STATIC") { Some(Win16HostSystemClass::Static) }
    else if name.eq_ignore_ascii_case(b"LISTBOX") { Some(Win16HostSystemClass::ListBox) }
    else if name.eq_ignore_ascii_case(b"COMBOBOX") { Some(Win16HostSystemClass::ComboBox) }
    else if name.eq_ignore_ascii_case(b"SCROLLBAR") { Some(Win16HostSystemClass::ScrollBar) }
    else if name.eq_ignore_ascii_case(b"MDICLIENT") { Some(Win16HostSystemClass::MdiClient) }
    else { None }
}

fn system_class_name(kind: Win16HostSystemClass) -> &'static [u8] {
    match kind {
        Win16HostSystemClass::Button => b"BUTTON",
        Win16HostSystemClass::Edit => b"EDIT",
        Win16HostSystemClass::Static => b"STATIC",
        Win16HostSystemClass::ListBox => b"LISTBOX",
        Win16HostSystemClass::ComboBox => b"COMBOBOX",
        Win16HostSystemClass::ScrollBar => b"SCROLLBAR",
        Win16HostSystemClass::MdiClient => b"MDICLIENT",
    }
}
