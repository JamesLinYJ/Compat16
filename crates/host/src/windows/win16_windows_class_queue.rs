//! USER class registration and native task-queue bindings.

use std::sync::atomic::{AtomicU64, Ordering};

use runtime::{
    Win16ClassBackground, Win16HostClass, Win16HostClassSpec, Win16HostCursor, Win16HostIcon,
    Win16HostTaskQueue, Win16RegisteredClass,
};

use super::*;
use crate::windows::win16_gdi_objects::NativeClassBackground;

#[cfg(test)]
#[path = "win16_class_resource_resolver_tests.rs"]
mod class_resource_resolver_tests;

static NEXT_CLASS_ID: AtomicU64 = AtomicU64::new(1);

impl Win16Windows {
    pub(in crate::windows) fn window_enumeration(
        &mut self, query: runtime::Win16WindowEnumerationQuery,
    ) -> Result<runtime::Win16WindowEnumerationReply, RuntimeError> {
        let (response, result) = std::sync::mpsc::channel();
        self.send(WorkerCommand::WindowEnumeration { query, response })?;
        result.recv().map_err(|_| worker_stopped("enumerate native USER windows"))?
    }
    pub(in crate::windows) fn control_identity(
        &mut self, query: runtime::Win16HostControlQuery,
    ) -> Result<runtime::Win16HostControlQueryReply, RuntimeError> {
        let (response, result) = std::sync::mpsc::channel();
        self.send(WorkerCommand::QueryControlIdentity { query, response })?;
        result.recv().map_err(|_| worker_stopped("query native control identity"))?
    }
    pub(in crate::windows) fn system_class_info(
        &mut self, kind: runtime::Win16HostSystemClass,
        images: &Win16Images, objects: &mut Win16Objects,
    ) -> Result<Option<runtime::Win16HostSystemClassInfo>, RuntimeError> {
        let (response, result) = std::sync::mpsc::channel();
        self.send(WorkerCommand::QuerySystemClass { kind, response })?;
        let Some(info) = result.recv().map_err(|_| worker_stopped("query predefined USER class"))??
            else { return Ok(None); };
        let background = if info.background == 0 { None }
            else if info.background <= (windows_sys::Win32::Graphics::Gdi::COLOR_MENUBAR + 1) as usize {
                Some(Win16ClassBackground::SystemColor((info.background - 1) as u16))
            } else {
                Some(Win16ClassBackground::Brush(objects.intern_borrowed(info.background as _)?))
            };
        Ok(Some(runtime::Win16HostSystemClassInfo {
            procedure: info.procedure,
            spec: Win16HostClassSpec {
                style: info.style, class_extra: info.class_extra, window_extra: info.window_extra,
                icon: images.adopt_borrowed_icon(info.icon as _)?,
                cursor: images.adopt_borrowed_cursor(info.cursor as _)?,
                background, system_class: Some(kind),
            },
        }))
    }

    pub(in crate::windows) fn register_class(
        &mut self,
        spec: Win16HostClassSpec,
        images: &Win16Images,
        objects: &Win16Objects,
    ) -> Result<Option<Win16RegisteredClass>, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 native window worker has been aborted",
            ));
        }
        let Some(icon) = resolve_icon(spec.icon, images)? else { return Ok(None); };
        let Some(cursor) = resolve_cursor(spec.cursor, images)? else { return Ok(None); };
        let Some(background) = resolve_background(spec.background, objects)
            else { return Ok(None); };
        let id = NEXT_CLASS_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 native class identity exhausted",
                )
            })?;
        let class = Win16HostClass(id);
        let (reply, response) = std::sync::mpsc::channel();
        self.send(WorkerCommand::RegisterClass {
            class,
            spec,
            icon,
            cursor,
            background,
            response: reply,
        })?;
        response
            .recv()
            .map_err(|_| worker_stopped("register Win16 class"))?
    }

    /// Replace one resource on the native class `window` belongs to. The
    /// native handle is resolved here, so the worker receives only an opaque
    /// resource value and never a runtime-owned guest handle.
    pub(in crate::windows) fn replace_class_resource(
        &mut self,
        class: Win16HostClass,
        window: runtime::Win16HostWindow,
        resource: runtime::Win16HostClassResource,
        images: &Win16Images,
        objects: &Win16Objects,
    ) -> Result<bool, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 native window worker has been aborted",
            ));
        }
        let native = match resource {
            runtime::Win16HostClassResource::Icon(icon) => {
                let Some(value) = resolve_icon(icon, images)? else { return Ok(false); };
                NativeClassResource::Icon(value)
            }
            runtime::Win16HostClassResource::Cursor(cursor) => {
                let Some(value) = resolve_cursor(cursor, images)? else { return Ok(false); };
                NativeClassResource::Cursor(value)
            }
            runtime::Win16HostClassResource::Background(background) => {
                let Some(value) = resolve_background(background, objects) else { return Ok(false); };
                NativeClassResource::Background(value)
            }
        };
        let (reply, response) = std::sync::mpsc::channel();
        self.send(WorkerCommand::ReplaceClassResource {
            class,
            window,
            resource: native,
            response: reply,
        })?;
        response
            .recv()
            .map_err(|_| worker_stopped("replace a Win16 class resource"))?
    }

    pub(in crate::windows) fn initialize_user_queue(&mut self) -> Result<(), RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 native window worker has been aborted",
            ));
        }
        let (reply, response) = std::sync::mpsc::channel();
        self.send(WorkerCommand::InitializeQueue { response: reply })?;
        response
            .recv()
            .map_err(|_| worker_stopped("initialize the Win16 native USER queue"))?
    }

    pub(in crate::windows) fn bind_task_queue(
        &self,
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
    ) -> Result<Option<Win16HostTaskQueue>, RuntimeError> {
        if self.aborted {
            return Ok(None);
        }
        self.worker()?
            .bind_task_queue(owner, guest_htask, task_selector_generation)
    }

    pub(in crate::windows) fn retire_task_queue(
        &self,
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
        queue: Win16HostTaskQueue,
    ) -> Result<bool, RuntimeError> {
        // Abort quiesces guest callbacks but deliberately leaves the USER
        // worker available until task queue incarnations have been retired.
        self.worker()?.retire_task_queue(
            owner,
            guest_htask,
            task_selector_generation,
            queue,
        )
    }

    pub(in crate::windows) fn ctl3d_frame(
        &self,
        window: runtime::Win16HostWindow,
    ) -> Result<Option<runtime::Win16HostCtl3dFrameFacts>, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 native window worker has been aborted",
            ));
        }
        let (reply, response) = std::sync::mpsc::channel();
        self.send(WorkerCommand::Ctl3dFrame {
            window,
            response: reply,
        })?;
        response
            .recv()
            .map_err(|_| worker_stopped("read a Win16 CTL3D dialog frame"))
    }

    pub(in crate::windows) fn get_key_state(&self, key: i32) -> Result<i16, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 native window worker has been aborted",
            ));
        }
        let (reply, response) = std::sync::mpsc::channel();
        self.send(WorkerCommand::GetKeyState {
            key,
            response: reply,
        })?;
        response
            .recv()
            .map_err(|_| worker_stopped("read Win16 key state"))
    }

    pub(in crate::windows) fn keyboard(
        &self,
        call: runtime::Win16HostKeyboardCall,
    ) -> Result<runtime::Win16HostKeyboardResult, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 native window worker has been aborted"));
        }
        let (response, result) = std::sync::mpsc::channel();
        self.send(WorkerCommand::Keyboard { call, response })?;
        result.recv().map_err(|_| worker_stopped("translate Win16 keyboard input"))?
    }

    pub(in crate::windows) fn unregister_class(&mut self, class: Win16HostClass) -> bool {
        let Ok(worker) = self.worker() else {
            return false;
        };
        let (reply, response) = std::sync::mpsc::channel();
        if worker
            .send(WorkerCommand::UnregisterClass {
                class,
                response: reply,
            })
            .is_err()
        {
            return false;
        }
        response.recv().unwrap_or(false)
    }
}

/// Resolve an opaque host icon token into its native handle. `None`
/// means the host holds no such image, so the replacement must not proceed.
fn resolve_icon(
    icon: Option<Win16HostIcon>,
    images: &Win16Images,
) -> Result<Option<usize>, RuntimeError> {
    match icon {
        Some(token) => Ok(images.native_icon(token)?.map(|native| native as usize)),
        // A cleared field keeps the native class field NULL.
        None => Ok(Some(0)),
    }
}

/// The cursor counterpart of `resolve_icon`.
fn resolve_cursor(
    cursor: Option<Win16HostCursor>,
    images: &Win16Images,
) -> Result<Option<usize>, RuntimeError> {
    match cursor {
        Some(token) => Ok(images.native_cursor(token)?.map(|native| native as usize)),
        None => Ok(Some(0)),
    }
}

/// Resolve a guest class background into the brush the native class stores.
/// A system color uses the OS-owned brush the registration path also uses.
fn resolve_background(
    background: Option<Win16ClassBackground>,
    objects: &Win16Objects,
) -> Option<NativeClassBackground> {
    match background {
        Some(Win16ClassBackground::SystemColor(color)) => {
            // SAFETY: GetSysColorBrush only reads the host's color table.
            let handle = unsafe {
                windows_sys::Win32::Graphics::Gdi::GetSysColorBrush(i32::from(color))
            };
            if handle.is_null() { None } else { Some(NativeClassBackground::shared(handle as usize)) }
        }
        Some(Win16ClassBackground::Brush(token)) => {
            objects.class_background(token)
        }
        None => Some(NativeClassBackground::default()),
    }
}
