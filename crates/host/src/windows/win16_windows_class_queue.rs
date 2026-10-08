//! USER class registration and native task-queue bindings.

use std::sync::atomic::{AtomicU64, Ordering};

use runtime::{
    Win16ClassBackground, Win16HostClass, Win16HostClassSpec, Win16HostTaskQueue,
    Win16RegisteredClass,
};

use super::*;

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
        let icon = match spec.icon {
            Some(token) => match images.native_icon(token)? {
                Some(native) => native as usize,
                None => return Ok(None),
            },
            None => 0,
        };
        let cursor = match spec.cursor {
            Some(token) => match images.native_cursor(token)? {
                Some(native) => native as usize,
                None => return Ok(None),
            },
            None => 0,
        };
        let background = match spec.background {
            Some(Win16ClassBackground::SystemColor(color)) => {
                // GetSysColorBrush is OS-owned and remains valid without a
                // matching DeleteObject. The numeric value is host-private.
                let handle = unsafe {
                    windows_sys::Win32::Graphics::Gdi::GetSysColorBrush(i32::from(color))
                };
                if handle.is_null() {
                    return Ok(None);
                }
                handle as usize
            }
            Some(Win16ClassBackground::Brush(token)) => match objects.native_brush(token) {
                Some(native) => native as usize,
                None => return Ok(None),
            },
            None => 0,
        };
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
