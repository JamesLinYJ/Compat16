use super::*;

pub(super) fn create_notify_window(
    context: &NotifyWindowContext,
) -> Result<(HWND, [u16; 32], HINSTANCE), MciNotifyWindowCreateFailure> {
    let class_id = NEXT_WINDOW_CLASS
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value: u64| {
            value.checked_add(1)
        })
        .map_err(|_| MciNotifyWindowCreateFailure {
            primary: RuntimeError::new(
                Kind::ResourceExhausted,
                "MCI window class identity exhausted",
            ),
            cleanup: None,
            registered_class: None,
        })?;
    let mut class_name = [0_u16; 32];
    let prefix = b"Win16MciNotify";
    for (destination, source) in class_name.iter_mut().zip(prefix.iter().copied()) {
        *destination = u16::from(source);
    }
    let mut digits = [0_u16; 16];
    let mut value = class_id;
    for index in (0..digits.len()).rev() {
        let digit = (value & 0xf) as u8;
        digits[index] = if digit < 10 {
            u16::from(b'0' + digit)
        } else {
            u16::from(b'a' + digit - 10)
        };
        value >>= 4;
    }
    let start = prefix.len();
    class_name[start..start + digits.len()].copy_from_slice(&digits);
    class_name[start + digits.len()] = 0;
    let instance = crate::windows::win32_safe::current_module();
    if instance.is_null() {
        return Err(MciNotifyWindowCreateFailure {
            primary: last_error("get MCI owner module handle"),
            cleanup: None,
            registered_class: None,
        });
    }
    let class = WNDCLASSW {
        lpfnWndProc: Some(mci_notification_window_proc),
        hInstance: instance,
        lpszClassName: class_name.as_ptr(),
        ..Default::default()
    };
    // SAFETY: RegisterClassW reads a caller-owned WNDCLASSW whose string pointers stay live for the call.
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(MciNotifyWindowCreateFailure {
            primary: last_error("register hidden MCI notification class"),
            cleanup: None,
            registered_class: None,
        });
    }
    let context_pointer = (context as *const NotifyWindowContext).cast::<core::ffi::c_void>();
    // SAFETY: CreateWindowExW receives caller-owned class and title strings that stay live for the call. The creation parameter is null or a live record.
    let window = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            ptr::null_mut(),
            instance,
            context_pointer,
        )
    };
    if window.is_null() {
        // Capture GetLastError before the cleanup API can overwrite it.
        let primary = last_error("create hidden MCI notification window");
        // SAFETY: UnregisterClassW receives the class name and instance that registered the class.
        let unregistered = unsafe { UnregisterClassW(class_name.as_ptr(), instance) } != 0;
        return Err(MciNotifyWindowCreateFailure {
            primary,
            cleanup: (!unregistered)
                .then(|| last_error("unregister failed MCI notification class")),
            registered_class: (!unregistered).then_some(RegisteredMciClass {
                name: class_name,
                instance,
            }),
        });
    }
    Ok((window, class_name, instance))
}

pub(super) struct RegisteredMciClass {
    pub(super) name: [u16; 32],
    pub(super) instance: HINSTANCE,
}

pub(super) struct MciNotifyWindowCreateFailure {
    pub(super) primary: RuntimeError,
    pub(super) cleanup: Option<RuntimeError>,
    pub(super) registered_class: Option<RegisteredMciClass>,
}

#[derive(Debug)]
pub(super) struct MciStartupFailure {
    pub(super) primary: RuntimeError,
    pub(super) cleanup: RuntimeError,
}

impl std::fmt::Display for MciStartupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; class cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for MciStartupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.cleanup.kind() == Kind::InternalInvariant {
            Some(&self.cleanup)
        } else {
            Some(&self.primary)
        }
    }
}

pub(super) fn retire_notification_window(
    sink: HWND,
    class_name: &[u16; 32],
    instance: HINSTANCE,
    context: &NotifyWindowContext,
    resolved_causes: &mut Vec<Arc<RuntimeError>>,
) -> (bool, bool) {
    let _keep_callback_context_alive = context;
    let mut first_failure = None;
    while { crate::windows::win32_safe::is_window(sink) } != 0 {
        if { crate::windows::win32_safe::destroy_window(sink) } != 0 {
            continue;
        }
        let error = last_error("destroy hidden MCI notification window");
        if { crate::windows::win32_safe::is_window(sink) } == 0 {
            first_failure.get_or_insert(error);
            break;
        }
        first_failure.get_or_insert(error);
        pump_messages();
        thread::sleep(RETIRE_RETRY);
    }
    retire_registered_class_with_failure(
        RegisteredMciClass {
            name: *class_name,
            instance,
        },
        context,
        &mut first_failure,
    );
    if let Some(error) = first_failure {
        eprintln!("runtime: MCI sink cleanup recovered after failure: {error}");
        resolved_causes.push(Arc::new(error));
    }
    // The loop exits only after IsWindow reports absence, and the class helper
    // returns only after UnregisterClassW reports success.
    ({ crate::windows::win32_safe::is_window(sink) } == 0, true)
}

pub(super) fn retire_registered_class(class: RegisteredMciClass, context: &NotifyWindowContext) {
    let mut first_failure = None;
    retire_registered_class_with_failure(class, context, &mut first_failure);
    if let Some(error) = first_failure {
        eprintln!("runtime: MCI class cleanup recovered after failure: {error}");
    }
}

fn retire_registered_class_with_failure(
    class: RegisteredMciClass,
    context: &NotifyWindowContext,
    first_failure: &mut Option<RuntimeError>,
) {
    let _keep_callback_context_alive = context;
    loop {
        // SAFETY: UnregisterClassW receives the class name and instance that registered the class.
        if unsafe { UnregisterClassW(class.name.as_ptr(), class.instance) } != 0 {
            return;
        }
        first_failure.get_or_insert_with(|| last_error("unregister hidden MCI notification class"));
        thread::sleep(RETIRE_RETRY);
    }
}
