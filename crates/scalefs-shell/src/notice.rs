use crate::ffi::{self, Guid, Hresult, Hstring};
use crate::register::APP_ID;
use core::ffi::c_void;

const S_OK: Hresult = 0;
const S_FALSE: Hresult = 1;
const RPC_E_CHANGED_MODE: Hresult = 0x8001_0106_u32 as i32;
const RO_INIT_MULTITHREADED: u32 = 1;

const IID_TOAST_NOTIFICATION_MANAGER_STATICS: Guid = Guid::new(
    0x50ac_103f,
    0xd235,
    0x4598,
    [0xbb, 0xef, 0x98, 0xfe, 0x4d, 0x1a, 0x3a, 0xd4],
);
const IID_TOAST_NOTIFICATION_FACTORY: Guid = Guid::new(
    0x0412_4b20,
    0x82c6,
    0x4229,
    [0xb1, 0x09, 0xfd, 0x9e, 0xd4, 0x66, 0x2b, 0x53],
);
const IID_XML_DOCUMENT: Guid = Guid::new(
    0xf7f3_a506,
    0x1e87,
    0x42d6,
    [0xbc, 0xfb, 0xb8, 0xc8, 0x09, 0xfa, 0x54, 0x94],
);
const IID_XML_DOCUMENT_IO: Guid = Guid::new(
    0x6cd0_e74e,
    0xee65,
    0x4489,
    [0x9e, 0xbf, 0xca, 0x43, 0xe8, 0x7b, 0xa6, 0x37],
);

type QueryInterfaceFn =
    unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Hresult;
type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;

#[repr(C)]
struct InspectableVtbl {
    query_interface: QueryInterfaceFn,
    _add_ref: usize,
    release: ReleaseFn,
    _get_iids: usize,
    _get_runtime_class_name: usize,
    _get_trust_level: usize,
}

#[repr(C)]
struct ToastNotificationManagerStaticsVtbl {
    _base: InspectableVtbl,
    _create_toast_notifier: usize,
    create_toast_notifier_with_id:
        unsafe extern "system" fn(*mut c_void, Hstring, *mut *mut c_void) -> Hresult,
}

#[repr(C)]
struct ToastNotifierVtbl {
    _base: InspectableVtbl,
    show: unsafe extern "system" fn(*mut c_void, *mut c_void) -> Hresult,
    _hide: usize,
    get_setting: unsafe extern "system" fn(*mut c_void, *mut i32) -> Hresult,
}

#[repr(C)]
struct ToastNotificationFactoryVtbl {
    _base: InspectableVtbl,
    create_toast_notification:
        unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> Hresult,
}

#[repr(C)]
struct XmlDocumentIoVtbl {
    _base: InspectableVtbl,
    load_xml: unsafe extern "system" fn(*mut c_void, Hstring) -> Hresult,
}

fn failed(call: &str, hr: Hresult) -> String {
    format!("{call} failed (0x{:08x})", hr as u32)
}

struct Object(*mut c_void);

impl Object {
    fn take(hr: Hresult, raw: *mut c_void, call: &str) -> Result<Object, String> {
        let object = (!raw.is_null()).then_some(Object(raw));
        match (hr >= 0, object) {
            (true, Some(object)) => Ok(object),
            (true, None) => Err(format!("{call} returned no object")),
            (false, _) => Err(failed(call, hr)),
        }
    }

    unsafe fn vtbl<T>(&self) -> &T {
        unsafe { &**(self.0 as *const *const T) }
    }

    fn query(&self, iid: &Guid, name: &str) -> Result<Object, String> {
        let mut raw = std::ptr::null_mut();
        let hr = unsafe { (self.vtbl::<InspectableVtbl>().query_interface)(self.0, iid, &mut raw) };
        Object::take(hr, raw, &format!("QueryInterface({name})"))
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe { (self.vtbl::<InspectableVtbl>().release)(self.0) };
    }
}

struct HString(Hstring);

impl HString {
    fn new(text: &str) -> Result<HString, String> {
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut handle: Hstring = std::ptr::null_mut();
        let hr =
            unsafe { ffi::WindowsCreateString(units.as_ptr(), units.len() as u32, &mut handle) };
        if hr < 0 {
            return Err(failed("WindowsCreateString", hr));
        }
        Ok(HString(handle))
    }
}

impl Drop for HString {
    fn drop(&mut self) {
        unsafe { ffi::WindowsDeleteString(self.0) };
    }
}

struct Runtime {
    counted: bool,
}

impl Runtime {
    fn enter() -> Result<Runtime, String> {
        let hr = unsafe { ffi::RoInitialize(RO_INIT_MULTITHREADED) };
        match hr {
            S_OK | S_FALSE => Ok(Runtime { counted: true }),
            RPC_E_CHANGED_MODE => Ok(Runtime { counted: false }),
            other => Err(failed("RoInitialize", other)),
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if self.counted {
            unsafe { ffi::RoUninitialize() };
        }
    }
}

fn factory(class: &str, iid: &Guid) -> Result<Object, String> {
    let name = HString::new(class)?;
    let mut raw = std::ptr::null_mut();
    let hr = unsafe { ffi::RoGetActivationFactory(name.0, iid, &mut raw) };
    Object::take(hr, raw, &format!("RoGetActivationFactory({class})"))
}

fn activate(class: &str) -> Result<Object, String> {
    let name = HString::new(class)?;
    let mut raw = std::ptr::null_mut();
    let hr = unsafe { ffi::RoActivateInstance(name.0, &mut raw) };
    Object::take(hr, raw, &format!("RoActivateInstance({class})"))
}

pub fn safe_to_remove(device: Option<&str>) {
    let (title, body) = crate::text::safe_removal_notice(device);
    let line = match show(&crate::toast::xml(&title, &body)) {
        Ok(setting) => {
            format!("scalefs-shell: notice shown as '{APP_ID}' ({setting}): [{title}] [{body}]")
        }
        Err(why) => format!("scalefs-shell: notice not shown: {why}"),
    };
    ffi::debug_line(&line);
}

fn show(xml: &str) -> Result<String, String> {
    let _runtime = Runtime::enter()?;
    let Toast { notifier, toast } = prepare(xml)?;
    let setting = setting(&notifier);
    let hr = unsafe { (notifier.vtbl::<ToastNotifierVtbl>().show)(notifier.0, toast.0) };
    if hr < 0 {
        return Err(failed("Show", hr));
    }
    Ok(setting)
}

struct Toast {
    notifier: Object,
    toast: Object,
}

fn prepare(xml: &str) -> Result<Toast, String> {
    let manager = factory(
        "Windows.UI.Notifications.ToastNotificationManager",
        &IID_TOAST_NOTIFICATION_MANAGER_STATICS,
    )?;
    let app_id = HString::new(APP_ID)?;
    let mut raw = std::ptr::null_mut();
    let hr = unsafe {
        (manager
            .vtbl::<ToastNotificationManagerStaticsVtbl>()
            .create_toast_notifier_with_id)(manager.0, app_id.0, &mut raw)
    };
    let notifier = Object::take(hr, raw, "CreateToastNotifierWithId")?;

    let document = activate("Windows.Data.Xml.Dom.XmlDocument")?;
    let loader = document.query(&IID_XML_DOCUMENT_IO, "IXmlDocumentIO")?;
    let content = HString::new(xml)?;
    let hr = unsafe { (loader.vtbl::<XmlDocumentIoVtbl>().load_xml)(loader.0, content.0) };
    if hr < 0 {
        return Err(failed("LoadXml", hr));
    }
    let document = document.query(&IID_XML_DOCUMENT, "IXmlDocument")?;

    let toasts = factory(
        "Windows.UI.Notifications.ToastNotification",
        &IID_TOAST_NOTIFICATION_FACTORY,
    )?;
    let mut raw = std::ptr::null_mut();
    let hr = unsafe {
        (toasts
            .vtbl::<ToastNotificationFactoryVtbl>()
            .create_toast_notification)(toasts.0, document.0, &mut raw)
    };
    let toast = Object::take(hr, raw, "CreateToastNotification")?;
    Ok(Toast { notifier, toast })
}

fn setting(notifier: &Object) -> String {
    let mut setting = 0i32;
    let hr =
        unsafe { (notifier.vtbl::<ToastNotifierVtbl>().get_setting)(notifier.0, &mut setting) };
    if hr < 0 {
        return format!("setting unreadable, 0x{:08x}", hr as u32);
    }
    match setting {
        0 => "enabled".into(),
        1 => "turned off for this application".into(),
        2 => "turned off for the user".into(),
        3 => "turned off by group policy".into(),
        4 => "turned off by manifest".into(),
        other => format!("setting {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_toast_is_built_through_the_runtime() {
        let _runtime = Runtime::enter().expect("the Windows Runtime initializes");
        let built = prepare(&crate::toast::xml("Title", "The 'x' device")).expect("a toast");
        assert!(!setting(&built.notifier).is_empty());
    }

    #[test]
    fn a_malformed_payload_fails_before_anything_is_shown() {
        let _runtime = Runtime::enter().expect("the Windows Runtime initializes");
        let why = prepare("<toast><visual>")
            .err()
            .expect("the payload is refused");
        assert!(why.starts_with("LoadXml failed"), "{why}");
    }

    #[test]
    fn the_guard_balances_only_its_own_initialization() {
        let first = Runtime::enter().expect("first");
        let again = Runtime::enter().expect("again (S_FALSE)");
        assert!(first.counted && again.counted);
        drop(again);
        drop(first);
        assert_eq!(unsafe { ffi::RoInitialize(0) }, S_OK);
        let inside = Runtime::enter().expect("a single-threaded apartment is usable");
        assert!(!inside.counted);
        drop(inside);
        unsafe { ffi::RoUninitialize() };
    }
}
