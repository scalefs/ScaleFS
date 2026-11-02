use crate::ffi::{self, Guid, Hresult, from_wide_ptr, wide};
use core::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

pub const CLSID_EJECT: Guid = Guid::new(
    0x858c_f4ec,
    0x8cf3,
    0x4f38,
    [0xbd, 0x79, 0x5c, 0xa4, 0x1d, 0x17, 0x52, 0x37],
);

const IID_IUNKNOWN: Guid = Guid::new(0, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
const IID_ICLASSFACTORY: Guid = Guid::new(1, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
const IID_IEXPLORERCOMMAND: Guid = Guid::new(
    0xa08c_e4d0,
    0xfa25,
    0x44ab,
    [0xb5, 0x7c, 0xc7, 0xb1, 0xc3, 0x23, 0xe0, 0xb9],
);

const S_OK: Hresult = 0;
const S_FALSE: Hresult = 1;
const E_NOTIMPL: Hresult = 0x8000_4001_u32 as i32;
const E_NOINTERFACE: Hresult = 0x8000_4002_u32 as i32;
const E_POINTER: Hresult = 0x8000_4003_u32 as i32;
const E_FAIL: Hresult = 0x8000_4005_u32 as i32;
const CLASS_E_NOAGGREGATION: Hresult = 0x8004_0110_u32 as i32;
const CLASS_E_CLASSNOTAVAILABLE: Hresult = 0x8004_0111_u32 as i32;

const ECS_ENABLED: u32 = 0;
const ECS_HIDDEN: u32 = 2;
const ECF_DEFAULT: u32 = 0;

const SIGDN_NORMALDISPLAY: u32 = 0;
const SIGDN_FILESYSPATH: u32 = 0x8005_8000;

static LIVE: AtomicUsize = AtomicUsize::new(0);

pub struct Pin;
impl Pin {
    pub fn new() -> Pin {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Pin
    }
}
impl Drop for Pin {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

type QueryInterfaceFn =
    unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Hresult;
type RefFn = unsafe extern "system" fn(*mut c_void) -> u32;

#[repr(C)]
struct UnknownVtbl {
    query_interface: QueryInterfaceFn,
    add_ref: RefFn,
    release: RefFn,
}

#[repr(C)]
struct ClassFactoryVtbl {
    base: UnknownVtbl,
    create_instance: unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        *const Guid,
        *mut *mut c_void,
    ) -> Hresult,
    lock_server: unsafe extern "system" fn(*mut c_void, i32) -> Hresult,
}

type ItemsTextFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut u16) -> Hresult;

#[repr(C)]
struct ExplorerCommandVtbl {
    base: UnknownVtbl,
    get_title: ItemsTextFn,
    get_icon: ItemsTextFn,
    get_tool_tip: ItemsTextFn,
    get_canonical_name: unsafe extern "system" fn(*mut c_void, *mut Guid) -> Hresult,
    get_state: unsafe extern "system" fn(*mut c_void, *mut c_void, i32, *mut u32) -> Hresult,
    invoke: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> Hresult,
    get_flags: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hresult,
    enum_sub_commands: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> Hresult,
}

#[repr(C)]
struct ShellItemArrayVtbl {
    base: UnknownVtbl,
    _bind_to_handler: usize,
    _get_property_store: usize,
    _get_property_description_list: usize,
    _get_attributes: usize,
    get_count: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hresult,
    get_item_at: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> Hresult,
}

#[repr(C)]
struct ShellItemVtbl {
    base: UnknownVtbl,
    _bind_to_handler: usize,
    _get_parent: usize,
    get_display_name: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16) -> Hresult,
}

#[repr(C)]
struct Factory {
    vtbl: &'static ClassFactoryVtbl,
}

static FACTORY_VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
    base: UnknownVtbl {
        query_interface: factory_query_interface,
        add_ref: factory_add_ref,
        release: factory_release,
    },
    create_instance: factory_create_instance,
    lock_server: factory_lock_server,
};

static FACTORY: Factory = Factory {
    vtbl: &FACTORY_VTBL,
};

unsafe extern "system" fn factory_query_interface(
    this: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    if out.is_null() || iid.is_null() {
        return E_POINTER;
    }
    let iid = unsafe { *iid };
    if iid == IID_IUNKNOWN || iid == IID_ICLASSFACTORY {
        unsafe { *out = this };
        return S_OK;
    }
    unsafe { *out = std::ptr::null_mut() };
    E_NOINTERFACE
}

unsafe extern "system" fn factory_add_ref(_this: *mut c_void) -> u32 {
    2
}

unsafe extern "system" fn factory_release(_this: *mut c_void) -> u32 {
    1
}

unsafe extern "system" fn factory_create_instance(
    _this: *mut c_void,
    outer: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = std::ptr::null_mut() };
    if !outer.is_null() {
        return CLASS_E_NOAGGREGATION;
    }
    let command = Box::into_raw(Box::new(Command {
        vtbl: &COMMAND_VTBL,
        refs: AtomicU32::new(1),
        _pin: Pin::new(),
    })) as *mut c_void;
    unsafe {
        let hr = command_query_interface(command, iid, out);
        command_release(command);
        hr
    }
}

unsafe extern "system" fn factory_lock_server(_this: *mut c_void, lock: i32) -> Hresult {
    if lock != 0 {
        LIVE.fetch_add(1, Ordering::SeqCst);
    } else {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
    S_OK
}

#[repr(C)]
struct Command {
    vtbl: &'static ExplorerCommandVtbl,
    refs: AtomicU32,
    _pin: Pin,
}

static COMMAND_VTBL: ExplorerCommandVtbl = ExplorerCommandVtbl {
    base: UnknownVtbl {
        query_interface: command_query_interface,
        add_ref: command_add_ref,
        release: command_release,
    },
    get_title: command_get_title,
    get_icon: command_not_implemented_text,
    get_tool_tip: command_not_implemented_text,
    get_canonical_name: command_get_canonical_name,
    get_state: command_get_state,
    invoke: command_invoke,
    get_flags: command_get_flags,
    enum_sub_commands: command_enum_sub_commands,
};

unsafe extern "system" fn command_query_interface(
    this: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    if out.is_null() || iid.is_null() {
        return E_POINTER;
    }
    let iid = unsafe { *iid };
    if iid == IID_IUNKNOWN || iid == IID_IEXPLORERCOMMAND {
        unsafe {
            command_add_ref(this);
            *out = this;
        }
        return S_OK;
    }
    unsafe { *out = std::ptr::null_mut() };
    E_NOINTERFACE
}

unsafe extern "system" fn command_add_ref(this: *mut c_void) -> u32 {
    let command = unsafe { &*(this as *const Command) };
    command.refs.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn command_release(this: *mut c_void) -> u32 {
    let left = unsafe { &*(this as *const Command) }
        .refs
        .fetch_sub(1, Ordering::SeqCst)
        - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this as *mut Command) });
    }
    left
}

fn task_string(text: &str, out: *mut *mut u16) -> Hresult {
    if out.is_null() {
        return E_POINTER;
    }
    let text = wide(text);
    unsafe { ffi::SHStrDupW(text.as_ptr(), out) }
}

unsafe extern "system" fn command_get_title(
    _this: *mut c_void,
    _items: *mut c_void,
    out: *mut *mut u16,
) -> Hresult {
    task_string(crate::text::eject_caption(), out)
}

unsafe extern "system" fn command_not_implemented_text(
    _this: *mut c_void,
    _items: *mut c_void,
    out: *mut *mut u16,
) -> Hresult {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    E_NOTIMPL
}

unsafe extern "system" fn command_get_canonical_name(
    _this: *mut c_void,
    out: *mut Guid,
) -> Hresult {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = CLSID_EJECT };
    S_OK
}

unsafe extern "system" fn command_get_state(
    _this: *mut c_void,
    items: *mut c_void,
    _ok_to_be_slow: i32,
    state: *mut u32,
) -> Hresult {
    if state.is_null() {
        return E_POINTER;
    }
    let shown = unsafe { single_item(items, SIGDN_FILESYSPATH) }
        .and_then(|path| crate::outcome::drive_root_letter(&path))
        .is_some_and(crate::eject::is_ejectable_scalefs_volume);
    unsafe { *state = if shown { ECS_ENABLED } else { ECS_HIDDEN } };
    S_OK
}

unsafe extern "system" fn command_invoke(
    _this: *mut c_void,
    items: *mut c_void,
    _bind: *mut c_void,
) -> Hresult {
    let Some(path) = (unsafe { single_item(items, SIGDN_FILESYSPATH) }) else {
        return E_FAIL;
    };
    let Some(letter) = crate::outcome::drive_root_letter(&path) else {
        return E_FAIL;
    };
    let display = unsafe { single_item(items, SIGDN_NORMALDISPLAY) }.unwrap_or(path);
    let pin = Pin::new();
    std::thread::spawn(move || {
        crate::eject::run(letter, &display);
        drop(pin);
    });
    S_OK
}

unsafe extern "system" fn command_get_flags(_this: *mut c_void, out: *mut u32) -> Hresult {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = ECF_DEFAULT };
    S_OK
}

unsafe extern "system" fn command_enum_sub_commands(
    _this: *mut c_void,
    out: *mut *mut c_void,
) -> Hresult {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    E_NOTIMPL
}

unsafe fn single_item(items: *mut c_void, sigdn: u32) -> Option<String> {
    if items.is_null() {
        return None;
    }
    let array = unsafe { &**(items as *const *const ShellItemArrayVtbl) };
    let mut count = 0u32;
    if unsafe { (array.get_count)(items, &mut count) } != S_OK || count != 1 {
        return None;
    }
    let mut item: *mut c_void = std::ptr::null_mut();
    if unsafe { (array.get_item_at)(items, 0, &mut item) } != S_OK || item.is_null() {
        return None;
    }
    let shell_item = unsafe { &**(item as *const *const ShellItemVtbl) };
    let mut name: *mut u16 = std::ptr::null_mut();
    let hr = unsafe { (shell_item.get_display_name)(item, sigdn, &mut name) };
    let text = if hr == S_OK && !name.is_null() {
        let text = unsafe { from_wide_ptr(name) };
        unsafe { ffi::CoTaskMemFree(name as *mut c_void) };
        Some(text)
    } else {
        None
    };
    unsafe { (shell_item.base.release)(item) };
    text
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const Guid,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    if out.is_null() || clsid.is_null() || iid.is_null() {
        return E_POINTER;
    }
    unsafe { *out = std::ptr::null_mut() };
    if unsafe { *clsid } != CLSID_EJECT {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    unsafe { factory_query_interface(&FACTORY as *const Factory as *mut c_void, iid, out) }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> Hresult {
    if LIVE.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}
