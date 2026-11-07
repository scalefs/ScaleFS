use super::*;

static DISPLAY_NAME_REQUESTS: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct FakeArray {
    vtbl: *const ShellItemArrayVtbl,
    item: *mut c_void,
}

#[repr(C)]
struct FakeItem {
    vtbl: *const ShellItemVtbl,
}

unsafe extern "system" fn fake_query_interface(
    _this: *mut c_void,
    _iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    E_NOINTERFACE
}

unsafe extern "system" fn fake_ref(_this: *mut c_void) -> u32 {
    1
}

unsafe extern "system" fn fake_get_count(_this: *mut c_void, count: *mut u32) -> Hresult {
    unsafe { *count = 1 };
    S_OK
}

unsafe extern "system" fn fake_get_item_at(
    this: *mut c_void,
    index: u32,
    out: *mut *mut c_void,
) -> Hresult {
    if index != 0 {
        return E_FAIL;
    }
    unsafe { *out = (*(this as *const FakeArray)).item };
    S_OK
}

unsafe extern "system" fn fake_get_display_name(
    _this: *mut c_void,
    _sigdn: u32,
    out: *mut *mut u16,
) -> Hresult {
    DISPLAY_NAME_REQUESTS.fetch_add(1, Ordering::SeqCst);
    unsafe { *out = std::ptr::null_mut() };
    E_FAIL
}

const UNKNOWN: UnknownVtbl = UnknownVtbl {
    query_interface: fake_query_interface,
    add_ref: fake_ref,
    release: fake_ref,
};

static ARRAY_VTBL: ShellItemArrayVtbl = ShellItemArrayVtbl {
    base: UNKNOWN,
    _bind_to_handler: 0,
    _get_property_store: 0,
    _get_property_description_list: 0,
    _get_attributes: 0,
    get_count: fake_get_count,
    get_item_at: fake_get_item_at,
};

static ITEM_VTBL: ShellItemVtbl = ShellItemVtbl {
    base: UNKNOWN,
    _bind_to_handler: 0,
    _get_parent: 0,
    get_display_name: fake_get_display_name,
};

#[test]
fn get_state_answers_synchronously_even_when_it_is_not_ok_to_be_slow() {
    let item = FakeItem { vtbl: &ITEM_VTBL };
    let array = FakeArray {
        vtbl: &ARRAY_VTBL,
        item: &item as *const FakeItem as *mut c_void,
    };
    DISPLAY_NAME_REQUESTS.store(0, Ordering::SeqCst);
    let mut state = u32::MAX;
    let hr = unsafe {
        command_get_state(
            std::ptr::null_mut(),
            &array as *const FakeArray as *mut c_void,
            0,
            &mut state,
        )
    };
    assert_eq!(hr, S_OK, "a call that is not OK to be slow still answers");
    assert!(
        DISPLAY_NAME_REQUESTS.load(Ordering::SeqCst) >= 1,
        "the item's path was resolved: the probe ran"
    );
    assert_ne!(state, u32::MAX, "a state was written");
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> isize;
    fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
}

const WAIT_OBJECT_0: u32 = 0;

static MODULE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn spare_module() -> (Vec<u16>, isize) {
    for name in ["fltlib.dll", "hid.dll", "msimg32.dll", "mpr.dll", "pdh.dll"] {
        let wide = crate::ffi::wide(name);
        if unsafe { crate::ffi::GetModuleHandleW(wide.as_ptr()) } != 0 {
            continue;
        }
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module != 0 {
            return (wide, module);
        }
    }
    panic!("no spare system module to watch");
}

fn loaded(name: &[u16]) -> bool {
    unsafe { crate::ffi::GetModuleHandleW(name.as_ptr()) != 0 }
}

fn ended(worker: &std::thread::JoinHandle<()>) -> bool {
    use std::os::windows::io::AsRawHandle;
    unsafe { WaitForSingleObject(worker.as_raw_handle() as isize, 10_000) == WAIT_OBJECT_0 }
}

#[test]
fn a_worker_keeps_its_module_mapped_until_its_thread_has_ended() {
    let _turn = MODULE_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (name, module) = spare_module();
    let (started_tx, started) = std::sync::mpsc::channel();
    let (finish, finish_rx) = std::sync::mpsc::channel::<()>();
    let worker = start_worker(
        std::thread::Builder::new().name("worker-lifetime".into()),
        module as *const c_void,
        move || {
            started_tx.send(()).unwrap();
            let _ = finish_rx.recv();
        },
    )
    .expect("the worker starts");
    started.recv().unwrap();
    unsafe { crate::ffi::FreeLibrary(module) };
    assert!(
        loaded(&name),
        "the worker's reference keeps the module mapped"
    );
    finish.send(()).unwrap();
    assert!(ended(&worker), "the worker thread ended");
    assert!(!loaded(&name), "the reference went with the thread");
    drop(worker);
}

#[test]
fn a_worker_that_cannot_start_releases_its_reference() {
    let _turn = MODULE_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (name, module) = spare_module();
    let refused = start_worker(
        std::thread::Builder::new().stack_size(usize::MAX / 2),
        module as *const c_void,
        || {},
    );
    assert_eq!(refused.err(), Some(E_FAIL));
    unsafe { crate::ffi::FreeLibrary(module) };
    assert!(!loaded(&name), "nothing else holds the module");
}

#[test]
fn a_panicking_job_still_releases_its_module() {
    let _turn = MODULE_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (name, module) = spare_module();
    let worker = start_worker(
        std::thread::Builder::new().name("worker-panics-on-purpose".into()),
        module as *const c_void,
        || panic!("a job that panics, on purpose"),
    )
    .expect("the worker starts");
    unsafe { crate::ffi::FreeLibrary(module) };
    assert!(ended(&worker), "the worker thread ended");
    assert!(!loaded(&name), "released despite the panic");
    drop(worker);
}
