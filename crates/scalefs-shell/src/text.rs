use crate::ffi::{self, from_wide, wide};
use std::sync::OnceLock;

pub const EJECT_CAPTION: &str = "@shell32.dll,-31382";
pub const PROBLEM_TITLE: &str = "@hotplug.dll,-2254";
pub const IN_USE: &str = "@hotplug.dll,-1206";
pub const EJECT_FAILED: &str = "@shell32.dll,-33338";
pub const NOTICE_TITLE: &str = "@hotplug.dll,-2261";
pub const NOTICE_BODY: &str = "@hotplug.dll,-2260";
pub const NOTICE_BODY_PLAIN: &str = "@hotplug.dll,-2266";

pub fn indirect(source: &str) -> Option<String> {
    let source = wide(source);
    let mut out = vec![0u16; 1024];
    let hr = unsafe {
        ffi::SHLoadIndirectString(
            source.as_ptr(),
            out.as_mut_ptr(),
            out.len() as u32,
            std::ptr::null_mut(),
        )
    };
    let text = from_wide(&out);
    (hr == 0 && !text.is_empty()).then_some(text)
}

pub fn eject_caption() -> &'static str {
    static CAPTION: OnceLock<String> = OnceLock::new();
    CAPTION.get_or_init(|| {
        let plain = indirect(EJECT_CAPTION).unwrap_or_else(|| "Eject".to_string());
        accelerated(&plain).unwrap_or(plain)
    })
}

pub fn fill(template: &str, value: &str) -> String {
    template
        .replacen("%1!ls!", value, 1)
        .replacen("%s", value, 1)
}

pub fn safe_removal_notice(device: Option<&str>) -> (String, String) {
    let title = indirect(NOTICE_TITLE).unwrap_or_else(|| "Safe To Remove Hardware".to_string());
    let body = match device {
        Some(name) => indirect(NOTICE_BODY)
            .map(|template| fill(&template, name))
            .unwrap_or_else(|| {
                format!("The '{name}' device can now be safely removed from the computer.")
            }),
        None => indirect(NOTICE_BODY_PLAIN)
            .unwrap_or_else(|| "This device can now be safely removed from the computer.".into()),
    };
    (title, body)
}

fn accelerated(plain: &str) -> Option<String> {
    struct Search<'a> {
        plain: &'a str,
        found: Option<String>,
    }
    unsafe extern "system" fn each(
        module: isize,
        _kind: *const u16,
        name: *mut u16,
        param: isize,
    ) -> i32 {
        let search = unsafe { &mut *(param as *mut Search) };
        let menu = unsafe { ffi::LoadMenuW(module, name) };
        if menu != 0 {
            search.found = find_in_menu(menu, search.plain);
            unsafe { ffi::DestroyMenu(menu) };
        }
        i32::from(search.found.is_none())
    }
    let shell32 = wide("shell32.dll");
    let module = unsafe { ffi::GetModuleHandleW(shell32.as_ptr()) };
    if module == 0 {
        return None;
    }
    let mut search = Search { plain, found: None };
    const RT_MENU: usize = 4;
    unsafe {
        ffi::EnumResourceNamesW(
            module,
            RT_MENU as *const u16,
            each,
            &mut search as *mut Search as isize,
        );
    }
    search.found
}

fn find_in_menu(menu: isize, plain: &str) -> Option<String> {
    const MF_BYPOSITION: u32 = 0x400;
    let count = unsafe { ffi::GetMenuItemCount(menu) };
    for position in 0..count.max(0) {
        let mut text = [0u16; 256];
        unsafe {
            ffi::GetMenuStringW(
                menu,
                position as u32,
                text.as_mut_ptr(),
                text.len() as i32,
                MF_BYPOSITION,
            )
        };
        let text = from_wide(&text);
        if text.contains('&') && text.replace('&', "") == plain {
            return Some(text);
        }
        let sub = unsafe { ffi::GetSubMenu(menu, position) };
        if sub != 0
            && let Some(found) = find_in_menu(sub, plain)
        {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_fill_both_styles() {
        assert_eq!(
            fill("Problem Ejecting %s", "ScaleFS (P:)"),
            "Problem Ejecting ScaleFS (P:)"
        );
        assert_eq!(
            fill("An error occurred while ejecting '%1!ls!'.", "ScaleFS (P:)"),
            "An error occurred while ejecting 'ScaleFS (P:)'."
        );
    }

    #[test]
    fn the_caption_is_windows_own_word() {
        let plain = indirect(EJECT_CAPTION).expect("shell32 carries the Eject caption");
        assert!(!plain.is_empty());
        assert_eq!(eject_caption().replace('&', ""), plain);
    }

    #[test]
    fn the_notice_is_windows_own_wording() {
        let title = indirect(NOTICE_TITLE).expect("hotplug carries the notice's title");
        let named = indirect(NOTICE_BODY).expect("hotplug carries the named notice");
        let plain = indirect(NOTICE_BODY_PLAIN).expect("hotplug carries the unnamed notice");
        assert!(!title.is_empty());
        assert_eq!(named.matches("%s").count(), 1, "one name insert: {named}");
        assert!(!plain.contains('%'), "no insert: {plain}");
        let (shown_title, body) = safe_removal_notice(Some("ScaleFS volume"));
        assert_eq!(shown_title, title);
        assert_eq!(body, fill(&named, "ScaleFS volume"));
        assert!(body.contains("ScaleFS volume") && !body.contains("%s"));
        assert_eq!(safe_removal_notice(None), (title, plain));
    }
}
