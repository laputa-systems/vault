const SERVICE: &str = "dev.joshuarli.vault.secure";
#[cfg(not(test))]
const LEGACY_SERVICE: &str = "dev.joshuarli.vault";

#[cfg(not(test))]
mod imp {
    use super::{LEGACY_SERVICE, SERVICE};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::passwords;
    use security_framework_sys::access_control::kSecAccessControlUserPresence;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemUpdate};
    use std::ffi::c_void;
    use std::ptr;

    // Pointer-type coercion helper. The kSec* constants from
    // security-framework-sys are typed as CFStringRef = *const __CFString;
    // we need *const c_void for sec_str.
    unsafe fn sec_str(c: *const c_void) -> CFString {
        unsafe { CFString::wrap_under_get_rule(c as _) }
    }

    macro_rules! k {
        ($const:ident) => {
            ($const as *const c_void)
        };
    }

    fn query_dict(
        service: &str,
        name: &str,
    ) -> CFDictionary<CFString, core_foundation::base::CFType> {
        let pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![
            (
                unsafe { sec_str(k!(kSecClass)) },
                unsafe { sec_str(k!(kSecClassGenericPassword)) }.into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrService)) },
                CFString::from(service).into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrAccount)) },
                CFString::from(name).into_CFType(),
            ),
        ];
        CFDictionary::from_CFType_pairs(&pairs)
    }

    fn create(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlUserPresence,
        )
        .map_err(|e| format!("vault: set failed: {e}"))?;

        let pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![
            (
                unsafe { sec_str(k!(kSecClass)) },
                unsafe { sec_str(k!(kSecClassGenericPassword)) }.into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrService)) },
                CFString::from(service).into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrAccount)) },
                CFString::from(name).into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecValueData)) },
                CFData::from_buffer(value).into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrAccessControl)) },
                access_control.into_CFType(),
            ),
        ];
        let attributes = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe {
            SecItemAdd(
                attributes.as_concrete_TypeRef(),
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(format!("vault: set failed: OSStatus {status}"));
        }
        Ok(())
    }

    fn cleanup_legacy(name: &str) -> Result<(), String> {
        match passwords::delete_generic_password(LEGACY_SERVICE, name) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == errSecItemNotFound => Ok(()),
            Err(e) => Err(format!("vault: {name}: legacy cleanup failed: {e}")),
        }
    }

    pub fn set(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        let query = query_dict(service, name);

        let update_pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![(
            unsafe { sec_str(k!(kSecValueData)) },
            CFData::from_buffer(value).into_CFType(),
        )];
        let update = CFDictionary::from_CFType_pairs(&update_pairs);

        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };

        if status == 0 {
            return cleanup_legacy(name);
        }

        if status == errSecItemNotFound {
            create(service, name, value)?;
            return cleanup_legacy(name);
        }

        Err(format!(
            "vault: set failed: SecItemUpdate returned OSStatus {status}"
        ))
    }

    pub fn get(service: &str, name: &str) -> Result<String, String> {
        let password = passwords::get_generic_password(service, name)
            .map_err(|e| format!("vault: {name}: {e}"))?;
        String::from_utf8(password).map_err(|e| format!("vault: invalid UTF-8 in {name}: {e}"))
    }

    pub fn remove(service: &str, name: &str) -> Result<(), String> {
        match passwords::delete_generic_password(service, name) {
            Ok(()) => cleanup_legacy(name),
            Err(e) if e.code() == errSecItemNotFound && service == SERVICE => {
                match passwords::delete_generic_password(LEGACY_SERVICE, name) {
                    Ok(()) => Ok(()),
                    Err(legacy) if legacy.code() == errSecItemNotFound => {
                        Err(format!("vault: {name}: not found"))
                    }
                    Err(legacy) => Err(format!("vault: {name}: {legacy}")),
                }
            }
            Err(e) => Err(format!("vault: {name}: delete failed: {e}")),
        }
    }

    pub fn purge(service: &str) -> Result<usize, String> {
        let names = list(service)?;
        let mut count = names.len();
        for name in &names {
            remove(service, name)?;
        }

        if service == SERVICE {
            let legacy_names = list(LEGACY_SERVICE)?;
            count += legacy_names.len();
            for name in &legacy_names {
                remove(LEGACY_SERVICE, name)?;
            }
        }
        Ok(count)
    }

    pub fn list(service: &str) -> Result<Vec<String>, String> {
        let items = match ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
        {
            Ok(items) => items,
            Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(format!("vault: {e}")),
        };

        let mut names = Vec::new();
        for item in &items {
            if let Some(dict) = item.simplify_dict()
                && let Some(account) = dict.get("acct")
            {
                names.push(account.clone());
            }
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod imp {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    type Store = Mutex<HashMap<(String, String), Vec<u8>>>;

    static STORE: LazyLock<Store> = LazyLock::new(|| Mutex::new(HashMap::new()));
    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    pub(super) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap()
    }

    pub fn set(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        STORE
            .lock()
            .unwrap()
            .insert((service.to_string(), name.to_string()), value.to_vec());
        Ok(())
    }

    pub fn get(service: &str, name: &str) -> Result<String, String> {
        let guard = STORE.lock().unwrap();
        let value = guard
            .get(&(service.to_string(), name.to_string()))
            .ok_or_else(|| format!("vault: {}: not found", name))?;
        String::from_utf8(value.clone())
            .map_err(|e| format!("vault: invalid UTF-8 in {}: {}", name, e))
    }

    pub fn remove(service: &str, name: &str) -> Result<(), String> {
        STORE
            .lock()
            .unwrap()
            .remove(&(service.to_string(), name.to_string()))
            .map(|_| ())
            .ok_or_else(|| format!("vault: {}: not found", name))
    }

    pub fn purge(service: &str) -> Result<usize, String> {
        let service = service.to_string();
        let mut guard = STORE.lock().unwrap();
        let before = guard.keys().filter(|(s, _)| *s == service).count();
        guard.retain(|(s, _), _| *s != service);
        Ok(before)
    }

    pub fn list(service: &str) -> Result<Vec<String>, String> {
        let service = service.to_string();
        let guard = STORE.lock().unwrap();
        let mut names: Vec<String> = guard
            .keys()
            .filter(|(s, _)| *s == service)
            .map(|(_, name)| name.clone())
            .collect();
        names.sort();
        Ok(names)
    }
}

pub fn set_secret(name: &str, value: &[u8]) -> Result<(), String> {
    imp::set(SERVICE, name, value)
}

pub fn get_secret(name: &str) -> Result<String, String> {
    imp::get(SERVICE, name)
}

pub fn delete_secret(name: &str) -> Result<(), String> {
    imp::remove(SERVICE, name)
}

pub fn purge_secrets() -> Result<usize, String> {
    imp::purge(SERVICE)
}

pub fn list_secrets() -> Result<Vec<String>, String> {
    imp::list(SERVICE)
}

#[cfg(test)]
fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    imp::test_guard()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(name: &str) -> String {
        format!("TEST_{name}")
    }

    #[test]
    fn roundtrip() {
        let _guard = test_guard();
        set_secret(&k("R1"), b"hunter2").unwrap();
        assert_eq!(get_secret(&k("R1")).unwrap(), "hunter2");
    }

    #[test]
    fn overwrite_updates() {
        let _guard = test_guard();
        set_secret(&k("OW"), b"first").unwrap();
        set_secret(&k("OW"), b"second").unwrap();
        assert_eq!(get_secret(&k("OW")).unwrap(), "second");
    }

    #[test]
    fn get_missing_is_not_found() {
        let _guard = test_guard();
        let err = get_secret(&k("NOEXIST")).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn delete_missing_is_not_found() {
        let _guard = test_guard();
        let err = delete_secret(&k("NOEXIST")).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn delete_then_get_is_missing() {
        let _guard = test_guard();
        set_secret(&k("DEL"), b"x").unwrap();
        delete_secret(&k("DEL")).unwrap();
        assert!(get_secret(&k("DEL")).unwrap_err().contains("not found"));
    }

    #[test]
    fn double_delete_errors() {
        let _guard = test_guard();
        set_secret(&k("DD"), b"x").unwrap();
        delete_secret(&k("DD")).unwrap();
        assert!(delete_secret(&k("DD")).unwrap_err().contains("not found"));
    }

    #[test]
    fn empty_value() {
        let _guard = test_guard();
        set_secret(&k("EMPTY"), b"").unwrap();
        assert_eq!(get_secret(&k("EMPTY")).unwrap(), "");
    }

    #[test]
    fn multiline_value() {
        let _guard = test_guard();
        let secret = "line1\nline2\r\nline3";
        set_secret(&k("ML"), secret.as_bytes()).unwrap();
        assert_eq!(get_secret(&k("ML")).unwrap(), secret);
    }

    #[test]
    fn unicode_value() {
        let _guard = test_guard();
        let secret = "café 🚀 ñoño";
        set_secret(&k("UNI"), secret.as_bytes()).unwrap();
        assert_eq!(get_secret(&k("UNI")).unwrap(), secret);
    }

    #[test]
    fn non_utf8_rejected_on_get() {
        let _guard = test_guard();
        set_secret(&k("BIN"), &[0xFF, 0xFE, 0x00]).unwrap();
        let err = get_secret(&k("BIN")).unwrap_err();
        assert!(err.contains("invalid UTF-8"), "{err}");
    }

    #[test]
    fn special_chars_in_name() {
        let _guard = test_guard();
        set_secret("TEST_UNDER_SCORE.DOT-DASH", b"val").unwrap();
        assert_eq!(get_secret("TEST_UNDER_SCORE.DOT-DASH").unwrap(), "val");
    }

    #[test]
    fn list_reflects_additions_and_deletions() {
        let _guard = test_guard();
        set_secret(&k("L1"), b"a").unwrap();
        set_secret(&k("L2"), b"b").unwrap();
        set_secret(&k("L3"), b"c").unwrap();

        let names = list_secrets().unwrap();
        assert!(names.contains(&k("L1")));
        assert!(names.contains(&k("L2")));
        assert!(names.contains(&k("L3")));

        delete_secret(&k("L1")).unwrap();
        delete_secret(&k("L3")).unwrap();

        let names = list_secrets().unwrap();
        assert!(!names.contains(&k("L1")));
        assert!(names.contains(&k("L2")));
        assert!(!names.contains(&k("L3")));

        delete_secret(&k("L2")).unwrap();
    }

    #[test]
    fn list_never_contains_values() {
        let _guard = test_guard();
        set_secret(&k("LV"), b"secret-value-123").unwrap();
        let names = list_secrets().unwrap();
        assert!(names.contains(&k("LV")));
        assert!(!names.contains(&"secret-value-123".to_string()));
        delete_secret(&k("LV")).unwrap();
    }

    #[test]
    fn purge_removes_all_for_service() {
        let _guard = test_guard();
        for name in list_secrets().unwrap() {
            if name.starts_with("TEST_P") {
                delete_secret(&name).unwrap();
            }
        }
        set_secret(&k("P1"), b"a").unwrap();
        set_secret(&k("P2"), b"b").unwrap();
        set_secret(&k("P3"), b"c").unwrap();

        let count = purge_secrets().unwrap();
        assert!(count >= 3, "expected at least 3 purged, got {count}");

        let names = list_secrets().unwrap();
        assert!(!names.contains(&k("P1")));
        assert!(!names.contains(&k("P2")));
        assert!(!names.contains(&k("P3")));
    }

    #[test]
    fn purge_empty_returns_zero() {
        let _guard = test_guard();
        for name in list_secrets().unwrap() {
            if name.starts_with("TEST_") {
                let _ = delete_secret(&name);
            }
        }
        assert_eq!(purge_secrets().unwrap(), 0);
    }
}
