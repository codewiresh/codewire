//! Whether this Mac's screen is locked for the user running cw (#5976).
//!
//! Virtualization.framework protects a VM checkpoint's saved state with a
//! Secure Enclave key that macOS releases only while the Mac is unlocked, so
//! restoring one on a locked Mac fails inside the framework
//! (`errSecInteractionNotAllowed`), while capturing one works. The login
//! window records each console session in the I/O Registry root's
//! `IOConsoleUsers`, and a session whose screen is locked carries
//! `CGSSessionScreenIsLocked`. Reading it needs no window server connection,
//! so it also works for a supervisor started over ssh.

/// One console session's fields that decide a lock.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConsoleSession {
    uid: Option<i64>,
    screen_locked: bool,
}

/// Whether `uid`'s console session says its screen is locked. No session for
/// `uid`, or none that says so, is not called locked: a restore then meets
/// the framework's own error.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn locked_for(sessions: &[ConsoleSession], uid: i64) -> bool {
    sessions
        .iter()
        .any(|session| session.uid == Some(uid) && session.screen_locked)
}

/// Whether this Mac's screen is locked for the user running cw; never on
/// another OS, and not when the I/O Registry cannot be read.
pub fn screen_locked() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = i64::from(unsafe { libc::getuid() });
        ffi::console_sessions().is_some_and(|sessions| locked_for(&sessions, uid))
    }
    #[cfg(not(target_os = "macos"))]
    false
}

#[cfg(target_os = "macos")]
mod ffi {
    use std::ffi::{CStr, c_char, c_void};

    use super::ConsoleSession;

    type CFTypeRef = *const c_void;
    type CFIndex = isize;
    type CFTypeID = usize;
    const UTF8: u32 = 0x0800_0100;
    /// `kCFNumberSInt64Type`.
    const SINT64: CFIndex = 4;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            allocator: CFTypeRef,
            text: *const c_char,
            encoding: u32,
        ) -> CFTypeRef;
        fn CFRelease(object: CFTypeRef);
        fn CFGetTypeID(object: CFTypeRef) -> CFTypeID;
        fn CFArrayGetTypeID() -> CFTypeID;
        fn CFArrayGetCount(array: CFTypeRef) -> CFIndex;
        fn CFArrayGetValueAtIndex(array: CFTypeRef, index: CFIndex) -> CFTypeRef;
        fn CFDictionaryGetTypeID() -> CFTypeID;
        fn CFDictionaryGetValue(dictionary: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFNumberGetTypeID() -> CFTypeID;
        fn CFNumberGetValue(number: CFTypeRef, kind: CFIndex, value: *mut c_void) -> u8;
        fn CFBooleanGetTypeID() -> CFTypeID;
        fn CFBooleanGetValue(boolean: CFTypeRef) -> u8;
    }

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IORegistryGetRootEntry(main_port: u32) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: CFTypeRef,
            allocator: CFTypeRef,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: u32) -> i32;
    }

    /// A Core Foundation object this code created, released once on drop.
    struct Owned(CFTypeRef);

    impl Owned {
        fn new(object: CFTypeRef) -> Option<Self> {
            (!object.is_null()).then_some(Self(object))
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the object came from a Create function, is non-null,
            // and this is its one release.
            unsafe { CFRelease(self.0) }
        }
    }

    fn string(text: &CStr) -> Option<Owned> {
        // SAFETY: the text is NUL-terminated and outlives the call; a null
        // allocator is the default one.
        Owned::new(unsafe { CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), UTF8) })
    }

    /// `dictionary[key]` as an i64, when it is a number.
    fn number(dictionary: CFTypeRef, key: &Owned) -> Option<i64> {
        // SAFETY: `dictionary` is a live CFDictionary and `key` a live
        // CFString; the value is borrowed from the dictionary, its type is
        // checked before it is read, and `value` is an i64 as SINT64 says.
        unsafe {
            let object = CFDictionaryGetValue(dictionary, key.0);
            if object.is_null() || CFGetTypeID(object) != CFNumberGetTypeID() {
                return None;
            }
            let mut value = 0_i64;
            (CFNumberGetValue(object, SINT64, (&raw mut value).cast()) != 0).then_some(value)
        }
    }

    /// `dictionary[key]` when it is a boolean.
    fn boolean(dictionary: CFTypeRef, key: &Owned) -> Option<bool> {
        // SAFETY: as in `number`, with a CFBoolean.
        unsafe {
            let object = CFDictionaryGetValue(dictionary, key.0);
            if object.is_null() || CFGetTypeID(object) != CFBooleanGetTypeID() {
                return None;
            }
            Some(CFBooleanGetValue(object) != 0)
        }
    }

    /// The I/O Registry root's console sessions, or `None` when it cannot be
    /// read as an array.
    pub(super) fn console_sessions() -> Option<Vec<ConsoleSession>> {
        let users_key = string(c"IOConsoleUsers")?;
        let uid_key = string(c"kCGSSessionUserIDKey")?;
        let locked_key = string(c"CGSSessionScreenIsLocked")?;
        // SAFETY: port 0 is kIOMainPortDefault; the root entry is released
        // once, after the property is copied out of it.
        let users = unsafe {
            let root = IORegistryGetRootEntry(0);
            if root == 0 {
                return None;
            }
            let users = IORegistryEntryCreateCFProperty(root, users_key.0, std::ptr::null(), 0);
            IOObjectRelease(root);
            Owned::new(users)?
        };
        // SAFETY: `users` is live; each element is borrowed from it and its
        // type checked before it is read as a dictionary.
        unsafe {
            if CFGetTypeID(users.0) != CFArrayGetTypeID() {
                return None;
            }
            let sessions = (0..CFArrayGetCount(users.0))
                .map(|index| CFArrayGetValueAtIndex(users.0, index))
                .filter(|session| {
                    !session.is_null() && CFGetTypeID(*session) == CFDictionaryGetTypeID()
                })
                .map(|session| ConsoleSession {
                    uid: number(session, &uid_key),
                    screen_locked: boolean(session, &locked_key).unwrap_or(false),
                })
                .collect();
            Some(sessions)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: i64 = 501;

    fn session(uid: i64, screen_locked: bool) -> ConsoleSession {
        ConsoleSession {
            uid: Some(uid),
            screen_locked,
        }
    }

    #[test]
    fn only_this_users_session_saying_locked_is_locked() {
        assert!(locked_for(&[session(ME, true)], ME));
        assert!(!locked_for(&[session(ME, false)], ME));
        // Another user's locked session (fast user switching) is not ours.
        assert!(!locked_for(&[session(502, true), session(ME, false)], ME));
        assert!(locked_for(&[session(502, false), session(ME, true)], ME));
    }

    #[test]
    fn no_session_or_no_uid_is_not_called_locked() {
        assert!(!locked_for(&[], ME));
        assert!(!locked_for(
            &[ConsoleSession {
                uid: None,
                screen_locked: true,
            }],
            ME
        ));
    }
}
