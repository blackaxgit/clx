//! macOS Keychain ACL relaxation for CLX credential items.
//!
//! # Why this exists
//!
//! The `keyring` crate creates macOS generic-password items with the default
//! restrictive ACL: only the exact creating binary (matched by its
//! code-signing designated requirement / cdhash) may read the item without a
//! password prompt. Homebrew ships an adhoc-signed `clx`, so its code
//! identity is unstable: macOS treats each launch as a different application,
//! "Always Allow" never sticks, and the keychain password dialog reappears
//! on every launch.
//!
//! # What this does
//!
//! When CLX writes a credential, and via `clx keychain-trust` for items
//! created by older CLX versions, we (re)attach a permissive `SecAccess`
//! that is **not** bound to the calling binary's identity. The access object
//! is created with `SecAccessCreate(name, NULL, &access)`: passing a NULL
//! trusted-applications array yields the documented Apple "any application"
//! access (every application on this user account may use the item for the
//! standard authorizations without prompting). This is exactly the state a
//! user reaches by choosing "Allow all applications" for the item in
//! Keychain Access. We then bind it to the item with
//! `SecKeychainItemSetAccess`.
//!
//! `SecAccessCreate` and `SecKeychainItemSetAccess` are decades-stable
//! Security.framework C symbols. The maintained `security-framework` crate
//! does not wrap `SecAccessCreate` / `SecKeychainItemSetAccess` (only the
//! Touch-ID `SecAccessControl` flavor), so we declare these two specific
//! externs ourselves and link them via the `security-framework` crate, which
//! already links `Security.framework` on macOS. We use the crate's
//! high-level `SecKeychain` to *locate* the item (no fragile FFI for the
//! search path).
//!
//! # Security tradeoff (documented on purpose)
//!
//! This deliberately relaxes the ACL on **CLX's own credential items only**
//! to "any application on this user account". It is a conscious local-trust
//! decision: it removes the per-launch prompt at the cost of letting other
//! local applications running as the same user read these specific items.
//! It does not weaken any other keychain item and is the same trust the user
//! would otherwise grant by hand. The first store per process prints a
//! one-line stderr notice, and `clx keychain-trust` states it explicitly.
//!
//! # Portability
//!
//! Every effectful path is behind `#[cfg(target_os = "macos")]`. On all
//! other operating systems these functions are no-ops (Linux Secret Service
//! / libsecret does not have the adhoc-binary re-prompt problem), so the
//! crate builds unchanged on Linux/CI/Windows.

/// Which keychain-trust action a given item requires.
///
/// Factored out as a pure value so the decision logic is unit-testable
/// without touching the real keychain. The effectful code maps each variant
/// to the corresponding Security.framework call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// The item exists; relax its ACL to "any application".
    Relax,
    /// The item does not exist; nothing to repair (not an error).
    Skip,
}

/// Pure policy: given whether the keychain item was found, decide the action.
///
/// Kept separate from any FFI so it can be exhaustively unit-tested with no
/// keychain access. The real code calls this after a `find_generic_password`
/// probe and dispatches on the result.
#[must_use]
pub fn decide_access(item_found: bool) -> AccessDecision {
    if item_found {
        AccessDecision::Relax
    } else {
        AccessDecision::Skip
    }
}

/// A human-readable, side-effect-free description of the trust tradeoff,
/// surfaced by the `clx keychain-trust` command so the user understands what
/// the relaxed ACL means. Pure: returns a static string, easy to assert on.
#[must_use]
pub const fn trust_tradeoff_notice() -> &'static str {
    "CLX will set its keychain credential items to be readable by any \
     application on this user account so macOS stops re-prompting on every \
     launch. This is a deliberate local-trust tradeoff (identical to \
     choosing \"Allow all applications\" in Keychain Access) and applies \
     only to CLX's own items."
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::super::{CredentialError, KeychainTrustReport};

    /// Non-macOS no-op: relaxing the ACL is meaningless where the
    /// adhoc-binary re-prompt problem does not exist.
    pub fn relax_item_access(_service: &str, _account: &str) {}

    /// Non-macOS no-op repair: reports zero work and `macos = false` so
    /// callers can print "nothing to do" and exit 0.
    pub fn repair_service_items(
        _service: &str,
        _names: &[String],
    ) -> Result<KeychainTrustReport, CredentialError> {
        Ok(KeychainTrustReport {
            relaxed: 0,
            missing: 0,
            macos: false,
        })
    }
}

#[cfg(target_os = "macos")]
// The only `unsafe` in the crate. Scoped to this macOS-gated module and
// confined to two decades-stable Security.framework FFI calls
// (`SecAccessCreate`, `SecKeychainItemSetAccess`) plus the matching
// `CFRelease`. The workspace-wide `unsafe_code = "deny"` stays in force
// everywhere else; this narrow, audited exception is required because the
// maintained `security-framework` crate does not wrap the legacy SecAccess
// API. Each unsafe block has a documented safety invariant below.
#[allow(unsafe_code)]
mod imp {
    use super::super::{CredentialError, KeychainTrustReport};
    use super::{AccessDecision, decide_access};

    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::os::macos::keychain::SecKeychain;
    use tracing::{debug, warn};

    // ---- Minimal, stable Security.framework FFI -------------------------
    //
    // The high-level `security-framework` crate intentionally does not wrap
    // the legacy `SecAccess` / `SecKeychainItemSetAccess` API (it only wraps
    // the modern Touch-ID `SecAccessControl`). These two symbols have been
    // stable in `Security.framework` for ~20 years. They are resolved
    // through the framework that the `security-framework` crate already
    // links on macOS, so no extra build script / link directive is needed.

    #[allow(non_camel_case_types)]
    type OSStatus = i32;
    #[allow(non_camel_case_types)]
    type CFTypeRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type SecAccessRef = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type SecKeychainItemRef = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type CFArrayRef = *const std::ffi::c_void;

    const ERR_SEC_SUCCESS: OSStatus = 0;
    /// `errSecItemNotFound` (-25300): item is absent. Treated as "nothing to
    /// repair", never an error.
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;

    unsafe extern "C" {
        /// Create a `SecAccess`. Passing `trustedlist == NULL` yields the
        /// documented "any application" access (no per-app restriction, no
        /// read prompt). We never pass a restrictive list.
        fn SecAccessCreate(
            descriptor: CFStringRef,
            trustedlist: CFArrayRef,
            access_ref: *mut SecAccessRef,
        ) -> OSStatus;

        /// Replace the access object bound to a keychain item.
        fn SecKeychainItemSetAccess(item_ref: SecKeychainItemRef, access: SecAccessRef)
        -> OSStatus;

        fn CFRelease(cf: CFTypeRef);
    }

    /// Build the permissive "any application" `SecAccess` and bind it to the
    /// given raw keychain item ref. Returns `Ok(())` when the item's ACL is
    /// now permissive.
    ///
    /// # Safety
    ///
    /// `item_ref` must be a live `SecKeychainItemRef` obtained from the
    /// keychain in this call (we get it from `find_generic_password`).
    fn apply_any_app_access(
        item_ref: SecKeychainItemRef,
        descriptor: &str,
    ) -> Result<(), CredentialError> {
        let cf_desc = CFString::new(descriptor);
        let mut access: SecAccessRef = std::ptr::null_mut();

        // NULL trusted-app list == "any application" access (Apple-documented
        // behavior). We deliberately never construct a trusted-app list, so
        // the resulting item is not bound to any binary identity.
        let status = unsafe {
            SecAccessCreate(
                cf_desc.as_concrete_TypeRef(),
                std::ptr::null(),
                &raw mut access,
            )
        };
        if status != ERR_SEC_SUCCESS || access.is_null() {
            return Err(CredentialError::Keychain(format!(
                "SecAccessCreate failed (OSStatus {status})"
            )));
        }

        let set_status = unsafe { SecKeychainItemSetAccess(item_ref, access) };
        unsafe { CFRelease(access.cast::<std::ffi::c_void>().cast_const()) };

        if set_status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(map_os_status(set_status))
        }
    }

    /// Map a non-success `OSStatus` to an actionable `CredentialError`.
    fn map_os_status(status: OSStatus) -> CredentialError {
        match status {
            // errSecAuthFailed / errSecInteractionNotAllowed: keychain
            // locked or non-interactive. Actionable, never a panic.
            -25293 | -25308 => CredentialError::AccessDenied(
                "macOS keychain is locked or not accessible. Unlock the login \
                 keychain (open Keychain Access) and retry."
                    .to_string(),
            ),
            other => CredentialError::Keychain(format!(
                "SecKeychainItemSetAccess failed (OSStatus {other})"
            )),
        }
    }

    /// Relax one item (best-effort; used on the store hot path). Logs and
    /// swallows every failure: the secret is already written, so a keychain
    /// quirk must not turn `store` into an error.
    pub fn relax_item_access(service: &str, account: &str) {
        match relax_one(service, account) {
            Ok(AccessDecision::Relax) => {
                debug!("Relaxed keychain ACL for item '{account}'");
            }
            Ok(AccessDecision::Skip) => {
                debug!("Keychain item '{account}' absent; no ACL to relax");
            }
            Err(e) => {
                // Non-fatal: the credential is stored; only the prompt-free
                // guarantee is at risk. Surfaced at warn for diagnosability.
                warn!("Could not relax keychain ACL for '{account}': {e}");
            }
        }
    }

    /// Locate one generic-password item and, if present, relax its ACL.
    /// Idempotent: re-running on an already-permissive item just rebinds an
    /// equivalent permissive access object (no duplicate item, no error).
    fn relax_one(service: &str, account: &str) -> Result<AccessDecision, CredentialError> {
        let keychain = SecKeychain::default().map_err(|e| {
            CredentialError::ServiceUnavailable(format!("Cannot open login keychain: {e}"))
        })?;

        match keychain.find_generic_password(service, account) {
            Ok((_pw, item)) => {
                debug_assert_eq!(decide_access(true), AccessDecision::Relax);
                let raw = item.as_CFTypeRef().cast_mut();
                apply_any_app_access(raw, service)?;
                Ok(AccessDecision::Relax)
            }
            Err(e) => {
                // security-framework maps errSecItemNotFound to a wrapped
                // OSStatus; compare on the code to stay version-stable.
                if e.code() == ERR_SEC_ITEM_NOT_FOUND {
                    Ok(decide_access(false))
                } else if e.code() == -25293 || e.code() == -25308 {
                    Err(map_os_status(e.code()))
                } else {
                    Err(CredentialError::Keychain(format!(
                        "find_generic_password('{account}') failed: {e}"
                    )))
                }
            }
        }
    }

    /// Repair every named CLX item under `service`. Missing items are counted
    /// (not errors). A locked keychain aborts with an actionable error rather
    /// than silently doing nothing.
    pub fn repair_service_items(
        service: &str,
        names: &[String],
    ) -> Result<KeychainTrustReport, CredentialError> {
        let mut relaxed = 0usize;
        let mut missing = 0usize;

        for name in names {
            match relax_one(service, name)? {
                AccessDecision::Relax => relaxed += 1,
                AccessDecision::Skip => missing += 1,
            }
        }

        Ok(KeychainTrustReport {
            relaxed,
            missing,
            macos: true,
        })
    }
}

pub use imp::{relax_item_access, repair_service_items};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_access_relaxes_when_item_present() {
        assert_eq!(decide_access(true), AccessDecision::Relax);
    }

    #[test]
    fn decide_access_skips_when_item_absent() {
        assert_eq!(decide_access(false), AccessDecision::Skip);
    }

    #[test]
    fn trust_tradeoff_notice_states_any_application_scope() {
        let n = trust_tradeoff_notice();
        assert!(n.contains("any application"));
        assert!(n.contains("local-trust"));
        // Must scope the tradeoff to CLX's own items, not all keychain items.
        assert!(n.contains("only to CLX"));
    }

    #[test]
    fn access_decision_is_total_over_bool() {
        // Exhaustive: the pure policy must classify both inputs and the two
        // variants must be distinct (guards against a future regression that
        // collapses them).
        assert_ne!(decide_access(true), decide_access(false));
    }
}
