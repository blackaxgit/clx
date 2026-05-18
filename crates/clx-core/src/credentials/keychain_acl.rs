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
//! # Two distinct paths (do not conflate them)
//!
//! 1. **Store-time (NEW credentials), zero prompt.** When CLX itself writes a
//!    credential it is, by definition, the authorized creating process for
//!    that brand-new item, so attaching a permissive "any application"
//!    `SecAccess` via `SecAccessCreate(name, NULL, &access)` +
//!    `SecKeychainItemSetAccess` does NOT prompt: the process just authored
//!    the item and already holds the right to set its access.
//!    [`relax_item_access`] keeps this behavior unchanged.
//!
//! 2. **Repair (PRE-EXISTING items created by older CLX), at most one
//!    prompt.** Items written by a previous, differently-identified adhoc
//!    `clx` carry a restrictive ACL bound to that stale code identity.
//!    *Reading* such an item prompts (identity mismatch) and *modifying* its
//!    ACL via `SecKeychainItemSetAccess` prompts again -- and the grant does
//!    not stick because the adhoc cdhash is unstable. A per-item
//!    `find + SetAccess` loop therefore prompts up to `2 * N` times for `N`
//!    items, every run. That is the bug `clx keychain-trust` had.
//!
//!    The Apple-documented mechanism for exactly this scenario
//!    (CI / third-party / adhoc-signed tools) is the keychain *partition
//!    list*. `man security` (set-generic-password-partition-list): "Sets the
//!    partition list for a generic password. The partition list is an extra
//!    parameter in the ACL which limits access to the item based on an
//!    application's code signature. You must present the keychain's password
//!    to change a partition list." Matching is by `-s <service>`; omitting
//!    `-a` matches **every** account under that service, so a SINGLE
//!    invocation relaxes ALL `com.clx.credentials` items at once -- one
//!    password entry total, not one per item. Adding `unsigned:` to the
//!    partition list is what lets the adhoc/unsigned `clx` and `clx-mcp`
//!    binaries read the items afterwards without prompting.
//!
//! # Why shell out to `/usr/bin/security` here (and only here)
//!
//! An earlier project decision avoided shelling to `security` for the STORE
//! path. That decision is still correct and unchanged: store-time must be
//! zero-prompt and achieves that via creation-time `SecAccess` (path 1
//! above), which never needs the partition-list tool. The REPAIR of
//! pre-existing, restrictively-ACL'd items is a fundamentally different
//! problem: the partition list cannot be set via the public `SecAccess` C
//! API at all, and `set-generic-password-partition-list` is the only
//! documented, single-prompt way to do it. We use it ONLY in the repair
//! command, we never pass the keychain password on argv (we omit `-k` so
//! `security` prompts once, securely, itself), and we make exactly one call.
//!
//! # Security tradeoff (documented on purpose)
//!
//! This deliberately relaxes the ACL on **CLX's own credential items only**
//! so any application on this user account may read them without a prompt.
//! It is a conscious local-trust decision: it removes the per-launch prompt
//! at the cost of letting other local applications running as the same user
//! read these specific items. It does not weaken any other keychain item and
//! is the same trust the user would otherwise grant by hand.
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
/// without touching the real keychain. The effectful store-time code maps
/// each variant to the corresponding Security.framework call.
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
/// keychain access. The store-time code calls this after a
/// `find_generic_password` probe and dispatches on the result.
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

/// One-time message the `clx keychain-trust` command prints BEFORE doing any
/// work, so the user knows the single login-keychain password prompt that
/// `/usr/bin/security` will raise is expected and deliberate. Pure.
#[must_use]
pub const fn one_prompt_notice() -> &'static str {
    "macOS will ask for your login (keychain) password ONCE so CLX can relax \
     the access control on its own credential items and stop re-prompting on \
     every launch. This is a deliberate, local, one-time trust change. \
     Enter your macOS login password at the prompt (or Cancel to abort with \
     no changes)."
}

/// The partition-list value applied to CLX credential items.
///
/// * `apple:` / `apple-tool:` keep Apple's own tooling able to use the item
///   (the conventional baseline -- see `security dump-keychain` examples).
/// * `unsigned:` is the partition that an adhoc-signed / unsigned binary
///   (Homebrew's `clx`, `clx-mcp`) falls into. Including it is precisely
///   what stops the per-launch prompt for those binaries.
///
/// Public + `const` so the exact policy is assertable in a unit test without
/// the keychain.
pub const CLX_PARTITION_LIST: &str = "apple:,apple-tool:,unsigned:";

/// Build the exact `/usr/bin/security` argument vector for the single
/// partition-list call that relaxes EVERY item under `service`.
///
/// This is the structural guarantee that the repair is one operation, not a
/// per-item loop: there is no account (`-a`) filter, so `security` matches
/// all accounts under `-s <service>` and relaxes them in one invocation, and
/// `-k` is intentionally omitted so the keychain password is NEVER placed on
/// the process argv -- `security` prompts for it once, securely, itself.
///
/// Pure and total: returns the argv as owned strings so a unit test can
/// assert the invariants (single call, service-only match, no secret on
/// argv, `unsigned:` present) with zero keychain access.
#[must_use]
pub fn build_partition_list_argv(service: &str, login_keychain_path: &str) -> Vec<String> {
    vec![
        "set-generic-password-partition-list".to_string(),
        "-S".to_string(),
        CLX_PARTITION_LIST.to_string(),
        "-s".to_string(),
        service.to_string(),
        // NOTE: deliberately no `-a <account>` (match ALL accounts under the
        // service in ONE call) and deliberately no `-k <password>` (omitting
        // it makes `security` prompt once, securely; the secret never touches
        // argv / the process table).
        login_keychain_path.to_string(),
    ]
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::super::{CredentialError, KeychainTrustReport};

    /// Non-macOS no-op: relaxing the ACL is meaningless where the
    /// adhoc-binary re-prompt problem does not exist.
    pub fn relax_item_access(_service: &str, _account: &str) {}

    /// Non-macOS no-op repair: reports zero work and `macos = false` so
    /// callers can print "nothing to do" and exit 0. Never prompts.
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
// `CFRelease`, used ONLY by the zero-prompt store-time path. The
// workspace-wide `unsafe_code = "deny"` stays in force everywhere else; this
// narrow, audited exception is required because the maintained
// `security-framework` crate does not wrap the legacy SecAccess API. The
// repair path uses no `unsafe` at all (it shells to `/usr/bin/security`).
#[allow(unsafe_code)]
mod imp {
    use std::path::PathBuf;
    use std::process::Command;

    use super::super::{CredentialError, KeychainTrustReport};
    use super::{AccessDecision, build_partition_list_argv, decide_access};

    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::os::macos::keychain::SecKeychain;
    use tracing::{debug, info, warn};

    // ---- Minimal, stable Security.framework FFI -------------------------
    //
    // Used ONLY by the zero-prompt store-time path (`relax_item_access`).
    // The high-level `security-framework` crate intentionally does not wrap
    // the legacy `SecAccess` / `SecKeychainItemSetAccess` API (it only wraps
    // the modern Touch-ID `SecAccessControl`). These two symbols have been
    // stable in `Security.framework` for ~20 years.

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
    /// given raw keychain item ref. Used ONLY at store time, where the
    /// calling process just authored the item and is therefore already
    /// authorized to set its access (no prompt).
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

    /// Relax one item at STORE time (best-effort, zero prompt). The calling
    /// process just authored the item, so `SecKeychainItemSetAccess` does
    /// not prompt. Logs and swallows every failure: the secret is already
    /// written, so a keychain quirk must not turn `store` into an error.
    ///
    /// This is the unchanged Wave 4g store-time path: do NOT route the
    /// repair command through here (that is what caused the per-item
    /// prompt storm).
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

    /// Locate one generic-password item and, if present, relax its ACL via
    /// the `SecAccess` API. STORE-TIME ONLY.
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

    /// Resolve the login keychain path for the current user.
    ///
    /// `security set-generic-password-partition-list` defaults to the
    /// default keychain when no path is given, but we pass it explicitly so
    /// the operation is unambiguous and testable. `~/Library/Keychains/
    /// login.keychain-db` is the modern (10.12+) login keychain path.
    fn login_keychain_path() -> Result<String, CredentialError> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            CredentialError::ServiceUnavailable(
                "HOME is not set; cannot locate login keychain".into(),
            )
        })?;
        let p: PathBuf = [
            PathBuf::from(home),
            PathBuf::from("Library"),
            PathBuf::from("Keychains"),
            PathBuf::from("login.keychain-db"),
        ]
        .iter()
        .collect();
        Ok(p.to_string_lossy().into_owned())
    }

    /// Probe (no prompt) whether ANY item under `service` exists at all.
    ///
    /// `find_generic_password` with only a service match would still need an
    /// account, so we instead check the supplied candidate names: if every
    /// one is absent there is nothing to repair and we must not prompt. This
    /// lookup does NOT prompt for absent items (errSecItemNotFound is
    /// returned without a dialog) and, for a CLX-written item whose ACL we
    /// already relaxed, also does not prompt -- giving us a prompt-free
    /// short-circuit on the common "already relaxed" / "nothing stored"
    /// cases.
    fn any_item_present(service: &str, names: &[String]) -> bool {
        let Ok(keychain) = SecKeychain::default() else {
            // Cannot open the keychain to probe; assume work may be needed
            // and let the single `security` call surface the real error.
            return true;
        };
        for name in names {
            match keychain.find_generic_password(service, name) {
                Ok(_) => return true,
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                // Any other error (locked, ACL-restricted pre-0.8.0 item)
                // means an item very likely exists and needs repair.
                Err(_) => return true,
            }
        }
        false
    }

    /// Repair every CLX item under `service` with AT MOST ONE password
    /// prompt, regardless of how many items exist.
    ///
    /// Mechanism: a SINGLE `/usr/bin/security
    /// set-generic-password-partition-list -S <list> -s <service>
    /// <login-keychain>` invocation. Because there is no `-a` account
    /// filter, `security` matches and relaxes ALL accounts under the service
    /// in one call. `-k` is omitted so `security` itself prompts once,
    /// securely, for the login keychain password (the secret never touches
    /// our argv).
    ///
    /// Idempotent / no-op safety: if no CLX items exist we short-circuit
    /// with zero prompts. If items exist and are already relaxed, re-running
    /// the partition-list call is harmless (it just re-asserts the same
    /// list); `security` still prompts once for the keychain password
    /// because the OS gates the partition-list write on it -- so the
    /// strongest guarantee we can give for the "items exist" case is exactly
    /// one prompt, never the previous per-item storm.
    pub fn repair_service_items(
        service: &str,
        names: &[String],
    ) -> Result<KeychainTrustReport, CredentialError> {
        // Prompt-free short-circuit: nothing stored => nothing to do.
        if !any_item_present(service, names) {
            debug!("No CLX keychain items under '{service}'; nothing to repair (no prompt)");
            return Ok(KeychainTrustReport {
                relaxed: 0,
                missing: names.len(),
                macos: true,
            });
        }

        let keychain_path = login_keychain_path()?;
        let argv = build_partition_list_argv(service, &keychain_path);

        debug!(
            "Running single `security {}` (one keychain-password prompt for ALL items)",
            argv.join(" ")
        );

        // ONE process. ONE prompt. No `-k` on argv: `security` opens its own
        // secure prompt for the login keychain password. We inherit stdio so
        // that prompt reaches the user's terminal / the GUI dialog appears.
        let status = Command::new("/usr/bin/security")
            .args(&argv)
            .status()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CredentialError::ServiceUnavailable(
                        "/usr/bin/security not found; cannot relax keychain partition list".into(),
                    )
                } else {
                    CredentialError::Keychain(format!("failed to spawn /usr/bin/security: {e}"))
                }
            })?;

        if status.success() {
            info!(
                "Relaxed keychain partition list for all '{service}' items in a single operation"
            );
            // `security` does not report a per-item count; report the
            // candidate count we know about so the CLI can render a result.
            Ok(KeychainTrustReport {
                relaxed: names.len(),
                missing: 0,
                macos: true,
            })
        } else {
            // Non-zero exit: wrong password, user cancelled, or locked
            // keychain. No partial per-item state exists because this was a
            // single atomic call. Actionable, never a panic.
            Err(CredentialError::AccessDenied(format!(
                "`security set-generic-password-partition-list` exited with {status}. \
                 This usually means the login-keychain password was incorrect or the \
                 prompt was cancelled. No changes were made; re-run `clx keychain-trust` \
                 and enter your macOS login password."
            )))
        }
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

    #[test]
    fn one_prompt_notice_states_single_password_entry() {
        let n = one_prompt_notice();
        assert!(n.contains("ONCE"));
        assert!(n.to_lowercase().contains("login"));
        assert!(n.contains("Cancel"));
    }

    #[test]
    fn partition_list_includes_unsigned_for_adhoc_binaries() {
        // `unsigned:` is the load-bearing partition: without it the
        // adhoc/unsigned Homebrew `clx` / `clx-mcp` would keep prompting.
        assert!(CLX_PARTITION_LIST.contains("unsigned:"));
        // Apple tooling baseline preserved.
        assert!(CLX_PARTITION_LIST.contains("apple:"));
        assert!(CLX_PARTITION_LIST.contains("apple-tool:"));
    }

    #[test]
    fn argv_is_a_single_partition_list_call_not_a_per_item_loop() {
        let argv = build_partition_list_argv(
            "com.clx.credentials",
            "/Users/u/Library/Keychains/login.keychain-db",
        );
        // The subcommand is the documented single-shot partition-list setter.
        assert_eq!(argv[0], "set-generic-password-partition-list");
        // Service-only match (-s) with NO account filter (-a): one call
        // relaxes every account under the service. This is the structural
        // proof that the repair is one operation, not N.
        assert!(argv.iter().any(|a| a == "-s"));
        assert!(
            !argv.iter().any(|a| a == "-a"),
            "an -a account filter would force one call per account (the bug)"
        );
        // Partition list is passed via -S.
        let s_idx = argv.iter().position(|a| a == "-S").expect("-S present");
        assert_eq!(argv[s_idx + 1], CLX_PARTITION_LIST);
        // Login keychain path is the final positional arg.
        assert_eq!(
            argv.last().unwrap(),
            "/Users/u/Library/Keychains/login.keychain-db"
        );
    }

    #[test]
    fn argv_never_carries_the_keychain_password() {
        let argv = build_partition_list_argv("svc", "/path/login.keychain-db");
        // `-k` (password on argv) must NEVER be emitted: `security` prompts
        // securely for it instead, so the secret never enters the process
        // table / argv.
        assert!(
            !argv.iter().any(|a| a == "-k"),
            "the keychain password must never be placed on argv"
        );
    }

    #[test]
    fn argv_threads_service_name_through_unchanged() {
        let argv = build_partition_list_argv("com.example.svc", "/k");
        let s_idx = argv.iter().position(|a| a == "-s").expect("-s present");
        assert_eq!(argv[s_idx + 1], "com.example.svc");
    }
}
