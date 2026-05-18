//! `clx keychain-trust` command.
//!
//! Re-applies a permissive "any application on this user account"
//! `SecAccess` to CLX's macOS Keychain credential items so the keychain
//! stops re-prompting on every launch of the adhoc-signed Homebrew binary.
//!
//! New items get this access automatically at store time (see
//! `clx_core::credentials::keychain_acl`). This command exists to repair
//! items created by pre-0.8.0 CLX, which still carry the default restrictive
//! ACL.
//!
//! macOS only. On every other OS it prints a clear no-op message and exits 0
//! (Linux Secret Service / Windows Credential Manager do not have the
//! adhoc-binary re-prompt problem).

use anyhow::{Context, Result};
use colored::Colorize;

use clx_core::credentials::CredentialStore;
use clx_core::credentials::keychain_acl::{one_prompt_notice, trust_tradeoff_notice};

use crate::Cli;

/// Handle `clx keychain-trust`.
///
/// On macOS this performs the repair with AT MOST ONE password prompt: a
/// single `/usr/bin/security set-generic-password-partition-list` call
/// relaxes every CLX credential item at once. We tell the user about that
/// one prompt up front (human output only -- never on the JSON path, which
/// must stay machine-clean) so the keychain dialog is expected, not
/// surprising. When no CLX items exist the repair short-circuits with zero
/// prompts.
pub fn cmd_keychain_trust(cli: &Cli) -> Result<()> {
    let store = CredentialStore::new();

    // Up-front, one-time heads-up about the single login-keychain prompt.
    // Stdout-safe to suppress under --json so piped/automated output is not
    // polluted; the user running it interactively still sees it.
    if !cli.json && cfg!(target_os = "macos") {
        println!("{}", one_prompt_notice().yellow());
        println!();
    }

    let report = store
        .repair_keychain_trust()
        .context("Failed to relax keychain ACL on CLX credential items")?;

    if !report.macos {
        // Non-macOS: nothing to do, exit 0 cleanly. Unchanged no-op.
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "platform": "non-macos",
                    "status": "noop",
                    "message": "keychain trust is a macOS-only concern; nothing to do",
                })
            );
        } else {
            println!("keychain trust is a macOS-only concern; nothing to do.");
        }
        return Ok(());
    }

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "platform": "macos",
                "status": "ok",
                "relaxed": report.relaxed,
                "missing": report.missing,
                "tradeoff": trust_tradeoff_notice(),
            })
        );
    } else if report.relaxed == 0 {
        // Prompt-free short-circuit: nothing stored, so nothing to repair.
        println!(
            "{} No CLX keychain items found; nothing to relax (no password prompt needed).",
            "OK:".green().bold(),
        );
    } else {
        println!(
            "{} Relaxed the keychain partition list for all CLX credential items \
             in a single operation.",
            "Success:".green().bold(),
        );
        println!();
        println!("{}", trust_tradeoff_notice().yellow());
        println!();
        println!(
            "macOS should no longer prompt for the CLX keychain password on launch. \
             Re-running this command is safe (idempotent)."
        );
    }

    Ok(())
}
