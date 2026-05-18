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
use clx_core::credentials::keychain_acl::trust_tradeoff_notice;

use crate::Cli;

/// Handle `clx keychain-trust`.
pub fn cmd_keychain_trust(cli: &Cli) -> Result<()> {
    let store = CredentialStore::new();

    let report = store
        .repair_keychain_trust()
        .context("Failed to relax keychain ACL on CLX credential items")?;

    if !report.macos {
        // Non-macOS: nothing to do, exit 0 cleanly.
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
    } else {
        println!(
            "{} Relaxed keychain ACL on {} CLX credential item{} ({} not present).",
            "Success:".green().bold(),
            report.relaxed,
            if report.relaxed == 1 { "" } else { "s" },
            report.missing,
        );
        println!();
        println!("{}", trust_tradeoff_notice().yellow());
        println!();
        println!("macOS should no longer prompt for the CLX keychain password on launch.");
    }

    Ok(())
}
