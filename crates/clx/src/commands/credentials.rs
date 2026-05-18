//! Credentials command: manage credentials in the configured backend.
//!
//! The default backend is a local age-encrypted file (`~/.clx/credentials.age`)
//! that NEVER touches the macOS keychain and never prompts. `clx credentials
//! migrate` is the only path that may read the legacy keychain, and only
//! when the user explicitly runs it.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

use clx_core::config::{Config, ProviderConfig};
use clx_core::credentials::{CredentialBackendKind, CredentialStore};

use crate::Cli;
use crate::types::CredentialsListOutput;

#[derive(Subcommand)]
pub enum CredentialsAction {
    /// Store a credential in the configured credential backend (encrypted
    /// file by default, macOS keychain only if opted in)
    Set {
        /// Credential key (e.g., `OPENAI_API_KEY`)
        key: String,
        /// Credential value
        value: String,
    },

    /// Retrieve a credential from the configured credential backend
    /// (encrypted file by default, macOS keychain only if opted in)
    Get {
        /// Credential key to retrieve
        key: String,
    },

    /// List all stored credential keys
    List,

    /// Delete a credential from the configured backend
    Delete {
        /// Credential key to delete
        key: String,
    },

    /// Migrate a credential from the legacy macOS keychain into the
    /// configured (file) backend. Explicit/opt-in: this is the ONLY command
    /// that may read the old keychain (a single macOS prompt may appear,
    /// only if the secret is keychain-only).
    Migrate {
        /// Credential key to migrate (e.g. `azure-prod-api-key`).
        key: String,
    },
}

/// Credentials management command handler
pub fn cmd_credentials(cli: &Cli, action: &CredentialsAction) -> Result<()> {
    // Use the configured backend (default `file`). Loading config never
    // touches the keychain.
    let kind = Config::load()
        .ok()
        .and_then(|c| c.credential_backend_kind().ok())
        .unwrap_or(CredentialBackendKind::File);
    let store = CredentialStore::from_config(kind);

    match action {
        CredentialsAction::Set { key, value } => {
            store
                .store(key, value)
                .context("Failed to store credential")?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "set",
                        "key": key,
                        "success": true
                    })
                );
            } else {
                println!(
                    "{} Credential '{}' stored successfully.",
                    "Success:".green().bold(),
                    key.cyan()
                );
            }
        }

        CredentialsAction::Get { key } => {
            match store.get(key) {
                Ok(Some(value)) => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "key": key,
                                "value": value
                            })
                        );
                    } else {
                        // Print only the value for easy piping
                        println!("{value}");
                    }
                }
                Ok(None) => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "key": key,
                                "value": null,
                                "error": "Credential not found"
                            })
                        );
                    } else {
                        anyhow::bail!("Credential '{key}' not found");
                    }
                }
                Err(e) => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "key": key,
                                "error": e.to_string()
                            })
                        );
                    } else {
                        anyhow::bail!("Failed to retrieve credential '{key}': {e}");
                    }
                }
            }
        }

        CredentialsAction::List => {
            let keys = store.list().context("Failed to list credentials")?;

            // Load providers for annotation (best-effort; ignore errors so the
            // list command still works when the config is absent or malformed).
            let providers = Config::load().map(|c| c.providers).unwrap_or_default();

            if cli.json {
                let output = CredentialsListOutput {
                    credentials: keys.clone(),
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "Stored Credentials".cyan().bold());
                println!("{}", "=".repeat(40));
                println!();

                if keys.is_empty() {
                    println!("{}", "No credentials stored.".dimmed());
                } else {
                    for key in &keys {
                        // Annotate keys of the form `<provider-name>-api-key`
                        // when that provider name is present in the loaded
                        // config. The canonical credential naming uses a
                        // hyphen separator (e.g. `azure-prod-api-key`).
                        let annotation = key
                            .strip_suffix("-api-key")
                            .and_then(|provider_name| providers.get(provider_name))
                            .map(|pc| {
                                let kind = match pc {
                                    ProviderConfig::Ollama(_) => "ollama",
                                    ProviderConfig::AzureOpenai(_) => "azure_openai",
                                };
                                format!(" ({kind})")
                            })
                            .unwrap_or_default();
                        println!("  {} {}{}", "*".green(), key, annotation.dimmed());
                    }
                    println!();
                    println!(
                        "Total: {} credential{}",
                        keys.len(),
                        if keys.len() == 1 { "" } else { "s" }
                    );
                }
            }
        }

        CredentialsAction::Migrate { key } => {
            // Already resolvable without the keychain? Then do NOT read it
            // (avoids reintroducing the prompt for no reason).
            if let Ok(Some(_)) = store.get(key) {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "action": "migrate",
                            "key": key,
                            "migrated": false,
                            "reason": "already present in the configured backend"
                        })
                    );
                } else {
                    println!(
                        "{} '{}' is already in the {} backend; nothing to migrate.",
                        "OK:".green().bold(),
                        key.cyan(),
                        store.backend_label()
                    );
                }
                return Ok(());
            }

            // Explicit, opt-in single keychain read. THIS is the only place
            // a single macOS keychain prompt may appear, and only because
            // the user ran `migrate` and the secret is keychain-only.
            let keychain = CredentialStore::from_config(CredentialBackendKind::Keychain);
            match keychain.get(key) {
                Ok(Some(value)) => {
                    store
                        .store(key, &value)
                        .context("Failed to write migrated credential to file backend")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "action": "migrate",
                                "key": key,
                                "migrated": true
                            })
                        );
                    } else {
                        println!(
                            "{} Migrated '{}' from the macOS keychain into the {} \
                             backend. Future reads are local-file only (zero prompts).",
                            "Success:".green().bold(),
                            key.cyan(),
                            store.backend_label()
                        );
                    }
                }
                Ok(None) => {
                    anyhow::bail!(
                        "no credential '{key}' found in the legacy keychain (nothing to \
                         migrate). If you have the secret, run: clx credentials set {key} \
                         '<your-key>'"
                    );
                }
                Err(e) => {
                    anyhow::bail!("failed to read '{key}' from the legacy keychain: {e}");
                }
            }
        }

        CredentialsAction::Delete { key } => {
            store.delete(key).context("Failed to delete credential")?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "delete",
                        "key": key,
                        "success": true
                    })
                );
            } else {
                println!(
                    "{} Credential '{}' deleted.",
                    "Success:".green().bold(),
                    key.cyan()
                );
            }
        }
    }

    Ok(())
}
