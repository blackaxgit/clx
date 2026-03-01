//! Credentials command: manage credentials stored in the system keychain.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

use clx_core::credentials::CredentialStore;

use crate::Cli;
use crate::types::CredentialsListOutput;

#[derive(Subcommand)]
pub enum CredentialsAction {
    /// Store a credential in the system keychain
    Set {
        /// Credential key (e.g., `OPENAI_API_KEY`)
        key: String,
        /// Credential value
        value: String,
    },

    /// Retrieve a credential from the system keychain
    Get {
        /// Credential key to retrieve
        key: String,
    },

    /// List all stored credential keys
    List,

    /// Delete a credential from the system keychain
    Delete {
        /// Credential key to delete
        key: String,
    },
}

/// Credentials management command handler
pub fn cmd_credentials(cli: &Cli, action: &CredentialsAction) -> Result<()> {
    let store = CredentialStore::new();

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
                        println!("  {} {}", "*".green(), key);
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
