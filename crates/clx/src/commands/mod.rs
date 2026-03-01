//! Command handlers for the CLX CLI.

pub mod config;
pub mod credentials;
pub mod embeddings;
pub mod install;
pub mod recall;
pub mod rules;
pub mod version;

// Re-export command handlers for convenient access
pub use config::cmd_config;
pub use credentials::cmd_credentials;
pub use embeddings::{cmd_embed_backfill, cmd_embeddings};
pub use install::{cmd_install, cmd_uninstall};
pub use recall::cmd_recall;
pub use rules::cmd_rules;
pub use version::{cmd_default, cmd_version};

// Re-export subcommand enums needed by the CLI dispatch
pub use config::ConfigAction;
pub use credentials::CredentialsAction;
pub use embeddings::EmbeddingsAction;
pub use rules::RulesAction;
