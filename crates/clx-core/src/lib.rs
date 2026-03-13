//! CLX Core Library
//!
//! This crate provides the core functionality for the CLX Claude Code extension:
//! - Command validation and policy enforcement
//! - Context persistence with `SQLite` storage
//! - Shared types and error definitions
//! - Configuration management

pub mod config;
pub mod credentials;
pub mod embeddings;
pub mod error;
pub mod ollama;
pub mod paths;
pub mod policy;
pub mod recall;
pub mod redaction;
pub mod storage;
pub mod text;
pub mod types;

pub use error::{Error, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
