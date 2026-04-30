//! CLX Core Library
//!
//! This crate provides the core functionality for the CLX Claude Code extension:
//! - Command validation and policy enforcement
//! - Context persistence with `SQLite` storage
//! - Shared types and error definitions
//! - Configuration management

pub mod config;
pub mod credentials;
pub mod llm;
pub mod embeddings;
pub mod error;
pub mod llm_health;
pub mod paths;
pub mod policy;
pub mod recall;
pub mod redaction;
pub mod storage;
pub mod text;
pub mod types;

pub use error::{Error, Result};

use std::sync::Once;

static SQLITE_VEC_INIT: Once = Once::new();

/// Initialize the sqlite-vec extension for all future `SQLite` connections.
///
/// Uses `sqlite3_auto_extension` to register the vec0 virtual table module
/// so that every new `rusqlite::Connection` automatically has vector search
/// capability. Safe to call multiple times (only executes once).
///
/// # Safety
/// Uses `unsafe` for FFI call to `sqlite3_auto_extension` and `std::mem::transmute`
/// to cast the C function pointer. This is the documented pattern from the
/// sqlite-vec crate: <https://alexgarcia.xyz/sqlite-vec/rust.html>
#[allow(unsafe_code)]
pub fn init_sqlite_vec() {
    SQLITE_VEC_INIT.call_once(|| {
        unsafe {
            rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute::<
                *const (),
                unsafe extern "C" fn(
                    *mut rusqlite::ffi::sqlite3,
                    *mut *const i8,
                    *const rusqlite::ffi::sqlite3_api_routines,
                ) -> i32,
            >(
                sqlite_vec::sqlite3_vec_init as *const (),
            )));
        }
        tracing::debug!("sqlite-vec extension registered via sqlite3_auto_extension");
    });
}

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
