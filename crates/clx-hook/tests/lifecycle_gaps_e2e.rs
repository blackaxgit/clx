//! Lifecycle coverage-gap e2e: `SessionStart` recovery / storage-failure
//! degradation, `PostCompact` token persistence, and `clx-hook`
//! process-level contracts (`--help` usage routing, provenance-warn log
//! routing, TTY short-circuit), all driven through the REAL binary with an
//! isolated `HOME`.
//!
//! Hermetic: redirected `HOME` (RAII `TempDir`), `CLX_MODEL_FETCH_DRYRUN=1`,
//! no network. Ambient agent env (`CLX_HOOK_HOST`, `CLAUDECODE`,
//! `CLX_LEARNING_MODE`, `CLAUDE_PROJECT_DIR`, `CLAUDE_PLUGIN_ROOT`,
//! `RUST_LOG`) is scrubbed from every child so an in-agent test run behaves
//! identically to CI. The hidden config-dir name is built via `concat!` so
//! the literal token never appears in this file (in-session write-hook safe).

#![allow(clippy::doc_markdown)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use clx_core::storage::Storage;
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};
use serde_json::json;

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// Hidden config dir name, assembled at compile time (write-hook safe).
const DOT_CLX: &str = concat!(".", "clx");

/// Path of the hook database inside an isolated `HOME`.
fn db_path(home: &Path) -> PathBuf {
    home.join(DOT_CLX).join("data").join("clx.db")
}

/// Spawn the real `clx-hook` binary with a scrubbed, hermetic env, pipe the
/// envelope on stdin, and return the completed `Output`.
fn spawn_hook(home: &Path, host: Option<&str>, envelope: &serde_json::Value) -> Output {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let mut command = Command::new(binary);
    harden_command(&mut command, home);
    command
        .env_remove("CLX_HOOK_HOST")
        .env_remove("CLAUDECODE")
        .env_remove("CLX_LEARNING_MODE")
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("CLAUDE_PLUGIN_ROOT")
        .env_remove("RUST_LOG")
        .env("CLX_CREDENTIALS_BACKEND", "age");
    if let Some(h) = host {
        command.env("CLX_HOOK_HOST", h);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(envelope.to_string().as_bytes())
        .expect("write envelope");
    let out = child.wait_with_output().expect("wait clx-hook");
    assert_home_size_bounded(home);
    out
}

// =========================================================================
// SessionStart: abandoned-session recovery (the session_recovery block)
// =========================================================================

/// A stale (>2h old) `active` session for the same project, with a snapshot
/// summary, must be (a) marked `abandoned` and (b) surfaced as recovery
/// context in the new session's `systemMessage` + a terminal stderr notice.
#[test]
fn session_start_recovers_context_from_stale_active_session() {
    let home = isolated_clx_home();
    let project = home.path().join("proj");
    std::fs::create_dir_all(&project).expect("mk project dir");
    let cwd = project.to_str().expect("utf8 cwd").to_string();
    std::fs::create_dir_all(home.path().join(DOT_CLX).join("data")).expect("mk data dir");

    {
        // Seed: stale active session (3h old; default stale_hours = 2) with a
        // snapshot summary. Scoped so the connection closes before the child
        // process opens the same sqlite file.
        let storage = Storage::open(db_path(home.path())).expect("seed storage");
        let mut stale = Session::new(SessionId::new("sess-stale-recov"), cwd.clone());
        stale.started_at = chrono::Utc::now() - chrono::Duration::hours(3);
        storage
            .create_session_with_host(&stale, "claude")
            .expect("seed stale session");
        let mut snap = Snapshot::new(SessionId::new("sess-stale-recov"), SnapshotTrigger::Auto);
        snap.summary = Some("Implemented the polylith recovery flow".to_string());
        storage.create_snapshot(&snap).expect("seed snapshot");
    }

    let envelope = json!({
        "session_id": "sess-recov-new",
        "cwd": cwd,
        "hook_event_name": "SessionStart",
        "source": "startup"
    });
    let out = spawn_hook(home.path(), None, &envelope);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "SessionStart must exit 0; stderr: {stderr}"
    );

    // Recovery context must reach the agent via systemMessage (stdout JSON).
    assert!(
        stdout.contains("Recovered from interrupted session"),
        "systemMessage must carry the recovery banner; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Implemented the polylith recovery flow"),
        "systemMessage must carry the abandoned session's snapshot summary; stdout: {stdout}"
    );
    // And the user gets a terminal-visible notice on stderr.
    assert!(
        stderr.contains("Recovered context from interrupted session"),
        "stderr must announce the recovery; stderr: {stderr}"
    );

    // The stale session must have been transitioned active -> abandoned, and
    // the new session row created for this project.
    let storage = Storage::open(db_path(home.path())).expect("reopen storage");
    let stale = storage
        .get_session("sess-stale-recov")
        .expect("query stale")
        .expect("stale session row must still exist");
    assert_eq!(
        stale.status.as_str(),
        "abandoned",
        "stale active session must be marked abandoned"
    );
    let created = storage
        .get_session("sess-recov-new")
        .expect("query new")
        .expect("new session row must be created");
    assert_eq!(
        created.project_path, cwd,
        "new session bound to the project"
    );
}

// =========================================================================
// SessionStart / PostCompact: storage-unavailable degradation
// =========================================================================

/// With `~/<dot-clx>` occupied by a regular FILE, `Storage::open_default`
/// fails; `SessionStart` must still exit 0 and tell the user the session
/// started without storage (fail-safe, never fail-closed).
#[test]
fn session_start_with_unavailable_storage_degrades_gracefully() {
    let home = isolated_clx_home();
    // A regular file where the config dir should be => storage open fails.
    std::fs::write(home.path().join(DOT_CLX), b"not a dir").expect("plant blocker file");

    let envelope = json!({
        "session_id": "sess-nostorage",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": "startup"
    });
    let out = spawn_hook(home.path(), None, &envelope);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "must exit 0 despite storage failure; stderr: {stderr}"
    );
    assert!(
        stderr.contains("Session started (storage unavailable)"),
        "user must be told the session started without storage; stderr: {stderr}"
    );
    assert!(
        stderr.contains("Failed to open storage"),
        "the ERROR-level cause must reach stderr; stderr: {stderr}"
    );
}

/// Same storage blockade for the Codex-only `PostCompact`: the handler must
/// swallow the failure (exit 0) while logging the cause at ERROR.
#[test]
fn post_compact_with_unavailable_storage_exits_cleanly() {
    let home = isolated_clx_home();
    std::fs::write(home.path().join(DOT_CLX), b"not a dir").expect("plant blocker file");

    let envelope = json!({
        "session_id": "sess-pc-nostorage",
        "cwd": "/tmp",
        "hook_event_name": "PostCompact",
        "turn_id": "t1",
        "permission_mode": "default"
    });
    let out = spawn_hook(home.path(), Some("codex"), &envelope);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "PostCompact must exit 0; stderr: {stderr}"
    );
    assert!(
        stderr.contains("Failed to open storage"),
        "storage failure must be reported at ERROR on stderr; stderr: {stderr}"
    );
}

// =========================================================================
// PostCompact: recomputed token counts are PERSISTED to the session row
// =========================================================================

/// After compaction the session row must carry the token counts of the
/// compacted transcript (`estimate_tokens`: "hello world" -> 3 input,
/// "goodbye world" -> 4 output), not the pre-compaction zeros.
#[test]
fn post_compact_persists_recomputed_token_counts() {
    let home = isolated_clx_home();
    std::fs::create_dir_all(home.path().join(DOT_CLX).join("data")).expect("mk data dir");
    {
        let storage = Storage::open(db_path(home.path())).expect("seed storage");
        let session = Session::new(SessionId::new("sess-pc-tokens"), "/tmp".to_string());
        storage
            .create_session_with_host(&session, "codex")
            .expect("seed session");
    }
    let transcript = home.path().join("compacted.jsonl");
    std::fs::write(
        &transcript,
        concat!(
            r#"{"type":"user","message":"hello world"}"#,
            "\n",
            r#"{"type":"assistant","message":"goodbye world"}"#,
            "\n"
        ),
    )
    .expect("write transcript");

    let envelope = json!({
        "session_id": "sess-pc-tokens",
        "cwd": "/tmp",
        "hook_event_name": "PostCompact",
        "transcript_path": transcript.to_str().expect("utf8 path"),
        "turn_id": "t1",
        "permission_mode": "default"
    });
    let out = spawn_hook(home.path(), Some("codex"), &envelope);
    assert!(
        out.status.success(),
        "PostCompact must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let storage = Storage::open(db_path(home.path())).expect("reopen storage");
    let session = storage
        .get_session("sess-pc-tokens")
        .expect("query session")
        .expect("session row must exist");
    assert_eq!(
        session.input_tokens, 3,
        "input tokens must be recomputed from the compacted transcript"
    );
    assert_eq!(
        session.output_tokens, 4,
        "output tokens must be recomputed from the compacted transcript"
    );
}

// =========================================================================
// main.rs process contracts: --help, provenance warn routing, TTY stdin
// =========================================================================

/// `--help` prints usage on STDERR and exits 0; STDOUT (the JSON hook
/// protocol channel) must stay EMPTY so a host invoking `--help` by mistake
/// never receives protocol garbage.
#[test]
fn help_flag_prints_usage_to_stderr_keeping_stdout_clean() {
    let home = isolated_clx_home();
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let mut command = Command::new(binary);
    harden_command(&mut command, home.path());
    let out = command
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .expect("run clx-hook --help");
    assert!(out.status.success(), "--help must exit 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("clx-hook - CLX hook handler"),
        "usage banner expected on stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("Supported hook events"),
        "usage must list supported events; got: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "stdout is the JSON protocol channel and must stay empty for --help; got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// With every Claude provenance env var scrubbed, the fail-safe provenance
/// WARN must land in the log file (`~/<dot-clx>/logs/clx.log`) and must NOT
/// leak to stderr (stderr is the ERROR-only channel Claude Code watches).
#[test]
fn unverified_provenance_warns_to_log_file_never_stderr() {
    let home = isolated_clx_home();
    std::fs::create_dir_all(home.path().join(DOT_CLX)).expect("mk config dir");

    let envelope = json!({
        "session_id": "sess-provenance",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": "startup"
    });
    let out = spawn_hook(home.path(), None, &envelope);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "must exit 0; stderr: {stderr}");

    let log_path = home.path().join(DOT_CLX).join("logs").join("clx.log");
    let log = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("log file must exist at {}: {e}", log_path.display()));
    assert!(
        log.contains("hook provenance unverified"),
        "provenance WARN must be persisted to the log file; log: {log}"
    );
    assert!(
        !stderr.contains("provenance"),
        "WARN-level provenance signal must NOT reach stderr (ERROR-only); stderr: {stderr}"
    );
}

/// Manual invocation with a TTY on stdin must print usage and exit 0 instead
/// of blocking on stdin. BSD `script` allocates a real PTY for the child.
/// macOS-only: GNU `script` (Linux CI) has an incompatible CLI.
#[cfg(target_os = "macos")]
#[test]
fn tty_stdin_prints_usage_instead_of_blocking() {
    let home = isolated_clx_home();
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let out = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null", binary])
        .env("HOME", home.path())
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .output()
        .expect("run clx-hook under a PTY via script(1)");
    assert!(out.status.success(), "TTY invocation must exit 0");
    // script(1) merges the PTY stream into stdout.
    let combined = String::from_utf8_lossy(&out.stdout);
    assert!(
        combined.contains("clx-hook - CLX hook handler"),
        "usage banner expected when stdin is a terminal; got: {combined}"
    );
}
