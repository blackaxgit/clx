//! Integration test: the startup version-skew warning must go to STDERR only.
//!
//! clx-hook's STDOUT carries the JSON hook protocol consumed by the host
//! (Claude Code). A warning leaking onto STDOUT would corrupt that protocol, so
//! we run the real binary against a tempdir HOME (which makes `clx_dir()`
//! resolve to `<tmp>/.clx`) holding a stale stamp and assert the warning lands
//! on STDERR while STDOUT stays clean.
//!
//! No `CLX_HOME` seam is used (deliberately, per project constraints): the home
//! is steered purely through the standard `HOME` env var that `dirs::home_dir`
//! already honors.

use std::fs;
use std::path::Path;
use std::process::Command;

fn hook_bin() -> &'static str {
    env!("CARGO_BIN_EXE_clx-hook")
}

/// Run the real clx-hook with `home` as HOME and empty piped stdin, returning
/// (stdout, stderr). Piped (non-terminal) stdin is required so the binary takes
/// the hook-processing path rather than the usage short-circuit.
fn run_hook_with_home(home: &Path) -> (String, String) {
    use std::process::Stdio;

    let mut child = Command::new(hook_bin())
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");

    // Drop stdin immediately so the child reads EOF on an empty payload.
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait clx-hook");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn skew_warning_goes_to_stderr_not_stdout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path();
    let bin = home.join(".clx").join("bin");
    fs::create_dir_all(&bin).expect("create bin dir");
    // Stale stamp: a version that cannot match the running binary.
    fs::write(bin.join(".clx-version"), "0.0.0-stale\n").expect("write stamp");

    let (stdout, stderr) = run_hook_with_home(home);

    assert!(
        !stdout.contains("version skew"),
        "skew warning must NOT appear on STDOUT (would corrupt the hook protocol); stdout was: {stdout:?}"
    );
    assert!(
        stderr.contains("CLX version skew"),
        "skew warning must appear on STDERR; stderr was: {stderr:?}"
    );
    assert!(
        stderr.contains("0.0.0-stale"),
        "warning must name the stale installed version; stderr was: {stderr:?}"
    );
}

#[test]
fn no_warning_when_no_stamp_present() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path();
    // No .clx/bin/.clx-version stamp: CLX is not installed, so no skew reported.

    let (stdout, stderr) = run_hook_with_home(home);

    assert!(
        !stderr.contains("version skew"),
        "absent stamp must not produce a skew warning; stderr was: {stderr:?}"
    );
    assert!(
        !stdout.contains("version skew"),
        "absent stamp must not write skew to STDOUT either; stdout was: {stdout:?}"
    );
}
