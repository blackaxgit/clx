//! Bounded, TOCTOU-hardened file reads for paths CLX did not choose itself.
//!
//! Three call sites in this codebase read a file whose path is either
//! externally supplied or otherwise not fully trusted (a credential-store
//! file that could have been replaced out from under us, a project
//! instructions file living in a repo we don't control, a config file a
//! user points the CLI at). Reading such a path with plain
//! `std::fs::read`/`read_to_string` has two failure modes:
//!
//! * A FIFO, character device (`/dev/zero`), block device, or socket at the
//!   path blocks or streams forever. A naive `metadata.len()` size check
//!   does not catch this: all of these report length 0, so the check passes
//!   and the subsequent read never terminates (unbounded memory growth ->
//!   OOM/SIGKILL, or the process simply hangs on a FIFO with no writer).
//! * A directory or a legitimate-looking but enormous regular file wastes
//!   CPU and memory if read in full before any size check runs.
//!
//! [`read_bounded`] and [`read_bounded_to_string`] close both holes. They
//! generalize the pattern already established in
//! `clx-hook/src/transcript.rs` (`safe_transcript_path` /
//! `MAX_TRANSCRIPT_BYTES`), with one hardening improvement: this helper
//! calls `File::open` FIRST and `fstat`s the open handle (`file.metadata()`)
//! rather than `std::fs::metadata(path)` on the path, which closes the
//! TOCTOU window between checking the path and opening it. Opening the
//! handle and `fstat`-ing it also already resolves symlinks to the real
//! target, so no separate canonicalization step is needed here (unlike
//! `transcript.rs`, which canonicalizes for its own path-echoing reasons).
//!
//! ## Why the open itself is non-blocking on Unix
//!
//! Opening-before-stat has a sharp edge that the naive fix would reintroduce
//! the exact bug it's meant to close: a plain, blocking `File::open` on a
//! FIFO with **no writer connected** does not return at all until a writer
//! shows up (confirmed empirically: `open()` alone hangs, no `read()`
//! required). That means the open call itself — before we ever get to the
//! file-type check — would hang forever on exactly the FIFO case this
//! module exists to reject. To avoid that, the Unix open path sets
//! `O_NONBLOCK`. Per POSIX this makes a read-only FIFO open return
//! immediately regardless of whether a writer is attached; it has no effect
//! on regular files (open and read never block on those), so the flag is a
//! no-op for the common case and only changes behavior for the exact
//! pathological case it targets. The file-type check below still runs
//! before any `read`, so a FIFO is rejected without the process ever
//! blocking on it.
//!
//! This module never logs. Callers decide whether a rejection is a
//! best-effort skip (`warn!` + continue) or a hard error, and whether the
//! path needs `redact_secrets` before it appears in a log line or error
//! message.

use std::fs::{File, FileType};
use std::io::{ErrorKind, Read};
use std::path::Path;

/// Open `path` read-only such that the open call itself cannot block.
///
/// On Unix this sets `O_NONBLOCK`, which is what prevents a blocking hang
/// when `path` is a FIFO with no writer attached (see module docs). The
/// flag is inert for regular files. Non-Unix targets have no equivalent
/// named-pipe-at-a-path hazard reachable via `std::fs::File::open`, so a
/// plain open is used there.
fn open_nonblocking(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

/// Error returned by [`read_bounded`] / [`read_bounded_to_string`].
///
/// Variants are distinct — rather than a single IO error bucket — so
/// callers can tell "there is no file here" (often a legitimate, silent
/// case) apart from "there IS something here but we refuse to read it"
/// (never silent: treating a refusal as equivalent to "absent" can be
/// actively harmful, e.g. the credentials-store call site, which must not
/// let a directory or FIFO dropped at `credentials.age` be mistaken for
/// "no credentials yet" and subsequently overwritten).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No file exists at the given path. Mapped from `ErrorKind::NotFound`
    /// on `File::open`.
    #[error("file not found")]
    NotFound,

    /// The path exists but is not a regular file: FIFO, character or block
    /// device, directory, or socket. All of these report
    /// `metadata.len() == 0`, which is exactly why this check must run
    /// before, and independently of, the size check below — a size-only
    /// guard would let every one of them through.
    #[error("not a regular file: {file_type:?}")]
    NotRegularFile {
        /// The actual file type found at the path.
        file_type: FileType,
    },

    /// The path is a regular file, but its size (read via `fstat` on the
    /// already-open handle) exceeds the caller-supplied cap.
    #[error("file is {len} bytes, exceeding the {cap} byte cap")]
    TooLarge {
        /// Size reported by `fstat`.
        len: u64,
        /// Cap the caller passed in.
        cap: u64,
    },

    /// Any other IO failure: opening (other than not-found), reading, or
    /// (for [`read_bounded_to_string`]) the file's bytes not being valid
    /// UTF-8 (reported as `ErrorKind::InvalidData`).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Read up to `cap` bytes from the regular file at `path`.
///
/// Rejects (see [`Error`]):
/// * a missing path (`Error::NotFound`);
/// * anything that is not a regular file (`Error::NotRegularFile`) — this
///   is what catches a FIFO, character/block device, directory, or socket,
///   all of which would otherwise pass a naive `len() == 0` size check;
/// * a regular file whose `fstat`-reported size exceeds `cap`
///   (`Error::TooLarge`).
///
/// Even after the size gate passes, the actual read is still bounded by
/// `Read::take(cap)`: a regular file can grow between the `fstat` and the
/// read (a second, narrower TOCTOU window than the path-vs-handle one that
/// opening-then-`fstat`-ing already closed), so the reader itself must
/// never trust the earlier length forever.
pub fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, Error> {
    let file = open_nonblocking(path).map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            Error::NotFound
        } else {
            Error::Io(e)
        }
    })?;

    // fstat the OPEN handle, not `std::fs::metadata(path)`: stat-then-open
    // leaves a window where the path can be swapped between the check and
    // the open (TOCTOU). fstat on an already-open fd has no such window.
    let metadata = file.metadata()?;

    if !metadata.file_type().is_file() {
        return Err(Error::NotRegularFile {
            file_type: metadata.file_type(),
        });
    }

    let len = metadata.len();
    if len > cap {
        return Err(Error::TooLarge { len, cap });
    }

    // Pre-allocate by the bounded, already-validated length -- never by a
    // raw untrusted value -- then still read through `take(cap)` in case
    // the file grows between the fstat above and this read.
    let prealloc = usize::try_from(len.min(cap)).unwrap_or(usize::MAX);
    let mut buf = Vec::with_capacity(prealloc);
    file.take(cap).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Like [`read_bounded`], but decodes the result as UTF-8.
///
/// Invalid UTF-8 is reported as `Error::Io` with `ErrorKind::InvalidData`,
/// matching how `std::fs::read_to_string` folds the same failure into
/// `io::Error`.
pub fn read_bounded_to_string(path: &Path, cap: u64) -> Result<String, Error> {
    let bytes = read_bounded(path, cap)?;
    String::from_utf8(bytes).map_err(|e| Error::Io(std::io::Error::new(ErrorKind::InvalidData, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).expect("create test file");
        f.write_all(bytes).expect("write test file");
        path
    }

    #[test]
    fn happy_path_reads_back_byte_identical() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_file(tmp.path(), "small.txt", b"hello bounded world");

        let bytes = read_bounded(&path, 1024).expect("read_bounded should succeed");
        assert_eq!(bytes, b"hello bounded world");

        let text = read_bounded_to_string(&path, 1024).expect("read_bounded_to_string");
        assert_eq!(text, "hello bounded world");
    }

    #[test]
    fn one_byte_over_cap_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_file(tmp.path(), "over.bin", &[0u8; 11]);

        let err =
            read_bounded(&path, 10).expect_err("11 bytes over a 10 byte cap must be rejected");
        match err {
            Error::TooLarge { len, cap } => {
                assert_eq!(len, 11);
                assert_eq!(cap, 10);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn exactly_at_cap_is_accepted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_file(tmp.path(), "exact.bin", &[7u8; 10]);

        let bytes = read_bounded(&path, 10).expect("exactly-at-cap file must be accepted");
        assert_eq!(bytes.len(), 10);
    }

    #[test]
    fn missing_path_is_not_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.txt");

        let err = read_bounded(&path, 1024).expect_err("missing file must error");
        assert!(matches!(err, Error::NotFound));
    }

    #[test]
    fn directory_is_not_a_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("a-directory");
        fs::create_dir(&dir_path).expect("mkdir");

        let err = read_bounded(&dir_path, 1024).expect_err("directory must be rejected");
        match err {
            Error::NotRegularFile { file_type } => assert!(file_type.is_dir()),
            other => panic!("expected NotRegularFile, got {other:?}"),
        }
    }

    #[test]
    fn invalid_utf8_is_reported_as_io_invalid_data() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_file(tmp.path(), "invalid.bin", &[0xFF, 0xFE, 0xFD]);

        let err = read_bounded_to_string(&path, 1024).expect_err("invalid UTF-8 must error");
        match err {
            Error::Io(io_err) => assert_eq!(io_err.kind(), ErrorKind::InvalidData),
            other => panic!("expected Io(InvalidData), got {other:?}"),
        }
    }

    // FIFOs are unix-only. No `nix`/`libc` dev-dependency exists in this
    // crate (checked before adding this test), so the FIFO is created by
    // shelling out to the `mkfifo` binary rather than pulling in a new
    // dependency just for one test. If `mkfifo` is unavailable in the test
    // environment, the test skips instead of failing.
    #[cfg(unix)]
    #[test]
    fn fifo_is_not_a_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fifo_path = tmp.path().join("a-fifo");

        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status();
        let Ok(status) = status else {
            eprintln!("skipping fifo_is_not_a_regular_file: `mkfifo` not available");
            return;
        };
        if !status.success() {
            eprintln!("skipping fifo_is_not_a_regular_file: `mkfifo` failed");
            return;
        }

        // No writer is ever connected to this FIFO. A plain blocking
        // `File::open` would hang here indefinitely (verified: the open
        // call itself blocks on a writerless FIFO, not just the read) --
        // that is precisely the hang `open_nonblocking`'s `O_NONBLOCK` is
        // there to prevent. This call must return promptly with
        // `NotRegularFile` rather than hang the test.
        let err = read_bounded(&fifo_path, 1024).expect_err("FIFO must be rejected");
        match err {
            Error::NotRegularFile { file_type } => {
                assert!(!file_type.is_file());
            }
            other => panic!("expected NotRegularFile, got {other:?}"),
        }
    }
}
