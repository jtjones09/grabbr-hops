//! A per-daemon shared secret that gates the frontend IPC channel.
//!
//! # Why this exists
//!
//! The frontend channel carries `FrontendRequest::AuthorizeKey` — it can write
//! the KVM's trust store. On unix the listener is a `UnixListener` guarded by
//! filesystem permissions, but on Windows it is a plain
//! `TcpListener::bind("127.0.0.1:5252")` that **any local process can reach**,
//! with no authentication at all. That made the trust store writable by anything
//! running as the user, and plausibly by a web page: `text/plain` is
//! CORS-safelisted, so a `fetch()` needs no preflight, and the listener's
//! line-delimited parser previously skipped unparseable lines instead of hanging
//! up — so an HTTP request's preamble was discarded and a request body carrying
//! valid JSON was executed.
//!
//! The token closes both. It is deliberately **not** `cfg(windows)`-only: the
//! unix path is already permission-protected, but one code path that is compiled
//! and tested everywhere is worth more than a Windows-only branch that no test
//! and no non-Windows build ever exercises.
//!
//! # What it is not
//!
//! This is a *local* authorization boundary, not a cryptographic protocol. Any
//! process that can read the token file can already read `config.toml` and the
//! TLS identity next to it, at which point the machine is lost regardless. The
//! goal is to stop a process (or page) that can *reach a socket* but cannot
//! *read the user's config directory*.

use std::io;
use std::path::PathBuf;

const TOKEN_FILE: &str = "ipc-token";
const TOKEN_BYTES: usize = 32;

/// The token lives with `config.toml`, in the user-scoped config directory —
/// deliberately NOT beside the socket. On macOS the socket is under
/// `~/Library/Caches`, which the OS may purge; a token that vanishes while the
/// daemon still holds it in memory would lock every frontend out with no
/// obvious cause.
///
/// Mirrors the path logic in the `hops` crate's config module (that helper is
/// not reachable from here, and duplicating four lines beats a dependency
/// inversion for it). Honours `XDG_CONFIG_HOME`, which is also what lets the
/// tests point a whole instance at a scratch directory.
pub fn token_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join(TOKEN_FILE))
}

fn config_dir() -> io::Result<PathBuf> {
    let missing = |v: &str| io::Error::new(io::ErrorKind::NotFound, format!("{v} is not set"));
    #[cfg(unix)]
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => {
            PathBuf::from(std::env::var("HOME").map_err(|_| missing("HOME"))?).join(".config")
        }
    };
    #[cfg(not(unix))]
    let base = match std::env::var("LOCALAPPDATA") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(std::env::var("USERPROFILE").map_err(|_| missing("USERPROFILE"))?)
            .join(".config"),
    };
    Ok(base.join("lan-mouse"))
}

/// Read the existing token, or mint one. Called by the daemon at startup.
///
/// The file is created `0600` on unix. On Windows it inherits the ACL of the
/// user's `%LOCALAPPDATA%`, which is already user-scoped — the same protection
/// `config.toml` and the TLS key rely on.
pub fn load_or_create() -> io::Result<String> {
    load_or_create_at(&token_path()?)
}

/// [`load_or_create`] for the token kept at `path`.
pub fn load_or_create_at(path: &std::path::Path) -> io::Result<String> {
    if let Ok(existing) = read_at(path) {
        let existing = existing.trim().to_string();
        // a truncated or hand-mangled token would lock every frontend out with a
        // confusing failure, so replace anything that isn't well-formed
        if existing.len() == TOKEN_BYTES * 2 && existing.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(existing);
        }
        log::warn!("{path:?}: malformed IPC token — minting a new one");
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut raw = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut raw)
        .map_err(|e| io::Error::other(format!("no OS randomness available: {e}")))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    write_private(path, &token)?;
    log::info!("minted a new IPC token at {path:?}");
    Ok(token)
}

/// Read the token. Called by frontends (GUI / TUI / CLI) before connecting.
pub fn read() -> io::Result<String> {
    Ok(read_at(&token_path()?)?.trim().to_string())
}

/// The token file's contents, refusing a link at its path.
///
/// Reading through a link would hand a frontend, or the daemon's own
/// malformed-token check, the contents of whatever was linked there (#196).
#[cfg(unix)]
fn read_at(path: &std::path::Path) -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| link_refused(path, e))?;
    let mut text = String::new();
    f.read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(not(unix))]
fn read_at(path: &std::path::Path) -> io::Result<String> {
    std::fs::read_to_string(path)
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, token: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // 0600 from the moment it exists — never create-then-chmod, which leaves a
    // window where the token is world-readable.
    //
    // O_NOFOLLOW so the write cannot land on whatever a link at this path
    // points at. The daemon is meant to run as the owner of this directory,
    // but one run with more privilege — `sudo -E hops daemon` — would
    // otherwise truncate and overwrite the link's target (#196).
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| link_refused(path, e))?;
    f.write_all(token.as_bytes())
}

/// A refusal caused by a link at `path`, said plainly; anything else unchanged.
///
/// `ELOOP` from an `O_NOFOLLOW` open reads as "Too many levels of symbolic
/// links", which describes a loop the user does not have.
#[cfg(unix)]
fn link_refused(path: &std::path::Path, e: io::Error) -> io::Error {
    if e.raw_os_error() != Some(libc::ELOOP) {
        return e;
    }
    let target = std::fs::read_link(path)
        .map(|t| format!(" to {}", t.display()))
        .unwrap_or_default();
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{}: hops will not write through a symbolic link{target}. \
             Remove the link, then start hops again.",
            path.display()
        ),
    )
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, token: &str) -> io::Result<()> {
    std::fs::write(path, token)
}

/// Constant-time comparison. The offered token arrives from an unauthenticated
/// peer, so an early-exit `==` would leak its correct prefix a byte at a time.
pub fn matches(expected: &str, offered: &str) -> bool {
    let (a, b) = (expected.as_bytes(), offered.as_bytes());
    // length is not secret (it is a fixed-width hex string), but the compare
    // itself must not short-circuit
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(all(test, unix))]
mod links {
    //! A link where the token belongs is refused, and what it points at is left
    //! alone, so a daemon running with more privilege than this directory's
    //! owner cannot be made to overwrite another file (#196).
    use std::io::Write;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hops-token-link-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    // LEDGER T1 | class B | 1 error + 4 file on disk: token::load_or_create_at
    #[test]
    fn a_link_where_the_token_belongs_is_refused_and_its_target_untouched() {
        let d = scratch("mint");
        let target = d.join("someone-elses-file");
        std::fs::write(&target, b"not the token\n").expect("seed");
        let token = d.join("ipc-token");
        std::os::unix::fs::symlink(&target, &token).expect("link");

        let refused = super::load_or_create_at(&token).expect_err("a link must be refused");
        let said = refused.to_string();
        assert!(
            said.contains("symbolic link") && said.contains("ipc-token"),
            "the refusal must name the link: {said}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "not the token\n",
            "the link's target must be untouched"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // LEDGER T2 | class B | 1 error: token::read_at, the frontends' read
    #[test]
    fn reading_a_token_through_a_link_is_refused() {
        let d = scratch("read");
        let target = d.join("a-secret");
        let mut f = std::fs::File::create(&target).expect("seed");
        f.write_all(&[b'a'; 64]).expect("write");
        drop(f);
        let token = d.join("ipc-token");
        std::os::unix::fs::symlink(&target, &token).expect("link");

        let refused = super::read_at(&token).expect_err("a link must be refused");
        assert!(
            refused.to_string().contains("symbolic link"),
            "the refusal must say why: {refused}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn only_the_exact_token_matches() {
        let t = "a".repeat(64);
        assert!(matches(&t, &t.clone()));
        assert!(!matches(&t, &"b".repeat(64)), "different token rejected");
        assert!(!matches(&t, &"a".repeat(63)), "truncated token rejected");
        assert!(!matches(&t, ""), "empty token rejected");
        // a correct prefix must not be treated as a match
        let mut near = "a".repeat(63);
        near.push('b');
        assert!(!matches(&t, &near), "near-miss rejected");
    }
}
