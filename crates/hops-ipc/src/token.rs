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
        Err(_) => PathBuf::from(std::env::var("HOME").map_err(|_| missing("HOME"))?).join(".config"),
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
    let path = token_path()?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
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
    write_private(&path, &token)?;
    log::info!("minted a new IPC token at {path:?}");
    Ok(token)
}

/// Read the token. Called by frontends (GUI / TUI / CLI) before connecting.
pub fn read() -> io::Result<String> {
    Ok(std::fs::read_to_string(token_path()?)?.trim().to_string())
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, token: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // 0600 from the moment it exists — never create-then-chmod, which leaves a
    // window where the token is world-readable.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(token.as_bytes())
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
