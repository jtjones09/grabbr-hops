//! A per-daemon shared secret that gates the frontend IPC channel.
//!
//! # Why this exists
//!
//! The frontend channel carries `FrontendRequest::AuthorizeKey` — it can write
//! the KVM's trust store. On unix the listener is a `UnixListener` guarded by
//! filesystem permissions. On Windows it was a plain
//! `TcpListener::bind("127.0.0.1:5252")` that **any local process could
//! reach**, with no authentication at all, and plausibly a web page:
//! `text/plain` is CORS-safelisted, so a `fetch()` needs no preflight, and the
//! listener's line-delimited parser skipped unparseable lines instead of
//! hanging up. It is now a named pipe that grants this user alone (#110).
//!
//! Both ends prove they hold the token without sending it ([`crate::proof`]),
//! so a frontend also knows it reached the daemon and not something that
//! took the endpoint first (#96). On Windows the token also names the pipe.
//! None of it is `cfg(windows)`-only: one code path that is compiled and
//! tested everywhere is worth more than a Windows-only branch that no test
//! and no non-Windows build ever exercises.
//!
//! # What it is not
//!
//! This is a *local* authorization boundary, not a cryptographic protocol. Any
//! process that can read the token file can already read `config.toml` and the
//! TLS identity next to it, at which point the machine is lost regardless. The
//! goal is to stop a process (or page) that can *reach a socket* but cannot
//! *read the user's config directory*. What a process that *can* read it may
//! do to trust is stated in the crate docs (#107).

use std::io;
use std::path::PathBuf;

const TOKEN_FILE: &str = "ipc-token";
const TOKEN_BYTES: usize = 32;
/// The token's length as frontends send it: two hex digits per byte.
pub(crate) const TOKEN_CHARS: usize = TOKEN_BYTES * 2;

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

/// Read the existing token, or mint one. Called by the daemon at startup, and
/// on Windows by frontends too, since the token names the daemon's pipe.
///
/// The file is created `0600` on unix. On Windows it inherits the ACL of the
/// user's `%LOCALAPPDATA%`, which is already user-scoped — the same protection
/// `config.toml` and the TLS key rely on.
pub fn load_or_create() -> io::Result<String> {
    load_or_create_at(&token_path()?)
}

/// [`load_or_create`] for the token kept at `path`.
///
/// Where there is no token yet, two processes may mint one at once. Only one
/// creates the file; the other reads the token it wrote. On Windows the token
/// names the pipe, and two tokens would put two daemons on two pipes.
pub fn load_or_create_at(path: &std::path::Path) -> io::Result<String> {
    let found = read_settled(path);
    if let Ok(existing) = &found {
        if let Some(token) = well_formed(existing) {
            return Ok(token);
        }
        // a truncated or hand-mangled token would lock every frontend out with a
        // confusing failure, so replace anything that isn't well-formed
        log::warn!("{path:?}: malformed IPC token — minting a new one");
    }
    let absent = matches!(&found, Err(e) if e.kind() == io::ErrorKind::NotFound);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut raw = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut raw)
        .map_err(|e| io::Error::other(format!("no OS randomness available: {e}")))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    match write_private(path, &token, absent) {
        Ok(()) => {}
        // Another process minted it first: use theirs.
        Err(e) if absent && e.kind() == io::ErrorKind::AlreadyExists => {
            return well_formed(&read_settled(path)?).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: the token another process wrote is malformed",
                        path.display()
                    ),
                )
            });
        }
        Err(e) => return Err(e),
    }
    log::info!("minted a new IPC token at {path:?}");
    Ok(token)
}

/// How long a token file that holds nothing yet, or the start of a token,
/// is read again before it counts as mangled.
const MINT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// The file at `path`, read again while it holds nothing yet or the start
/// of a token, for up to [`MINT_GRACE`]: another process that has just
/// created it may not have written it yet, however long the system keeps it
/// from running, and taking the empty file for a mangled one would replace
/// the token that process is about to use. Anything else is read once.
fn read_settled(path: &std::path::Path) -> io::Result<String> {
    let deadline = std::time::Instant::now() + MINT_GRACE;
    let mut text = read_at(path)?;
    while being_written(&text) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
        text = read_at(path)?;
    }
    Ok(text)
}

/// Whether `text` is what a token file holds part-way through being
/// written: nothing, or fewer hex digits than a token has.
fn being_written(text: &str) -> bool {
    text.len() < TOKEN_CHARS && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The token in `text`, if it is one.
fn well_formed(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() == TOKEN_CHARS && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| text.to_string())
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

/// Write `token` to `path`, readable by this user alone. With `new`, only if
/// there is no file there yet.
#[cfg(unix)]
fn write_private(path: &std::path::Path, token: &str, new: bool) -> io::Result<()> {
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
        .create_new(new)
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
fn write_private(path: &std::path::Path, token: &str, new: bool) -> io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(new)
        .truncate(true)
        .open(path)?;
    f.write_all(token.as_bytes())
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
mod minted_once {
    //! Processes that find no token and mint one at the same moment end up
    //! holding the same token. On Windows the token names the daemon's pipe,
    //! and a frontend and a daemon holding two tokens look for each other on
    //! two pipes.

    use super::load_or_create_at;

    // LEDGER T9609 | class B | 1 return values of token::load_or_create_at + 4 file on disk
    #[test]
    fn minters_racing_for_a_missing_token_all_hold_the_one_written() {
        let dir = std::env::temp_dir().join(format!("hops-token-race-{}", std::process::id()));
        let mut disagreed = Vec::new();
        for round in 0..20 {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("a scratch directory");
            let path = dir.join("ipc-token");
            let start = std::sync::Arc::new(std::sync::Barrier::new(8));
            let minters: Vec<_> = (0..8)
                .map(|_| {
                    let (path, start) = (path.clone(), start.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        load_or_create_at(&path).map_err(|e| e.to_string())
                    })
                })
                .collect();
            let held: Vec<_> = minters
                .into_iter()
                .map(|m| m.join().expect("a minter"))
                .collect();
            let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
            if held.iter().any(|h| h.as_deref() != Ok(on_disk.as_str())) {
                disagreed.push((round, held, on_disk));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            disagreed.is_empty(),
            "minters racing for a missing token came away holding tokens other \
             than the one on disk: {disagreed:?}"
        );
    }

    /// A minter that has created the file and is kept from writing it for a
    /// while, as a loaded system may do, still has its token used: taken for
    /// a mangled one, the empty file was replaced, and the two processes held
    /// two tokens.
    // LEDGER T9629 | class B | 1 return value of token::load_or_create_at + 4 file on disk
    #[test]
    fn a_token_file_not_yet_written_is_waited_for() {
        const THEIRS: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let dir = std::env::temp_dir().join(format!("hops-token-slow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("ipc-token");
        // Created, as `create_new` leaves it, and not yet written.
        std::fs::File::create(&path).expect("the other minter's empty file");
        let writing = {
            let path = path.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(200));
                std::fs::write(&path, THEIRS).expect("the other minter writes");
            })
        };
        let held = load_or_create_at(&path).map_err(|e| e.to_string());
        writing.join().expect("the other minter");
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            (held.as_deref(), on_disk.as_str()),
            (Ok(THEIRS), THEIRS),
            "(the token this process holds, the token on disk). A file another \
             minter had created and not yet written was replaced."
        );
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
